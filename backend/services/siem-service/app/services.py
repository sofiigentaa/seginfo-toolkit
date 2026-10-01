"""Business logic for siem-service: ingesta -> normalizacion ECS -> indexado
en OpenSearch -> evaluacion de reglas Sigma habilitadas -> creacion de
Alert cuando corresponde -> notificacion best-effort a soar-service para
que evalue playbooks de respuesta. Todo es deteccion/analisis sobre datos
ya ingeridos; no se ejecuta ninguna accion contra el evento de origen."""
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.ecs import normalize_event
from app.sigma import evaluate_rule
from app.models import SigmaRule, Alert, AlertStatus
from app import opensearch_client

logger = configure_logging("siem-service")

SOAR_SERVICE_URL = os.getenv("SOAR_SERVICE_URL", "http://soar-service:8000")
THREATINTEL_SERVICE_URL = os.getenv("THREATINTEL_SERVICE_URL", "http://threatintel-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def ingest_events(db: AsyncSession, os_client, payload) -> tuple[int, int]:
    organization_id = payload.organization_id or DEFAULT_ORGANIZATION_ID
    indexed = 0
    alerts_created = 0

    rules_result = await db.execute(
        select(SigmaRule).where(SigmaRule.organization_id == organization_id, SigmaRule.is_enabled.is_(True))
    )
    enabled_rules = list(rules_result.scalars().all())

    for event_in in payload.events:
        document = normalize_event(event_in.model_dump(), organization_id)
        await opensearch_client.index_event(os_client, document)
        indexed += 1

        for rule in enabled_rules:
            try:
                matched = evaluate_rule(document, rule.detection)
            except Exception as exc:  # regla mal formada no debe tumbar la ingesta
                logger.warning("regla sigma invalida, se omite", extra={"rule_id": rule.id, "error": str(exc)})
                continue
            if matched:
                alert = await _create_alert(db, rule, document, organization_id)
                alerts_created += 1
                await _enrich_alert_with_threat_intel(alert, document)
                await _notify_soar(alert, organization_id)

    await db.flush()
    return indexed, alerts_created


async def _create_alert(db: AsyncSession, rule: SigmaRule, event: dict, organization_id: str) -> Alert:
    alert = Alert(
        organization_id=organization_id,
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        matched_event=event,
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)
    logger.info("alerta generada", extra={"alert_id": alert.id, "rule": rule.name, "severity": rule.severity.value})
    return alert


def _extract_ips_from_event(event: dict) -> list[str]:
    """Funcion pura: junta las IPs presentes en un documento ECS-lite ya
    normalizado (ver app/ecs.py::normalize_event -- event["source"]["ip"]
    / event["destination"]["ip"], que vienen de source_ip/dest_ip en
    LogEventIn) para mandarlas a threatintel-service. Deduplica y descarta
    vacios (un evento sin source_ip o sin dest_ip normaliza a "")."""
    ips = [
        (event.get("source") or {}).get("ip") or "",
        (event.get("destination") or {}).get("ip") or "",
    ]
    return list(dict.fromkeys(ip for ip in ips if ip))


def _malicious_ips_from_lookup(lookup_results: list[dict]) -> dict:
    """Funcion pura: de la respuesta de POST /internal/lookup-batch de
    threatintel-service, se queda solo con las IPs que vinieron marcadas
    is_malicious=True -- a proposito, para no inflar Alert.threat_intel
    con ruido de IPs limpias o que no se pudieron chequear (None)."""
    return {
        r["ip"]: {k: v for k, v in r.items() if k != "ip"}
        for r in lookup_results
        if r.get("is_malicious") is True
    }


async def _enrich_alert_with_threat_intel(alert: Alert, event: dict) -> None:
    """Best-effort, igual patron que _notify_soar de mas abajo: si
    threatintel-service no responde (esta caido, tarda, devuelve un error),
    la alerta ya quedo guardada igual, sin enriquecimiento -- esto nunca
    debe tumbar la ingesta ni la creacion de la alerta."""
    ips = _extract_ips_from_event(event)
    if not ips:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(f"{THREATINTEL_SERVICE_URL}/internal/lookup-batch", json={"ips": ips})
            response.raise_for_status()
            results = response.json().get("results", [])
    except httpx.HTTPError as exc:
        logger.warning("no se pudo enriquecer la alerta con threat intel", extra={"alert_id": alert.id, "error": str(exc)})
        return

    malicious = _malicious_ips_from_lookup(results)
    if malicious:
        alert.threat_intel = malicious


async def _notify_soar(alert: Alert, organization_id: str) -> None:
    """Best-effort: si soar-service no responde, la alerta ya quedo guardada
    igual; esto solo dispara la evaluacion automatica de playbooks."""
    payload = {
        "alert_id": alert.id,
        "rule_name": alert.rule_name,
        "severity": alert.severity.value,
        "event": alert.matched_event,
        "organization_id": organization_id,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SOAR_SERVICE_URL}/trigger", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo notificar a soar-service", extra={"alert_id": alert.id, "error": str(exc)})


async def create_rule(db: AsyncSession, payload, organization_id: str) -> SigmaRule:
    rule = SigmaRule(**payload.model_dump(), organization_id=organization_id)
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


async def list_rules(db: AsyncSession, organization_id: str, enabled_only: bool = False) -> list[SigmaRule]:
    query = select(SigmaRule).where(SigmaRule.organization_id == organization_id)
    if enabled_only:
        query = query.where(SigmaRule.is_enabled.is_(True))
    result = await db.execute(query.order_by(SigmaRule.name))
    return list(result.scalars().all())


async def get_rule(db: AsyncSession, rule_id: str, organization_id: str) -> SigmaRule | None:
    rule = await db.get(SigmaRule, rule_id)
    if rule is None or rule.organization_id != organization_id:
        return None
    return rule


async def update_rule(db: AsyncSession, rule: SigmaRule, payload) -> SigmaRule:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    await db.flush()
    await db.refresh(rule)
    return rule


async def delete_rule(db: AsyncSession, rule: SigmaRule) -> None:
    await db.delete(rule)
    await db.flush()


# Reglas recomendadas para arrancar sin tener que escribir JSON a mano --
# pensadas especificamente para el pipeline de escaneos (scan-service manda
# un evento por hallazgo con event.category=vulnerability y
# sentinelops.severity segun lo que informo el scanner, ver
# scan-service/app/services.py::_forward_findings_to_siem_service).
# Idempotente: seed_default_rules no duplica una regla si ya existe una con
# el mismo nombre en esta organizacion.
DEFAULT_RULES: list[dict] = [
    {
        "name": "Hallazgo critico de escaneo",
        "description": "Un escaneo (nmap/trivy/nuclei/openvas) reporto un hallazgo de severidad critica.",
        "severity": "critical",
        "tags": ["scan", "vulnerability", "critical"],
        "detection": {
            "selection_1": {"event.category": "vulnerability", "sentinelops.severity": "critical"},
            "condition": "selection_1",
        },
    },
    {
        "name": "Hallazgo alto de escaneo",
        "description": "Un escaneo reporto un hallazgo de severidad alta.",
        "severity": "high",
        "tags": ["scan", "vulnerability", "high"],
        "detection": {
            "selection_1": {"event.category": "vulnerability", "sentinelops.severity": "high"},
            "condition": "selection_1",
        },
    },
    {
        "name": "Login fallido repetido en cuenta administrativa",
        "description": "Evento de autenticacion fallida sobre una cuenta admin/root -- util para forwarders de logs de auth.",
        "severity": "medium",
        "tags": ["auth", "brute-force"],
        "detection": {
            "selection_1": {"event.action": "user_login", "event.outcome": "failure", "user.name": ["admin", "root"]},
            "condition": "selection_1",
        },
    },
]


async def seed_default_rules(db: AsyncSession, organization_id: str) -> list[SigmaRule]:
    existing_result = await db.execute(
        select(SigmaRule.name).where(SigmaRule.organization_id == organization_id)
    )
    existing_names = {row[0] for row in existing_result.all()}

    created: list[SigmaRule] = []
    for spec in DEFAULT_RULES:
        if spec["name"] in existing_names:
            continue
        rule = SigmaRule(
            organization_id=organization_id,
            name=spec["name"],
            description=spec["description"],
            severity=spec["severity"],
            tags=spec["tags"],
            detection=spec["detection"],
            is_enabled=True,
        )
        db.add(rule)
        created.append(rule)

    if created:
        await db.flush()
        for rule in created:
            await db.refresh(rule)
    return created


async def list_alerts(
    db: AsyncSession, organization_id: str, status_filter: str | None = None, severity: str | None = None
) -> list[Alert]:
    query = select(Alert).where(Alert.organization_id == organization_id)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if severity:
        query = query.where(Alert.severity == severity)
    result = await db.execute(query.order_by(Alert.created_at.desc()))
    return list(result.scalars().all())


async def get_alert(db: AsyncSession, alert_id: str, organization_id: str) -> Alert | None:
    alert = await db.get(Alert, alert_id)
    if alert is None or alert.organization_id != organization_id:
        return None
    return alert


def _resolve_alert_update(
    current_notes: str, current_acknowledged_by: str, payload_status, payload_notes: str | None, actor: str
) -> tuple[str, str]:
    """Funcion pura: calcula (notes, acknowledged_by) resultantes de aplicar
    un AlertUpdate sobre los valores actuales. payload_notes es None cuando
    el caller no mando notas (ej. los botones Reconocer/Cerrar de la UI, que
    solo mandan {status}) -- en ese caso NO se debe pisar la nota ya
    guardada. acknowledged_by solo se actualiza al pasar a 'acknowledged'
    (bug historico: PATCH /alerts/{id} sobreescribia notes con "" en cada
    cambio de estado porque AlertUpdate.notes tenia default "" en vez de
    None, ver app/schemas.py::AlertUpdate)."""
    new_notes = current_notes if payload_notes is None else payload_notes
    new_acknowledged_by = actor if payload_status == AlertStatus.acknowledged else current_acknowledged_by
    return new_notes, new_acknowledged_by


async def update_alert(db: AsyncSession, alert: Alert, payload, actor: str) -> Alert:
    alert.status = payload.status
    alert.notes, alert.acknowledged_by = _resolve_alert_update(
        alert.notes, alert.acknowledged_by, payload.status, payload.notes, actor
    )
    await db.flush()
    await db.refresh(alert)
    return alert


async def search_logs(os_client, organization_id: str, query_text: str | None, host: str | None, size: int) -> list[dict]:
    must = [{"term": {"organization_id": organization_id}}]
    if query_text:
        must.append({"match": {"message": query_text}})
    if host:
        must.append({"term": {"host.name": host}})
    query = {"bool": {"must": must}}
    return await opensearch_client.search_events(os_client, query, size)
