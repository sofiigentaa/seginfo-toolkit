"""Business logic for vuln-service: ingesta de hallazgos normalizados,
enriquecimiento (CVSS/EPSS/KEV), calculo de prioridad y workflow de triage
(confirmar / falso positivo / riesgo aceptado / remediado)."""
import os
from datetime import datetime, timezone
import httpx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from backend.shared.security import create_access_token
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.models import Vulnerability, VulnStatus, VulnSeverity
from app import enrichment

logger = configure_logging("vuln-service")

ASSET_SERVICE_URL = os.getenv("ASSET_SERVICE_URL", "http://asset-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_severity(value: str) -> VulnSeverity:
    try:
        return VulnSeverity(value)
    except ValueError:
        return VulnSeverity.info


async def _get_asset_criticality(asset_id: str | None, organization_id: str) -> str:
    """Best-effort: consulta asset-service por la criticidad del activo para
    ponderar el priority_score. Si el activo no existe o el servicio no
    responde, se asume criticidad 'medium' (no bloquea la ingesta).

    asset-service exige un JWT valido (get_current_claims) en GET
    /assets/{id} y ademas filtra por organization_id -- se emite un JWT de
    servicio-a-servicio de corta vida con el MISMO org_id que este hallazgo
    (no un token generico), para que la consulta caiga dentro del tenant
    correcto y nunca pueda leer un activo de otra organizacion."""
    if not asset_id:
        return "medium"
    token = create_access_token("system:vuln-service", "admin", org_id=organization_id)
    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{ASSET_SERVICE_URL}/assets/{asset_id}", headers=headers)
            if resp.status_code == 200:
                return resp.json().get("criticality", "medium")
    except httpx.HTTPError as exc:
        logger.warning("no se pudo consultar asset-service", extra={"asset_id": asset_id, "error": str(exc)})
    return "medium"


async def ingest_findings(db: AsyncSession, payload) -> tuple[int, int]:
    """Crea o actualiza registros de Vulnerability a partir de hallazgos de
    scan-service. Deduplica por (asset_id, cve_id o titulo) para no crear un
    registro nuevo por cada corrida de escaneo sobre el mismo activo, SIEMPRE
    dentro de la misma organizacion (dos tenants pueden tener assets con el
    mismo id solo si comparten... en realidad nunca, los ids son uuid, pero
    el filtro de organization_id se mantiene por defensa en profundidad)."""
    organization_id = payload.organization_id or DEFAULT_ORGANIZATION_ID
    created, updated = 0, 0
    asset_criticality = await _get_asset_criticality(payload.asset_id, organization_id)

    for finding in payload.findings:
        existing = await _find_existing(db, organization_id, payload.asset_id, finding.cve_id, finding.title)
        if existing is not None:
            existing.scan_job_id = payload.scan_job_id or existing.scan_job_id
            existing.source_scanner = payload.scanner_type or existing.source_scanner
            existing.description = finding.description or existing.description
            existing.updated_at = _now()
            updated += 1
            vuln = existing
        else:
            vuln = Vulnerability(
                organization_id=organization_id,
                cve_id=finding.cve_id,
                title=finding.title,
                description=finding.description,
                severity=_normalize_severity(finding.severity),
                source_scanner=payload.scanner_type,
                scan_job_id=payload.scan_job_id,
                asset_id=payload.asset_id,
                package=finding.package or "",
                installed_version=finding.installed_version or "",
                fixed_version=finding.fixed_version or "",
                port=finding.port,
                service=finding.service or "",
            )
            db.add(vuln)
            await db.flush()
            created += 1

        if finding.cve_id:
            await _enrich(vuln, asset_criticality)
        else:
            vuln.priority_score = enrichment.compute_priority_score(None, None, False, asset_criticality)

    await db.flush()
    return created, updated


async def _find_existing(
    db: AsyncSession, organization_id: str, asset_id: str | None, cve_id: str | None, title: str
) -> Vulnerability | None:
    query = select(Vulnerability).where(
        Vulnerability.organization_id == organization_id, Vulnerability.status != VulnStatus.remediated
    )
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.where(Vulnerability.cve_id == cve_id)
    else:
        query = query.where(Vulnerability.cve_id.is_(None), Vulnerability.title == title)
    result = await db.execute(query.limit(1))
    return result.scalar_one_or_none()


async def _enrich(vuln: Vulnerability, asset_criticality: str) -> None:
    cvss_score, cvss_vector = await enrichment.fetch_cvss(vuln.cve_id)
    epss_score = await enrichment.fetch_epss(vuln.cve_id)
    is_kev, kev_date = await enrichment.check_kev(vuln.cve_id)

    vuln.cvss_score = cvss_score if cvss_score is not None else vuln.cvss_score
    vuln.cvss_vector = cvss_vector or vuln.cvss_vector
    vuln.epss_score = epss_score if epss_score is not None else vuln.epss_score
    vuln.is_kev = is_kev or vuln.is_kev
    vuln.kev_date_added = kev_date or vuln.kev_date_added
    vuln.priority_score = enrichment.compute_priority_score(vuln.cvss_score, vuln.epss_score, vuln.is_kev, asset_criticality)
    vuln.last_enriched_at = _now()


async def reenrich_vulnerability(db: AsyncSession, vuln: Vulnerability) -> Vulnerability:
    if vuln.cve_id:
        organization_id = vuln.organization_id or DEFAULT_ORGANIZATION_ID
        asset_criticality = await _get_asset_criticality(vuln.asset_id, organization_id)
        await _enrich(vuln, asset_criticality)
        await db.flush()
    return vuln


async def list_vulnerabilities(
    db: AsyncSession,
    organization_id: str,
    status_filter: str | None = None,
    severity: str | None = None,
    asset_id: str | None = None,
    min_priority: float | None = None,
    scan_job_id: str | None = None,
) -> list[Vulnerability]:
    query = select(Vulnerability).where(Vulnerability.organization_id == organization_id)
    if status_filter:
        query = query.where(Vulnerability.status == status_filter)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if min_priority is not None:
        query = query.where(Vulnerability.priority_score >= min_priority)
    if scan_job_id:
        # Usado por la pagina de Escaneos para mostrar los resultados
        # enriquecidos (severidad/CVSS/EPSS/remediacion) de UN escaneo
        # puntual. OJO: si el mismo activo se volvio a escanear despues,
        # ingest_findings reasigna scan_job_id al escaneo MAS RECIENTE que
        # toco cada fila (ver ese metodo) -- este filtro muestra el estado
        # actual de esas vulnerabilidades, que puede no coincidir 1 a 1 con
        # los hallazgos crudos de un escaneo viejo si hubo un rescan.
        query = query.where(Vulnerability.scan_job_id == scan_job_id)
    result = await db.execute(query.order_by(Vulnerability.priority_score.desc(), Vulnerability.created_at.desc()))
    return list(result.scalars().all())


async def get_vulnerability(db: AsyncSession, vuln_id: str, organization_id: str) -> Vulnerability | None:
    vuln = await db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.organization_id != organization_id:
        return None
    return vuln


async def triage_vulnerability(db: AsyncSession, vuln: Vulnerability, payload, actor: str) -> Vulnerability:
    vuln.status = payload.status
    vuln.triage_note = payload.note
    vuln.triaged_by = actor
    vuln.updated_at = _now()
    await db.flush()
    await db.refresh(vuln)
    return vuln


async def get_stats(db: AsyncSession, organization_id: str) -> dict:
    total_result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.organization_id == organization_id)
    )
    total = total_result.scalar_one()

    by_status = dict(
        (row[0].value, row[1])
        for row in (await db.execute(
            select(Vulnerability.status, func.count(Vulnerability.id))
            .where(Vulnerability.organization_id == organization_id)
            .group_by(Vulnerability.status)
        )).all()
    )
    by_severity = dict(
        (row[0].value, row[1])
        for row in (await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.organization_id == organization_id)
            .group_by(Vulnerability.severity)
        )).all()
    )
    kev_result = await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.organization_id == organization_id, Vulnerability.is_kev.is_(True)
        )
    )
    kev_count = kev_result.scalar_one()

    avg_result = await db.execute(
        select(func.avg(Vulnerability.priority_score)).where(Vulnerability.organization_id == organization_id)
    )
    avg_priority = avg_result.scalar_one() or 0.0

    return {
        "total": total,
        "by_status": by_status,
        "by_severity": by_severity,
        "kev_count": kev_count,
        "avg_priority_score": round(float(avg_priority), 2),
    }
