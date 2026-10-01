"""Business logic for asm-service: descubrimiento pasivo de subdominios via
Certificate Transparency (crt.sh) + chequeo del certificado TLS que un host
ya esta sirviendo publicamente. NUNCA hace escaneo activo de puertos/red:
crt.sh solo consulta registros publicos ya existentes, y el chequeo TLS es
un handshake normal al puerto 443 de un hostname que el usuario configuro
como propio (lo mismo que hace cualquier navegador al visitar el sitio).

Funciones puras (testeables sin DB/red/TLS real) arriba; funciones de I/O
(con manejo de error acotado, nunca deben tumbar el scheduler) abajo."""
import hashlib
import os
import ssl
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.logging import configure_logging
from app.models import (
    AlertSeverity,
    DiscoveredAsset,
    MonitoredDomain,
    SslCertificate,
    SurfaceAlert,
    SurfaceAlertType,
)

logger = configure_logging("asm-service")

SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")

# Como maximo estos hostnames activos se chequean por TLS en una sola
# corrida de un dominio -- evita que un dominio con miles de subdominios
# (o una CT log ruidosa) haga que una corrida tarde horas y bloquee al
# resto de los dominios de la cola del scheduler.
MAX_TLS_CHECKS_PER_RUN = 50

CRTSH_URL = "https://crt.sh/"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Logica pura ------------------------------------------------------

def normalize_domain(raw: str) -> str:
    """Normaliza lo que el usuario tipeo en el formulario de alta a un
    dominio plano ('empresa.com'): minusculas, sin protocolo, sin path ni
    query string. Levanta ValueError si lo que queda no parece un dominio
    (sin ningun punto) -- ese ValueError es lo que el endpoint POST /domains
    convierte en un 400."""
    domain = (raw or "").strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
            break
    # Cualquier cosa despues de la primera "/" es path -- si el usuario
    # pego "empresa.com/login" o una URL completa, nos quedamos solo con
    # el host. Mismo criterio para "?" (query string) por si pega la URL
    # con parametros.
    domain = domain.split("/", 1)[0].split("?", 1)[0]
    domain = domain.strip().rstrip(".")
    if not domain or "." not in domain:
        raise ValueError(f"Dominio invalido: '{raw}' -- se espera algo como 'empresa.com'")
    return domain


def parse_crtsh_entries(entries: list[dict]) -> set[str]:
    """crt.sh (?output=json) devuelve una lista de objetos por certificado;
    el campo 'name_value' puede tener VARIOS hostnames separados por '\\n'
    (todos los SANs de ese mismo certificado). Los wildcards ('*.empresa.com')
    se normalizan al dominio base ('empresa.com') -- un wildcard cubre
    cualquier subdominio de primer nivel, y lo que a este servicio le
    importa es la lista de hostnames "raiz" a los que despues intentarles
    un chequeo TLS real; guardar el '*.' tal cual no aporta nada ahi."""
    hostnames: set[str] = set()
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value") or ""
        for raw_name in name_value.split("\n"):
            name = raw_name.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]
            if name:
                hostnames.add(name)
    return hostnames


def diff_new_hostnames(known: set[str], discovered: set[str]) -> set[str]:
    """Hostnames en `discovered` que todavia no estaban en `known`."""
    return discovered - known


def cert_alert_for_expiry(not_after: datetime, now: datetime) -> tuple[str, str] | None:
    """Decide si el vencimiento de un certificado amerita una alerta, y con
    que severidad. Reglas (en este orden -- la primera que aplica gana):
    ya vencido -> critical; vence en <= 7 dias -> high; vence en <= 30
    dias -> medium; mas de 30 dias -> sin alerta (None)."""
    delta = not_after - now
    if delta.total_seconds() <= 0:
        return ("cert_expired", "critical")
    days_left = delta.total_seconds() / 86400
    if days_left <= 7:
        return ("cert_expiring", "high")
    if days_left <= 30:
        return ("cert_expiring", "medium")
    return None


def should_create_alert(existing_unacknowledged_alerts_for_host: list, alert_type: str, cooldown_hours: int = 24) -> bool:
    """Evita crear una alerta nueva en cada corrida del scheduler (cada
    ASM_CHECK_INTERVAL_HOURS) si ya existe una sin reconocer del MISMO tipo
    para el MISMO host, creada hace menos de `cooldown_hours`. Acepta
    cualquier objeto con atributos `.alert_type` y `.created_at` (instancias
    de SurfaceAlert en produccion; objetos simples en los tests, sin
    necesidad de DB)."""
    cutoff = _now() - timedelta(hours=cooldown_hours)
    for existing in existing_unacknowledged_alerts_for_host:
        existing_type = getattr(existing, "alert_type", None)
        existing_type_value = getattr(existing_type, "value", existing_type)
        if existing_type_value == alert_type and existing.created_at >= cutoff:
            return False
    return True


def _parse_asn1_date(value: str | None) -> datetime | None:
    """Parsea el formato de fecha que devuelve ssl.SSLSocket.getpeercert()
    para notBefore/notAfter, ej. 'Jun  1 12:00:00 2024 GMT'. Siempre viene
    en GMT (ver documentacion del modulo ssl), asi que se fija tzinfo=UTC
    a mano en vez de confiar en que %Z lo interprete (%Z es poco fiable
    entre plataformas)."""
    if not value:
        return None
    cleaned = value.replace(" GMT", "").strip()
    try:
        return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _format_cert_name(name_tuple) -> str:
    """getpeercert() devuelve issuer/subject como una tupla de RDNs, cada
    uno una tupla de pares (clave, valor) -- ej. (((('countryName','US'),),
    (('organizationName','Let's Encrypt'),)). Lo aplanamos a un string
    legible tipo 'countryName=US,organizationName=...' para guardarlo en
    SslCertificate.issuer/subject (columnas de texto simple)."""
    if not name_tuple:
        return ""
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ",".join(parts)[:500]


# --- I/O ----------------------------------------------------------------

async def fetch_crtsh_subdomains(domain: str, http_client: httpx.AsyncClient) -> set[str]:
    """GET a crt.sh (Certificate Transparency, publico, solo lectura de
    registros ya existentes -- NUNCA un escaneo activo). Ante cualquier
    falla (timeout, 503, HTML de error en vez de JSON -- crt.sh a veces
    devuelve eso bajo carga) se loguea un warning y se devuelve un set
    vacio: esta funcion NUNCA propaga la excepcion hacia el caller, para
    que un crt.sh caido no tumbe la corrida completa del dominio (el
    dominio raiz igual se sigue chequeando por TLS, ver run_domain_check)."""
    try:
        response = await http_client.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "SentinelOps-ASM/1.0"},
            timeout=20.0,
        )
        response.raise_for_status()
        entries = response.json()
        if not isinstance(entries, list):
            raise ValueError("respuesta de crt.sh no es una lista JSON")
        return parse_crtsh_entries(entries)
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("no se pudo consultar crt.sh", extra={"domain": domain, "error": str(exc)})
        return set()


async def fetch_tls_certificate(hostname: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Abre una conexion TLS real (handshake TLS normal, igual al que hace
    cualquier navegador) contra hostname:port SOLO para leer el certificado
    que el host ya esta sirviendo -- no valida la cadena de confianza
    (check_hostname=False, verify_mode=CERT_NONE) a proposito, porque el
    objetivo es leer el certificado que sea (incluso uno vencido o
    autofirmado), no rechazarlo como haria un browser.

    Devuelve un dict con issuer/subject/not_before/not_after/fingerprint_sha256
    en exito, o {"error": "<mensaje corto>"} ante CUALQUIER falla (timeout,
    connection refused, DNS que no resuelve, handshake roto) -- nunca tira
    una excepcion hacia el caller; ese 'error' es lo que puebla
    SslCertificate.last_error.

    LIMITACION CONOCIDA: con verify_mode=CERT_NONE, ssl.SSLSocket.getpeercert()
    puede devolver un dict vacio en vez de la cadena parseada, dependiendo
    de la version de Python/OpenSSL (ver https://bugs.python.org/issue32450).
    Para ese caso se intenta releer el certificado en formato DER
    (getpeercert(binary_form=True)) y parsearlo con el modulo `cryptography`
    si esta disponible (ya viene instalado transitivamente via
    python-jose[cryptography], usado por backend.shared.security). Si
    `cryptography` no esta disponible o el DER tampoco vino, se devuelve un
    error explicito -- el soporte de certificados autofirmados/con cadena
    rota queda PARCIAL, documentado aca a proposito: la gran mayoria de
    sitios en produccion sirven certs de una CA publica, donde este camino
    no hace falta."""
    try:
        return await _do_fetch_tls_certificate(hostname, port, timeout)
    except Exception as exc:  # noqa: BLE001 -- nunca debe escaparse hacia run_domain_check/el scheduler
        return {"error": f"{type(exc).__name__}: {exc}"[:500]}


async def _do_fetch_tls_certificate(hostname: str, port: int, timeout: float) -> dict:
    import asyncio

    async def _connect_and_read() -> dict:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(hostname, port, ssl=ssl_context, server_hostname=hostname)
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            peercert = writer.get_extra_info("peercert")
            if not peercert and ssl_object is not None:
                peercert = ssl_object.getpeercert()

            if peercert:
                fingerprint = ""
                if ssl_object is not None:
                    der = ssl_object.getpeercert(binary_form=True)
                    if der:
                        fingerprint = hashlib.sha256(der).hexdigest()
                return {
                    "issuer": _format_cert_name(peercert.get("issuer")),
                    "subject": _format_cert_name(peercert.get("subject")),
                    "not_before": _parse_asn1_date(peercert.get("notBefore")),
                    "not_after": _parse_asn1_date(peercert.get("notAfter")),
                    "fingerprint_sha256": fingerprint,
                }

            # peercert vacio (tipico con verify_mode=CERT_NONE en algunas
            # versiones de Python) -- intento de fallback via DER crudo +
            # `cryptography`, ver docstring de fetch_tls_certificate.
            if ssl_object is not None:
                der = ssl_object.getpeercert(binary_form=True)
                if der:
                    return _parse_der_certificate(der)
            return {"error": "el servidor no devolvio informacion de certificado utilizable (posible autofirmado; soporte parcial)"}
        finally:
            writer.close()

    return await asyncio.wait_for(_connect_and_read(), timeout=timeout)


def _parse_der_certificate(der: bytes) -> dict:
    """Fallback cuando ssl.getpeercert() no trae nada usable (ver
    _do_fetch_tls_certificate). Requiere el paquete `cryptography` -- si no
    esta instalado, devuelve un error explicito en vez de fallar duro."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return {"error": "no se pudo leer el certificado (cadena no verificada y falta 'cryptography' para parsear el DER -- soporte parcial de certs autofirmados)"}
    try:
        cert = x509.load_der_x509_certificate(der)
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        return {
            "issuer": cert.issuer.rfc4514_string()[:500],
            "subject": cert.subject.rfc4514_string()[:500],
            "not_before": not_before,
            "not_after": not_after,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }
    except Exception as exc:  # noqa: BLE001 -- este es ya el ultimo fallback, cualquier falla vuelve error legible
        return {"error": f"error parseando certificado DER: {exc}"[:500]}


def _severity_value(severity) -> str:
    return getattr(severity, "value", severity)


async def _unacknowledged_alerts_for_host(
    db: AsyncSession, organization_id: str | None, hostname: str, alert_type: str
) -> list[SurfaceAlert]:
    result = await db.execute(
        select(SurfaceAlert).where(
            SurfaceAlert.organization_id == organization_id,
            SurfaceAlert.hostname == hostname,
            SurfaceAlert.alert_type == alert_type,
            SurfaceAlert.is_acknowledged.is_(False),
        )
    )
    return list(result.scalars().all())


async def _create_alert_if_needed(
    db: AsyncSession,
    monitored_domain: MonitoredDomain,
    hostname: str,
    alert_type: SurfaceAlertType,
    severity: AlertSeverity,
    detail: str,
) -> SurfaceAlert | None:
    unacknowledged = await _unacknowledged_alerts_for_host(
        db, monitored_domain.organization_id, hostname, alert_type.value
    )
    if not should_create_alert(unacknowledged, alert_type.value):
        return None
    alert = SurfaceAlert(
        organization_id=monitored_domain.organization_id,
        monitored_domain_id=monitored_domain.id,
        alert_type=alert_type,
        hostname=hostname,
        severity=severity,
        detail=detail[:1000],
    )
    db.add(alert)
    await db.flush()
    await _forward_alert_to_siem(alert, monitored_domain.organization_id)
    return alert


async def run_domain_check(db: AsyncSession, monitored_domain: MonitoredDomain, http_client: httpx.AsyncClient) -> None:
    """Orquesta una corrida completa de monitoreo para un MonitoredDomain:
    1) descubre subdominios via crt.sh, los diffea contra lo ya conocido,
       crea filas + alertas para los nunca vistos, y marca is_active=False
       en los que dejaron de aparecer (sin borrarlos -- se conserva el
       historico). El dominio raiz mismo SIEMPRE se considera activo, aunque
       crt.sh no lo devuelva como entrada separada.
    2) para como maximo MAX_TLS_CHECKS_PER_RUN activos activos, chequea el
       certificado TLS que estan sirviendo y genera alertas de vencimiento
       o de fallo de chequeo segun corresponda."""
    domain = monitored_domain.domain
    discovered = await fetch_crtsh_subdomains(domain, http_client)
    discovered.add(domain)

    existing_result = await db.execute(
        select(DiscoveredAsset).where(DiscoveredAsset.monitored_domain_id == monitored_domain.id)
    )
    existing_by_hostname: dict[str, DiscoveredAsset] = {a.hostname: a for a in existing_result.scalars().all()}
    known_hostnames = set(existing_by_hostname.keys())

    now = _now()
    new_hostnames = diff_new_hostnames(known_hostnames, discovered)
    for hostname in new_hostnames:
        asset = DiscoveredAsset(
            organization_id=monitored_domain.organization_id,
            monitored_domain_id=monitored_domain.id,
            hostname=hostname,
            first_seen_at=now,
            last_seen_at=now,
            is_active=True,
        )
        db.add(asset)
        existing_by_hostname[hostname] = asset
        await _create_alert_if_needed(
            db, monitored_domain, hostname, SurfaceAlertType.new_subdomain, AlertSeverity.info,
            f"Nuevo subdominio detectado via Certificate Transparency: {hostname}",
        )

    for hostname, asset in existing_by_hostname.items():
        if hostname in discovered:
            asset.is_active = True
            asset.last_seen_at = now
        else:
            asset.is_active = False
    await db.flush()

    active_assets = [a for a in existing_by_hostname.values() if a.is_active][:MAX_TLS_CHECKS_PER_RUN]
    for asset in active_assets:
        await _check_certificate_for_asset(db, monitored_domain, asset, now)
    await db.flush()


async def _check_certificate_for_asset(
    db: AsyncSession, monitored_domain: MonitoredDomain, asset: DiscoveredAsset, now: datetime
) -> None:
    cert_data = await fetch_tls_certificate(asset.hostname)

    cert_result = await db.execute(
        select(SslCertificate).where(
            SslCertificate.organization_id == monitored_domain.organization_id,
            SslCertificate.hostname == asset.hostname,
        )
    )
    cert = cert_result.scalar_one_or_none()
    if cert is None:
        cert = SslCertificate(organization_id=monitored_domain.organization_id, hostname=asset.hostname)
        db.add(cert)
    cert.last_checked_at = now

    error = cert_data.get("error")
    if error:
        cert.last_error = error[:500]
        await _create_alert_if_needed(
            db, monitored_domain, asset.hostname, SurfaceAlertType.cert_check_failed, AlertSeverity.low,
            f"No se pudo chequear el certificado TLS de {asset.hostname}: {error}",
        )
        return

    cert.last_error = ""
    cert.issuer = cert_data.get("issuer", "")
    cert.subject = cert_data.get("subject", "")
    cert.not_before = cert_data.get("not_before")
    cert.not_after = cert_data.get("not_after")
    cert.fingerprint_sha256 = cert_data.get("fingerprint_sha256", "")

    if cert.not_after is None:
        return
    expiry_alert = cert_alert_for_expiry(cert.not_after, now)
    if expiry_alert is None:
        return
    alert_type_value, severity_value = expiry_alert
    await _create_alert_if_needed(
        db, monitored_domain, asset.hostname, SurfaceAlertType(alert_type_value), AlertSeverity(severity_value),
        f"El certificado de {asset.hostname} vence el {cert.not_after.isoformat()}",
    )


async def _forward_alert_to_siem(alert: SurfaceAlert, organization_id: str | None) -> None:
    """Best-effort, mismo patron que scan-service::_forward_findings_to_siem_service:
    si siem-service no responde, la alerta ya quedo guardada igual en este
    servicio. Solo se reenvian severidades high/critical -- info/low/medium
    (subdominio nuevo, cooldown de fallos de chequeo, vencimiento lejano) no
    ensucian el SIEM."""
    severity = _severity_value(alert.severity)
    if severity not in ("high", "critical"):
        return
    payload = {
        "organization_id": organization_id,
        "events": [
            {
                "host": alert.hostname,
                "event_action": "asm_alert",
                "event_category": "network",
                "event_outcome": "success",
                "message": alert.detail,
                "source_type": "asm",
                "asset_id": None,
                "severity": severity,
            }
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SIEM_SERVICE_URL}/logs/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar alerta a siem-service", extra={"alert_id": alert.id, "error": str(exc)})


# --- Scheduler ------------------------------------------------------------

async def check_all_enabled_domains(session_factory) -> None:
    """Llamado por el scheduler en proceso (APScheduler, ver app/main.py)
    cada ASM_CHECK_INTERVAL_HOURS. Itera TODOS los MonitoredDomain
    habilitados de TODAS las organizaciones -- un dominio que falla (crt.sh
    caido, excepcion no prevista) no debe impedir que se chequeen los
    demas, asi que cada dominio corre en su propia sesion/try-except,
    exactamente como scan-service aisla cada ScanJob programado."""
    async with session_factory() as db:
        result = await db.execute(select(MonitoredDomain).where(MonitoredDomain.is_enabled.is_(True)))
        domain_ids = [d.id for d in result.scalars().all()]

    async with httpx.AsyncClient() as http_client:
        for domain_id in domain_ids:
            await run_domain_check_now(session_factory, domain_id, http_client)


async def run_domain_check_now(session_factory, domain_id: str, http_client: httpx.AsyncClient | None = None) -> None:
    """Corre un chequeo para UN dominio, con su propia sesion de DB -- usado
    tanto por el job periodico (check_all_enabled_domains) como por
    POST /domains/{id}/check-now (via BackgroundTasks, ver app/main.py)."""
    async with session_factory() as db:
        domain = await db.get(MonitoredDomain, domain_id)
        if domain is None or not domain.is_enabled:
            return
        try:
            if http_client is not None:
                await run_domain_check(db, domain, http_client)
            else:
                async with httpx.AsyncClient() as owned_client:
                    await run_domain_check(db, domain, owned_client)
            await db.commit()
        except Exception as exc:  # noqa: BLE001 -- un dominio no debe tumbar el scheduler ni dejar la sesion colgada
            logger.error("error chequeando dominio de superficie", extra={"domain_id": domain_id, "error": str(exc)})
            await db.rollback()


# --- CRUD ------------------------------------------------------------------

async def domain_exists(db: AsyncSession, organization_id: str | None, domain: str) -> bool:
    result = await db.execute(
        select(MonitoredDomain.id).where(
            MonitoredDomain.organization_id == organization_id, MonitoredDomain.domain == domain
        )
    )
    return result.first() is not None


async def create_domain(db: AsyncSession, domain: str, organization_id: str | None, created_by: str) -> MonitoredDomain:
    monitored = MonitoredDomain(domain=domain, organization_id=organization_id, created_by=created_by)
    db.add(monitored)
    await db.flush()
    await db.refresh(monitored)
    return monitored


async def list_domains(db: AsyncSession, organization_id: str | None) -> list[MonitoredDomain]:
    result = await db.execute(
        select(MonitoredDomain).where(MonitoredDomain.organization_id == organization_id).order_by(MonitoredDomain.domain)
    )
    return list(result.scalars().all())


async def get_domain(db: AsyncSession, domain_id: str, organization_id: str | None) -> MonitoredDomain | None:
    """organization_id obligatorio, mismo criterio que asset-service::get_asset:
    devuelve None tanto si el dominio no existe como si es de otra
    organizacion, para no filtrar por timing/existencia cual es cual."""
    domain = await db.get(MonitoredDomain, domain_id)
    if domain is None or domain.organization_id != organization_id:
        return None
    return domain


async def delete_domain(db: AsyncSession, domain: MonitoredDomain) -> None:
    await db.delete(domain)
    await db.flush()


async def list_assets_for_domain(db: AsyncSession, monitored_domain_id: str, organization_id: str | None) -> list[DiscoveredAsset]:
    result = await db.execute(
        select(DiscoveredAsset)
        .where(
            DiscoveredAsset.monitored_domain_id == monitored_domain_id,
            DiscoveredAsset.organization_id == organization_id,
        )
        .order_by(DiscoveredAsset.hostname)
    )
    return list(result.scalars().all())


async def list_alerts(
    db: AsyncSession, organization_id: str | None, acknowledged: bool | None = None
) -> list[SurfaceAlert]:
    query = select(SurfaceAlert).where(SurfaceAlert.organization_id == organization_id)
    if acknowledged is not None:
        query = query.where(SurfaceAlert.is_acknowledged.is_(acknowledged))
    result = await db.execute(query.order_by(SurfaceAlert.created_at.desc()))
    return list(result.scalars().all())


async def get_alert(db: AsyncSession, alert_id: str, organization_id: str | None) -> SurfaceAlert | None:
    alert = await db.get(SurfaceAlert, alert_id)
    if alert is None or alert.organization_id != organization_id:
        return None
    return alert


async def acknowledge_alert(db: AsyncSession, alert: SurfaceAlert, acknowledged_by: str) -> SurfaceAlert:
    alert.is_acknowledged = True
    alert.acknowledged_by = acknowledged_by
    await db.flush()
    await db.refresh(alert)
    return alert
