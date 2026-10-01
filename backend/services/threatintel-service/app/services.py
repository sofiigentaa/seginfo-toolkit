"""Business logic for threatintel-service: dado una IP (tipicamente
source_ip/dest_ip de un evento de log ingerido por siem-service), resuelve
si es una IP maliciosa conocida contra fuentes externas (AbuseIPDB, MISP),
cacheando el resultado 24hs para no gastar cupo de esas fuentes en la misma
IP una y otra vez. No ejecuta ninguna accion de contencion -- solo
enriquece con contexto; eso es responsabilidad de soar-service/
integration-service."""
import asyncio
import ipaddress
import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import SessionLocal
from backend.shared.logging import configure_logging
from app.models import IpReputationCache

logger = configure_logging("threatintel-service")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
MISP_URL = os.getenv("MISP_URL", "")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")

CACHE_TTL_HOURS = 24

# Catalogo publico de categorias de AbuseIPDB (no cambia entre cuentas, no
# hace falta llamar a ningun endpoint para resolverlo) -- se usa solo para
# mostrar algo mas legible que un id numerico en la UI. Un id que no este
# en este mapa (categoria nueva que AbuseIPDB agregue mas adelante) se deja
# como el numero tal cual, en vez de fallar o inventar un nombre.
ABUSEIPDB_CATEGORIES: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def is_private_or_reserved_ip(ip: str) -> bool:
    """Funcion pura. CRITICO para no gastar cupo de la API externa
    (AbuseIPDB free tier: 1000 consultas/dia) chequeando IPs internas
    (10.x, 172.16-31.x, 192.168.x, 127.x, etc) que jamas van a estar en una
    blacklist publica -- ver lookup_ip. Una IP invalida (no parseable) se
    trata como privada/reservada a proposito: nunca se manda algo que no
    es una IP valida a una API externa."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast


def is_cache_fresh(ttl_expires_at: datetime, now: datetime) -> bool:
    """Funcion pura. En el limite exacto (now == ttl_expires_at) se
    considera vencida -- ttl_expires_at es el instante en el que el cache
    deja de ser valido, no el ultimo instante en que todavia lo es."""
    return now < ttl_expires_at


def parse_abuseipdb_response(json_body: dict, malicious_score_threshold: int = 50) -> dict:
    """Funcion pura: extrae score/categorias de la respuesta cruda de
    GET /api/v2/check de AbuseIPDB (ver _check_abuseipdb). Separada a
    proposito del cliente HTTP para poder testear el parseo sin mockear
    httpx -- una respuesta vacia o con forma inesperada nunca tira
    excepcion, devuelve un resultado neutro (score 0, no maliciosa)."""
    data = json_body.get("data") if isinstance(json_body, dict) else None
    if not isinstance(data, dict):
        return {"score": 0, "is_malicious": False, "categories": []}

    score = data.get("abuseConfidenceScore")
    if not isinstance(score, int):
        score = 0

    category_ids: set[int] = set()
    for report in data.get("reports") or []:
        if not isinstance(report, dict):
            continue
        for cat_id in report.get("categories") or []:
            if isinstance(cat_id, int):
                category_ids.add(cat_id)

    categories = [ABUSEIPDB_CATEGORIES.get(cat_id, str(cat_id)) for cat_id in sorted(category_ids)]

    return {
        "score": score,
        "is_malicious": score >= malicious_score_threshold,
        "categories": categories,
    }


async def _check_abuseipdb(ip: str, http_client: httpx.AsyncClient) -> dict:
    """Si no hay API key configurada, NO se llama a la API -- se devuelve
    directo "no se pudo chequear" sin gastar ningun request (ver
    is_private_or_reserved_ip para el otro caso en el que tampoco se
    llama). Cualquier error de red/HTTP tampoco tira excepcion hacia
    arriba: mismo resultado "no se pudo chequear", nunca tumba el lookup."""
    if not ABUSEIPDB_API_KEY:
        return {"source": "abuseipdb", "is_malicious": None, "score": None, "categories": []}
    try:
        response = await http_client.get(
            ABUSEIPDB_API_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=10,
        )
        response.raise_for_status()
        parsed = parse_abuseipdb_response(response.json())
        return {"source": "abuseipdb", **parsed}
    except httpx.HTTPError as exc:
        logger.warning("no se pudo consultar AbuseIPDB", extra={"ip": ip, "error": str(exc)})
        return {"source": "abuseipdb", "is_malicious": None, "score": None, "categories": []}


async def _check_misp(ip: str, http_client: httpx.AsyncClient) -> dict | None:
    """MISP es opcional (mejor esfuerzo): si MISP_URL/MISP_API_KEY no estan
    seteadas, se omite en silencio -- no es un error, esa fuente
    simplemente no esta disponible en esta instalacion. None (no un dict)
    marca "omitida", distinto de un resultado real con is_malicious=None
    (que significa "se intento y fallo")."""
    if not MISP_URL or not MISP_API_KEY:
        return None
    try:
        response = await http_client.post(
            f"{MISP_URL}/attributes/restSearch",
            json={"returnFormat": "json", "value": ip, "type": ["ip-src", "ip-dst"]},
            headers={"Authorization": MISP_API_KEY, "Accept": "application/json"},
            timeout=10,
        )
        response.raise_for_status()
        body = response.json()
        attributes = []
        if isinstance(body, dict):
            attributes = (body.get("response") or {}).get("Attribute") or []
        return {"source": "misp", "is_malicious": len(attributes) > 0, "score": None, "categories": []}
    except httpx.HTTPError as exc:
        logger.warning("no se pudo consultar MISP", extra={"ip": ip, "error": str(exc)})
        return None


def _combine_results(ip: str, results: list[dict]) -> dict:
    """Funcion pura: combina los resultados de las fuentes que realmente
    respondieron (excluye las que devolvieron None, ej. MISP sin
    configurar) en un solo veredicto -- si CUALQUIER fuente marca la IP
    como maliciosa, el resultado final lo es; el score es el mayor de los
    disponibles; las categorias se unen sin duplicados, preservando orden
    de aparicion. Si ninguna fuente pudo chequear (todas devolvieron
    is_malicious=None, o no habia ninguna fuente configurada), el
    resultado final tambien es "no se pudo chequear"."""
    checked = [r for r in results if r.get("is_malicious") is not None]
    if not checked:
        source = results[0]["source"] if results else "none"
        return {"ip": ip, "is_malicious": None, "score": None, "source": source, "categories": []}

    is_malicious = any(r["is_malicious"] for r in checked)
    scores = [r["score"] for r in checked if r.get("score") is not None]
    score = max(scores) if scores else None
    categories: list[str] = []
    for r in checked:
        for cat in r.get("categories") or []:
            if cat not in categories:
                categories.append(cat)
    source = "+".join(r["source"] for r in checked)
    return {"ip": ip, "is_malicious": is_malicious, "score": score, "source": source, "categories": categories}


async def lookup_ip(db: AsyncSession, ip: str, http_client: httpx.AsyncClient | None = None) -> dict:
    """Orquesta el lookup completo de una IP: IP privada/invalida -> hecho
    directo (nunca es "maliciosa conocida", es simplemente interna, y
    nunca gasta cupo externo); cache fresco -> se devuelve tal cual;
    sino -> consulta las fuentes configuradas, combina, actualiza el cache
    (upsert por ip) y devuelve el resultado nuevo."""
    if is_private_or_reserved_ip(ip):
        return {"ip": ip, "is_malicious": False, "score": None, "source": "internal", "categories": [], "cached": False}

    now = _now()
    result = await db.execute(select(IpReputationCache).where(IpReputationCache.ip == ip))
    cached_row = result.scalar_one_or_none()
    if cached_row is not None and is_cache_fresh(cached_row.ttl_expires_at, now):
        return {
            "ip": ip,
            "is_malicious": cached_row.is_malicious,
            "score": cached_row.score,
            "source": cached_row.source,
            "categories": cached_row.categories,
            "cached": True,
        }

    owns_client = http_client is None
    if owns_client:
        http_client = httpx.AsyncClient()
    try:
        abuse_result = await _check_abuseipdb(ip, http_client)
        misp_result = await _check_misp(ip, http_client)
    finally:
        if owns_client:
            await http_client.aclose()

    combined = _combine_results(ip, [r for r in (abuse_result, misp_result) if r is not None])

    if cached_row is None:
        cached_row = IpReputationCache(ip=ip)
        db.add(cached_row)
    cached_row.source = combined["source"]
    cached_row.is_malicious = combined["is_malicious"]
    cached_row.score = combined["score"]
    cached_row.categories = combined["categories"]
    cached_row.checked_at = now
    cached_row.ttl_expires_at = now + timedelta(hours=CACHE_TTL_HOURS)
    await db.flush()

    combined["cached"] = False
    return combined


async def lookup_batch(db: AsyncSession, ips: list[str]) -> list[dict]:
    """Resuelve una lista de IPs en paralelo (asyncio.gather), no
    secuencial -- pensado para el enriquecimiento de una alerta con varias
    IPs (source_ip + dest_ip) sin que una IP lenta de resolver frene a las
    demas. IMPORTANTE: cada IP usa su PROPIA sesion de DB (no la `db` que
    recibe esta funcion) porque AsyncSession no es seguro para usarse desde
    varias corutinas al mismo tiempo -- compartir una sola sesion entre las
    tareas de gather puede pisarse internamente y tirar errores intermitentes
    del driver. `db` se deja sin usar a proposito (mantiene la firma
    simetrica con el resto de las funciones de este modulo, que si reciben
    la sesion del request)."""
    unique_ips = list(dict.fromkeys(ip for ip in ips if ip))
    if not unique_ips:
        return []

    async def _lookup_one(ip: str) -> dict:
        async with httpx.AsyncClient() as http_client, SessionLocal() as session:
            result = await lookup_ip(session, ip, http_client)
            await session.commit()
            return result

    return list(await asyncio.gather(*(_lookup_one(ip) for ip in unique_ips)))
