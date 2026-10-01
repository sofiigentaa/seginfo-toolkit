"""Business logic for coderepo-service: escaneo de repositorios de codigo
del cliente en modo SOLO LECTURA/analisis DEFENSIVO.

Alcance no negociable (ver tambien app/models.py): este modulo clona un
repositorio via HTTPS (con git, en un directorio temporal SIEMPRE
borrado al terminar) y lo analiza con dos herramientas de deteccion:

  1. gitleaks -- secretos/credenciales commiteados por error, en TODO el
     historial de git (por eso el clone es completo, sin --depth 1: un
     secreto commiteado y despues borrado en un commit posterior SIGUE
     expuesto en el historial).
  2. trivy fs --scanners vuln -- dependencias vulnerables en manifiestos
     (package-lock.json, requirements.txt, go.mod, etc.), solo sobre el
     checkout actual (no hace falta historial para esto).

NUNCA se escribe nada en el repositorio del cliente, ni se ejecuta ningun
codigo del repositorio clonado (no se corre npm/pip install, un build, un
test, ni se importa/ejecuta nada del contenido clonado) -- solo se lee
como texto/archivos para estas dos herramientas de analisis estatico. Si
algo en el futuro sugiere lo contrario, esa sugerencia esta fuera de
alcance y no debe implementarse aca.

Funciones puras (testeables sin git/gitleaks/trivy real, sin red, sin DB)
arriba; funciones de I/O (subprocess, con manejo de error acotado -- NUNCA
deben tumbar el sync completo ni el servicio) despues; scheduler y CRUD al
final. Mismo patron estructural que cloud-service/app/services.py."""
import asyncio
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.crypto import decrypt_secret, encrypt_secret
from backend.shared.logging import configure_logging
from app.models import RepoScanStatus, RepoTarget, SecretFinding, SecretSeverity

logger = configure_logging("coderepo-service")

VULN_SERVICE_URL = os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000")

# Mismo nombre de variable de entorno y mismo default que
# scan-service/app/scanners/trivy.py -- OJO: en docker-compose.yml este
# path se monta a un volumen PROPIO (coderepo_trivy_cache), distinto del
# `trivy_cache` de scan-service, para que dos contenedores nunca escriban
# la misma cache de trivy en simultaneo (podria corromper el archivo bolt
# de la DB). Ver el reporte de este cambio para el bloque exacto.
TRIVY_CACHE_DIR = os.getenv("TRIVY_CACHE_DIR", "/root/.cache/trivy")

_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

# Cualquier URL con credenciales embebidas ("user:token@host" o
# "token@host") se redacta con esto ANTES de guardarse en
# last_scan_error o de loguearse -- ver redact_url.
_CREDENTIALS_IN_URL_RE = re.compile(r"://[^\s@/]+@")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Logica pura -----------------------------------------------------------

def validate_repo_url(url: str) -> bool:
    """True solo si `url` empieza con "https://". Rechazamos a proposito
    git@/ssh:// -- HTTPS + token es mas simple y suficiente, y evita tener
    que manejar claves SSH."""
    return bool(url) and url.startswith("https://")


def build_authenticated_clone_url(repo_url: str, token: str | None) -> str:
    """Convencion de GitHub para autenticar clones HTTPS con un token
    (funciona igual en GitLab con cualquier user): insertar
    "x-access-token:{token}@" justo despues del esquema. Sin token,
    devuelve la URL tal cual (repo publico)."""
    if not token:
        return repo_url
    return repo_url.replace("https://", f"https://x-access-token:{token}@", 1)


def redact_url(text: str) -> str:
    """Para cualquier mensaje de error/log que pueda contener una URL de
    clone con credenciales embebidas: reemplaza "usuario:token@" o
    "token@" (antes del host) por "***@". Nunca debe aparecer un token en
    last_scan_error ni en ningun log."""
    if not text:
        return text
    return _CREDENTIALS_IN_URL_RE.sub("://***@", text)


def redact_secret_match(raw: str) -> str:
    """JAMAS se persiste ni se muestra el secreto real. El relleno se
    limita a 20 caracteres para no generar strings gigantes con secretos
    larguisimos."""
    raw = raw or ""
    if len(raw) <= 6:
        return "••••"
    padding = min(len(raw) - 5, 20)
    return f"{raw[:3]}{'•' * padding}{raw[-2:]}"


def classify_gitleaks_severity(rule_id: str) -> SecretSeverity:
    rule = (rule_id or "").lower()
    if any(marker in rule for marker in ("private-key", "aws", "gcp", "azure", "service-account")):
        return SecretSeverity.critical
    if any(marker in rule for marker in ("token", "api-key", "apikey", "secret", "password", "generic")):
        return SecretSeverity.high
    return SecretSeverity.medium


def parse_gitleaks_report(raw_json: str) -> list[dict]:
    """gitleaks con --report-format json devuelve una lista (puede ser []
    si no hay hallazgos, o directamente vacio/no-JSON en algunas versiones
    si no hay leaks) -- cualquier error de parseo devuelve [] sin excepcion.
    NUNCA incluye Match/Secret crudos en el dict devuelto, solo la version
    redactada (ver redact_secret_match)."""
    try:
        data = json.loads(raw_json) if raw_json and raw_json.strip() else []
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, list):
        return []

    findings: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("RuleID", "")
        findings.append(
            {
                "rule_id": rule_id,
                "description": item.get("Description", ""),
                "file_path": item.get("File", ""),
                "start_line": item.get("StartLine"),
                "commit_hash": item.get("Commit", ""),
                "severity": classify_gitleaks_severity(rule_id),
                "match_redacted": redact_secret_match(item.get("Secret") or item.get("Match") or ""),
            }
        )
    return findings


def build_trivy_fs_vuln_cmd(repo_path: str, cache_dir: str) -> list[str]:
    """Funcion pura (sin I/O) para poder testear la construccion del
    comando sin ejecutar trivy de verdad. Mismos flags que
    scan-service/app/scanners/trivy.py, modo `fs --scanners vuln`."""
    return [
        "trivy", "fs",
        "--scanners", "vuln",
        "--format", "json", "--quiet", "--timeout", "8m",
        "--cache-dir", cache_dir,
        "--skip-db-update", "--skip-java-db-update",
        repo_path,
    ]


def parse_trivy_vuln_json(raw_json: str, repo_name: str) -> list[dict]:
    """Identica logica de mapeo de severidad a
    scan-service/app/scanners/trivy.py::_parse_trivy_json, pero el titulo
    identifica el repo (ver spec). Devuelve dicts con las claves exactas
    que espera FindingIn de vuln-service."""
    findings: list[dict] = []
    try:
        data = json.loads(raw_json) if raw_json.strip() else {}
    except json.JSONDecodeError:
        return findings

    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "title": f"{vuln.get('VulnerabilityID', 'CVE-desconocido')} en {vuln.get('PkgName', '')} (repo: {repo_name})",
                    "description": (vuln.get("Title") or vuln.get("Description") or "")[:1000],
                    "severity": _TRIVY_SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info"),
                    "cve_id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                }
            )
    return findings


def should_create_secret_finding(existing_same_key: list[dict]) -> bool:
    """Recibe los hallazgos previos para la misma
    (repo_target_id, rule_id, file_path, start_line), cada uno con
    {"is_acknowledged": bool}. True si la lista esta vacia o el ULTIMO
    (el mas reciente) esta reconocido -- mismo patron exacto que
    cloud-service::should_create_finding."""
    if not existing_same_key:
        return True
    return bool(existing_same_key[-1].get("is_acknowledged"))


# --- I/O (subprocess: git/gitleaks/trivy) -----------------------------------
# Ninguna de estas funciones debe tumbar el sync completo ni el servicio si
# falla -- ver run_repo_scan, que envuelve todo en un try/except amplio.
# Cualquier mensaje que pudiera contener la URL con token SIEMPRE pasa por
# redact_url antes de guardarse o loguearse.

async def _clone_repo(repo_url: str, branch: str, token: str | None, dest_dir: str) -> None:
    """Clona el repo COMPLETO (sin --depth 1: necesitamos el historial
    completo de git para gitleaks). Timeout de 180s."""
    authenticated_url = build_authenticated_clone_url(repo_url, token)
    cmd = ["git", "clone", "--branch", branch, "--single-branch", authenticated_url, dest_dir]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError("timeout clonando el repositorio (180s)")
    except FileNotFoundError:
        raise RuntimeError("git no esta instalado en este contenedor")

    if proc.returncode != 0:
        raise RuntimeError(redact_url(stderr.decode(errors="replace")[:2000]))


async def _run_gitleaks(repo_path: str) -> list[dict]:
    """--exit-code 0 es CLAVE: gitleaks por default sale con codigo 1 si
    encuentra leaks, y sin este flag este wrapper interpretaria eso como
    que el comando "fallo" cuando en realidad funciono perfecto y
    encontro algo. Si gitleaks no esta instalado o timeoutea, se loguea y
    se devuelve [] (no tumba el resto del sync)."""
    report_path = os.path.join(repo_path, ".gitleaks-report.json")
    cmd = [
        "gitleaks", "detect",
        "--source", repo_path,
        "--report-format", "json",
        "--report-path", report_path,
        "--exit-code", "0",
        "--no-banner",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
    except FileNotFoundError:
        logger.warning("gitleaks no esta instalado en este contenedor")
        return []
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning("gitleaks: timeout de escaneo (300s)")
        return []

    if proc.returncode != 0:
        logger.warning("gitleaks fallo", extra={"error": stderr.decode(errors="replace")[:500]})
        return []

    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            raw_json = fh.read()
    except OSError:
        return []
    return parse_gitleaks_report(raw_json)


async def _run_trivy_fs(repo_path: str, repo_name: str) -> list[dict]:
    """Analogo a scan-service/app/scanners/trivy.py::TrivyDriver.run, con
    el mismo reintento sin --skip-db-update una vez si la DB no esta
    inicializada."""
    cmd = build_trivy_fs_vuln_cmd(repo_path, TRIVY_CACHE_DIR)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=540)
    except FileNotFoundError:
        logger.warning("trivy no esta instalado en este contenedor")
        return []
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning("trivy: timeout de escaneo (540s)")
        return []

    raw = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    if proc.returncode not in (0, 1):
        if "--skip-db-update" in err or "database is not initialized" in err.lower() or "no such file" in err.lower():
            fallback_cmd = [c for c in cmd if c not in ("--skip-db-update", "--skip-java-db-update")]
            try:
                proc2 = await asyncio.create_subprocess_exec(
                    *fallback_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout2, stderr2 = await asyncio.wait_for(proc2.communicate(), timeout=540)
            except asyncio.TimeoutError:
                proc2.kill()
                await proc2.wait()
                logger.warning("trivy: timeout de escaneo (540s, incluyo descarga inicial de la DB)")
                return []
            if proc2.returncode not in (0, 1):
                logger.warning("trivy fallo (reintento sin --skip-db-update)", extra={"error": stderr2.decode(errors="replace")[:500]})
                return []
            return parse_trivy_vuln_json(stdout2.decode(errors="replace"), repo_name)
        logger.warning("trivy fallo", extra={"error": err[:500]})
        return []

    return parse_trivy_vuln_json(raw, repo_name)


async def _run_refresh_cmd(cmd: list[str], label: str, timeout: int) -> None:
    """Mismo patron que scan-service::_run_refresh_cmd: un refresco de
    datos de escaner fallido (red caida, binario ausente en un entorno de
    test, etc.) solo se loguea, nunca tumba el scheduler ni el servicio."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            logger.warning(f"{label}: fallo (codigo {proc.returncode})", extra={"stderr": stderr.decode(errors="replace")[:500]})
        else:
            logger.info(f"{label}: ok")
    except FileNotFoundError:
        logger.warning(f"{label}: binario no encontrado en este contenedor, se omite")
    except asyncio.TimeoutError:
        logger.warning(f"{label}: timeout ({timeout}s)")
    except Exception as exc:  # noqa: BLE001 -- nunca debe tumbar el scheduler
        logger.warning(f"{label}: error inesperado: {exc}")


async def refresh_trivy_db() -> None:
    """Refresca la base de datos de CVEs de trivy en segundo plano (ver
    Dockerfile: se predescarga una vez en build-time). Se registra como
    job periodico de APScheduler (ver app/main.py) para que cada escaneo
    individual pueda correr con --skip-db-update sin quedar con una DB
    eternamente vieja."""
    await _run_refresh_cmd(
        ["trivy", "image", "--download-db-only", "--cache-dir", TRIVY_CACHE_DIR],
        "refresh_trivy_db",
        timeout=600,
    )


async def _forward_vulnerabilities_to_vuln_service(findings: list[dict], repo_name: str, organization_id: str | None) -> None:
    """Best-effort: si vuln-service no responde, el escaneo ya quedo
    guardado igual (el contador last_scan_vulnerabilities_found ya se
    actualizo); esto solo adelanta la ingesta para priorizacion
    automatica. Mismo endpoint/payload shape que
    scan-service::_forward_findings_to_vuln_service."""
    payload = {
        "scan_job_id": None,
        "asset_id": None,
        "scanner_type": "trivy_repo",
        "findings": findings,
        "organization_id": organization_id,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{VULN_SERVICE_URL}/vulnerabilities/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar hallazgos a vuln-service", extra={"repo": repo_name, "error": str(exc)})


async def _existing_secret_findings_for_key(
    db: AsyncSession, organization_id: str | None, repo_target_id: str, rule_id: str, file_path: str, start_line: int | None,
) -> list[SecretFinding]:
    result = await db.execute(
        select(SecretFinding)
        .where(
            SecretFinding.organization_id == organization_id,
            SecretFinding.repo_target_id == repo_target_id,
            SecretFinding.rule_id == rule_id,
            SecretFinding.file_path == file_path,
            SecretFinding.start_line == start_line,
        )
        .order_by(SecretFinding.created_at.asc())
    )
    return list(result.scalars().all())


async def _create_secret_finding_if_needed(db: AsyncSession, target: RepoTarget, item: dict) -> SecretFinding | None:
    existing = await _existing_secret_findings_for_key(
        db, target.organization_id, target.id, item.get("rule_id", ""), item.get("file_path", ""), item.get("start_line")
    )
    existing_dicts = [{"is_acknowledged": f.is_acknowledged} for f in existing]
    if not should_create_secret_finding(existing_dicts):
        return None
    finding = SecretFinding(
        organization_id=target.organization_id,
        repo_target_id=target.id,
        rule_id=item.get("rule_id", ""),
        description=(item.get("description") or "")[:500],
        file_path=(item.get("file_path") or "")[:500],
        start_line=item.get("start_line"),
        commit_hash=(item.get("commit_hash") or "")[:100],
        severity=item["severity"],
        match_redacted=item.get("match_redacted", ""),
    )
    db.add(finding)
    await db.flush()
    return finding


async def run_repo_scan(db: AsyncSession, target: RepoTarget) -> None:
    """Orquesta un escaneo completo de un RepoTarget dentro de un
    tempfile.mkdtemp() SIEMPRE limpiado en un finally (incluso si algo
    falla a mitad de camino): descifra el token si existe, clona,
    corre gitleaks y trivy fs, guarda SecretFinding nuevos (con dedup),
    reenvia vulnerabilidades a vuln-service, y actualiza el estado del
    target. Cualquier excepcion no prevista se atrapa aca y deja
    last_scan_status=error -- NUNCA propaga (ni tumba el scheduler ni el
    servicio)."""
    now = _now()
    tmp_dir = tempfile.mkdtemp(prefix="coderepo-scan-")
    try:
        try:
            token = decrypt_secret(target.github_token_encrypted) if target.github_token_encrypted else None

            await _clone_repo(target.repo_url, target.branch, token, tmp_dir)

            secret_items = await _run_gitleaks(tmp_dir)
            vuln_items = await _run_trivy_fs(tmp_dir, target.name)

            for item in secret_items:
                await _create_secret_finding_if_needed(db, target, item)

            # Contador del ULTIMO escaneo (no acumulado, ver app/models.py):
            # refleja lo DETECTADO en esta corrida, incluso si algunos
            # hallazgos ya estaban registrados de una corrida anterior.
            target.last_scan_secrets_found = len(secret_items)
            target.last_scan_vulnerabilities_found = len(vuln_items)

            if vuln_items:
                await _forward_vulnerabilities_to_vuln_service(vuln_items, target.name, target.organization_id)

            target.last_scan_at = now
            target.last_scan_status = RepoScanStatus.ok
            target.last_scan_error = ""
            await db.flush()
        except Exception as exc:  # noqa: BLE001 -- un repo roto nunca debe tumbar el sync ni el scheduler
            error_message = redact_url(str(exc))[:2000]
            logger.error("error escaneando repositorio", extra={"repo_target_id": target.id, "error": error_message})
            target.last_scan_at = now
            target.last_scan_status = RepoScanStatus.error
            target.last_scan_error = error_message
            await db.flush()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# --- Scheduler ---------------------------------------------------------------

async def scan_all_enabled_targets(session_factory) -> None:
    """Llamado por el scheduler en proceso (APScheduler, ver app/main.py)
    cada CODEREPO_SCAN_INTERVAL_HOURS. Itera TODOS los RepoTarget
    habilitados de TODAS las organizaciones, secuencial -- un repo roto
    nunca frena el escaneo de los demas (mismo patron que
    cloud-service::sync_all_enabled_accounts)."""
    async with session_factory() as db:
        result = await db.execute(select(RepoTarget).where(RepoTarget.is_enabled.is_(True)))
        target_ids = [t.id for t in result.scalars().all()]

    for target_id in target_ids:
        await run_repo_scan_now(session_factory, target_id)


async def run_repo_scan_now(session_factory, target_id: str) -> None:
    """Corre un escaneo para UN repo, con su propia sesion de DB -- usado
    tanto por el job periodico (scan_all_enabled_targets) como por
    POST /repos/{id}/scan-now (via BackgroundTasks, ver app/main.py)."""
    async with session_factory() as db:
        target = await db.get(RepoTarget, target_id)
        if target is None or not target.is_enabled:
            return
        try:
            await run_repo_scan(db, target)
            await db.commit()
        except Exception as exc:  # noqa: BLE001 -- un repo no debe tumbar el scheduler ni dejar la sesion colgada
            logger.error("error en scan de repositorio", extra={"repo_target_id": target_id, "error": redact_url(str(exc))})
            await db.rollback()


# --- CRUD --------------------------------------------------------------------

async def create_target(db: AsyncSession, payload, organization_id: str | None, created_by: str) -> RepoTarget:
    target = RepoTarget(
        name=payload.name,
        repo_url=payload.repo_url,
        branch=payload.branch or "main",
        github_token_encrypted=encrypt_secret(payload.github_token) or "",
        organization_id=organization_id,
        created_by=created_by,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


async def list_targets(db: AsyncSession, organization_id: str | None) -> list[RepoTarget]:
    result = await db.execute(
        select(RepoTarget).where(RepoTarget.organization_id == organization_id).order_by(RepoTarget.name)
    )
    return list(result.scalars().all())


async def get_target(db: AsyncSession, target_id: str, organization_id: str | None) -> RepoTarget | None:
    """organization_id obligatorio, mismo criterio que
    cloud-service::get_account: devuelve None tanto si el target no
    existe como si es de otra organizacion."""
    target = await db.get(RepoTarget, target_id)
    if target is None or target.organization_id != organization_id:
        return None
    return target


async def delete_target(db: AsyncSession, target: RepoTarget) -> None:
    await db.delete(target)
    await db.flush()


async def list_secrets(
    db: AsyncSession, organization_id: str | None, repo_target_id: str | None = None, is_acknowledged: bool | None = False,
) -> list[SecretFinding]:
    query = select(SecretFinding).where(SecretFinding.organization_id == organization_id)
    if repo_target_id is not None:
        query = query.where(SecretFinding.repo_target_id == repo_target_id)
    if is_acknowledged is not None:
        query = query.where(SecretFinding.is_acknowledged.is_(is_acknowledged))
    result = await db.execute(query.order_by(SecretFinding.created_at.desc()))
    return list(result.scalars().all())


async def get_secret(db: AsyncSession, finding_id: str, organization_id: str | None) -> SecretFinding | None:
    finding = await db.get(SecretFinding, finding_id)
    if finding is None or finding.organization_id != organization_id:
        return None
    return finding


async def acknowledge_secret(db: AsyncSession, finding: SecretFinding, is_acknowledged: bool, acknowledged_by: str) -> SecretFinding:
    finding.is_acknowledged = is_acknowledged
    finding.acknowledged_by = acknowledged_by if is_acknowledged else ""
    await db.flush()
    await db.refresh(finding)
    return finding
