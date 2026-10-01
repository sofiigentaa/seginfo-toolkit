"""Business logic for scan-service: orquestacion de jobs de escaneo
DEFENSIVOS (solo deteccion) y reenvio de hallazgos normalizados a
vuln-service para priorizacion (CVSS/EPSS/KEV)."""
import asyncio
import os
import secrets
import hashlib
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import ScanJob, ScanStatus, ScanSchedule, ScanAgent, AgentScanJob
from app.scanners import get_driver, DRIVERS

logger = configure_logging("scan-service")

VULN_SERVICE_URL = os.getenv("VULN_SERVICE_URL", "http://vuln-service:8000")
SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _run_refresh_cmd(cmd: list[str], label: str, timeout: int) -> None:
    """Corre un comando de refresco de datos de escaner (DB de trivy,
    templates de nuclei) en segundo plano. Nunca levanta excepcion --
    un refresh fallido (red caida, binario ausente en un entorno de test,
    etc.) solo se loguea, no debe tumbar el scheduler ni el servicio."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            logger.warning(
                f"{label}: fallo (codigo {proc.returncode})",
                extra={"stderr": stderr.decode(errors="replace")[:500]},
            )
        else:
            logger.info(f"{label}: ok")
    except FileNotFoundError:
        logger.warning(f"{label}: binario no encontrado en este contenedor, se omite")
    except asyncio.TimeoutError:
        logger.warning(f"{label}: timeout ({timeout}s)")
    except Exception as exc:  # noqa: BLE001 -- nunca debe tumbar el scheduler
        logger.warning(f"{label}: error inesperado: {exc}")


async def refresh_trivy_db() -> None:
    """Refresca la base de datos de CVEs de trivy en segundo plano. Se
    registra como job periodico de APScheduler (ver app/main.py) para que
    cada escaneo individual pueda correr con --skip-db-update (ver
    app/scanners/trivy.py) sin quedar con una DB eternamente vieja."""
    from app.scanners.trivy import TRIVY_CACHE_DIR

    await _run_refresh_cmd(
        ["trivy", "image", "--download-db-only", "--cache-dir", TRIVY_CACHE_DIR],
        "refresh_trivy_db",
        timeout=600,
    )


async def refresh_nuclei_templates() -> None:
    """Refresca las plantillas de nuclei en segundo plano (ver
    app/scanners/nuclei.py, que corre con -duc para no pagar este costo
    en cada escaneo individual)."""
    await _run_refresh_cmd(
        ["nuclei", "-update-templates", "-silent"],
        "refresh_nuclei_templates",
        timeout=300,
    )


async def create_scan_job(db: AsyncSession, payload, actor: str, organization_id: str) -> ScanJob:
    job = ScanJob(
        organization_id=organization_id,
        name=payload.name,
        scanner_type=payload.scanner_type,
        target=payload.target,
        asset_id=payload.asset_id,
        options=payload.options,
        created_by=actor,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)
    return job


async def list_scan_jobs(
    db: AsyncSession, organization_id: str, status_filter: str | None = None, scanner_type: str | None = None
) -> list[ScanJob]:
    query = select(ScanJob).where(ScanJob.organization_id == organization_id)
    if status_filter:
        query = query.where(ScanJob.status == status_filter)
    if scanner_type:
        query = query.where(ScanJob.scanner_type == scanner_type)
    result = await db.execute(query.order_by(ScanJob.created_at.desc()))
    return list(result.scalars().all())


async def get_scan_job(db: AsyncSession, job_id: str, organization_id: str) -> ScanJob | None:
    job = await db.get(ScanJob, job_id)
    if job is None or job.organization_id != organization_id:
        return None
    return job


TERMINAL_SCAN_STATUSES = {"completed", "failed", "scanner_unavailable", "cancelled"}
CANCELLABLE_SCAN_STATUSES = {"pending", "running"}


def is_deletable_status(status_value) -> bool:
    """Un escaneo (propio o de agente remoto) solo se puede borrar una vez
    terminado -- pending/running todavia pueden estar corriendo en
    background_tasks o esperando el proximo polling del agente."""
    value = status_value.value if hasattr(status_value, "value") else status_value
    return value in TERMINAL_SCAN_STATUSES


def is_cancellable_status(status_value) -> bool:
    """Solo tiene sentido cancelar un escaneo que todavia no llego a un
    estado terminal -- uno completed/failed/scanner_unavailable/cancelled ya
    no tiene nada corriendo que cancelar."""
    value = status_value.value if hasattr(status_value, "value") else status_value
    return value in CANCELLABLE_SCAN_STATUSES


# --- Cancelacion de escaneos en curso ---
# Diccionario en memoria (job_id -> asyncio.Task) de los escaneos que estan
# corriendo AHORA en este mismo proceso de scan-service. Alcanza con que sea
# en memoria (no en la DB) porque solo tiene sentido cancelar un escaneo
# mientras el proceso que lo esta corriendo sigue vivo: si el contenedor se
# reinicio, cualquier job que haya quedado "running" en la DB ya esta
# huerfano de todas formas (nadie lo esta corriendo), y cancel_scan_job mas
# abajo lo detecta (no hay tarea registrada) y lo marca cancelado
# directamente sin necesidad de matar nada. Un solo dict de proceso alcanza
# porque scan-service corre como una sola instancia -- mismo supuesto que ya
# usa el scheduler de ScanSchedule (ver app/main.py).
_RUNNING_SCAN_TASKS: dict[str, "asyncio.Task"] = {}


def register_running_scan(job_id: str, task: "asyncio.Task") -> None:
    _RUNNING_SCAN_TASKS[job_id] = task


def unregister_running_scan(job_id: str) -> None:
    _RUNNING_SCAN_TASKS.pop(job_id, None)


def cancel_running_scan(job_id: str) -> bool:
    """Pide la cancelacion del escaneo si esta corriendo en ESTE proceso
    (via Task.cancel() -- ver execute_scan_job, que atrapa el
    CancelledError resultante para matar el subproceso del driver y dejar
    el job en estado 'cancelled' en vez de dejarlo colgado). Devuelve False
    si no hay ninguna tarea viva registrada para ese job_id (ya termino, o
    quedo huerfana de un reinicio del contenedor) -- en ese caso quien
    llama tiene que marcar el estado 'cancelled' a mano, no hay nada que
    matar."""
    task = _RUNNING_SCAN_TASKS.get(job_id)
    if task is None or task.done():
        return False
    task.cancel()
    return True


async def cancel_scan_job(db: AsyncSession, job: ScanJob) -> ScanJob:
    """Cancela un escaneo pending/running (ver is_cancellable_status, que ya
    se valido en el endpoint antes de llamar aca). Si hay una tarea viva
    corriendo este job en este proceso, le pide la cancelacion -- el propio
    execute_scan_job termina de escribir el estado final cuando el
    CancelledError le llega. Si no hay ninguna tarea viva (job huerfano de
    un reinicio del contenedor, o todavia no llego a registrarse), se marca
    cancelado aca mismo porque no hay nada corriendo que vaya a hacerlo."""
    if not cancel_running_scan(job.id):
        job.status = ScanStatus.cancelled
        job.error_message = "Cancelado por el usuario"
        job.finished_at = _now()
        await db.flush()
    return job


async def delete_scan_job(db: AsyncSession, job: ScanJob) -> None:
    """Solo se borran escaneos ya terminados (completed/failed/scanner_unavailable) --
    uno en pending/running todavia puede estar corriendo en background_tasks."""
    await db.delete(job)
    await db.flush()


def scanners_status() -> dict:
    return {scanner_type.value: driver.is_available() for scanner_type, driver in DRIVERS.items()}


async def create_schedule(db: AsyncSession, payload, actor: str, organization_id: str) -> ScanSchedule:
    schedule = ScanSchedule(
        organization_id=organization_id,
        name=payload.name,
        scanner_type=payload.scanner_type,
        target=payload.target,
        options=payload.options,
        frequency=payload.frequency,
        hour=payload.hour,
        minute=payload.minute,
        day_of_week=payload.day_of_week,
        created_by=actor,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


async def list_schedules(db: AsyncSession, organization_id: str | None = None) -> list[ScanSchedule]:
    """organization_id opcional SOLO para el uso interno del lifespan
    (re-registrar los jobs de TODAS las organizaciones al arrancar el
    scheduler en proceso) -- todo endpoint HTTP siempre lo pasa."""
    query = select(ScanSchedule)
    if organization_id is not None:
        query = query.where(ScanSchedule.organization_id == organization_id)
    result = await db.execute(query.order_by(ScanSchedule.created_at.desc()))
    return list(result.scalars().all())


async def get_schedule(db: AsyncSession, schedule_id: str, organization_id: str) -> ScanSchedule | None:
    schedule = await db.get(ScanSchedule, schedule_id)
    if schedule is None or schedule.organization_id != organization_id:
        return None
    return schedule


async def set_schedule_enabled(db: AsyncSession, schedule: ScanSchedule, enabled: bool) -> ScanSchedule:
    schedule.enabled = enabled
    await db.flush()
    return schedule


async def delete_schedule(db: AsyncSession, schedule: ScanSchedule) -> None:
    await db.delete(schedule)
    await db.flush()


async def run_scheduled_scan(session_factory, schedule_id: str) -> None:
    """Llamado por el scheduler en proceso (APScheduler, ver app/main.py)
    cuando le toca disparar a una regla. Crea un ScanJob nuevo -- igual que
    si un usuario lo hubiera lanzado a mano -- y lo ejecuta con el mismo
    codigo (execute_scan_job) que usa la creacion manual."""
    async with session_factory() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if schedule is None or not schedule.enabled:
            return
        job = ScanJob(
            organization_id=schedule.organization_id,
            name=f"{schedule.name or schedule.scanner_type.value} (programado)",
            scanner_type=schedule.scanner_type,
            target=schedule.target,
            options=schedule.options,
            created_by=f"scheduler:{schedule.name or schedule.id}",
        )
        db.add(job)
        schedule.last_run_at = _now()
        await db.flush()
        job_id = job.id
        await db.commit()

    try:
        await execute_scan_job(session_factory, job_id)
        status_note = "ok"
    except Exception as exc:  # noqa: BLE001 -- se registra en la propia regla, no se pierde silenciosamente
        logger.error("error corriendo escaneo programado", extra={"schedule_id": schedule_id, "error": str(exc)})
        status_note = f"error: {exc}"[:500]

    async with session_factory() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if schedule is not None:
            schedule.last_status = status_note
            await db.commit()


def driver_exception_error_message(exc: Exception) -> str:
    """Mensaje guardado en ScanJob.error_message cuando el driver levanta una
    excepcion no prevista (no capturada ya como ScanResult.error) -- funcion
    pura, separada de execute_scan_job, para poder testear el formato y el
    truncado a 2000 caracteres (limite de la columna, ver app/models.py)
    sin correr un scanner de verdad ni tocar la DB."""
    return f"Error inesperado del driver de escaneo: {exc}"[:2000]


async def execute_scan_job(session_factory, job_id: str) -> None:
    """Corre en background (via BackgroundTasks, o desde run_scheduled_scan
    para las reglas programadas). Usa su propia sesion de DB porque la
    request original ya termino cuando esto se ejecuta.

    Se auto-registra en _RUNNING_SCAN_TASKS mientras corre (via
    asyncio.current_task()) para que POST /scans/{id}/cancel pueda pedirle
    la cancelacion con Task.cancel() -- sea quien sea quien haya arrancado
    esta corrutina (BackgroundTasks de FastAPI o el scheduler de
    APScheduler), asyncio.current_task() devuelve la misma Task real que
    la esta ejecutando.

    Todo el cuerpo queda envuelto en un try/except CancelledError (no solo
    la llamada al driver): la cancelacion puede llegar en cualquier punto
    de espera, incluso antes de que el driver arranque a correr. Ese
    CancelledError se atrapa aca y NUNCA se re-lanza -- si escapara,
    run_scheduled_scan no lo atraparia con su `except Exception` (desde
    Python 3.8, CancelledError hereda de BaseException a proposito, para
    que nadie lo confunda con un error real del scanner), y quedaria como
    una excepcion sin manejar en el background task de FastAPI."""
    task = asyncio.current_task()
    if task is not None:
        register_running_scan(job_id, task)
    try:
        async with session_factory() as db:
            job = await db.get(ScanJob, job_id)
            if job is None:
                return

            driver = get_driver(job.scanner_type)
            if not driver.is_available():
                job.status = ScanStatus.scanner_unavailable
                job.error_message = f"El binario '{driver.binary_name}' no esta disponible en este contenedor"
                job.finished_at = _now()
                await db.commit()
                logger.warning("scanner no disponible", extra={"job_id": job_id, "scanner": job.scanner_type.value})
                return

            job.status = ScanStatus.running
            job.started_at = _now()
            await db.commit()

            # driver.run() ya atrapa sus propios errores esperados (binario
            # ausente, timeout) y los devuelve como ScanResult.error -- pero un
            # driver puede levantar una excepcion no prevista (permiso denegado
            # al crear el subproceso, error de parseo no capturado, etc). Sin
            # este try/except, esa excepcion se escapa de este background task
            # (FastAPI solo la loguea, no hay nadie esperando la respuesta) y el
            # job se queda en estado "running" para siempre: nunca pasa a un
            # estado terminal, asi que ni se puede reintentar a mano ni se puede
            # borrar (is_deletable_status exige un estado terminal).
            try:
                result = await driver.run(job.target, job.options or {})
            except Exception as exc:  # noqa: BLE001 -- nunca debe dejar el job colgado en "running"
                job = await db.get(ScanJob, job_id)
                job.status = ScanStatus.failed
                job.error_message = driver_exception_error_message(exc)
                job.finished_at = _now()
                await db.commit()
                logger.error("scan fallo con excepcion no manejada", extra={"job_id": job_id, "error": str(exc)})
                return

            job = await db.get(ScanJob, job_id)
            job.raw_result = (result.raw_output or "")[:200_000]
            job.finished_at = _now()
            if result.error:
                job.status = ScanStatus.failed
                job.error_message = result.error[:2000]
                logger.error("scan fallo", extra={"job_id": job_id, "error": result.error[:500]})
            else:
                job.status = ScanStatus.completed
                job.findings = result.findings
                logger.info("scan completado", extra={"job_id": job_id, "hallazgos": len(result.findings)})
            await db.commit()

            if result.findings:
                await _forward_findings_to_vuln_service(job)
                await _forward_findings_to_siem_service(job)
    except asyncio.CancelledError:
        # El usuario pidio cancelar (POST /scans/{id}/cancel -> cancel_scan_job
        # -> cancel_running_scan -> Task.cancel()). Los drivers ya atrapan este
        # mismo CancelledError junto al subproceso que tengan corriendo para
        # matarlo antes de volver a levantarlo (ver app/scanners/*.py) -- aca
        # solo queda dejar el job en un estado terminal. Se abre una sesion
        # NUEVA porque la sesion de arriba puede haber quedado en un estado
        # intermedio inconsistente si la cancelacion llego a mitad de un
        # commit/flush.
        async with session_factory() as db:
            job = await db.get(ScanJob, job_id)
            if job is not None and is_cancellable_status(job.status):
                job.status = ScanStatus.cancelled
                job.error_message = "Cancelado por el usuario"
                job.finished_at = _now()
                await db.commit()
        logger.info("scan cancelado", extra={"job_id": job_id})
    finally:
        unregister_running_scan(job_id)


async def _forward_findings_to_vuln_service(job: ScanJob) -> None:
    """Best-effort: si vuln-service no responde, el job de escaneo ya quedo
    guardado igual (los findings estan en ScanJob.findings); esto solo
    adelanta la ingesta para priorizacion automatica."""
    payload = {
        "scan_job_id": job.id,
        "asset_id": job.asset_id,
        "scanner_type": job.scanner_type.value,
        "findings": job.findings,
        "organization_id": job.organization_id,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{VULN_SERVICE_URL}/vulnerabilities/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar hallazgos a vuln-service", extra={"job_id": job.id, "error": str(exc)})


def _findings_to_siem_events(scanner_type: str, target: str, asset_id: str | None, findings: list[dict]) -> list[dict]:
    """Un evento ECS-lite por hallazgo, para que siem-service pueda
    evaluar reglas Sigma sobre resultados de escaneo (ver
    app/services.py::DEFAULT_RULES de siem-service, que ya trae reglas
    para severidad critica/alta de este mismo pipeline)."""
    return [
        {
            "host": target,
            "event_action": "scan_finding",
            "event_category": "vulnerability",
            "event_outcome": "success",
            "message": finding.get("title", ""),
            "source_type": scanner_type,
            "asset_id": asset_id,
            "severity": finding.get("severity", "info"),
        }
        for finding in findings
    ]


async def _forward_findings_to_siem_service(job: ScanJob) -> None:
    """Best-effort, igual que _forward_findings_to_vuln_service: si
    siem-service no responde, el job de escaneo ya quedo guardado igual."""
    payload = {
        "organization_id": job.organization_id,
        "events": _findings_to_siem_events(job.scanner_type.value, job.target, job.asset_id, job.findings),
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SIEM_SERVICE_URL}/logs/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar hallazgos a siem-service", extra={"job_id": job.id, "error": str(exc)})


# --- Agentes de escaneo remoto ---
# La key en si (no un hash lento tipo bcrypt) es la fuente de entropia:
# la genera el servidor con secrets.token_urlsafe, no la elige una persona,
# asi que sha256 alcanza y es barato para chequear en cada poll (que puede
# ocurrir cada pocos segundos por agente).

def _hash_agent_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


async def create_agent(db: AsyncSession, payload, actor: str, organization_id: str) -> tuple[ScanAgent, str]:
    api_key = secrets.token_urlsafe(32)
    agent = ScanAgent(
        organization_id=organization_id, name=payload.name, key_hash=_hash_agent_key(api_key), created_by=actor
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    return agent, api_key


async def list_agents(db: AsyncSession, organization_id: str) -> list[ScanAgent]:
    result = await db.execute(
        select(ScanAgent).where(ScanAgent.organization_id == organization_id).order_by(ScanAgent.created_at.desc())
    )
    return list(result.scalars().all())


async def get_agent(db: AsyncSession, agent_id: str, organization_id: str) -> ScanAgent | None:
    agent = await db.get(ScanAgent, agent_id)
    if agent is None or agent.organization_id != organization_id:
        return None
    return agent


async def get_agent_by_key(db: AsyncSession, api_key: str) -> ScanAgent | None:
    result = await db.execute(select(ScanAgent).where(ScanAgent.key_hash == _hash_agent_key(api_key)))
    return result.scalar_one_or_none()


async def delete_agent(db: AsyncSession, agent: ScanAgent) -> None:
    await db.delete(agent)
    await db.flush()


async def delete_agent_scan_job(db: AsyncSession, job: AgentScanJob) -> None:
    """Mismo criterio que delete_scan_job: solo estados terminales."""
    await db.delete(job)
    await db.flush()


async def create_agent_scan_job(db: AsyncSession, payload, actor: str, organization_id: str) -> AgentScanJob:
    job = AgentScanJob(
        organization_id=organization_id,
        agent_id=payload.agent_id,
        name=payload.name,
        scanner_type=payload.scanner_type,
        target=payload.target,
        options=payload.options,
        created_by=actor,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)
    return job


async def list_agent_scan_jobs(db: AsyncSession, organization_id: str, agent_id: str | None = None) -> list[AgentScanJob]:
    query = select(AgentScanJob).where(AgentScanJob.organization_id == organization_id)
    if agent_id:
        query = query.where(AgentScanJob.agent_id == agent_id)
    result = await db.execute(query.order_by(AgentScanJob.created_at.desc()))
    return list(result.scalars().all())


async def get_agent_scan_job(db: AsyncSession, job_id: str, organization_id: str) -> AgentScanJob | None:
    job = await db.get(AgentScanJob, job_id)
    if job is None or job.organization_id != organization_id:
        return None
    return job


async def poll_agent_jobs(db: AsyncSession, agent: ScanAgent, max_jobs: int = 5) -> list[AgentScanJob]:
    """Le entrega al agente sus jobs 'pending' y los pasa a 'assigned' en el
    mismo paso, para que un segundo poll (del mismo agente reiniciado, o de
    una instancia duplicada por error) no se lleve el mismo job dos veces."""
    agent.last_seen_at = _now()
    result = await db.execute(
        select(AgentScanJob)
        .where(AgentScanJob.agent_id == agent.id, AgentScanJob.status == "pending")
        .order_by(AgentScanJob.created_at.asc())
        .limit(max_jobs)
    )
    jobs = list(result.scalars().all())
    for job in jobs:
        job.status = "assigned"
        job.assigned_at = _now()
    await db.flush()
    return jobs


SUBMITTABLE_AGENT_JOB_STATUSES = {"pending", "assigned"}


def is_submittable_status(status_value: str) -> bool:
    """Un agente solo puede reportar el resultado de un job que todavia no
    tiene un resultado final. Sin este chequeo, un doble submit (el agente
    reintentando tras perder la respuesta del primer POST, o dos procesos
    de agente corriendo por error con la misma api key) podia sobreescribir
    un resultado ya guardado (completed/failed) y volver a reenviar los
    mismos hallazgos a vuln-service/siem-service como si fueran nuevos."""
    return status_value in SUBMITTABLE_AGENT_JOB_STATUSES


async def get_agent_job_for_agent(db: AsyncSession, agent: ScanAgent, job_id: str) -> AgentScanJob | None:
    """Nunca se deja que un agente vea/escriba el resultado de un job que no
    es suyo -- ni por error de programacion del lado del agente, ni por una
    key comprometida usada para adivinar ids de otro agente."""
    job = await db.get(AgentScanJob, job_id)
    if job is None or job.agent_id != agent.id:
        return None
    return job


async def submit_agent_result(db: AsyncSession, agent: ScanAgent, job: AgentScanJob, payload) -> AgentScanJob:
    job.status = payload.status
    job.findings = payload.findings
    job.error_message = payload.error_message[:2000]
    job.finished_at = _now()
    agent.last_seen_at = _now()
    await db.flush()
    if payload.status == "completed" and payload.findings:
        await _forward_agent_findings_to_vuln_service(job)
        await _forward_agent_findings_to_siem_service(job)
    return job


async def _forward_agent_findings_to_vuln_service(job: AgentScanJob) -> None:
    """Mismo patron best-effort que _forward_findings_to_vuln_service: si
    vuln-service no responde, el job ya quedo guardado igual con sus
    findings. asset_id siempre None aca porque un agente remoto escanea
    targets de red (IP/CIDR), no un asset ya inventariado."""
    payload = {
        "scan_job_id": job.id,
        "asset_id": None,
        "scanner_type": job.scanner_type,
        "findings": job.findings,
        "organization_id": job.organization_id,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{VULN_SERVICE_URL}/vulnerabilities/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning(
            "no se pudo reenviar hallazgos de agente remoto a vuln-service",
            extra={"job_id": job.id, "error": str(exc)},
        )


async def _forward_agent_findings_to_siem_service(job: AgentScanJob) -> None:
    """Mismo patron best-effort, ver _forward_findings_to_siem_service."""
    payload = {
        "organization_id": job.organization_id,
        "events": _findings_to_siem_events(job.scanner_type, job.target, None, job.findings),
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SIEM_SERVICE_URL}/logs/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning(
            "no se pudo reenviar hallazgos de agente remoto a siem-service",
            extra={"job_id": job.id, "error": str(exc)},
        )
