"""scan-service entrypoint: orquestacion de escaneres defensivos
(nmap/trivy/nuclei/openvas) en modo SOLO DETECCION. Ver
app/scanners/base.py y docs/architecture.md para el alcance."""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.base import JobLookupError

from sqlalchemy import text
from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import (
    ScanJobCreate,
    ScanJobOut,
    ScanScheduleCreate,
    ScanScheduleUpdate,
    ScanScheduleOut,
    ScanAgentCreate,
    ScanAgentOut,
    ScanAgentCreated,
    AgentScanJobCreate,
    AgentScanJobOut,
    AgentPollResponse,
    AgentPollJob,
    AgentResultSubmit,
)
from app.dependencies import get_current_claims, require_role, get_agent_from_key
from app import services

logger = configure_logging("scan-service")
scan_jobs_total = Counter("scan_jobs_total", "Jobs de escaneo creados", ["scanner_type"])

# Scheduler en proceso para las reglas de escaneo recurrente (ScanSchedule).
# Una sola instancia de scan-service = un solo scheduler -- no hace falta
# infraestructura de colas para esto, y es el mismo patron simple que ya
# usa el resto de la plataforma (sin brokers externos).
# timezone explicito a proposito, y en los DOS lugares que lo piden
# (el scheduler Y cada CronTrigger, mas abajo): sin esto, APScheduler
# intenta autodetectar la zona horaria del sistema (tzlocal) y en una
# imagen Debian "slim" como la de este contenedor eso puede fallar duro
# al arrancar (o al crear cualquier regla) si el sistema reporta una
# zona para la que no tiene datos de zoneinfo instalados -- tumbando
# todo el servicio. Default UTC; configurable con SCHEDULER_TIMEZONE si
# se quiere que las horas de las reglas (hour/minute) se interpreten en
# otra zona.
_SCHEDULER_TZ = os.getenv("SCHEDULER_TIMEZONE", "UTC")
scheduler = AsyncIOScheduler(timezone=_SCHEDULER_TZ)


def _job_id(schedule_id: str) -> str:
    return f"scan-schedule:{schedule_id}"


def _cron_trigger_for(schedule) -> CronTrigger:
    if schedule.frequency == "weekly":
        return CronTrigger(
            day_of_week=schedule.day_of_week, hour=schedule.hour, minute=schedule.minute, timezone=_SCHEDULER_TZ
        )
    return CronTrigger(hour=schedule.hour, minute=schedule.minute, timezone=_SCHEDULER_TZ)


def _register_job(schedule) -> None:
    scheduler.add_job(
        services.run_scheduled_scan,
        trigger=_cron_trigger_for(schedule),
        args=[SessionLocal, schedule.id],
        id=_job_id(schedule.id),
        replace_existing=True,
        misfire_grace_time=3600,
    )


def _unregister_job(schedule_id: str) -> None:
    try:
        scheduler.remove_job(_job_id(schedule_id))
    except JobLookupError:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for table in ("scan_schedules", "scan_jobs", "scan_agents", "agent_scan_jobs"):
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
            await conn.execute(text(
                f"UPDATE {table} SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
            ))
    async with SessionLocal() as db:
        for schedule in await services.list_schedules(db):
            if schedule.enabled:
                _register_job(schedule)
    # Refresh periodico de datos de escaner (DB de CVEs de trivy, plantillas
    # de nuclei) en segundo plano -- asi cada escaneo individual no paga el
    # costo de descarga/actualizacion (ver app/scanners/trivy.py y
    # app/scanners/nuclei.py, que corren con --skip-db-update / -duc).
    # next_run_time=ahora para que corra una vez apenas arranca el servicio
    # (por si el volumen persistente esta vacio en el primer `docker compose up`)
    # y despues cada N horas.
    from datetime import datetime as _dt
    scheduler.add_job(
        services.refresh_trivy_db,
        trigger=IntervalTrigger(hours=24),
        id="trivy-db-refresh",
        replace_existing=True,
        next_run_time=_dt.now(),
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        services.refresh_nuclei_templates,
        trigger=IntervalTrigger(hours=12),
        id="nuclei-templates-refresh",
        replace_existing=True,
        next_run_time=_dt.now(),
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info("scan-service iniciado", extra={"reglas_programadas": len(scheduler.get_jobs())})
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SentinelOps Scan Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "scan-service"}


@app.get("/scanners/status")
async def scanners_status(claims: dict = Depends(get_current_claims)):
    return services.scanners_status()


@app.post("/scans", response_model=ScanJobOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanJobCreate,
    background_tasks: BackgroundTasks,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.create_scan_job(db, payload, claims.get("sub", ""), org_id_from_claims(claims))
    await db.commit()
    scan_jobs_total.labels(scanner_type=payload.scanner_type.value).inc()
    logger.info("scan job creado", extra={"job_id": job.id, "scanner": payload.scanner_type.value})
    background_tasks.add_task(services.execute_scan_job, SessionLocal, job.id)
    return job


@app.get("/scans", response_model=list[ScanJobOut])
async def list_scans(
    status_filter: str | None = None,
    scanner_type: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_scan_jobs(db, org_id_from_claims(claims), status_filter, scanner_type)


@app.get("/scans/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    job = await services.get_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    return job


@app.delete("/scans/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    job_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    if not services.is_deletable_status(job.status):
        raise HTTPException(status_code=409, detail="Solo se pueden borrar escaneos ya finalizados")
    await services.delete_scan_job(db, job)
    await db.commit()
    logger.info("scan job borrado", extra={"job_id": job_id, "actor": claims.get("sub")})


@app.post("/scans/{job_id}/cancel", response_model=ScanJobOut)
async def cancel_scan(
    job_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo no encontrado")
    if not services.is_cancellable_status(job.status):
        raise HTTPException(status_code=409, detail="Solo se pueden cancelar escaneos pendientes o en curso")
    job = await services.cancel_scan_job(db, job)
    await db.commit()
    logger.info("scan job cancelado", extra={"job_id": job_id, "actor": claims.get("sub")})
    return job


@app.post("/scan-schedules", response_model=ScanScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScanScheduleCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.create_schedule(db, payload, claims.get("sub", ""), org_id_from_claims(claims))
    await db.commit()
    _register_job(schedule)
    logger.info("regla de escaneo programado creada", extra={"schedule_id": schedule.id})
    return schedule


@app.get("/scan-schedules", response_model=list[ScanScheduleOut])
async def list_schedules_endpoint(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_schedules(db, org_id_from_claims(claims))


@app.patch("/scan-schedules/{schedule_id}", response_model=ScanScheduleOut)
async def update_schedule(
    schedule_id: str,
    payload: ScanScheduleUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.get_schedule(db, schedule_id, org_id_from_claims(claims))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Regla de escaneo no encontrada")
    schedule = await services.set_schedule_enabled(db, schedule, payload.enabled)
    await db.commit()
    if payload.enabled:
        _register_job(schedule)
    else:
        _unregister_job(schedule_id)
    return schedule


@app.delete("/scan-schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    schedule = await services.get_schedule(db, schedule_id, org_id_from_claims(claims))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Regla de escaneo no encontrada")
    await services.delete_schedule(db, schedule)
    await db.commit()
    _unregister_job(schedule_id)


# --- Agentes de escaneo remoto ---
# El agente (remote-agent/agent.py) corre FUERA de Docker (en la misma PC
# o en cualquier maquina de la LAN) y hace polling hacia este puerto ya
# publicado (8003) -- nunca al reves, asi que no hace falta abrir ningun
# puerto de entrada en la red del cliente. Ver app/models.py::ScanAgent.

@app.post("/agents", response_model=ScanAgentCreated, status_code=status.HTTP_201_CREATED)
async def create_agent(
    payload: ScanAgentCreate,
    claims: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    agent, api_key = await services.create_agent(db, payload, claims.get("sub", ""), org_id_from_claims(claims))
    await db.commit()
    logger.info("agente de escaneo remoto creado", extra={"agent_id": agent.id})
    # api_key solo existe en texto plano en esta respuesta -- el servidor
    # ya solo tiene su hash guardado (ver ScanAgent.key_hash).
    return ScanAgentCreated(
        id=agent.id, name=agent.name, created_by=agent.created_by,
        created_at=agent.created_at, last_seen_at=agent.last_seen_at, api_key=api_key,
    )


@app.get("/agents", response_model=list[ScanAgentOut])
async def list_agents(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_agents(db, org_id_from_claims(claims))


@app.delete("/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: str,
    claims: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    agent = await services.get_agent(db, agent_id, org_id_from_claims(claims))
    if agent is None:
        raise HTTPException(status_code=404, detail="Agente no encontrado")
    await services.delete_agent(db, agent)
    await db.commit()


@app.post("/agent-scans", response_model=AgentScanJobOut, status_code=status.HTTP_201_CREATED)
async def create_agent_scan(
    payload: AgentScanJobCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    organization_id = org_id_from_claims(claims)
    agent = await services.get_agent(db, payload.agent_id, organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agente no encontrado")
    job = await services.create_agent_scan_job(db, payload, claims.get("sub", ""), organization_id)
    await db.commit()
    logger.info("job de escaneo remoto creado", extra={"job_id": job.id, "agent_id": payload.agent_id})
    return job


@app.get("/agent-scans", response_model=list[AgentScanJobOut])
async def list_agent_scans(
    agent_id: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_agent_scan_jobs(db, org_id_from_claims(claims), agent_id)


@app.delete("/agent-scans/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent_scan(
    job_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_agent_scan_job(db, job_id, org_id_from_claims(claims))
    if job is None:
        raise HTTPException(status_code=404, detail="Job de escaneo remoto no encontrado")
    if not services.is_deletable_status(job.status):
        raise HTTPException(status_code=409, detail="Solo se pueden borrar escaneos ya finalizados")
    await services.delete_agent_scan_job(db, job)
    await db.commit()
    logger.info("scan job remoto borrado", extra={"job_id": job_id, "actor": claims.get("sub")})


@app.post("/agents/poll", response_model=AgentPollResponse)
async def poll_agent(agent=Depends(get_agent_from_key), db: AsyncSession = Depends(get_db)):
    jobs = await services.poll_agent_jobs(db, agent)
    await db.commit()
    return AgentPollResponse(
        jobs=[
            AgentPollJob(id=j.id, scanner_type=j.scanner_type, target=j.target, options=j.options)
            for j in jobs
        ]
    )


@app.post("/agents/results/{job_id}", response_model=AgentScanJobOut)
async def submit_agent_result(
    job_id: str,
    payload: AgentResultSubmit,
    agent=Depends(get_agent_from_key),
    db: AsyncSession = Depends(get_db),
):
    job = await services.get_agent_job_for_agent(db, agent, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job no encontrado o no pertenece a este agente")
    if not services.is_submittable_status(job.status):
        raise HTTPException(
            status_code=409,
            detail="Este job de escaneo remoto ya tiene un resultado final, no se puede sobreescribir",
        )
    job = await services.submit_agent_result(db, agent, job, payload)
    await db.commit()
    logger.info("resultado de escaneo remoto recibido", extra={"job_id": job_id, "status": payload.status})
    return job
