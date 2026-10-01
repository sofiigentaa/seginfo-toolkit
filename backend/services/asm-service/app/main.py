"""asm-service entrypoint: monitoreo PASIVO de superficie externa (Attack
Surface Monitoring) -- descubrimiento de subdominios via Certificate
Transparency (crt.sh, una API publica de solo lectura) y chequeo del
certificado SSL que un host ya esta sirviendo publicamente (handshake TLS
normal al puerto 443, igual al de cualquier navegador). NUNCA hace escaneo
activo de puertos ni toca infraestructura de terceros mas alla de eso --
ver docs/architecture.md y el docstring de app/services.py."""
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import MonitoredDomainCreate, MonitoredDomainOut, DiscoveredAssetOut, SurfaceAlertOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("asm-service")

# Mismo motivo que en scan-service (ver app/main.py de ahi): timezone
# explicito para que APScheduler no intente autodetectar la zona horaria
# del sistema (tzlocal), lo que puede fallar duro al arrancar en una
# imagen Debian "slim" sin datos de zoneinfo para esa zona.
_SCHEDULER_TZ = os.getenv("SCHEDULER_TIMEZONE", "UTC")
scheduler = AsyncIOScheduler(timezone=_SCHEDULER_TZ)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migracion para instalaciones existentes, mismo patron que
        # asset-service/scan-service: agrega organization_id si falta y
        # backfillea filas viejas a la organizacion default.
        for table in ("monitored_domains", "discovered_assets", "ssl_certificates", "surface_alerts"):
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"))
            await conn.execute(text(
                f"UPDATE {table} SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
            ))

    # Un solo job periodico que chequea todos los dominios habilitados de
    # todas las organizaciones. next_run_time=ahora para que corra una vez
    # apenas arranca el servicio (mismo truco que el refresh de trivy/nuclei
    # en scan-service), y despues cada ASM_CHECK_INTERVAL_HOURS.
    scheduler.add_job(
        services.check_all_enabled_domains,
        trigger=IntervalTrigger(hours=int(os.getenv("ASM_CHECK_INTERVAL_HOURS", "12"))),
        args=[SessionLocal],
        id="asm-check-all-domains",
        replace_existing=True,
        next_run_time=datetime.now(),
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info("asm-service iniciado")
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SentinelOps ASM Service", version="0.1.0", lifespan=lifespan)
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
    return {"status": "ok", "service": "asm-service"}


@app.post("/domains", response_model=MonitoredDomainOut, status_code=status.HTTP_201_CREATED)
async def create_domain(
    payload: MonitoredDomainCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    try:
        normalized = services.normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    org_id = org_id_from_claims(claims)
    if await services.domain_exists(db, org_id, normalized):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ese dominio ya esta siendo monitoreado")

    domain = await services.create_domain(db, normalized, org_id, claims.get("sub", ""))
    await db.commit()
    logger.info("dominio agregado a monitoreo", extra={"domain_id": domain.id, "domain": domain.domain})
    return domain


@app.get("/domains", response_model=list[MonitoredDomainOut])
async def get_domains(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_domains(db, org_id_from_claims(claims))


@app.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    domain = await services.get_domain(db, domain_id, org_id_from_claims(claims))
    if domain is None:
        raise HTTPException(status_code=404, detail="Dominio monitoreado no encontrado")
    await services.delete_domain(db, domain)
    await db.commit()
    logger.info("dominio monitoreado borrado", extra={"domain_id": domain_id, "actor": claims.get("sub")})


@app.post("/domains/{domain_id}/check-now", status_code=status.HTTP_202_ACCEPTED)
async def check_domain_now(
    domain_id: str,
    background_tasks: BackgroundTasks,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    domain = await services.get_domain(db, domain_id, org_id_from_claims(claims))
    if domain is None:
        raise HTTPException(status_code=404, detail="Dominio monitoreado no encontrado")
    background_tasks.add_task(services.run_domain_check_now, SessionLocal, domain_id)
    logger.info("chequeo manual disparado", extra={"domain_id": domain_id, "actor": claims.get("sub")})
    return {"detail": "Chequeo disparado en segundo plano"}


@app.get("/domains/{domain_id}/assets", response_model=list[DiscoveredAssetOut])
async def get_domain_assets(
    domain_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)
):
    org_id = org_id_from_claims(claims)
    domain = await services.get_domain(db, domain_id, org_id)
    if domain is None:
        raise HTTPException(status_code=404, detail="Dominio monitoreado no encontrado")
    return await services.list_assets_for_domain(db, domain_id, org_id)


@app.get("/alerts", response_model=list[SurfaceAlertOut])
async def get_alerts(
    acknowledged: bool | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_alerts(db, org_id_from_claims(claims), acknowledged)


@app.patch("/alerts/{alert_id}", response_model=SurfaceAlertOut)
async def acknowledge_alert(
    alert_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    alert = await services.get_alert(db, alert_id, org_id_from_claims(claims))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    alert = await services.acknowledge_alert(db, alert, claims.get("sub", ""))
    await db.commit()
    return alert
