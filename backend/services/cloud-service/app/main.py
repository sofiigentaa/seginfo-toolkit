"""cloud-service entrypoint: integracion de solo LECTURA con una cuenta de
AWS del cliente -- trae automaticamente el inventario de instancias EC2 y
buckets S3 (en vez de cargarlos a mano) y detecta configuraciones
peligrosas (buckets S3 publicos, security groups abiertos a 0.0.0.0/0).
NUNCA crea, modifica ni borra ningun recurso en la cuenta de AWS del
cliente -- ver el docstring de app/services.py."""
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import org_id_from_claims
from app.models import CloudResourceType
from app.schemas import CloudAccountCreate, CloudAccountOut, CloudFindingOut, CloudFindingUpdate, CloudResourceOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("cloud-service")

# Mismo motivo que en asm-service/scan-service: timezone explicito para
# que APScheduler no intente autodetectar la zona horaria del sistema
# (tzlocal), lo que puede fallar duro al arrancar en una imagen Debian
# "slim" sin datos de zoneinfo para esa zona.
_SCHEDULER_TZ = os.getenv("SCHEDULER_TIMEZONE", "UTC")
scheduler = AsyncIOScheduler(timezone=_SCHEDULER_TZ)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        # Tablas 100% nuevas (no ALTER de una tabla existente) -- create_all
        # alcanza, no hace falta ningun ALTER TABLE/backfill como en los
        # servicios que ya tenian tablas antes de multi-tenancy.
        await conn.run_sync(Base.metadata.create_all)

    # Un solo job periodico que sincroniza todas las cuentas de AWS
    # habilitadas de todas las organizaciones. next_run_time=ahora para
    # que corra una vez apenas arranca el servicio, y despues cada
    # CLOUD_SYNC_INTERVAL_HOURS.
    scheduler.add_job(
        services.sync_all_enabled_accounts,
        trigger=IntervalTrigger(hours=int(os.getenv("CLOUD_SYNC_INTERVAL_HOURS", "6"))),
        args=[SessionLocal],
        id="cloud-sync-all-accounts",
        replace_existing=True,
        next_run_time=datetime.now(),
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info("cloud-service iniciado")
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SentinelOps Cloud Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


def _account_out(account) -> CloudAccountOut:
    """CloudAccountOut no tiene un campo `access_key_id_masked` en el
    modelo de DB -- se calcula al armar la respuesta, nunca se persiste
    (evita guardar en la base algo derivado que podria desincronizarse
    de la credencial real si esta se rota)."""
    from app.services import mask_access_key_id
    from backend.shared.crypto import decrypt_secret

    return CloudAccountOut(
        id=account.id,
        name=account.name,
        provider=account.provider,
        region=account.region,
        access_key_id_masked=mask_access_key_id(decrypt_secret(account.access_key_id_encrypted) or ""),
        is_enabled=account.is_enabled,
        last_sync_at=account.last_sync_at,
        last_sync_status=account.last_sync_status,
        last_sync_error=account.last_sync_error,
        created_by=account.created_by,
        created_at=account.created_at,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "cloud-service"}


@app.post("/accounts", response_model=CloudAccountOut, status_code=status.HTTP_201_CREATED)
async def create_account(
    payload: CloudAccountCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    account = await services.create_account(db, payload, org_id_from_claims(claims), claims.get("sub", ""))
    await db.commit()
    logger.info("cuenta de AWS agregada", extra={"cloud_account_id": account.id, "actor": claims.get("sub")})
    return _account_out(account)


@app.get("/accounts", response_model=list[CloudAccountOut])
async def get_accounts(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    accounts = await services.list_accounts(db, org_id_from_claims(claims))
    return [_account_out(a) for a in accounts]


@app.delete("/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    account_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    account = await services.get_account(db, account_id, org_id_from_claims(claims))
    if account is None:
        raise HTTPException(status_code=404, detail="Cuenta de AWS no encontrada")
    await services.delete_account(db, account)
    await db.commit()
    logger.info("cuenta de AWS borrada", extra={"cloud_account_id": account_id, "actor": claims.get("sub")})


@app.post("/accounts/{account_id}/sync-now", status_code=status.HTTP_202_ACCEPTED)
async def sync_account_now(
    account_id: str,
    background_tasks: BackgroundTasks,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    account = await services.get_account(db, account_id, org_id_from_claims(claims))
    if account is None:
        raise HTTPException(status_code=404, detail="Cuenta de AWS no encontrada")
    background_tasks.add_task(services.run_account_sync_now, SessionLocal, account_id)
    logger.info("sync manual disparado", extra={"cloud_account_id": account_id, "actor": claims.get("sub")})
    return {"detail": "Sync disparado en segundo plano"}


@app.get("/resources", response_model=list[CloudResourceOut])
async def get_resources(
    cloud_account_id: str | None = None,
    resource_type: CloudResourceType | None = None,
    is_active: bool | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_resources(
        db, org_id_from_claims(claims), cloud_account_id=cloud_account_id, resource_type=resource_type, is_active=is_active
    )


@app.get("/findings", response_model=list[CloudFindingOut])
async def get_findings(
    all: bool = False,
    is_acknowledged: bool | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    # Mismo criterio que GET /alerts en asm-service: por default solo se
    # muestran los hallazgos pendientes; ?all=true (o is_acknowledged
    # explicito) para ver otra cosa.
    effective = is_acknowledged if is_acknowledged is not None else (None if all else False)
    return await services.list_findings(db, org_id_from_claims(claims), effective)


@app.patch("/findings/{finding_id}", response_model=CloudFindingOut)
async def update_finding(
    finding_id: str,
    payload: CloudFindingUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    finding = await services.get_finding(db, finding_id, org_id_from_claims(claims))
    if finding is None:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    finding = await services.acknowledge_finding(db, finding, payload.is_acknowledged, claims.get("sub", ""))
    await db.commit()
    return finding
