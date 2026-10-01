"""notification-service entrypoint: canales configurables (email/Slack/
webhook generico) para avisar de alertas/incidentes. Por defecto en modo
DRY-RUN (NOTIFICATION_DRY_RUN=true): registra la notificacion que *se
enviaria* sin hacer ninguna llamada de red real, igual que el patron de
soar-service."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import text
from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import ChannelCreate, ChannelUpdate, ChannelOut, NotifyRequest, NotifyResult, NotifyLogOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("notification-service")
notifications_sent_total = Counter("notification_sent_total", "Notificaciones procesadas", ["channel_type", "status"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text(
            "ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        ))
        await conn.execute(text(
            "ALTER TABLE notification_logs ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        ))
        await conn.execute(text(
            f"UPDATE notification_channels SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text(
            f"UPDATE notification_logs SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    logger.info("notification-service iniciado", extra={"dry_run": services.dry_run_enabled()})
    yield


app = FastAPI(title="SentinelOps Notification Service", version="0.1.0", lifespan=lifespan)
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
    return {"status": "ok", "service": "notification-service", "dry_run": services.dry_run_enabled()}


@app.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
async def create_channel(
    payload: ChannelCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    channel = await services.create_channel(db, payload, org_id_from_claims(claims))
    await db.commit()
    return channel


@app.get("/channels", response_model=list[ChannelOut])
async def list_channels(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_channels(db, org_id_from_claims(claims))


@app.patch("/channels/{channel_id}", response_model=ChannelOut)
async def update_channel(
    channel_id: str,
    payload: ChannelUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    channel = await services.get_channel(db, channel_id, org_id_from_claims(claims))
    if channel is None:
        raise HTTPException(status_code=404, detail="Canal no encontrado")
    channel = await services.update_channel(db, channel, payload)
    await db.commit()
    return channel


@app.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    channel_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    channel = await services.get_channel(db, channel_id, org_id_from_claims(claims))
    if channel is None:
        raise HTTPException(status_code=404, detail="Canal no encontrado")
    await services.delete_channel(db, channel)
    await db.commit()
    logger.info("canal de notificacion borrado", extra={"channel_id": channel_id, "actor": claims.get("sub")})


@app.post("/notify", response_model=NotifyResult)
async def notify(
    payload: NotifyRequest,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    # Se pisa cualquier organization_id que venga en el body con el del JWT
    # -- un usuario autenticado nunca debe poder mandar notificaciones a
    # canales de otra organizacion solo cambiando este campo.
    payload.organization_id = org_id_from_claims(claims)
    logs = await services.notify(db, payload)
    await db.commit()
    for log in logs:
        notifications_sent_total.labels(channel_type=log.channel_type, status=log.status).inc()
    return NotifyResult(results=[NotifyLogOut.model_validate(l) for l in logs])


@app.get("/logs", response_model=list[NotifyLogOut])
async def list_logs(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_logs(db, org_id_from_claims(claims))


@app.post("/internal/notify", response_model=NotifyResult)
async def internal_notify(payload: NotifyRequest, db: AsyncSession = Depends(get_db)):
    """Igual que POST /notify pero sin requerir un JWT de usuario -- para
    llamadas servicio-a-servicio dentro de la red de docker-compose (ej.
    soar-service disparando una notificacion desde un playbook, ver
    app/actions/notify.py de soar-service), mismo patron que los
    endpoints /internal/actions/* de integration-service. organization_id
    lo manda el caller explicitamente (no hay JWT de donde derivarlo); si
    falta, se asume la organizacion default."""
    logs = await services.notify(db, payload)
    await db.commit()
    for log in logs:
        notifications_sent_total.labels(channel_type=log.channel_type, status=log.status).inc()
    return NotifyResult(results=[NotifyLogOut.model_validate(l) for l in logs])
