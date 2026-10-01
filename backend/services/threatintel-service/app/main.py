"""threatintel-service entrypoint: resuelve si una IP es maliciosa conocida
contra fuentes externas (AbuseIPDB, MISP), cacheando el resultado. Lo
consume tanto un usuario final (GET /lookup/{ip}, ej. desde el widget de
busqueda de Siem.tsx) como otro microservicio (POST /internal/lookup-batch,
ej. siem-service enriqueciendo una alerta nueva -- ver
siem-service/app/services.py::_enrich_alert_with_threat_intel)."""
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from app.schemas import IpReputationOut, LookupBatchRequest, LookupBatchResponse
from app.dependencies import get_current_claims
from app import services

logger = configure_logging("threatintel-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        # Tabla nueva (no existia antes de este servicio) -- a diferencia
        # del resto de los microservicios, no hace falta ninguna migracion
        # ALTER TABLE para instalaciones existentes: create_all alcanza.
        await conn.run_sync(Base.metadata.create_all)
    logger.info("threatintel-service iniciado")
    yield


app = FastAPI(title="SentinelOps Threat Intel Service", version="0.1.0", lifespan=lifespan)
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
    return {"status": "ok", "service": "threatintel-service"}


@app.get("/lookup/{ip}", response_model=IpReputationOut)
async def lookup(ip: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    # Cualquier rol autenticado alcanza -- es una consulta de solo lectura/
    # enriquecimiento, no hay ninguna accion sensible que proteger con un
    # RBAC mas granular (a diferencia de, por ejemplo, activar/desactivar
    # un activo en asset-service).
    async with httpx.AsyncClient() as http_client:
        result = await services.lookup_ip(db, ip, http_client)
    await db.commit()
    return result


@app.post("/internal/lookup-batch", response_model=LookupBatchResponse)
async def internal_lookup_batch(payload: LookupBatchRequest, db: AsyncSession = Depends(get_db)):
    """Endpoint interno (SIN auth de usuario -- mismo patron que
    /internal/rule-tags de siem-service o /internal/* de integration-service:
    pensado para llamadas servicio-a-servicio dentro de la red de
    docker-compose, no expuesto afuera de ella)."""
    results = await services.lookup_batch(db, payload.ips)
    return LookupBatchResponse(results=results)
