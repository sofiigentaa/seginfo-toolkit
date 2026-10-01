"""coderepo-service entrypoint: escaneo de repositorios de codigo del
cliente en modo SOLO LECTURA/analisis DEFENSIVO -- detecta secretos
commiteados por error (gitleaks, todo el historial de git) y dependencias
vulnerables (trivy fs, checkout actual). NUNCA escribe en el repositorio
del cliente ni ejecuta codigo del repositorio clonado -- ver el docstring
de app/services.py para el alcance completo."""
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
from app.models import RepoTarget
from app.schemas import RepoTargetCreate, RepoTargetOut, SecretFindingOut, SecretFindingUpdate
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("coderepo-service")

# Mismo motivo que en cloud-service/scan-service: timezone explicito para
# que APScheduler no intente autodetectar la zona horaria del sistema
# (tzlocal), lo que puede fallar duro al arrancar en una imagen Debian
# "slim" sin datos de zoneinfo para esa zona.
_SCHEDULER_TZ = os.getenv("SCHEDULER_TIMEZONE", "UTC")
scheduler = AsyncIOScheduler(timezone=_SCHEDULER_TZ)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        # Tablas 100% nuevas -- create_all alcanza, no hace falta ningun
        # ALTER TABLE/backfill.
        await conn.run_sync(Base.metadata.create_all)

    # Job periodico que escanea todos los repositorios habilitados de
    # todas las organizaciones. next_run_time=ahora para que corra una vez
    # apenas arranca el servicio, y despues cada
    # CODEREPO_SCAN_INTERVAL_HOURS. Default 24hs (mas alto que el de
    # cloud-service/asm-service): clonar+escanear repos completos es mas
    # pesado que un chequeo de dominio/cuenta AWS, no tiene sentido
    # correrlo cada pocas horas.
    scheduler.add_job(
        services.scan_all_enabled_targets,
        trigger=IntervalTrigger(hours=int(os.getenv("CODEREPO_SCAN_INTERVAL_HOURS", "24"))),
        args=[SessionLocal],
        id="coderepo-scan-all-targets",
        replace_existing=True,
        next_run_time=datetime.now(),
        misfire_grace_time=3600,
    )
    # Refresco periodico de la DB de CVEs de trivy (mismo patron que
    # scan-service::refresh_trivy_db, registrado ahi tambien via
    # APScheduler) -- cada escaneo individual corre con --skip-db-update.
    scheduler.add_job(
        services.refresh_trivy_db,
        trigger=IntervalTrigger(hours=24),
        id="coderepo-refresh-trivy-db",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info("coderepo-service iniciado")
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SentinelOps Code Repository Scan Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


def _target_out(target: RepoTarget) -> RepoTargetOut:
    """RepoTargetOut no tiene un campo con el token de GitHub -- solo
    has_token, calculado al armar la respuesta (nunca se devuelve el
    token ni en texto plano ni cifrado)."""
    return RepoTargetOut(
        id=target.id,
        name=target.name,
        repo_url=target.repo_url,
        branch=target.branch,
        has_token=bool(target.github_token_encrypted),
        is_enabled=target.is_enabled,
        last_scan_at=target.last_scan_at,
        last_scan_status=target.last_scan_status,
        last_scan_error=target.last_scan_error,
        last_scan_secrets_found=target.last_scan_secrets_found,
        last_scan_vulnerabilities_found=target.last_scan_vulnerabilities_found,
        created_by=target.created_by,
        created_at=target.created_at,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "coderepo-service"}


@app.post("/repos", response_model=RepoTargetOut, status_code=status.HTTP_201_CREATED)
async def create_repo(
    payload: RepoTargetCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    if not services.validate_repo_url(payload.repo_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="repo_url debe empezar con https:// (no se soportan git@/ssh://)",
        )
    target = await services.create_target(db, payload, org_id_from_claims(claims), claims.get("sub", ""))
    await db.commit()
    logger.info("repositorio agregado", extra={"repo_target_id": target.id, "actor": claims.get("sub")})
    return _target_out(target)


@app.get("/repos", response_model=list[RepoTargetOut])
async def get_repos(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    targets = await services.list_targets(db, org_id_from_claims(claims))
    return [_target_out(t) for t in targets]


@app.delete("/repos/{repo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_repo(
    repo_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    target = await services.get_target(db, repo_id, org_id_from_claims(claims))
    if target is None:
        raise HTTPException(status_code=404, detail="Repositorio no encontrado")
    await services.delete_target(db, target)
    await db.commit()
    logger.info("repositorio borrado", extra={"repo_target_id": repo_id, "actor": claims.get("sub")})


@app.post("/repos/{repo_id}/scan-now", status_code=status.HTTP_202_ACCEPTED)
async def scan_repo_now(
    repo_id: str,
    background_tasks: BackgroundTasks,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    target = await services.get_target(db, repo_id, org_id_from_claims(claims))
    if target is None:
        raise HTTPException(status_code=404, detail="Repositorio no encontrado")
    background_tasks.add_task(services.run_repo_scan_now, SessionLocal, repo_id)
    logger.info("scan manual disparado", extra={"repo_target_id": repo_id, "actor": claims.get("sub")})
    return {"detail": "Escaneo disparado en segundo plano"}


@app.get("/secrets", response_model=list[SecretFindingOut])
async def get_secrets(
    repo_target_id: str | None = None,
    all: bool = False,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    # Mismo criterio que GET /findings en cloud-service: por default solo
    # se muestran los hallazgos pendientes; ?all=true para ver todos.
    is_acknowledged = None if all else False
    return await services.list_secrets(db, org_id_from_claims(claims), repo_target_id=repo_target_id, is_acknowledged=is_acknowledged)


@app.patch("/secrets/{finding_id}", response_model=SecretFindingOut)
async def update_secret(
    finding_id: str,
    payload: SecretFindingUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    finding = await services.get_secret(db, finding_id, org_id_from_claims(claims))
    if finding is None:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    finding = await services.acknowledge_secret(db, finding, payload.is_acknowledged, claims.get("sub", ""))
    await db.commit()
    return finding
