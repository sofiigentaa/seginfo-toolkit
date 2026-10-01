"""asset-service entrypoint: CMDB de activos (inventario)."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import AssetCreate, AssetUpdate, AssetOut, AssetGroupCreate, AssetGroupOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("asset-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migracion para instalaciones existentes (create_all no altera
        # tablas que ya existian antes de multi-tenancy): agrega
        # organization_id si falta, backfillea filas viejas a la
        # organizacion default, y migra la constraint unica vieja de
        # asset_groups.name (global) a la nueva (por organizacion).
        await conn.execute(text(
            "ALTER TABLE assets ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        ))
        await conn.execute(text(
            "ALTER TABLE asset_groups ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        ))
        await conn.execute(text(
            f"UPDATE assets SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text(
            f"UPDATE asset_groups SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
        await conn.execute(text("ALTER TABLE asset_groups DROP CONSTRAINT IF EXISTS asset_groups_name_key"))
        # Postgres no soporta "ADD CONSTRAINT IF NOT EXISTS" -- se chequea
        # pg_constraint primero para que sea seguro correr esto en cada
        # arranque (create_all ya la crea sola en una tabla nueva via
        # __table_args__, asi que esto solo hace falta la primera vez que una
        # instalacion existente arranca con esta version).
        existing_constraint = await conn.execute(text(
            "SELECT 1 FROM pg_constraint WHERE conname = 'uq_asset_groups_org_name'"
        ))
        if existing_constraint.first() is None:
            await conn.execute(text(
                "ALTER TABLE asset_groups ADD CONSTRAINT uq_asset_groups_org_name "
                "UNIQUE (organization_id, name)"
            ))
    logger.info("asset-service iniciado")
    yield


app = FastAPI(title="SentinelOps Asset Service", version="0.1.0", lifespan=lifespan)
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
    return {"status": "ok", "service": "asset-service"}


@app.get("/assets", response_model=list[AssetOut])
async def get_assets(
    environment: str | None = None,
    criticality: str | None = None,
    include_inactive: bool = False,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    assets = await services.list_assets(
        db, org_id_from_claims(claims), environment, criticality, active_only=not include_inactive
    )
    return assets


@app.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    asset = await services.get_asset(db, asset_id, org_id_from_claims(claims))
    if asset is None:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    return asset


@app.post("/assets", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    asset = await services.create_asset(db, payload, org_id_from_claims(claims))
    await db.commit()
    logger.info("asset creado", extra={"asset_id": asset.id, "actor": claims.get("sub")})
    return asset


@app.patch("/assets/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    # is_active tiene el mismo peso que el DELETE de mas abajo (desactivar
    # un activo), que a proposito requiere un rol mas alto (admin/soc_manager,
    # sin analyst) -- sin este chequeo, un analyst podia lograr lo mismo
    # mandando is_active=False por PATCH, esquivando esa restriccion.
    if payload.is_active is not None and not services.can_set_active_state(claims.get("role")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes para activar/desactivar un activo")
    asset = await services.get_asset(db, asset_id, org_id_from_claims(claims))
    if asset is None:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    asset = await services.update_asset(db, asset, payload)
    await db.commit()
    return asset


@app.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_asset(
    asset_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    asset = await services.get_asset(db, asset_id, org_id_from_claims(claims))
    if asset is None:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    await services.deactivate_asset(db, asset)
    await db.commit()


@app.get("/asset-groups", response_model=list[AssetGroupOut])
async def get_groups(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.list_groups(db, org_id_from_claims(claims))


@app.post("/asset-groups", response_model=AssetGroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: AssetGroupCreate,
    claims: dict = Depends(require_role("admin", "soc_manager")),
    db: AsyncSession = Depends(get_db),
):
    group = await services.create_group(db, payload, org_id_from_claims(claims))
    await db.commit()
    return group
