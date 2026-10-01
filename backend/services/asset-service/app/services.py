"""Business logic for asset-service: CRUD sobre el CMDB de activos."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Asset, AssetGroup


async def list_assets(
    db: AsyncSession, organization_id: str, environment: str | None = None,
    criticality: str | None = None, active_only: bool = True,
) -> list[Asset]:
    query = select(Asset).where(Asset.organization_id == organization_id)
    if active_only:
        query = query.where(Asset.is_active.is_(True))
    if environment:
        query = query.where(Asset.environment == environment)
    if criticality:
        query = query.where(Asset.criticality == criticality)
    result = await db.execute(query.order_by(Asset.hostname))
    return list(result.scalars().all())


async def get_asset(db: AsyncSession, asset_id: str, organization_id: str) -> Asset | None:
    """organization_id es obligatorio (no opcional) a proposito: no existe
    ningun caller legitimo de este servicio que necesite leer un activo sin
    saber a que tenant pertenece -- todos los endpoints (y los otros
    microservicios que llaman a este via HTTP) ya tienen el org_id del JWT
    de quien esta pidiendo. Devuelve None si el activo existe pero es de
    otra organizacion, exactamente igual que si no existiera (evita filtrar
    por timing/existencia que el id pertenece a otro tenant)."""
    asset = await db.get(Asset, asset_id)
    if asset is None or asset.organization_id != organization_id:
        return None
    return asset


async def get_assets_by_ids(db: AsyncSession, asset_ids: list[str], organization_id: str) -> list[Asset]:
    if not asset_ids:
        return []
    result = await db.execute(
        select(Asset).where(Asset.id.in_(asset_ids), Asset.organization_id == organization_id)
    )
    return list(result.scalars().all())


async def create_asset(db: AsyncSession, payload, organization_id: str) -> Asset:
    asset = Asset(**payload.model_dump(), organization_id=organization_id)
    db.add(asset)
    await db.flush()
    await db.refresh(asset)
    return asset


# Mismo criterio de rol que exige el DELETE de mas abajo (deactivate_asset):
# admin/soc_manager, sin analyst. PATCH con is_active logra lo mismo que un
# DELETE (desactivar un activo) o lo revierte (reactivarlo), asi que tiene
# que quedar sujeto a la misma restriccion de rol -- ver app/main.py::update_asset.
def can_set_active_state(role: str | None) -> bool:
    return role in ("admin", "soc_manager")


async def update_asset(db: AsyncSession, asset: Asset, payload) -> Asset:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    await db.flush()
    await db.refresh(asset)
    return asset


async def deactivate_asset(db: AsyncSession, asset: Asset) -> Asset:
    asset.is_active = False
    await db.flush()
    return asset


async def list_groups(db: AsyncSession, organization_id: str) -> list[AssetGroup]:
    result = await db.execute(
        select(AssetGroup).where(AssetGroup.organization_id == organization_id).order_by(AssetGroup.name)
    )
    return list(result.scalars().all())


async def create_group(db: AsyncSession, payload, organization_id: str) -> AssetGroup:
    group = AssetGroup(**payload.model_dump(), organization_id=organization_id)
    db.add(group)
    await db.flush()
    await db.refresh(group)
    return group
