"""Business logic for case-service: CRUD de casos con SLA por prioridad,
timeline de auditoria, e importacion de PendingCase desde soar-service
(polling best-effort, ver app/main.py)."""
import os
from datetime import datetime, timedelta, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from backend.shared.security import create_access_token
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID
from app.models import Case, CaseTimelineEntry, CaseStatus, SLA_HOURS_BY_PRIORITY

logger = configure_logging("case-service")
SOAR_SERVICE_URL = os.getenv("SOAR_SERVICE_URL", "http://soar-service:8000")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8000")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Mismo grafo de transiciones que ya ofrece el frontend (ver
# STATUS_TRANSITIONS en frontend/src/pages/Cases.tsx): open<->in_progress,
# in_progress<->resolved, resolved<->closed, mas el atajo "Reabrir" desde
# closed directo a open. La UI ya restringe que boton se muestra segun el
# status actual, pero PATCH /cases/{case_id} no validaba nada server-side --
# un caller que no sea la UI (curl, otro servicio, un tab con un status
# viejo en memoria) podia poner cualquier status invalido.
CASE_STATUS_TRANSITIONS: dict[str, set[str]] = {
    CaseStatus.open.value: {CaseStatus.in_progress.value},
    CaseStatus.in_progress.value: {CaseStatus.resolved.value, CaseStatus.open.value},
    CaseStatus.resolved.value: {CaseStatus.closed.value, CaseStatus.in_progress.value},
    CaseStatus.closed.value: {CaseStatus.open.value},
}


def is_valid_status_transition(old_status, new_status) -> bool:
    """Regla de negocio pura (sin DB, testeable) que decide si se puede
    pasar de old_status a new_status -- mismo patron que
    is_deletable_status en scan-service/app/services.py. Maneja tanto el
    enum de SQLAlchemy (CaseStatus) como str plano via hasattr(.., "value").
    Quedarse en el mismo status (no-op) siempre es valido."""
    old_value = old_status.value if hasattr(old_status, "value") else old_status
    new_value = new_status.value if hasattr(new_status, "value") else new_status
    if old_value == new_value:
        return True
    return new_value in CASE_STATUS_TRANSITIONS.get(old_value, set())


def resolved_at_for_transition(new_status, current_resolved_at, now: datetime):
    """Regla de negocio pura (sin DB, testeable) que decide que valor debe
    tener resolved_at despues de una transicion de status via PATCH
    /cases/{case_id}.

    Bug real encontrado: update_case seteaba resolved_at cuando el caso
    pasaba a resolved/closed, pero nunca lo limpiaba cuando el caso se
    REABRIA (resolved/closed -> in_progress/open, ver
    CASE_STATUS_TRANSITIONS). Un caso reabierto quedaba con un
    resolved_at viejo -- cualquier metrica de MTTR/tiempo-de-resolucion
    que lo use (ej. report-service, que ya consume /cases) mostraria un
    caso todavia activo como si ya estuviese resuelto desde hace tiempo."""
    new_value = new_status.value if hasattr(new_status, "value") else new_status
    if new_value in (CaseStatus.resolved.value, CaseStatus.closed.value):
        return current_resolved_at or now
    if new_value in (CaseStatus.open.value, CaseStatus.in_progress.value):
        return None
    return current_resolved_at


async def _add_timeline_entry(db: AsyncSession, case_id: str, actor: str, action: str, notes: str = "") -> None:
    db.add(CaseTimelineEntry(case_id=case_id, actor=actor, action=action, notes=notes))
    await db.flush()


async def create_case(db: AsyncSession, payload, actor: str = "") -> Case:
    sla_due_at = _now() + timedelta(hours=SLA_HOURS_BY_PRIORITY[payload.priority])
    fields = payload.model_dump()
    fields["organization_id"] = fields.get("organization_id") or DEFAULT_ORGANIZATION_ID
    case = Case(**fields, sla_due_at=sla_due_at)
    db.add(case)
    await db.flush()
    await _add_timeline_entry(db, case.id, actor or payload.source, "case.created", f"Prioridad: {payload.priority.value}")
    await db.refresh(case, attribute_names=["timeline"])
    return case


async def list_cases(
    db: AsyncSession, organization_id: str,
    status_filter: str | None = None, priority: str | None = None, assignee: str | None = None,
) -> list[Case]:
    query = select(Case).options(selectinload(Case.timeline)).where(Case.organization_id == organization_id)
    if status_filter:
        query = query.where(Case.status == status_filter)
    if priority:
        query = query.where(Case.priority == priority)
    if assignee:
        query = query.where(Case.assignee == assignee)
    result = await db.execute(query.order_by(Case.created_at.desc()))
    return list(result.scalars().all())


async def get_case(db: AsyncSession, case_id: str, organization_id: str) -> Case | None:
    result = await db.execute(
        select(Case)
        .options(selectinload(Case.timeline))
        .where(Case.id == case_id, Case.organization_id == organization_id)
    )
    return result.scalar_one_or_none()


async def update_case(db: AsyncSession, case: Case, payload, actor: str) -> Case:
    changes = payload.model_dump(exclude_unset=True)
    old_status = case.status
    for field, value in changes.items():
        setattr(case, field, value)
    if "status" in changes and changes["status"] != old_status:
        case.resolved_at = resolved_at_for_transition(changes["status"], case.resolved_at, _now())
        await _add_timeline_entry(db, case.id, actor, "case.status_changed", f"{old_status.value} -> {changes['status'].value}")
    if changes:
        await _add_timeline_entry(db, case.id, actor, "case.updated", ", ".join(changes.keys()))
    await db.flush()
    await db.refresh(case, attribute_names=["timeline"])
    return case


async def add_timeline_entry(db: AsyncSession, case: Case, payload, actor: str) -> Case:
    await _add_timeline_entry(db, case.id, actor, payload.action, payload.notes)
    await db.flush()
    await db.refresh(case, attribute_names=["timeline"])
    return case


async def list_organization_ids() -> list[str]:
    """Consulta auth-service/internal/organizations (sin JWT -- endpoint
    interno de servicio-a-servicio, ver su docstring) para saber que
    organizaciones existen, sin necesitar un token de platform_admin.
    Best-effort: si auth-service no responde, devuelve lista vacia (el
    ciclo de sincronizacion simplemente no hace nada esa vuelta, ver
    app/main.py::_soar_sync_loop)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{AUTH_SERVICE_URL}/internal/organizations")
            resp.raise_for_status()
            return [org["id"] for org in resp.json()]
    except httpx.HTTPError as exc:
        logger.warning("no se pudo consultar auth-service/internal/organizations", extra={"error": str(exc)})
        return []


async def import_pending_cases_from_soar(db: AsyncSession, organization_id: str) -> tuple[int, int]:
    """Trae los PendingCase que soar-service no pudo crear directamente
    (porque case-service todavia no existia) y los materializa como Case
    aca. Idempotente por alert_id: si ya existe un caso con ese alert_id y
    source='soar-import', se saltea.

    soar-service exige JWT en GET /pending-cases y filtra por
    organization_id -- se emite un JWT de servicio-a-servicio con el mismo
    org_id que el admin que disparo esta importacion, para traer solo los
    casos pendientes de ESA organizacion."""
    token = create_access_token("system:case-service", "admin", org_id=organization_id)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{SOAR_SERVICE_URL}/pending-cases", headers={"Authorization": f"Bearer {token}"}
            )
            resp.raise_for_status()
            pending = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("no se pudo consultar pending-cases de soar-service", extra={"error": str(exc)})
        return 0, 0

    imported, skipped = 0, 0
    for item in pending:
        alert_id = item.get("alert_id")
        if alert_id:
            existing = await db.execute(
                select(Case).where(
                    Case.alert_id == alert_id, Case.source == "soar-import",
                    Case.organization_id == organization_id,
                )
            )
            if existing.scalar_one_or_none() is not None:
                skipped += 1
                continue

        sla_due_at = _now() + timedelta(hours=SLA_HOURS_BY_PRIORITY.get(item.get("priority", "medium"), 24))
        case = Case(
            organization_id=organization_id,
            title=item.get("title", "Caso importado de SOAR"),
            description=item.get("description", ""),
            priority=item.get("priority", "medium"),
            alert_id=alert_id,
            source="soar-import",
            sla_due_at=sla_due_at,
        )
        db.add(case)
        await db.flush()
        await _add_timeline_entry(db, case.id, "soar-service", "case.imported", "Importado desde pending-cases de soar-service")
        imported += 1

    await db.flush()
    return imported, skipped
