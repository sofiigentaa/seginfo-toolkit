"""Business logic for purple-service: gap analysis de cobertura de deteccion
MITRE ATT&CK. SOLO analiza datos (tags de reglas Sigma habilitadas en
siem-service vs. tecnicas declaradas en un ejercicio) -- no ejecuta nada,
ver docs/architecture.md 'Fuera de alcance'."""
import os
import re
from datetime import datetime, timezone
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.shared.logging import configure_logging
from app.models import PurpleExercise
from app.attack_data import ATTACK_TECHNIQUES
from app.schemas import TechniqueCoverage, CoverageResult

logger = configure_logging("purple-service")
SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")

_TAG_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def fetch_rule_tags(organization_id: str) -> list[dict]:
    """Llama al endpoint interno (sin auth de usuario) de siem-service que
    expone id/nombre/tags de reglas Sigma habilitadas, filtradas al tenant
    de quien pidio el reporte de cobertura. Si siem-service no responde,
    devuelve lista vacia (la cobertura se reporta en 0, nunca se inventan
    datos)."""
    url = f"{SIEM_SERVICE_URL}/internal/rule-tags"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params={"organization_id": organization_id})
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        logger.warning("no se pudo consultar siem-service para rule-tags", extra={"error": str(exc), "url": url})
        return []


def _rules_by_technique(rules: list[dict]) -> dict[str, list[str]]:
    """Mapea technique_id (ej. 'T1110') -> nombres de reglas que lo
    detectan, buscando tags con convencion 'attack.tXXXX' (case-insensitive,
    misma convencion que Sigma/MITRE CTI)."""
    mapping: dict[str, list[str]] = {}
    for rule in rules:
        for tag in rule.get("tags") or []:
            match = _TAG_TECHNIQUE_RE.search(str(tag))
            if not match:
                continue
            technique_id = match.group(1).upper()
            mapping.setdefault(technique_id, []).append(rule.get("name", rule.get("id", "?")))
    return mapping


def _build_coverage(technique_ids_scope, rule_map: dict[str, list[str]], exercise_id: str | None = None) -> CoverageResult:
    """technique_ids_scope=None significa "sin recorte, usar todo el
    catalogo" (caso de /coverage/overall). Una lista, incluso vacia,
    significa "el caller pidio un recorte especifico" y debe filtrarse
    como tal -- antes se usaba `if not technique_ids_scope` (verdad/
    falsedad), asi que un ejercicio con declared_technique_ids=[] caia en
    la misma rama que None y terminaba calculando la cobertura contra
    TODO el catalogo ATT&CK en vez de reportar 0 tecnicas declaradas."""
    universe = ATTACK_TECHNIQUES if technique_ids_scope is None else [
        t for t in ATTACK_TECHNIQUES if t["technique_id"] in technique_ids_scope
    ]
    techniques: list[TechniqueCoverage] = []
    by_tactic: dict[str, dict] = {}
    covered_count = 0
    for tech in universe:
        matching = rule_map.get(tech["technique_id"], [])
        covered = len(matching) > 0
        if covered:
            covered_count += 1
        tc = TechniqueCoverage(
            technique_id=tech["technique_id"],
            name=tech["name"],
            tactic=tech["tactic"],
            covered=covered,
            matching_rules=matching,
        )
        techniques.append(tc)
        bucket = by_tactic.setdefault(tech["tactic"], {"total": 0, "covered": 0})
        bucket["total"] += 1
        if covered:
            bucket["covered"] += 1
    total = len(universe)
    gaps = [t for t in techniques if not t.covered]
    return CoverageResult(
        exercise_id=exercise_id,
        total_techniques=total,
        covered_count=covered_count,
        coverage_pct=round((covered_count / total) * 100, 1) if total else 0.0,
        by_tactic=by_tactic,
        techniques=techniques,
        gaps=gaps,
    )


async def compute_overall_coverage(organization_id: str) -> CoverageResult:
    """Cobertura contra el catalogo completo de tecnicas de referencia
    (metrica de dashboard, no ligada a un ejercicio en particular)."""
    rules = await fetch_rule_tags(organization_id)
    rule_map = _rules_by_technique(rules)
    return _build_coverage(None, rule_map)


async def create_exercise(db: AsyncSession, payload, organization_id: str) -> PurpleExercise:
    exercise = PurpleExercise(
        organization_id=organization_id,
        name=payload.name,
        description=payload.description,
        declared_technique_ids=payload.declared_technique_ids,
    )
    db.add(exercise)
    await db.flush()
    return exercise


async def list_exercises(db: AsyncSession, organization_id: str) -> list[PurpleExercise]:
    result = await db.execute(
        select(PurpleExercise)
        .where(PurpleExercise.organization_id == organization_id)
        .order_by(PurpleExercise.created_at.desc())
    )
    return list(result.scalars().all())


async def get_exercise(db: AsyncSession, exercise_id: str, organization_id: str) -> PurpleExercise | None:
    result = await db.execute(
        select(PurpleExercise).where(
            PurpleExercise.id == exercise_id, PurpleExercise.organization_id == organization_id
        )
    )
    return result.scalar_one_or_none()


async def compute_coverage_for_exercise(db: AsyncSession, exercise: PurpleExercise) -> CoverageResult:
    """Calcula la cobertura de deteccion SOLO para las tecnicas que el
    ejercicio declara haber puesto a prueba (datos importados/declarados,
    nunca ejecutados por esta plataforma), y persiste el resultado en el
    propio ejercicio para consulta rapida posterior."""
    rules = await fetch_rule_tags(exercise.organization_id)
    rule_map = _rules_by_technique(rules)
    # declared_technique_ids es siempre una lista (nunca None, ver
    # app/models.py) -- se pasa tal cual, sin "or None": una lista vacia
    # debe recortar el universo a 0 tecnicas, no expandirlo a todo el
    # catalogo (ver _build_coverage).
    result = _build_coverage(exercise.declared_technique_ids, rule_map, exercise_id=exercise.id)
    exercise.last_coverage_result = result.model_dump()
    exercise.updated_at = _now()
    await db.flush()
    return result
