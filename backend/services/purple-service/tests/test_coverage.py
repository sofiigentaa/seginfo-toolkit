"""Tests para app/services.py: el core del gap-analysis de purple-service
(cruzar tags de reglas Sigma habilitadas contra tecnicas MITRE ATT&CK
declaradas). Solo se ejercitan las funciones puras (_rules_by_technique,
_build_coverage) -- nada de red ni DB, y nada de esto ejecuta tecnicas,
solo compara datos declarados (ver docs/architecture.md 'Fuera de
alcance')."""
from app.attack_data import ATTACK_TECHNIQUES
from app.services import _build_coverage, _rules_by_technique


def test_rules_by_technique_extracts_tagged_ids():
    rules = [
        {"id": "r1", "name": "Brute force detectado", "tags": ["attack.t1110", "log_source.auth"]},
        {"id": "r2", "name": "Sub-tecnica de phishing", "tags": ["ATTACK.T1566.001"]},
        {"id": "r3", "name": "Sin tag de attack", "tags": ["log_source.dns"]},
        {"id": "r4", "name": "Segunda regla para T1110", "tags": ["attack.T1110"]},
    ]
    mapping = _rules_by_technique(rules)

    assert mapping["T1110"] == ["Brute force detectado", "Segunda regla para T1110"]
    assert mapping["T1566.001"] == ["Sub-tecnica de phishing"]
    assert "T1566" not in mapping  # la sub-tecnica no debe contaminar la tecnica padre
    assert all("dns" not in v for v in mapping.values())


def test_rules_by_technique_handles_no_tags():
    assert _rules_by_technique([{"id": "r1", "name": "sin tags"}]) == {}
    assert _rules_by_technique([]) == {}


def test_build_coverage_full_universe():
    # Cubrimos exactamente 2 de las N tecnicas de referencia.
    covered_ids = [ATTACK_TECHNIQUES[0]["technique_id"], ATTACK_TECHNIQUES[2]["technique_id"]]
    rule_map = {tid: [f"regla-{tid}"] for tid in covered_ids}

    result = _build_coverage(None, rule_map)

    assert result.total_techniques == len(ATTACK_TECHNIQUES)
    assert result.covered_count == 2
    expected_pct = round((2 / len(ATTACK_TECHNIQUES)) * 100, 1)
    assert result.coverage_pct == expected_pct
    assert len(result.gaps) == len(ATTACK_TECHNIQUES) - 2
    assert all(not gap.covered for gap in result.gaps)


def test_build_coverage_scoped_to_declared_techniques():
    scope = [ATTACK_TECHNIQUES[0]["technique_id"], ATTACK_TECHNIQUES[1]["technique_id"]]
    rule_map = {ATTACK_TECHNIQUES[0]["technique_id"]: ["alguna-regla"]}

    result = _build_coverage(scope, rule_map, exercise_id="ex-1")

    assert result.exercise_id == "ex-1"
    assert result.total_techniques == 2
    assert result.covered_count == 1
    assert result.coverage_pct == 50.0
    assert {t.technique_id for t in result.techniques} == set(scope)


def test_build_coverage_empty_universe_reports_zero_not_error():
    result = _build_coverage(["T9999-no-existe"], {})
    assert result.total_techniques == 0
    assert result.coverage_pct == 0.0
    assert result.covered_count == 0


def test_by_tactic_aggregation_matches_technique_totals():
    result = _build_coverage(None, {})
    total_from_buckets = sum(bucket["total"] for bucket in result.by_tactic.values())
    assert total_from_buckets == result.total_techniques
    assert sum(bucket["covered"] for bucket in result.by_tactic.values()) == 0


def test_build_coverage_none_scope_uses_full_catalog():
    # None = "sin recorte" (caso de /coverage/overall): usa TODO el catalogo.
    result = _build_coverage(None, {})
    assert result.total_techniques == len(ATTACK_TECHNIQUES)


def test_build_coverage_truly_empty_scope_reports_zero_not_full_catalog():
    # Bug real: una lista vacia (ejercicio declarado sin ninguna tecnica)
    # caia en la misma rama que None y terminaba usando TODO el catalogo
    # ATT&CK en vez de reportar 0 tecnicas -- ver docstring de
    # _build_coverage en app/services.py.
    result = _build_coverage([], {"T1110": ["regla-x"]})
    assert result.total_techniques == 0
    assert result.covered_count == 0
    assert result.coverage_pct == 0.0
    assert result.techniques == []
    assert result.gaps == []
