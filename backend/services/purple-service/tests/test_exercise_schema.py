"""Tests para app/schemas.py::ExerciseCreate -- validacion de input pura
(pydantic), sin DB ni red. Cubre el bug real donde POST /exercises
aceptaba un ejercicio con declared_technique_ids=[] (el frontend ya lo
bloquea en el form, pero el endpoint tambien es usado por callers sin UI),
lo que despues hacia que el gap analysis calculara la cobertura contra
todo el catalogo ATT&CK en lugar de reportar 0 tecnicas declaradas (ver
test_coverage.py::test_build_coverage_truly_empty_scope_reports_zero_not_full_catalog)."""
import pytest
from pydantic import ValidationError

from app.schemas import ExerciseCreate


class TestExerciseCreateRequiresDeclaredTechniques:
    def test_at_least_one_declared_technique_is_accepted(self):
        exercise = ExerciseCreate(name="Simulacro phishing", declared_technique_ids=["T1566"])
        assert exercise.declared_technique_ids == ["T1566"]

    def test_empty_declared_technique_ids_is_rejected(self):
        with pytest.raises(ValidationError):
            ExerciseCreate(name="Ejercicio sin tecnicas", declared_technique_ids=[])

    def test_missing_declared_technique_ids_defaults_to_empty_and_is_rejected(self):
        # default_factory=list -- si el caller no manda el campo, cae en
        # el mismo caso de lista vacia y debe rechazarse igual.
        with pytest.raises(ValidationError):
            ExerciseCreate(name="Ejercicio sin tecnicas")
