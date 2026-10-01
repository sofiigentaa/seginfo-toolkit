"""Tests para app/services.py::_resolve_alert_update -- funcion pura, sin DB
ni red. Cubre un bug real: PATCH /alerts/{id} pisaba `notes` con "" en CADA
cambio de estado (los botones Reconocer/Cerrar de la UI solo mandan
{status}, sin notes) porque AlertUpdate.notes tenia default "" en vez de
None -- ver app/schemas.py::AlertUpdate y git history de este archivo."""
from app.models import AlertStatus
from app.services import _resolve_alert_update


class TestResolveAlertUpdate:
    def test_status_only_update_preserves_existing_notes(self):
        # Caso real: boton "Reconocer" de la UI, PATCH {status: "acknowledged"}
        # sin notes -- no debe borrar una nota ya guardada.
        notes, acknowledged_by = _resolve_alert_update(
            current_notes="nota previa del analista",
            current_acknowledged_by="",
            payload_status=AlertStatus.acknowledged,
            payload_notes=None,
            actor="ana@empresa.com",
        )
        assert notes == "nota previa del analista"

    def test_explicit_notes_overwrite_previous_notes(self):
        notes, _ = _resolve_alert_update(
            current_notes="nota vieja",
            current_acknowledged_by="",
            payload_status=AlertStatus.closed,
            payload_notes="nota nueva",
            actor="ana@empresa.com",
        )
        assert notes == "nota nueva"

    def test_explicit_empty_string_notes_clears_them_intentionally(self):
        # Un caller que SI manda notes="" (borrado intencional) debe poder
        # limpiar la nota -- solo None (campo ausente) se trata distinto.
        notes, _ = _resolve_alert_update(
            current_notes="nota vieja",
            current_acknowledged_by="",
            payload_status=AlertStatus.closed,
            payload_notes="",
            actor="ana@empresa.com",
        )
        assert notes == ""

    def test_acknowledging_sets_acknowledged_by_to_actor(self):
        _, acknowledged_by = _resolve_alert_update(
            current_notes="",
            current_acknowledged_by="",
            payload_status=AlertStatus.acknowledged,
            payload_notes=None,
            actor="ana@empresa.com",
        )
        assert acknowledged_by == "ana@empresa.com"

    def test_closing_does_not_touch_acknowledged_by(self):
        _, acknowledged_by = _resolve_alert_update(
            current_notes="",
            current_acknowledged_by="ana@empresa.com",
            payload_status=AlertStatus.closed,
            payload_notes=None,
            actor="otro@empresa.com",
        )
        assert acknowledged_by == "ana@empresa.com"
