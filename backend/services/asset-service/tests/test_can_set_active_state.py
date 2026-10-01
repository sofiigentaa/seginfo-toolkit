"""Tests de app/services.py::can_set_active_state -- la regla de RBAC que
decide si un rol puede activar/desactivar un activo via PATCH /assets/{id}.
Sin DB: solo logica pura, igual que test_schemas.py en este mismo paquete.

Tiene que coincidir exactamente con el rol que ya exige el DELETE
(deactivate_asset, ver app/main.py): admin/soc_manager, nunca analyst --
si no, un analyst podia lograr lo mismo que un DELETE mandando is_active=False
por PATCH, esquivando esa restriccion."""
from app.services import can_set_active_state


class TestCanSetActiveState:
    def test_admin_can_change_active_state(self):
        assert can_set_active_state("admin") is True

    def test_soc_manager_can_change_active_state(self):
        assert can_set_active_state("soc_manager") is True

    def test_analyst_cannot_change_active_state(self):
        assert can_set_active_state("analyst") is False

    def test_unknown_or_missing_role_cannot_change_active_state(self):
        assert can_set_active_state("otro_rol_desconocido") is False
        assert can_set_active_state(None) is False
