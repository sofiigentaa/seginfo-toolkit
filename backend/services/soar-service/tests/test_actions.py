"""Tests de la logica pura de soar-service: ranking de severidad,
resolucion de campos del contexto de una alerta, y el registro de acciones
de playbook. Todo lo relacionado a "dry-run por defecto" tambien se cubre
aca -- es la garantia de que SOAR nunca ejecuta una accion real sin que un
operador explicitamente ponga SOAR_DRY_RUN=false."""
import os

import pytest

from app.services import _severity_meets_minimum
from app.actions import get_action, ACTIONS
from app.actions.base import dry_run_enabled
from app.actions.block_ip import _resolve_field


class TestSeverityRanking:
    def test_higher_severity_meets_lower_minimum(self):
        assert _severity_meets_minimum("critical", "low") is True

    def test_equal_severity_meets_minimum(self):
        assert _severity_meets_minimum("medium", "medium") is True

    def test_lower_severity_does_not_meet_higher_minimum(self):
        assert _severity_meets_minimum("low", "critical") is False

    def test_unknown_severity_ranks_as_zero(self):
        # una severidad no reconocida nunca deberia superar un minimo real
        assert _severity_meets_minimum("no-existe", "low") is False


class TestDryRunDefaultsToTrue:
    def test_dry_run_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("SOAR_DRY_RUN", raising=False)
        assert dry_run_enabled() is True

    def test_dry_run_can_be_disabled_explicitly(self, monkeypatch):
        monkeypatch.setenv("SOAR_DRY_RUN", "false")
        assert dry_run_enabled() is False

    def test_any_other_value_keeps_dry_run_on(self, monkeypatch):
        # "cualquier cosa que no sea exactamente 'false'" se trata como
        # dry-run activo -- fallar hacia el lado seguro (nunca ejecutar).
        monkeypatch.setenv("SOAR_DRY_RUN", "no-se-que-puse-aca")
        assert dry_run_enabled() is True


class TestResolveField:
    def test_resolves_nested_path_from_event_context(self):
        context = {"event": {"source": {"ip": "10.0.0.5"}}}
        assert _resolve_field(context, "source.ip") == "10.0.0.5"

    def test_missing_path_returns_none(self):
        assert _resolve_field({"event": {}}, "source.ip") is None

    def test_missing_event_key_returns_none(self):
        assert _resolve_field({}, "source.ip") is None


class TestActionRegistry:
    # Bug real corregido: app/actions/__init__.py (el ACTIONS/get_action que
    # este test ejercita) estaba desincronizado del ACTIONS que de verdad
    # usaba el motor de ejecucion en app/services.py -- a este le faltaban
    # 'create_ticket' y 'notify'. Ahora services.py importa este mismo
    # registro, asi que una igualdad estricta (no solo >=) es la garantia de
    # que las 5 acciones declaradas en playbooks/*.yaml siempre se puedan
    # ejecutar.
    def test_all_five_defensive_actions_are_registered(self):
        assert set(ACTIONS.keys()) == {
            "block_ip", "isolate_host", "create_case", "create_ticket", "notify",
        }

    def test_get_action_returns_matching_executor(self):
        action = get_action("block_ip")
        assert action.action_name == "block_ip"

    def test_get_action_resolves_create_ticket_and_notify(self):
        # Estas dos son justamente las que faltaban antes del fix.
        assert get_action("create_ticket").action_name == "create_ticket"
        assert get_action("notify").action_name == "notify"

    def test_get_action_raises_for_unknown_name(self):
        with pytest.raises(KeyError):
            get_action("ejecutar_exploit")  # nunca va a existir -- fuera de alcance
