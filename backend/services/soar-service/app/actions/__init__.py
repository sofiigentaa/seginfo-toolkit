"""Registro de acciones de playbook disponibles (todas defensivas/dry-run
por defecto, ver base.py). UNICA fuente de verdad: app/services.py importa
ACTIONS/get_action de aca en vez de mantener su propio dict (bug real
corregido: este ACTIONS estaba desincronizado con el que de verdad usaba el
motor de ejecucion en services.py y le faltaban 'create_ticket' y 'notify' --
si algun caller hubiera llegado a usar este registro, esos dos steps de
playbook habrian fallado con 'Accion desconocida')."""
from app.actions.base import ActionExecutor
from app.actions.block_ip import BlockIpAction
from app.actions.isolate_host import IsolateHostAction
from app.actions.create_case import CreateCaseAction
from app.actions.create_ticket import CreateTicketAction
from app.actions.notify import NotifyAction

ACTIONS: dict[str, ActionExecutor] = {
    "block_ip": BlockIpAction(),
    "isolate_host": IsolateHostAction(),
    "create_case": CreateCaseAction(),
    "create_ticket": CreateTicketAction(),
    "notify": NotifyAction(),
}


def get_action(name: str) -> ActionExecutor:
    if name not in ACTIONS:
        raise KeyError(f"Accion de playbook desconocida: {name}")
    return ACTIONS[name]
