from dataclasses import dataclass


@dataclass
class DecisionAutonomia:
    riesgo: str
    permiso: bool
    confianza: float
    reversible: bool
    decision: str
    motivo: str


def decidir_autonomia(
    confianza: float,
    riesgo: str,
    permiso: bool,
    reversible: bool,
) -> DecisionAutonomia:
    riesgo = riesgo.lower()

    if not permiso:
        return DecisionAutonomia(
            riesgo, permiso, confianza, reversible,
            "PREGUNTAR",
            "No existe permiso previo para ejecutar esta accion.",
        )

    if riesgo == "alto":
        return DecisionAutonomia(
            riesgo, permiso, confianza, reversible,
            "PREGUNTAR",
            "La accion es de riesgo alto y requiere confirmacion.",
        )

    if not reversible and riesgo != "bajo":
        return DecisionAutonomia(
            riesgo, permiso, confianza, reversible,
            "PREGUNTAR",
            "La accion no es facilmente reversible.",
        )

    if riesgo == "bajo" and confianza >= 0.90:
        return DecisionAutonomia(
            riesgo, permiso, confianza, reversible,
            "ACTUAR",
            "Riesgo bajo, permiso concedido y confianza suficiente.",
        )

    if riesgo == "medio" and confianza >= 0.98 and reversible:
        return DecisionAutonomia(
            riesgo, permiso, confianza, reversible,
            "ACTUAR",
            "Riesgo medio, accion reversible, permiso y confianza muy alta.",
        )

    return DecisionAutonomia(
        riesgo, permiso, confianza, reversible,
        "PREGUNTAR",
        "BOTON necesita mas confianza o confirmacion del usuario.",
    )


def mostrar(nombre, decision):
    print(nombre)
    print(f"  Riesgo: {decision.riesgo}")
    print(f"  Permiso: {'si' if decision.permiso else 'no'}")
    print(f"  Confianza: {decision.confianza:.1%}")
    print(f"  Reversible: {'si' if decision.reversible else 'no'}")
    print(f"  Decision BOTON: {decision.decision}")
    print(f"  Motivo: {decision.motivo}")
    print()


def main():
    # Caso derivado del patron que acabamos de descubrir.
    mostrar(
        "Caso 1 - preparar reporte",
        decidir_autonomia(
            confianza=16 / 17,
            riesgo="bajo",
            permiso=True,
            reversible=True,
        ),
    )

    # Caso sensible: aunque haya mucha confianza, BOTON pregunta.
    mostrar(
        "Caso 2 - cancelar una cita",
        decidir_autonomia(
            confianza=0.99,
            riesgo="alto",
            permiso=True,
            reversible=False,
        ),
    )

    # Caso sin permiso: BOTON tampoco actua.
    mostrar(
        "Caso 3 - enviar informacion",
        decidir_autonomia(
            confianza=0.97,
            riesgo="medio",
            permiso=False,
            reversible=False,
        ),
    )


if __name__ == "__main__":
    main()
