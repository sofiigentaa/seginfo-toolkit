from dataclasses import dataclass
from typing import Callable


@dataclass
class Microsistema:
    nombre: str
    objetivo: str
    accion: str
    entrada: str
    salida: str
    verificacion: str
    estado: str = "PROPUESTO"


CATALOGO_SOLUCIONES: dict[str, Callable[[], Microsistema]] = {
    "generar_reporte": lambda: Microsistema(
        nombre="preparador_reporte",
        objetivo="Delegar la preparacion repetitiva de un reporte.",
        accion="generar_reporte",
        entrada="reporte_diario.xlsx",
        salida="reporte_diario.pdf",
        verificacion="comprobar que el PDF fue generado correctamente",
    ),
}


def construir_microsistema(acciones_delegables):
    for accion in acciones_delegables:
        constructor = CATALOGO_SOLUCIONES.get(accion)
        if constructor:
            return constructor()

    return None


def mostrar_microsistema(microsistema):
    if microsistema is None:
        print("BOTON aun no dispone de una solucion compatible.")
        return

    print("Microsistema construido por BOTON:")
    print(f"  Nombre: {microsistema.nombre}")
    print(f"  Objetivo: {microsistema.objetivo}")
    print(f"  Accion: {microsistema.accion}")
    print(f"  Entrada: {microsistema.entrada}")
    print(f"  Salida: {microsistema.salida}")
    print(f"  Verificacion: {microsistema.verificacion}")
    print(f"  Estado: {microsistema.estado}")


if __name__ == "__main__":
    microsistema = construir_microsistema(["generar_reporte"])
    mostrar_microsistema(microsistema)
