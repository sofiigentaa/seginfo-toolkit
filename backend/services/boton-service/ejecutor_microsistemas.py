from pathlib import Path
from datetime import datetime, timezone


SALIDAS_DIR = Path(__file__).resolve().parent / "salidas"


def ejecutar_microsistema(microsistema):
    SALIDAS_DIR.mkdir(exist_ok=True)

    if microsistema.accion != "generar_reporte":
        return {
            "estado": "NO_EJECUTADO",
            "verificado": False,
            "detalle": "No existe ejecutor compatible para esta accion.",
        }

    salida = SALIDAS_DIR / microsistema.salida
    contenido = (
        "BOTON - Reporte de prueba\n"
        "=========================\n"
        f"Generado: {datetime.now(timezone.utc).isoformat()}\n"
        f"Microsistema: {microsistema.nombre}\n"
        "Resultado: ejecucion simulada correctamente.\n"
    )
    salida.write_text(contenido, encoding="utf-8")

    verificado = salida.exists() and salida.stat().st_size > 0

    return {
        "estado": "EJECUTADO" if verificado else "ERROR",
        "verificado": verificado,
        "archivo": str(salida),
        "detalle": (
            "La salida fue creada y verificada."
            if verificado
            else "No se pudo verificar la salida."
        ),
    }


if __name__ == "__main__":
    from generador_microsistemas import construir_microsistema

    microsistema = construir_microsistema(["generar_reporte"])
    resultado = ejecutar_microsistema(microsistema)

    print("Resultado de ejecucion:")
    for clave, valor in resultado.items():
        print(f"  {clave}: {valor}")
