from detector_patrones import cargar_eventos, descubrir_secuencias


UMBRAL_CONFIANZA = 0.80
MINIMO_REPETICIONES = 3

# Primera heuristica de BOTON.
# No es Machine Learning: sirve para validar el flujo patron -> posible necesidad.
ACCIONES_DELEGABLES = {
    "generar_reporte",
    "crear_reporte",
    "enviar_reporte",
    "organizar_archivo",
    "mover_archivo",
    "procesar_archivo",
}


def evaluar_necesidad(secuencia, repeticiones, total_dias):
    confianza = repeticiones / total_dias if total_dias else 0

    tipos = [tipo for tipo, _ in secuencia]
    acciones_delegables = [
        tipo for tipo in tipos if tipo in ACCIONES_DELEGABLES
    ]

    criterios = {
        "se_repite": repeticiones >= MINIMO_REPETICIONES,
        "confianza_suficiente": confianza >= UMBRAL_CONFIANZA,
        "contiene_trabajo_delegable": bool(acciones_delegables),
    }

    es_candidata = all(criterios.values())

    return {
        "confianza": confianza,
        "criterios": criterios,
        "acciones_delegables": acciones_delegables,
        "es_candidata": es_candidata,
    }


def main():
    eventos = cargar_eventos()

    if not eventos:
        print("No hay eventos simulados suficientes para analizar.")
        return

    por_dia, secuencias = descubrir_secuencias(eventos)
    total_dias = len(por_dia)

    print(f"Dias analizados: {total_dias}")
    print()

    candidatas = 0

    for secuencia, repeticiones in secuencias.most_common():
        if repeticiones < 2:
            continue

        resultado = evaluar_necesidad(
            secuencia,
            repeticiones,
            total_dias,
        )

        if not resultado["es_candidata"]:
            continue

        candidatas += 1

        print(f"Posible necesidad automatizable #{candidatas}")
        for paso, (tipo, valor) in enumerate(secuencia, start=1):
            print(f"  {paso}. {tipo} -> {valor}")

        print(f"  Repeticiones: {repeticiones}")
        print(f"  Confianza: {resultado['confianza']:.1%}")
        print(
            "  Trabajo delegable detectado: "
            + ", ".join(resultado["acciones_delegables"])
        )
        print("  Estado: candidata para evaluacion de automatizacion")
        print()

    if candidatas == 0:
        print("BOTON todavia no encontro una necesidad automatizable.")


if __name__ == "__main__":
    main()
