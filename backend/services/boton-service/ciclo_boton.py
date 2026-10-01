from detector_patrones import cargar_eventos, descubrir_secuencias
from detector_necesidades import evaluar_necesidad
from autonomia import decidir_autonomia
from generador_microsistemas import construir_microsistema, mostrar_microsistema


def evaluar_riesgo(acciones_delegables):
    # Prototipo inicial: preparar/generar un reporte es una accion de bajo riesgo.
    if "generar_reporte" in acciones_delegables:
        return "bajo", True
    return "medio", False


def main():
    eventos = cargar_eventos()

    if not eventos:
        print("No hay eventos suficientes para analizar.")
        return

    por_dia, secuencias = descubrir_secuencias(eventos)
    total_dias = len(por_dia)

    print("=== CICLO DE DECISION DE BOTON ===")
    print(f"Dias analizados: {total_dias}")
    print()

    encontradas = 0

    for secuencia, repeticiones in secuencias.most_common():
        if repeticiones < 2:
            continue

        necesidad = evaluar_necesidad(secuencia, repeticiones, total_dias)

        if not necesidad["es_candidata"]:
            continue

        encontradas += 1
        confianza = necesidad["confianza"]
        acciones = necesidad["acciones_delegables"]
        riesgo, reversible = evaluar_riesgo(acciones)

        # En esta prueba el usuario ya concedio permiso para preparar reportes.
        permiso = True

        decision = decidir_autonomia(
            confianza=confianza,
            riesgo=riesgo,
            permiso=permiso,
            reversible=reversible,
        )

        print(f"Necesidad #{encontradas}")
        print("Patron descubierto:")
        for paso, (tipo, valor) in enumerate(secuencia, start=1):
            print(f"  {paso}. {tipo} -> {valor}")

        print(f"Repeticiones: {repeticiones}")
        print(f"Confianza: {confianza:.1%}")
        print("Trabajo delegable: " + ", ".join(acciones))
        print(f"Riesgo: {riesgo}")
        print(f"Permiso: {'si' if permiso else 'no'}")
        print(f"Reversible: {'si' if reversible else 'no'}")
        print(f"Decision BOTON: {decision.decision}")
        print(f"Motivo: {decision.motivo}")
        print()

        if decision.decision == "ACTUAR":
            microsistema = construir_microsistema(acciones)
            if microsistema:
                print("BOTON decidio actuar y construyo una solucion compatible.")
                mostrar_microsistema(microsistema)
                print("Siguiente etapa: ejecutar y verificar el resultado.")
            else:
                print("BOTON decidio actuar, pero aun no dispone de una solucion compatible.")
        else:
            print("Siguiente etapa: pedir confirmacion mediante la interfaz de BOTON.")
        print()

    if encontradas == 0:
        print("BOTON no encontro necesidades candidatas en este historial.")


if __name__ == "__main__":
    main()
