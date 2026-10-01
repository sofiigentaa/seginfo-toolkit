import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
BASE_DATOS = BASE_DIR / "boton.db"


def cargar_eventos():
    with sqlite3.connect(BASE_DATOS) as conexion:
        conexion.row_factory = sqlite3.Row
        filas = conexion.execute(
            """
            SELECT id, tipo, valor, contexto
            FROM eventos
            ORDER BY id ASC
            """
        ).fetchall()

    eventos = []
    for fila in filas:
        contexto = json.loads(fila["contexto"])
        dia = contexto.get("dia_simulado")
        hora = contexto.get("hora_simulada")

        if dia and hora:
            eventos.append(
                {
                    "id": fila["id"],
                    "tipo": fila["tipo"],
                    "valor": fila["valor"],
                    "dia": dia,
                    "hora": hora,
                }
            )

    return eventos


def descubrir_secuencias(eventos):
    por_dia = defaultdict(list)

    for evento in eventos:
        por_dia[evento["dia"]].append(evento)

    secuencias = Counter()

    for eventos_dia in por_dia.values():
        eventos_dia.sort(key=lambda evento: evento["hora"])

        secuencia = tuple(
            (evento["tipo"], evento["valor"])
            for evento in eventos_dia
        )

        if len(secuencia) >= 2:
            secuencias[secuencia] += 1

    return por_dia, secuencias


def mostrar_patrones(por_dia, secuencias):
    total_dias = len(por_dia)

    print(f"Dias analizados: {total_dias}")
    print()

    patrones = [
        (secuencia, repeticiones)
        for secuencia, repeticiones in secuencias.most_common()
        if repeticiones >= 2
    ]

    if not patrones:
        print("BOTON todavia no encontro patrones repetidos.")
        return

    print("Patrones descubiertos por BOTON:")
    print()

    for numero, (secuencia, repeticiones) in enumerate(patrones, start=1):
        confianza = repeticiones / total_dias

        print(f"Patron #{numero}")
        for paso, (tipo, valor) in enumerate(secuencia, start=1):
            print(f"  {paso}. {tipo} -> {valor}")

        print(f"  Repeticiones: {repeticiones}")
        print(f"  Confianza: {confianza:.1%}")
        print()


def main():
    eventos = cargar_eventos()

    if not eventos:
        print("No hay eventos simulados suficientes para analizar.")
        return

    por_dia, secuencias = descubrir_secuencias(eventos)
    mostrar_patrones(por_dia, secuencias)


if __name__ == "__main__":
    main()
