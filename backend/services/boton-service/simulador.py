from datetime import date, timedelta
import json
import random
import urllib.request


URL_BOTON = "http://127.0.0.1:8012/eventos"


def enviar_evento(tipo, valor, dia, hora):
    evento = {
        "fuente": "simulador",
        "tipo": tipo,
        "valor": valor,
        "contexto": {
            "dia_simulado": dia,
            "hora_simulada": hora,
        },
    }

    datos = json.dumps(evento).encode("utf-8")

    solicitud = urllib.request.Request(
        URL_BOTON,
        data=datos,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(solicitud) as respuesta:
        return json.loads(respuesta.read().decode("utf-8"))


def generar_historial(cantidad_dias=15):
    inicio = date(2026, 9, 2)

    for numero_dia in range(cantidad_dias):
        dia = (inicio + timedelta(days=numero_dia)).isoformat()

        # Variamos unos minutos para que los datos no sean identicos cada dia.
        minuto_base = random.randint(0, 4)

        eventos = [
            ("abrir_aplicacion", "correo", f"08:0{minuto_base}"),
            ("abrir_archivo", "reporte_diario.xlsx", f"08:0{minuto_base + 3}"),
            ("generar_reporte", "reporte_diario.pdf", f"08:{minuto_base + 7:02d}"),
        ]

        for tipo, valor, hora in eventos:
            respuesta = enviar_evento(tipo, valor, dia, hora)
            print(
                f"{dia} {hora} -> {tipo}: {valor} "
                f"(evento #{respuesta['evento']['id']})"
            )


if __name__ == "__main__":
    generar_historial()
