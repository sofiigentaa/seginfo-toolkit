import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(
    title="BOTON Service",
    description="Capa de inteligencia de BOTON: recibe eventos autorizados y construye memoria para aprendizaje.",
    version="0.2.0",
)

BASE_DIR = Path(__file__).resolve().parent.parent
BASE_DATOS = BASE_DIR / "boton.db"


class Evento(BaseModel):
    fuente: str = Field(..., examples=["siem-service"])
    tipo: str = Field(..., examples=["alerta_detectada"])
    valor: str = Field(..., examples=["nueva_alerta"])
    contexto: dict[str, Any] = Field(default_factory=dict)


def conectar():
    conexion = sqlite3.connect(BASE_DATOS)
    conexion.row_factory = sqlite3.Row
    return conexion


def crear_base_datos():
    with conectar() as conexion:
        conexion.execute(
            """
            CREATE TABLE IF NOT EXISTS eventos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fuente TEXT NOT NULL,
                tipo TEXT NOT NULL,
                valor TEXT NOT NULL,
                contexto TEXT NOT NULL,
                fecha TEXT NOT NULL
            )
            """
        )


crear_base_datos()


@app.get("/health")
def health():
    return {
        "servicio": "BOTON",
        "estado": "disponible",
        "version": "0.2.0",
        "memoria": "sqlite",
    }


@app.post("/eventos", status_code=201)
def recibir_evento(evento: Evento):
    fecha = datetime.now(timezone.utc).isoformat()
    contexto_json = json.dumps(evento.contexto, ensure_ascii=False)

    with conectar() as conexion:
        cursor = conexion.execute(
            """
            INSERT INTO eventos (fuente, tipo, valor, contexto, fecha)
            VALUES (?, ?, ?, ?, ?)
            """,
            (evento.fuente, evento.tipo, evento.valor, contexto_json, fecha),
        )
        evento_id = cursor.lastrowid

    registro = {
        "id": evento_id,
        "fuente": evento.fuente,
        "tipo": evento.tipo,
        "valor": evento.valor,
        "contexto": evento.contexto,
        "fecha": fecha,
    }
    return {"estado": "evento_recibido", "evento": registro}


@app.get("/eventos")
def listar_eventos():
    with conectar() as conexion:
        filas = conexion.execute(
            """
            SELECT id, fuente, tipo, valor, contexto, fecha
            FROM eventos
            ORDER BY id ASC
            """
        ).fetchall()

    eventos = [
        {
            "id": fila["id"],
            "fuente": fila["fuente"],
            "tipo": fila["tipo"],
            "valor": fila["valor"],
            "contexto": json.loads(fila["contexto"]),
            "fecha": fila["fecha"],
        }
        for fila in filas
    ]
    return {"cantidad": len(eventos), "eventos": eventos}
