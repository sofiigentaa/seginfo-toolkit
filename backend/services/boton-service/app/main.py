from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(
    title="BOTON Service",
    description="Capa de inteligencia de BOTON: recibe eventos autorizados y construye memoria para aprendizaje.",
    version="0.1.0",
)

_eventos: list[dict[str, Any]] = []


class Evento(BaseModel):
    fuente: str = Field(..., examples=["siem-service"])
    tipo: str = Field(..., examples=["alerta_detectada"])
    valor: str = Field(..., examples=["nueva_alerta"])
    contexto: dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health():
    return {
        "servicio": "BOTON",
        "estado": "disponible",
        "version": "0.1.0",
    }


@app.post("/eventos", status_code=201)
def recibir_evento(evento: Evento):
    registro = {
        "id": len(_eventos) + 1,
        "fuente": evento.fuente,
        "tipo": evento.tipo,
        "valor": evento.valor,
        "contexto": evento.contexto,
        "fecha": datetime.now(timezone.utc).isoformat(),
    }
    _eventos.append(registro)
    return {"estado": "evento_recibido", "evento": registro}


@app.get("/eventos")
def listar_eventos():
    return {"cantidad": len(_eventos), "eventos": _eventos}
