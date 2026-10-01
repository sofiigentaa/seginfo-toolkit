# BOTON Service

Primer nucleo del cerebro de BOTON dentro de SentinelOps.

## Objetivo inicial

BOTON no reemplaza los servicios existentes. Se ubica por encima de ellos para
recibir eventos autorizados, construir historial y, progresivamente, aprender
patrones, detectar necesidades y coordinar capacidades existentes.

## Estado v0.1

Esta primera version expone:

- `GET /health`: confirma que BOTON esta disponible.
- `POST /eventos`: recibe un evento autorizado.
- `GET /eventos`: muestra los eventos recibidos durante la ejecucion.

La memoria actual es temporal (en proceso). El siguiente paso sera persistir
los eventos y construir el primer detector de patrones.

## Ejecutar localmente

Desde `backend/services/boton-service`:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8012
```

Luego:

```text
http://127.0.0.1:8012/health
```

BOTON se desarrolla en la rama `boton-integration`.
