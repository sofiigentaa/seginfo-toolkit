FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/services/threatintel-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/services/threatintel-service/app ./app
COPY backend/services/threatintel-service/tests ./tests
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

# No corre como root dentro del contenedor: si un endpoint tuviera una
# vulnerabilidad de escritura/ejecucion de archivos (path traversal, una
# RCE en una dependencia de terceros, etc), correr como root le da a un
# atacante mas margen -- y en un escenario de escape de contenedor, ser
# root tambien del lado de afuera. UID/GID fijos (1001) para que el build
# sea reproducible entre servicios.
RUN groupadd -r -g 1001 sentinelops && useradd -r -u 1001 -g sentinelops -M -s /usr/sbin/nologin sentinelops \
    && chown -R sentinelops:sentinelops /app
USER sentinelops

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
