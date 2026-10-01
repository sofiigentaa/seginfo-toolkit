FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/services/cloud-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/services/cloud-service/app ./app
COPY backend/services/cloud-service/tests ./tests
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

# No corre como root dentro del contenedor -- mismo motivo y mismo UID/GID
# fijo (1001) que el resto de los servicios, ver Dockerfile de
# asset-service/asm-service.
RUN groupadd -r -g 1001 sentinelops && useradd -r -u 1001 -g sentinelops -M -s /usr/sbin/nologin sentinelops \
    && chown -R sentinelops:sentinelops /app
USER sentinelops

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
