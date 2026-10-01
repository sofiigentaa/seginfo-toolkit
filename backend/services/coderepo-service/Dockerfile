FROM python:3.11-slim

WORKDIR /app

# git: hace falta para clonar el repositorio del cliente (no esta en esta
# imagen base). gcc/libpq-dev: build de asyncpg/psycopg. curl/unzip:
# instalacion de trivy/gitleaks mas abajo.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl unzip git \
    && rm -rf /var/lib/apt/lists/*

# Trivy (dependencias vulnerables en manifiestos -- `trivy fs --scanners
# vuln`): mismo script oficial de aquasecurity que usa scan-service, ver
# ese Dockerfile.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Baja la base de datos de CVEs UNA VEZ en build-time (no en cada escaneo:
# ver app/services.py::build_trivy_fs_vuln_cmd, que corre con
# --skip-db-update). Se persiste despues en el volumen nombrado
# `coderepo_trivy_cache` (ver docker-compose.yml -- PROPIO de este
# servicio, nunca el `trivy_cache` de scan-service: dos contenedores
# escribiendo la misma cache de trivy en simultaneo puede corromper el
# archivo bolt de la DB). Un job periodico
# (app/services.py::refresh_trivy_db) la mantiene actualizada despues.
RUN mkdir -p /root/.cache/trivy && trivy image --download-db-only --cache-dir /root/.cache/trivy

# Gitleaks (secretos/credenciales en todo el historial de git): no tiene
# paquete apt ni script de instalacion propio, asi que se resuelve la
# ultima release de GitHub en build-time (mismo patron que nuclei en
# scan-service/Dockerfile, para no hardcodear una version que quede
# vieja) y se descarga el tarball ya compilado para linux_x64.
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") \
    && curl -sSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

COPY backend/services/coderepo-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/services/coderepo-service/app ./app
COPY backend/services/coderepo-service/tests ./tests
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

# No corre como root dentro del contenedor -- mismo motivo y mismo UID/GID
# fijo (1001) que el resto de los servicios, ver Dockerfile de
# asset-service/asm-service/cloud-service.
# El cache de trivy predescargado en build-time vive en /root/.cache/trivy
# (mismo path que usa scan-service) -- a diferencia de scan-service, este
# contenedor SI corre como usuario no-root, asi que ese directorio (y el
# volumen `coderepo_trivy_cache` montado ahi, ver docker-compose.yml)
# tambien se le entrega a `sentinelops`: sin este chown, refresh_trivy_db
# y cada escaneo individual fallarian con permiso denegado al intentar
# escribir en la cache.
RUN groupadd -r -g 1001 sentinelops && useradd -r -u 1001 -g sentinelops -M -s /usr/sbin/nologin sentinelops \
    && chown -R sentinelops:sentinelops /app /root/.cache/trivy
USER sentinelops

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
