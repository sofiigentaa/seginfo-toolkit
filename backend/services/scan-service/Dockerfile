FROM python:3.11-slim

WORKDIR /app

# nmap: paquete apt liviano y estable. trivy y nuclei se instalan aparte
# mas abajo (no tienen paquete apt en Debian). openvas NO se instala aca:
# gvmd/ospd-openvas es un producto completo (su propia base de datos +
# sincronizacion de feed de NVTs) que corre como servicios propios en
# docker-compose.yml (ver ese archivo, seccion GVM/OpenVAS). Este
# contenedor solo necesita el CLIENTE gvm-cli (paquete pip gvm-tools, mas
# abajo) para hablar por socket GMP con el gvmd de esos servicios.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl nmap unzip \
    && rm -rf /var/lib/apt/lists/*

# Trivy (CVEs conocidos en imagenes de contenedor / filesystems): script
# oficial de aquasecurity, instala el binario mas reciente en
# /usr/local/bin.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Baja la base de datos de CVEs UNA VEZ en build-time (no en cada escaneo:
# ver app/scanners/trivy.py, que corre con --skip-db-update). Se persiste
# despues en el volumen nombrado `trivy_cache` (ver docker-compose.yml) --
# Docker copia este contenido de la imagen al volumen la primera vez que
# se monta, asi que el primer arranque ya tiene la DB lista sin esperar
# nada. Un job periodico (app/services.py::refresh_trivy_db) la mantiene
# actualizada despues.
RUN mkdir -p /root/.cache/trivy && trivy image --download-db-only --cache-dir /root/.cache/trivy

# Nuclei (deteccion basada en plantillas): no tiene paquete apt ni script
# de instalacion propio como el de trivy, asi que se resuelve la ultima
# release de GitHub en build-time (para no hardcodear una version que
# quede vieja) y se descarga el binario ya compilado para linux_amd64.
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") \
    && curl -sSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# NUCLEI_TEMPLATES_DIR fijo (en vez de dejar que nuclei elija por defecto
# via XDG, que puede variar entre versiones) para que el volumen nombrado
# `nuclei_templates` (ver docker-compose.yml) siempre apunte al lugar
# correcto. Baja las plantillas UNA VEZ en build-time (no en cada escaneo:
# ver app/scanners/nuclei.py, que corre con -duc); se persisten despues
# (mismo mecanismo de copia-al-primer-montaje que trivy_cache, arriba).
# Un job periodico (app/services.py::refresh_nuclei_templates) las
# mantiene actualizadas.
ENV NUCLEI_TEMPLATES_DIR=/root/nuclei-templates
RUN nuclei -update-templates -silent || true

COPY backend/services/scan-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# gvm-tools: paquete pip que provee el binario gvm-cli, cliente GMP usado
# por app/scanners/openvas.py para hablar (via socket) con el gvmd que
# corre como su propio servicio en docker-compose.yml.
RUN pip install --no-cache-dir gvm-tools

COPY backend/services/scan-service/app ./app
COPY backend/services/scan-service/tests ./tests
COPY backend/shared ./backend/shared
RUN touch backend/__init__.py

ENV PYTHONPATH=/app

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
