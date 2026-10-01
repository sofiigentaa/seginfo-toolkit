# Arquitectura — SentinelOps

## Vision general

Microservicios independientes (FastAPI), cada uno con su propia base de datos
logica dentro de la misma instancia de Postgres, mas un frontend SPA en
React/TypeScript que les habla directo (no hay un API gateway separado: el
frontend guarda la URL base de cada servicio via las variables `VITE_*_API_BASE_URL`
de `.env`/`.env.example`).

La comunicacion entre microservicios es sincrona, por HTTP/REST (`httpx`),
nunca por una cola de mensajes: por ejemplo, purple-service le pregunta a
siem-service por sus reglas via `GET /internal/rule-tags`, y report-service
agrega datos de vuln-service/siem-service/case-service/purple-service con
`GET` directos, autenticado con un JWT de servicio-a-servicio de corta
duracion (`backend.shared.security.create_access_token`, ver
`report-service/app/services.py::_fetch`). No hay RabbitMQ ni ninguna otra
cola de mensajes en este proyecto (el diagrama original planeaba una, pero
la implementacion real quedo mas simple, sincrona, y asi se documenta aca).

Tampoco hay MinIO ni ningun object storage externo: los reportes generados
(PDF/CSV) se guardan como blob base64 en la propia tabla `generated_reports`
de Postgres (ver `report-service/app/models.py::GeneratedReport`) -- son
documentos chicos (reportes de texto/tablas, no adjuntos multimedia), asi
que no justifican un datastore aparte.

## Diagrama

\`\`\`mermaid
flowchart TB
    subgraph Cliente
        FE[Frontend React/TS<br/>Dashboard SOC]
    end

    subgraph Backend
        AUTH[auth-service<br/>JWT + MFA + RBAC]
        ASSET[asset-service<br/>CMDB]
        SCAN[scan-service<br/>orquestacion escaneres]
        VULN[vuln-service<br/>CVSS/EPSS/KEV]
        SIEM[siem-service<br/>ingesta + correlacion]
        SOAR[soar-service<br/>playbooks]
        CASE[case-service<br/>incidentes]
        PURPLE[purple-service<br/>gap analysis]
        REPORT[report-service<br/>PDF/HTML]
        NOTIF[notification-service]
        INTEG[integration-service]
    end

    subgraph Datos
        PG[(PostgreSQL)]
        REDIS[(Redis)]
        OS[(OpenSearch)]
    end

    FE --> AUTH
    FE --> ASSET
    FE --> SCAN
    FE --> VULN
    FE --> SIEM
    FE --> SOAR
    FE --> CASE
    FE --> PURPLE
    FE --> REPORT

    SCAN --> VULN
    SIEM --> SOAR
    SOAR --> CASE
    PURPLE --> SIEM
    REPORT --> VULN
    REPORT --> SIEM
    REPORT --> CASE
    REPORT --> PURPLE

    AUTH --> PG
    ASSET --> PG
    VULN --> PG
    CASE --> PG
    REPORT --> PG
    SIEM --> OS
    AUTH --> REDIS
\`\`\`

## Fuera de alcance (deliberado)

Este proyecto no implementa, y no va a implementar en fases futuras:

- Frameworks de C2 (Sliver, Mythic, Cobalt Strike o similares)
- Orquestacion de herramientas de explotacion (Metasploit, SQLmap en modo ataque)
- Tracking de "operaciones red team" como ejecucion de intrusion real
- Cualquier mecanismo que automatice un ataque contra un objetivo real

El modulo "purple team" se limita a: dado un conjunto de tecnicas MITRE ATT&CK
declaradas (importadas como datos, no ejecutadas), calcular que reglas de
deteccion SIEM las cubren y reportar gaps. Es analisis sobre datos, no ejecucion.

## Componentes agregados fuera de los 11 microservicios

### Stack OpenVAS/GVM (agregado 2026-09-25)

`scan-service` habla el protocolo GMP contra `gvmd` (via `gvm-cli`, socket unix
montado) para orquestar escaneos reales de OpenVAS. Eso requiere levantar el
stack de Greenbone Community Edition completo en `docker-compose.yml`: feeds de
datos (`vulnerability-tests`, `notus-data`, `scap-data`, `cert-bund-data`), su
propio Postgres (`pg-gvm`) y Redis (`gvm-redis`), `gvmd`, `openvas`/`openvasd` y
`ospd-openvas` -- alrededor de 15 servicios, sin la GUI web (`gsa`/`gsad`/nginx),
que no hace falta. Todos viven en una red Docker propia (`gvm_internal`), sin
salida a internet y sin camino de red hacia Postgres/Redis/el resto de los
microservicios de SentinelOps. El detalle de cada servicio y por que
`ospd-openvas` necesita capacidades de red elevadas esta comentado en linea en
`docker-compose.yml`; el resumen de riesgo/mitigacion esta en
`docs/security.md` (seccion "Elevation of Privilege").

### Agente de escaneo remoto (`remote-agent/`, opcional)

Script Python standalone (fuera de Docker) que resuelve un problema puntual:
en Docker Desktop (Windows/Mac) los contenedores quedan detras de NAT y no ven
la LAN real de la oficina/cliente, asi que un escaneo nmap contra esa LAN
lanzado desde `scan-service` no encuentra nada. `remote-agent/agent.py` corre
en una PC con visibilidad real a esa red (la misma donde esta SentinelOps, u
otra de la LAN), hace polling saliente contra `scan-service` (nunca al reves,
no requiere abrir puertos entrantes), se autentica con una API key propia
(nunca el JWT de un usuario) y solo sabe correr nmap en modo deteccion -- igual
que el driver de nmap del propio `scan-service`. Ver `remote-agent/README.md`
para el detalle y `docs/security.md` (seccion Spoofing) para el modelo de
autenticacion.

## Servicios por fase

Ver `STATUS.md` en la raiz del repo para el detalle fase por fase.
