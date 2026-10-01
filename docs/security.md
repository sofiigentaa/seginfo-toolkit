# SentinelOps -- modelo de amenazas (STRIDE)

Este documento aplica STRIDE (Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege) a la arquitectura descrita
en `docs/architecture.md`. El objetivo es dejar explicitas las mitigaciones ya
implementadas y las que quedan como trabajo futuro, no presentar la plataforma
como libre de riesgo.

## Alcance

Cubre los 11 microservicios backend, el frontend, y los componentes de
infraestructura de `docker-compose.yml` / `infra/`. No cubre el codigo de terceros
(FastAPI, SQLAlchemy, Postgres, etc.) mas alla de su configuracion.

## Spoofing (suplantacion de identidad)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un atacante se autentica como otro usuario | JWT firmado (HS256) + bcrypt para passwords + MFA opcional (TOTP) en auth-service | Rotacion de `JWT_SECRET_KEY`; soportar MFA obligatorio por rol |
| Un servicio interno se hace pasar por otro | Los endpoints `/internal/*` (siem-service, integration-service) no tienen auth de usuario porque asumen red interna confiable (docker-compose/k8s namespace) | mTLS o un token de servicio compartido entre microservicios si se expone la red interna fuera del cluster |
| Un agente de escaneo remoto (`remote-agent/agent.py`, fuera de Docker, para redes LAN que el contenedor de scan-service no ve) falso se hace pasar por un agente registrado | Autenticacion propia por API key (header `X-Agent-Key`, nunca el JWT de un usuario); scan-service solo persiste el hash sha256 de la key (`_hash_agent_key` en `scan-service/app/services.py`), nunca el valor en texto plano; el agente solo puede pedir jobs y correr nmap en modo deteccion, nunca ejecutar comandos arbitrarios | No hay rotacion de key sin borrar el agente (`DELETE /agents/{id}`) y crear uno nuevo; agregar rotacion sin perder el historial del agente |

## Tampering (alteracion de datos)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Modificar una alerta o caso para ocultar un incidente | Timeline de auditoria append-only en case-service; audit log con encadenamiento SHA-256 en auth-service | Extender el mismo encadenamiento hash a case-service y siem-service |
| Inyectar una condicion Sigma maliciosa que ejecute codigo | `app/sigma.py` evalua condiciones con un AST restringido (`_ALLOWED_CONDITION_NODES`), nunca `eval()` sobre texto arbitrario | Fuzzing periodico del evaluador de condiciones |
| Alterar un playbook YAML para ejecutar una accion no autorizada | Playbooks se sincronizan a Postgres al arrancar soar-service desde archivos versionados en el repo (revisados en PR) | Firmar los YAML de playbooks o restringir su origen a un directorio de solo-lectura en produccion |

## Repudiation (repudio)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un operador niega haber cerrado un caso o corrido un playbook | Timeline de casos y `PlaybookRunOut.triggered_by` registran actor y timestamp | Centralizar todos los logs estructurados (JSON, ver `backend/shared/logging.py`) en un SIEM externo con retencion garantizada |

## Information Disclosure (divulgacion de informacion)

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Filtrar vulnerabilidades/CVEs de un cliente a otro | Multi-tenant con aislamiento por fila (`organization_id` en cada tabla de cada servicio, filtrado en cada query -- ver `backend/shared/tenancy.py`); el JWT lleva `org_id` y cada endpoint lo usa para scopear sus consultas | Auditoria periodica de que todo query nuevo filtre por `organization_id` (revisar en code review, no hay un enforcement automatico a nivel de DB tipo RLS todavia) |
| Exponer secretos (JWT secret, password de DB) en el repo | `.env` esta en `.gitignore`; `infra/k8s/base/secret.yaml` tambien; Terraform usa `TF_VAR_db_password` en vez de un default | Adoptar un secret manager real (Vault, AWS Secrets Manager) en vez de Secrets planos de k8s |
| El endpoint interno `/internal/rule-tags` de siem-service devuelve datos de reglas sin autenticar | Solo expone id/nombre/tags (nunca la logica de deteccion completa) y se asume red interna no expuesta a internet | Restringir por NetworkPolicy de k8s a los Pods que realmente lo necesitan (purple-service) |

## Denial of Service

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un cliente HTTP abusivo agota conexiones a un servicio | Timeouts explicitos (10s) en todas las llamadas httpx entre servicios | Rate limiting a nivel de ingress/API gateway; readiness/liveness probes ya definidas en `infra/k8s/base` para que k8s reinicie Pods colgados |
| Un playbook mal configurado dispara un loop de acciones | Acciones de SOAR son idempotentes por diseño (bloquear la misma IP dos veces no es destructivo) y corren en dry-run por defecto | Circuit breaker / limite de ejecuciones por alerta en soar-service |

## Elevation of Privilege

| Amenaza | Mitigacion actual | Pendiente |
|---|---|---|
| Un usuario sin rol admin ejecuta una accion de contencion real | RBAC via claim `role` en el JWT, verificado con `require_role(...)` en cada endpoint sensible (crear conectores, generar reportes, etc.) | Auditoria periodica de que rol tiene acceso a que endpoint, a medida que se agregan mas roles |
| SOAR/integration-service ejecutan una accion real sin que un humano lo decida | Doble capa de dry-run independiente: `SOAR_DRY_RUN` e `INTEGRATION_DRY_RUN`, ambas en `"true"` por defecto en `docker-compose.yml`, `.env.example` e `infra/k8s/base/configmap.yaml`. Pasar a `"false"` es un cambio explicito de configuracion, nunca el valor de fabrica | Requerir ademas un conector configurado (ya implementado: sin conector habilitado, la accion queda `failed` aunque el dry-run este apagado) -- agregar una segunda aprobacion humana (four-eyes) antes de la primera ejecucion real en un cliente nuevo |
| El contenedor `ospd-openvas` (motor real de OpenVAS/GVM, agregado 2026-09-25) corre con `cap_add: [NET_ADMIN, NET_RAW]` y `security_opt: [seccomp=unconfined, apparmor=unconfined]` -- una elevacion de privilegios real, requerida por el propio compose oficial de Greenbone porque el motor arma paquetes crudos (sockets raw/ICMP/IP_HDRINCL) para el descubrimiento de hosts | El impacto de una eventual falla de ESE contenedor puntual (ningun otro servicio de SentinelOps tiene estas capacidades) esta acotado: vive en su propia red Docker `gvm_internal`, sin salida a internet y sin camino de red hacia Postgres/Redis ni el resto de los microservicios (scan-service le habla a gvmd por un socket unix montado, no por red); ademas tiene `no-new-privileges:true` (bloquea escalar por setuid/setgid aunque el seccomp/apparmor esten sin confinar). Ver el comentario en `docker-compose.yml` junto al servicio `ospd-openvas` para el detalle completo | Evaluar si Greenbone publica en el futuro un perfil seccomp scoped en vez de `unconfined`; considerar correr este contenedor puntual en un host/VM separado del resto del stack para clientes con requisitos de aislamiento mas estrictos |

## Resumen

Los controles mas fuertes de esta plataforma son estructurales, no solo de
codigo: **ninguna accion de contencion (bloquear IP, aislar host, enviar una
notificacion externa) puede llegar a un sistema real sin que dos flags de
entorno independientes se desactiven explicitamente y un conector real este
configurado.** Esto es intencional: el objetivo del producto es dar visibilidad
y automatizar el analisis, dejando la decision de actuar contra infraestructura
real siempre en manos de un humano.
