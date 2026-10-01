# Estado del proyecto SentinelOps (seginfo-toolkit)

Alcance: plataforma de ciberseguridad DEFENSIVA (SIEM/SOAR, gestion de vulnerabilidades
en modo escaneo, gestion de casos, cumplimiento, reportes, dashboard). No incluye
motores de ejecucion ofensiva ni integracion C2 (ver docs/architecture.md, seccion
"Fuera de alcance").

## Fases
- [x] Fase 1: Arquitectura + docker-compose + estructura + auth-service + frontend base
- [x] Fase 2: asset-service + scan-service (orquestacion de escaneres defensivos) + vuln-service
- [x] Fase 3: siem-service + soar-service
- [x] Fase 4: case-service + purple-service (metricas/gap-analysis, sin motor ofensivo)
- [x] Fase 5: report-service + notification-service + integration-service
- [x] Fase 6: K8s + Terraform + CI/CD + documentacion final + expansion de frontend

## Corrida de calidad (2026-09-26)

Las 6 fases planificadas ya estaban completas (ver arriba) y la corrida anterior
(2026-09-25) agrego el stack real de OpenVAS/GVM + el agente de escaneo remoto,
asi que esta corrida se dedico a verificacion y a cerrar una brecha de
documentacion que encontro, sin tocar codigo de los servicios:

- **Verificacion completa**: se corrio pytest real (no solo `py_compile`) en
  los 11 servicios backend con el venv compartido `backend/.venv` -- 182 tests,
  todos en verde (auth 11, asset 7, scan 52, vuln 20, case 9, integration 7,
  notification 9, report 14, siem 34, soar 13, purple 6). En el frontend,
  `npm run test -- --run` (35 tests, todos en verde) y `npx tsc --noEmit`
  (limpio, cero errores). `docker-compose.yml` se valido como YAML bien
  formado con PyYAML (no hay Docker en esta maquina de automatizacion para
  correr `docker compose config` de verdad -- eso ya lo cubre el job
  `compose-validate` de CI en un runner con Docker). Se reviso `.env.example`
  contra las variables que usa `docker-compose.yml`: todo esta declarado. Se
  busco `TODO`/`FIXME`/`XXX` en todo `backend/` y `frontend/src`: no hay
  ninguno real (los dos matches en backend son falsos positivos de texto,
  "tXXXX" de una convencion de tags ATT&CK y la palabra "TODOS" en espanol).
- **Brecha de documentacion encontrada y corregida**: la corrida del
  2026-09-25 agrego ~15 servicios del stack GVM/OpenVAS y el
  `remote-agent/` opcional al `docker-compose.yml`, pero `docs/architecture.md`
  y `docs/security.md` nunca se actualizaron para reflejarlo -- quedaban
  describiendo solo los 11 microservicios originales. Se agrego a
  `docs/architecture.md` una seccion nueva ("Componentes agregados fuera de
  los 11 microservicios") explicando el stack GVM (por que son ~15 servicios,
  que red Docker aislada usan, por que `ospd-openvas` necesita capacidades de
  red elevadas) y el `remote-agent` (que problema resuelve, modelo de
  autenticacion). Se agregaron dos filas a la tabla STRIDE de
  `docs/security.md`: en Spoofing, el modelo de autenticacion del
  remote-agent (API key propia, solo se persiste el hash, nunca la key en
  claro); en Elevation of Privilege, la elevacion real de `ospd-openvas`
  (`NET_ADMIN`/`NET_RAW` + seccomp/apparmor sin confinar) con su mitigacion
  (red Docker `gvm_internal` aislada sin salida a internet ni camino hacia el
  resto de la plataforma, comunicacion por socket unix en vez de red,
  `no-new-privileges`) y el pendiente (evaluar un perfil seccomp scoped si
  Greenbone lo publica, o aislar ese contenedor en un host separado para
  clientes con requisitos mas estrictos). Estos detalles ya estaban
  documentados como comentarios en linea en `docker-compose.yml` (de la
  corrida anterior) -- este cambio los sube al modelo de amenazas formal,
  que es donde alguien evaluando el producto realmente los va a buscar.
- No se toco codigo de ningun servicio: no hizo falta ningun fix, todo lo
  que se corrio ya estaba en verde.

## Ultima corrida
- Fecha: 2026-09-24
- Tipo: mejora de calidad (las 6 fases planificadas ya estaban completas,
  ver corrida anterior). Ademas, esta corrida retomo trabajo de tests que
  habia quedado escrito en disco sin commitear por una corrida anterior
  interrumpida (probablemente por el mismo .git/index.lock colgado que se
  encontro y resolvio al arrancar esta corrida) -- se reviso y se corrio
  cada test antes de commitear, no se asumio que estuviera bien.
- Que se hizo:
  - Tests reales con pytest en los 4 servicios con logica pura facil de
    testear sin base de datos real: auth-service
    (tests/test_security.py, 11 tests: hashing/verificacion de password,
    creacion/decodificacion de JWT, generacion y verificacion de codigos
    TOTP), vuln-service (test_cvss.py + test_priority_score.py, 13
    tests: parseo de vector CVSS v3.1 y calculo del score de
    priorizacion combinando CVSS/EPSS/KEV), purple-service
    (test_coverage.py, 6 tests: gap-analysis de cobertura ATT&CK) y
    scan-service (test_nmap_driver.py, 6 tests: parseo de XML de nmap a
    findings normalizados). 36 tests en total. Cada servicio tiene su
    conftest.py (agrega el path del servicio y la raiz del repo a
    sys.path) y pytest==8.3.3 en requirements.txt (dependencia
    solo-de-test); los Dockerfile copian tests/ a la imagen y `make
    test` corre pytest en los 4 servicios via `docker compose exec`.
  - Frontend: se extrajo la logica de "esta vencido el SLA de este caso"
    de src/pages/Cases.tsx a una funcion pura testeable
    (src/utils/sla.ts::isSlaBreached) y se agregaron tests con vitest
    para ella y para el helper existente errors.ts::connectionErrorDetail
    -- 13 tests. Se agrego vitest a devDependencies, un script "test" a
    package.json, y vite.config.ts ahora usa defineConfig de
    "vitest/config" para declarar la config de test junto a la de vite.
  - Se corrigio docs/architecture.md: describia RabbitMQ y MinIO como
    parte de la arquitectura, pero la implementacion real (ver
    docker-compose.yml y el codigo) nunca uso ninguno de los dos -- la
    comunicacion entre servicios es HTTP/REST sincrono con JWT de
    servicio-a-servicio, y los reportes se guardan como blob en Postgres.
    Se actualizo el diagrama Mermaid y el texto para reflejar la
    arquitectura real.
  - .github/workflows/ci.yml: se agregaron pasos reales de pytest (los 4
    servicios con tests/) al job backend-smoke y de `npm run test --
    --run` (vitest) al job frontend-build, reemplazando comentarios TODO
    que decian "todavia no existen tests automatizados" -- ya no es
    cierto.
- Validacion antes de commitear: se instalaron las dependencias minimas
  de cada servicio (fastapi, sqlalchemy, asyncpg, pydantic, etc.) y se
  corrio `python3 -m pytest -q` real en los 4 servicios -- 11+6+6+13 =
  36 tests, todos en verde. `python3 -m py_compile` sobre todo backend/
  sin errores. ci.yml y docker-compose.yml parseados como YAML valido
  con PyYAML. Para el frontend no se pudo correr `npm install`/vitest en
  esta maquina: reaparecio el mismo problema de mount lento para
  node_modules ya documentado en la corrida de Fase 6 (`npm install` y
  hasta `ls node_modules` llegan a colgarse en esta maquina de
  automatizacion). En su lugar se valido con `tsc --noEmit` que
  sla.ts/sla.test.ts/errors.test.ts/Cases.tsx compilan sin errores de
  sintaxis (los unicos errores de tsc son en archivos no tocados aca, por
  falta de node_modules instalado, no bugs reales); el job
  frontend-build de GitHub Actions corre los tests de verdad en un
  runner limpio donde este problema no existe.

## Cierre de calidad (2026-09-24, corrida especial "cierre a 100%")
Corrida adicional en la misma fecha, a pedido explicito de Manu, para
terminar la cobertura de tests que habia quedado a mitad de camino y
corregir lo que se encontrara roto -- no una fase nueva.

- Se instalaron las dependencias reales de los 4 servicios con tests
  (auth/purple/scan/vuln) y se corrio pytest de verdad: se encontro y
  corrigio un test flaky en auth-service
  (test_tampered_signature_is_rejected) -- tamperear el ULTIMO caracter
  de un JWT en base64url puede caer en un bit de padding no
  significativo y no cambiar el valor decodificado, dando un falso
  negativo. Se cambio a tamperear el PRIMER caracter de la firma, que
  siempre es significativo. Los otros 3 servicios ya estaban en verde.
- Se agregaron tests con pytest a los 7 servicios que todavia no
  tenian: asset-service (7, validacion de schemas), case-service (4,
  contrato de SLA_HOURS_BY_PRIORITY), integration-service (7, cifrado
  de credenciales de conector + dry-run), notification-service (9,
  validacion de canales + dry-run), report-service (8, exportacion
  CSV/PDF), siem-service (27, motor de reglas Sigma incluyendo que la
  evaluacion de `condition` este sandboxeada contra intentos de
  escape -- llamadas a funciones, acceso a atributos, imports -- y
  normalizacion ECS) y soar-service (13, ranking de severidad,
  resolucion de campos del contexto de una alerta, y dry-run). Mismo
  patron que los 4 servicios existentes: conftest.py + pytest en
  requirements.txt/Dockerfile. Total backend: 111 tests, todos en
  verde. Ahora los 11 microservicios backend tienen tests reales.
- Se corrigio `npm install` en el frontend: el node_modules de esta
  maquina tenia un zustand instalado de forma incompleta (faltaba
  esm/vanilla.d.mts, el archivo de tipos del que depende `create`) --
  no era un problema de mount lento como se penso en la corrida
  anterior, sino una instalacion corrupta de verdad. Se borro
  node_modules/package-lock.json y se reinstalo limpio. Eso destapo que
  `tsc --noEmit` (parte de `npm run build`) fallaba en TODO el frontend
  (9 errores de "implicitly has an 'any' type" en Layout/Billing/Login/
  Notifications/Organizations/SsoCallback/store/auth.ts) porque
  store/auth.ts llamaba a `create<AuthState>((set) => ...)` sin la
  forma "curried" que zustand 4 necesita para inferir bien el tipo de
  `set` (`create<AuthState>()((set) => ...)`). Se corrigio esa unica
  linea y los 9 errores desaparecieron. `npm run build` y `npx tsc
  --noEmit` quedan limpios de verdad, verificado en esta corrida (no
  solo con esbuild como aproximacion, como en la corrida anterior).
- Se agregaron mas tests de frontend: se extrajo la logica de
  interpretacion del error 402 de pago vencido de Login.tsx a una
  funcion pura (src/utils/loginError.ts::parseLoginError, 8 tests) y el
  formateo de fecha de Billing.tsx a src/utils/format.ts::formatDate (4
  tests) -- mismo patron que sla.ts. Frontend: 25 tests en total (antes
  13), todos en verde. No se agrego @testing-library/react en esta
  corrida (requeriria cambiar test.environment de "node" a "jsdom" y
  nuevas dependencias) -- queda como posible proximo paso si Manu quiere
  tests que rendericen componentes, no solo la logica pura que ya usan.
- Se corrigio docs/security.md: la fila de la tabla STRIDE sobre
  "no hay multi-tenant todavia" estaba desactualizada -- el
  multi-tenant por fila (organization_id) ya esta implementado en todos
  los servicios desde hace varias corridas. Se corrigio para reflejar
  el estado real.
- .github/workflows/ci.yml sigue sin poder commitearse (ver Pendiente).

## Pendiente -- decision de Manu, no es codigo
- [RESUELTO 2026-09-24] Manu le agrego el permiso 'Workflows: Read and
  write' al fine-grained PAT y .github/workflows/ci.yml ya esta
  commiteado y pusheado -- el job backend-smoke se actualizo para
  correr pytest en los 11 servicios (antes solo cubria los 4 que tenian
  tests en ese momento). CI corriendo en GitHub Actions desde el commit
  c1557db.
- Falta decidir el registry para publicar las imagenes Docker (GHCR es
  la opcion mas simple, no requiere credenciales de AWS) y agregar el
  login+push al job docker-build -- hoy ese job solo verifica que cada
  Dockerfile buildea, no publica nada.
- Ningun conector de firewall/EDR real esta configurado en
  integration-service (la plataforma sigue 100% dry-run por defecto,
  ver SOAR_DRY_RUN/INTEGRATION_DRY_RUN/NOTIFICATION_DRY_RUN) -- es
  intencional hasta que el usuario/operador lo decida explicitamente.
- infra/terraform sigue siendo un esqueleto de referencia, no aplicado
  contra ninguna cuenta de AWS real -- revisar costos, security groups
  y backend remoto de estado antes de un uso real (ver
  infra/terraform/README.md).
- Cobertura de tests que podria seguir creciendo (no bloqueante): tests
  de integracion/endpoint con DB de test (sqlite o testcontainers) para
  los 11 servicios -- hoy todos tienen unit tests de su logica pura,
  pero ninguno tiene un test que levante la app FastAPI completa contra
  una base real. Tests de frontend que rendericen componentes (con
  @testing-library/react) en vez de solo la logica pura extraida a
  utils/.

## Cierre del pedido de funcionalidades "100% funcional por botones" (2026-09-24)
Corrida a pedido explicito de Manu: hacer que Activos, Escaneos,
Vulnerabilidades, SIEM, SOAR, Casos, Purple Team, Reportes,
Notificaciones e Integraciones queden completas y usables con botones
(sin JSON/codigo a mano), y agregar una guia de uso dentro de la app.
Ejecutada en 10 fases, cada una commiteada y pusheada por separado:

- Activos: alta de activos + boton "Escanear (detectar fallos)" por
  fila que lanza un scan-job real contra ese activo.
- Escaneos: borrado por item de escaneos y agent-scans ya terminados
  (`DELETE /scans/{id}`, `DELETE /agent-scans/{id}`, solo en estados
  terminales).
- Vulnerabilidades: pasos de remediacion generados por reglas
  (`vuln-service/app/remediation.py`, sin IA/red) mostrados por fila +
  triage (confirmado/falso positivo/riesgo aceptado/remediado).
- SIEM: severidad agregada al esquema ECS-lite, 3 reglas Sigma
  recomendadas seedeables con un boton, y creador de reglas 100% por
  formulario (sin JSON a mano). Los hallazgos de scan-service ahora se
  forwardean tambien a SIEM (antes solo a vuln-service).
- SOAR: borrado de playbooks + creador de pasos de playbook por
  formulario (accion + parametros), sin textarea de JSON.
- Casos: sincronizacion automatica periodica con SOAR
  (`case-service::_soar_sync_loop`, mismo patron que
  `auth-service::_license_check_loop`) + gestion completa por botones
  (tomar/resolver/cerrar/reabrir, asignar, notas).
- Purple Team: declaracion de ejercicios por checklist de tecnicas
  ATT&CK + recalculo de cobertura y vista de gaps, todo por UI.
- Reportes: borrado de reportes generados por item.
- Notificaciones: dashboard + habilitar/deshabilitar/borrar canales.
- Integraciones: formularios estructurados por tipo de conector
  (firewall/EDR, ticketing) en vez de un textarea de config JSON.
- Ayuda: seccion nueva (`/help`), visible para todos los roles, con
  guia interactiva en espanol simple de cada funcion de la plataforma,
  busqueda de texto libre y progreso de lectura persistido en el
  navegador (mas una subseccion solo-admin para Organizaciones y pagos).

Validacion: cada fase se verifico con pytest real de los servicios
backend tocados, `tsc --noEmit`, `vitest run` y `npm run build` del
frontend antes de commitear -- todo en verde en las 10 fases.

## Escaneres: nmap/trivy/nuclei mas rapidos + OpenVAS real (2026-09-25)

Pedido de Manu: "los scaneres... todos tardan mucho y openvas no anda directamente".

- **nmap**: nuevo modo `fast`/`full` (toggle en "Nuevo escaneo" en la UI).
  `full` es el comportamiento historico (-sV -sC --script default,safe,
  timeout 180s). `fast` saca los scripts NSE (el mayor costo de tiempo),
  se queda con -sV, limita a --top-ports 100 si no se especifican puertos,
  y usa timeout 60s. Guardrail de scope (`_ALLOWED_EXTRA_FLAGS`) sin tocar.
- **trivy**: la DB de CVEs se bajaba en CADA escaneo. Ahora se descarga
  una vez al construir la imagen (Dockerfile) y se persiste en el volumen
  `trivy_cache`; el driver corre con `--skip-db-update`; un job periodico
  (`refresh_trivy_db`, cada 24hs via APScheduler) la mantiene actualizada
  en segundo plano. Fallback automatico a descarga si la cache esta vacia
  (primer arranque antes de que corra el refresh).
- **nuclei**: mismo problema con las plantillas -- se bajan una vez al
  construir la imagen, se persisten en `nuclei_templates`, el driver corre
  con `-duc` (disable update check), y `refresh_nuclei_templates` las
  actualiza cada 12hs en segundo plano.
- **OpenVAS**: antes no estaba instalado, y el driver ni siquiera se
  autenticaba ni disparaba un escaneo (solo hacia una consulta sin auth).
  Ahora es un stack GVM (Greenbone Community Edition) real:
  `docker-compose.yml` agrega ~16 servicios (feeds de NVTs, postgres
  propio de GVM, gvmd, openvas-scanner, ospd-openvas -- sin la GUI web
  gsa/gsad/nginx, que no hace falta para esto). `scan-service` habla con
  gvmd via `gvm-cli` (paquete pip `gvm-tools`, agregado a su Dockerfile)
  por el socket montado de gvmd. El driver nuevo
  (`app/scanners/openvas.py`) hace el flujo GMP completo: descubre
  dinamicamente config/scanner/port_list (no hardcodea UUIDs -- pueden
  faltar en instalaciones nuevas), crea target+task, lo arranca, hace
  poll hasta que termina (o timeout, `GVM_SCAN_TIMEOUT_SECONDS`, default
  1500s) y trae los resultados reales.

### Pasos manuales que le tocan a Manu (no puedo correr Docker desde aca)

1. `docker compose build` (va a tardar mas que antes: ahora tambien
   baja la DB de trivy y las plantillas de nuclei al construir la
   imagen de scan-service) y despues `docker compose up -d`.
2. **Primera sincronizacion del feed de GVM**: los contenedores
   `vulnerability-tests`, `notus-data`, `scap-data`, etc. bajan el feed
   completo de NVTs/CVEs de Greenbone la primera vez -- puede tardar
   **horas** y ocupar **varios GB** de disco. `docker compose logs -f
   gvmd` para ver el progreso; gvmd no queda realmente usable hasta que
   terminen.
3. **Bootstrap del usuario admin de GVM** (una sola vez, despues de que
   gvmd este arriba):
   ```
   docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='TU_PASSWORD_ACA'
   ```
   Despues completar `GVM_USER=admin` y `GVM_PASSWORD=TU_PASSWORD_ACA`
   en `.env` (mismo valor que se paso arriba) y reiniciar scan-service
   (`docker compose restart scan-service`).
4. **Nota de seguridad -- ospd-openvas (actualizado 2026-09-26)**: el
   servicio `ospd-openvas` corre con `cap_add: [NET_ADMIN, NET_RAW]` y
   `security_opt: [seccomp=unconfined, apparmor=unconfined]`. Esto NO se
   puede sacar: el motor openvas-scanner arma paquetes crudos el mismo
   (sockets raw, ICMP, IP_HDRINCL) para descubrimiento/fingerprinting de
   host, y esos syscalls estan bloqueados por el perfil seccomp default
   de Docker y por AppArmor -- asi lo requiere el propio compose oficial
   de Greenbone, sin un perfil scoped alternativo documentado. Sacarlo
   rompe el escaner.

   Lo que si se hizo para achicar el impacto si ESE contenedor puntual
   se ve comprometido (sin tocar esas dos capacidades, que son las que
   de verdad hacen falta):
   - `security_opt: no-new-privileges:true` -- bloquea escalar privilegios
     via setuid/setgid en cualquier binario que corra adentro.
   - Red Docker propia `gvm_internal` (`internal: true`, sin salida a
     internet) para TODO el stack GVM/OpenVAS -- ningun otro servicio de
     SentinelOps (postgres, redis, el resto de los microservicios)
     comparte esa red. `scan-service` no la necesita: habla con `gvmd`
     por el socket unix montado (`gvmd_socket_vol`), no por red. Asi,
     aunque `ospd-openvas` se vea comprometido, no tiene ningun camino de
     red hacia el resto de la plataforma.
   - Se evaluo `cap_drop: [ALL]` (dejar solo NET_ADMIN/NET_RAW en vez de
     heredar todo el set default de Docker encima) pero quedo afuera a
     proposito: no puedo levantar el contenedor desde aca para confirmar
     que el entrypoint de la imagen no necesita algun otro capability
     (ej. CHOWN/SETUID al arrancar) -- romper el arranque a ciegas es
     peor que dejar el mismo set que testea el compose oficial. Si
     despues de que este todo andando lo queres mas restrictivo, se
     puede probar `cap_drop: [ALL]` como cambio aislado y ver si el
     contenedor sigue arrancando bien.
5. Si algo falla al levantar el stack o al lanzar un escaneo OpenVAS,
   mandame los logs (`docker compose logs scan-service gvmd
   ospd-openvas`) para poder iterar -- no puedo ver los contenedores
   corriendo desde aca.

Validacion hecha desde aca: 52 tests de pytest en scan-service (nmap +
trivy + nuclei + openvas, todos como funciones puras sin I/O real) en
verde. No pude correr `docker compose build/up` (sin acceso a Docker en
este entorno) -- eso queda pendiente de que Manu lo corra y reporte.

## Auditoria funcional completa + 17 bugs corregidos (2026-09-26)

Pedido de Manu: "testeá toda la aplicación y arreglá lo que no anda". Se armo
un brief de auditoria profesional (metodologia: leer cada endpoint/pagina real,
rastrear cada boton hasta la DB y de vuelta, buscar RBAC/multi-tenancy roto,
dry-run mal aplicado, errores no manejados) y se corrio en 5 grupos en paralelo,
cada uno cubriendo un area de la plataforma, sin superposicion de archivos.
Ningun grupo hizo commit por su cuenta -- se reviso y se consolido todo en un
solo commit despues de correr los 204 tests backend + 41 tests frontend +
tsc + build, todo en verde.

**Bug critico de seguridad (auth-service)**: `POST /auth/mfa/enroll` permitia
reemplazar el secret de MFA de un usuario que YA tenia MFA activo sin pedir
ninguna prueba de que quien llamaba controlaba el dispositivo ya enrolado --
alcanzaba con un access_token valido (15 min, robable via XSS/log/dispositivo
prestado) para secuestrar el segundo factor de otra cuenta sin conocer su TOTP
ni su contrasena, y la victima no veia ninguna señal (mfa_enabled seguia en
True todo el tiempo). Ahora re-enrolar exige un TOTP valido del secret actual.

**Otros bugs reales corregidos** (17 en total, detalle completo en el historial
de commits): notas de analista borradas silenciosamente al cambiar el estado de
una alerta SIEM (siem-service); un job de escaneo que quedaba en "running" para
siempre si el driver tiraba una excepcion no prevista (scan-service); un agente
remoto podia pisar el resultado de un job ya terminado (scan-service); un
analyst podia desactivar un activo por PATCH esquivando la restriccion de rol
del DELETE (asset-service); el dashboard ejecutivo mostraba "0 alertas/casos"
en vez de distinguir "vacio" de "servicio caido" (Dashboard.tsx); reabrir un
caso no limpiaba `resolved_at`, dejando metricas de MTTR con datos viejos
(case-service); un ejercicio Purple Team sin tecnicas declaradas calculaba
cobertura contra TODO el catalogo ATT&CK en vez de reportar 0 (purple-service);
registro de acciones de playbook duplicado y desincronizado, le faltaban
`create_ticket`/`notify` a una de las dos copias (soar-service); botones
CSV/PDF de Reportes fallaban en silencio absoluto sin ningun mensaje de error
(Reports.tsx); `HTTPException` no importado en notification-service e
integration-service (un 404 esperado se convertia en 500 sin manejar); registro
exitoso mostrado como fallido si el login automático posterior fallaba
(Login.tsx); formulario de SSO y pantallas de facturacion arrastraban datos de
la organizacion anterior al cambiar de organizacion elegida (Organizations.tsx,
Billing.tsx); mutations sin `onError` en Siem.tsx/Soar.tsx (seedDefaults, panel
de ejecuciones).

**Cosas senaladas pero NO tocadas** (dudas explicitas de los agentes, no
"arregladas a ciegas"): posible condicion de carrera en el hash chain del audit
log de auth-service sin lock a nivel DB; `validate_id_token` (SSO/OIDC) confia
en el `alg` del header del id_token en vez de una whitelist fija (mitigado por
la libreria instalada, pero no es la practica mas correcta); contador
Prometheus `alerts_created_total` que nunca se incrementa de verdad (bug de
observabilidad, no afecta la UI); doble entrada de timeline en cada cambio de
estado de un caso; exportacion XLSX mencionada en el alcance original pero
nunca implementada (solo CSV/PDF) -- gap de alcance, no bug de comportamiento.

Verificacion: 204 tests de pytest (auth 16, asset 11, scan 60, vuln 20, case 15,
integration 8, notification 10, report 14, siem 39, soar 14, purple 11) + 41
tests de vitest + `tsc --noEmit` limpio + `npm run build` exitoso, todo en
verde antes de commitear.

## Nueva funcionalidad: Monitoreo de superficie externa + Inteligencia de amenazas (2026-09-26)

Pedido de Manu: de la lista de 8 funcionalidades nuevas propuestas, arrancar
por "Empresa con el 1 luego 2 luego 3" -- es decir, primero Monitoreo de
superficie externa + Inteligencia de amenazas, despues integraciones cloud
(AWS primero), despues escaneo de codigo/repositorios. El asistente con IA
queda pospuesto: Manu todavia no tiene API key de Anthropic para esa parte.

Se construyeron 2 microservicios nuevos en paralelo (sin superposicion de
archivos: cada uno con su directorio propio + una pagina de frontend nueva
exclusiva; `docker-compose.yml`/`.env.example`/`api.ts`/`types.ts`/
`Layout.tsx`/`App.tsx` quedaron fuera del alcance de ambos agentes y se
consolidaron centralmente despues).

**`threatintel-service` (puerto 8012)**: consulta reputacion de IPs contra
AbuseIPDB (y opcionalmente MISP) con cache de 24hs en `IpReputationCache`
(sin `organization_id` -- la reputacion de una IP es un hecho global, no de
tenant). Sin `ABUSEIPDB_API_KEY` configurada, nunca llama a la API externa
(para no gastar el cupo del free tier, 1000/dia) y devuelve directamente "no
se pudo chequear". `siem-service` ahora enriquece automaticamente cada alerta
nueva: extrae las IPs del evento que la disparo, les pregunta a
threatintel-service (`POST /internal/lookup-batch`, sin auth de usuario --
solo alcanzable dentro de la red interna, mismo patron que el resto de
`/internal/*`), y guarda en `Alert.threat_intel` solo las que resultaron
maliciosas conocidas. Todo con el mismo patron best-effort ya usado para
SOAR (`httpx.HTTPError` atrapado, nunca tumba la ingesta de logs). En el
frontend, la pagina SIEM ahora tiene un buscador manual de IP y una columna/
badge de Threat Intel en la tabla de alertas.

**`asm-service` (puerto 8013)**: monitoreo de superficie externa 100% pasivo
-- sin escaneo activo de puertos en ningun lado. Cada dominio que se agrega
via `POST /domains` se chequea automaticamente cada `ASM_CHECK_INTERVAL_HOURS`
horas (default 12): descubre subdominios nuevos consultando Certificate
Transparency logs (`crt.sh`, solo GET a registros publicos ya existentes) y
lee el certificado TLS de cada host expuesto (handshake estandar al puerto
443, sin validar la cadena, solo para poder leer certificados vencidos o
autofirmados sin que la lectura falle). Genera alertas automaticas
(`SurfaceAlert`) cuando aparece un subdominio nuevo o cuando un certificado
esta vencido o vence en <=7 dias (critico/alto) o <=30 dias (medio), con
cooldown de 24hs para no duplicar la misma alerta. Las alertas de severidad
alta/critica tambien se reenvian a siem-service. Nueva pagina de frontend
"Superficie Externa" (nav, entre Escaneos y Vulnerabilidades): alta de
dominios, tabla de dominios monitoreados con boton "Chequear ahora", tabla de
subdominios descubiertos, tabla de alertas con filtro pendiente/todas.

**Limitaciones conocidas** (documentadas por el equipo que lo construyo, no
son bugs): borrar un dominio monitoreado no borra en cascada sus activos/
alertas historicas (a proposito, para no perder historial); hay una ventana
de carrera sin impacto real si se deshabilita un dominio justo despues de
pedir "chequear ahora"; la lectura de certificados autofirmados/con cadena
rota depende de que el modulo `cryptography` este disponible como fallback
(ya viene instalado transitivamente) -- si fallara, se reporta un error
explicito en vez de fallar mudo.

**Paso manual pendiente para Manu**: conseguir una API key de AbuseIPDB
(gratis, https://www.abuseipdb.com/account/api, 1000 consultas/dia) y
pegarla en `ABUSEIPDB_API_KEY` del `.env` si quiere que threatintel-service
haga chequeos reales -- sin eso, la funcionalidad sigue andando pero siempre
devuelve "no se pudo chequear". MISP es opcional. Como siempre, correr
`docker compose build && docker compose up` para levantar los servicios
nuevos (no se puede correr Docker desde este entorno).

Verificacion antes de commitear: 21 tests nuevos en threatintel-service + 23
en asm-service + 48 en siem-service (40 preexistentes + 8 nuevas de
enriquecimiento), todos funciones puras sin I/O real; import de humo de
`app.main` en ambos servicios nuevos (rutas registradas OK); 41 tests de
vitest + `tsc --noEmit` limpio + `npm run build` exitoso en el frontend
completo.

## Nueva funcionalidad: Integraciones cloud, AWS (2026-09-26)

Segunda de las 8 funcionalidades pedidas por Manu, priorizada como #2 ("Empresa
con el 1 luego 2 luego 3", ya con superficie externa + threat intel hechos).
AWS primero (Azure/GCP quedan para mas adelante, no se tocan en este cambio).

**`cloud-service` (puerto 8014)**: trae automaticamente el inventario de una
cuenta de AWS (instancias EC2, buckets S3, security groups) en lugar de
cargarlo a mano, y detecta configuraciones peligrosas: buckets S3 publicos y
security groups con puertos abiertos a `0.0.0.0/0`. 100% de solo lectura hacia
AWS -- todas las llamadas son `Describe*`/`List*`/`Get*`, nunca se crea,
modifica ni borra nada en la cuenta del cliente. Sync automatico cada
`CLOUD_SYNC_INTERVAL_HOURS` horas (default 6) sobre todas las cuentas
habilitadas de todas las organizaciones; una cuenta con credenciales invalidas
o una llamada que falla (ej. `AccessDenied` en un bucket puntual) nunca frena
el sync del resto.

Las credenciales de AWS (`access_key_id`/`secret_access_key`) se cifran en la
base con el mismo mecanismo ya usado para SSO/conectores
(`backend/shared/crypto.py`, Fernet derivado de `ENCRYPTION_KEY`) y nunca se
devuelven por la API en texto plano ni cifradas -- solo una version enmascarada
del access key (`AKIA...WXYZ`). Los hallazgos de severidad alta/critica se
reenvian a siem-service con el mismo patron best-effort ya usado por
asm-service/scan-service.

Nueva pagina de frontend "Integraciones Cloud" (nav, junto a "Superficie
Externa"): conectar cuenta de AWS (con la politica IAM de solo lectura exacta
documentada en el formulario), tabla de cuentas conectadas con estado del
ultimo sync y boton "Sincronizar ahora", tabla de recursos descubiertos, tabla
de hallazgos peligrosos con filtro pendiente/todos y boton "Reconocer".

**Paso manual pendiente para Manu**: crear en AWS un usuario/rol IAM de SOLO
LECTURA con esta politica exacta (ver comentario completo en `.env.example`):
`ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `s3:ListAllMyBuckets`,
`s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`, `s3:GetPublicAccessBlock`,
`s3:GetBucketLocation` -- y despues conectar esa cuenta desde la pagina
"Integraciones Cloud" (las credenciales se configuran ahi, nunca por variable
de entorno). Como siempre, correr `docker compose build && docker compose up`
para levantar el servicio nuevo (no se puede correr Docker desde este
entorno).

Verificacion antes de commitear: 30 tests nuevos en cloud-service (funciones
puras, sin boto3/red/DB real) + 41 tests de vitest (sin cambios, no se tocaron
utils) + `tsc --noEmit` limpio + `npm run build` exitoso en el frontend
completo.

## Nueva funcionalidad: Escaneo de código y repositorios (2026-09-26)

Tercera de las 8 funcionalidades pedidas por Manu, priorizada como #3
(superficie externa/threat intel y cloud AWS ya hechas). Detecta contraseñas
o claves subidas por error a un repositorio de código y dependencias
vulnerables en el codigo, tal como se pidio.

**`coderepo-service` (puerto 8015)**: el usuario registra un repositorio
(URL HTTPS + rama + token opcional para repos privados). Un scheduler
periodico (cada `CODEREPO_SCAN_INTERVAL_HOURS` horas, default 24) y un boton
"Escanear ahora" clonan el repositorio COMPLETO (con todo el historial de
git, no solo el checkout actual -- un secreto commiteado por error y borrado
despues sigue expuesto en el historial) y corren dos herramientas
especializadas:

- **gitleaks**: revisa todo el historial de git buscando contraseñas, claves
  privadas, tokens de AWS/GCP/Azure/GitHub, etc. Los hallazgos se guardan en
  `coderepo-service` con severidad (`critical`/`high`/`medium` segun el tipo
  de regla) -- el valor real del secreto NUNCA se guarda ni se muestra, solo
  una version parcialmente oculta (ej `AKI••••••••••••WXYZ`).
- **trivy fs**: revisa manifiestos de dependencias (package-lock.json,
  requirements.txt, go.mod, etc.) contra la base de CVEs conocidas -- misma
  herramienta que ya usa scan-service para imagenes de contenedor, pero con
  su propia cache de DB separada (`coderepo_trivy_cache`, nunca comparte
  volumen con scan-service). Estos hallazgos se reenvian directamente a
  vuln-service (aparecen mezclados en la seccion Vulnerabilidades ya
  existente, no se duplican en una tabla nueva).

Es de solo lectura/analisis en todo momento: nunca se escribe nada en el
repositorio del cliente ni se ejecuta codigo del repositorio (nunca se corre
`npm install`, un build, un test, ni se importa nada de lo clonado). El
token de GitHub de un repo privado se cifra con el mismo mecanismo ya usado
para SSO/AWS (`backend/shared/crypto.py`) y nunca se devuelve por la API.

Nueva pagina de frontend "Código y Repositorios" (nav, junto a
"Integraciones Cloud"): alta de repositorio, tabla de repositorios con
estado del ultimo escaneo y contadores de secretos/vulnerabilidades
encontradas (con link directo a Vulnerabilidades), tabla de secretos
encontrados con filtro pendiente/todos y boton "Reconocer".

**Paso manual pendiente para Manu**: ninguno especial mas alla de
`docker compose build && docker compose up` -- gitleaks/trivy/git se
instalan solos en la imagen del servicio nuevo. Para repos privados, generar
un token de acceso personal de solo lectura (GitHub: "read-only, contents")
y pegarlo al conectar el repositorio desde la pagina.

Verificacion antes de commitear: 46 tests nuevos en coderepo-service
(funciones puras, sin git/gitleaks/trivy/red/DB real) + 41 tests de vitest
(sin cambios) + `tsc --noEmit` limpio + `npm run build` exitoso en el
frontend completo.

## Resultados de escaneos legibles: criticidad y remediacion a la vista (2026-09-27)

Manu pidio que los resultados de los escaneos se vean "de forma completa",
"facilmente legible", con criticidad asignada y medidas de remediacion. Al
revisar el codigo, `vuln-service` ya calculaba todo eso desde hace tiempo
(severidad, CVSS, EPSS, si esta en CISA KEV, un `priority_score` combinado,
y hasta pasos de remediacion sugeridos por regla en
`app/remediation.py`) -- la brecha real era que el frontend no lo mostraba
donde el usuario lo esperaba. No se duplico logica de remediacion en el
cliente: se reuso `vuln-service` como fuente unica de verdad.

- **`vuln-service`**: se agrego un filtro opcional `scan_job_id` a
  `GET /vulnerabilities` (`app/main.py` + `app/services.py`) para poder
  pedir "los hallazgos de ESTE escaneo puntual" sin tocar el modelo de
  datos. Ojo (documentado como comentario en el codigo): si el mismo activo
  se volvio a escanear despues, `ingest_findings` reasigna el
  `scan_job_id` de una vulnerabilidad al escaneo MAS RECIENTE que la toco
  -- este filtro muestra el estado actual de esas vulnerabilidades, no
  necesariamente los hallazgos crudos de un escaneo viejo si hubo un
  rescan.
- **Pagina "Escaneos"**: cada escaneo (tanto en "Escaneos realizados" como
  en "Escaneos remotos") tiene ahora un boton "Ver resultados" que despliega,
  sin salir de la pagina, cada hallazgo con su badge de severidad, CVE,
  paquete/version instalada -> version corregida (si aplica), puerto/servicio
  (si aplica), descripcion, y la lista de pasos de remediacion sugeridos. Si
  el escaneo fallo se muestra el motivo del error en vez de una tabla vacia;
  si todavia esta en curso, se avisa que los resultados van a aparecer solos
  cuando termine.
- **Pagina "Vulnerabilidades"**: se agregaron filtros por severidad y por
  estado (los resuelve el backend, via los mismos parametros que ya
  soportaba `GET /vulnerabilities`) mas una busqueda de texto libre por
  titulo/CVE/paquete (del lado del cliente, sobre el resultado ya filtrado).
  El detalle expandido de cada fila ahora tambien muestra la descripcion
  completa y tarjetas de paquete/puerto/origen antes de los pasos de
  remediacion (que ya existian). Se agregaron tarjetas de resumen para
  Criticas y Altas en la parte superior.

Verificacion antes de commitear: los 20 tests existentes de vuln-service
siguen en verde (pytest), import-sanity de `app.main` confirmando que las
rutas quedan bien registradas, `tsc --noEmit` limpio y `npm run build`
exitoso en el frontend completo.

**Paso manual pendiente para Manu**: solo hace falta reconstruir
`vuln-service` y `frontend` (no todo el stack) --
`docker compose build vuln-service frontend` y despues
`docker compose up -d vuln-service frontend`.

## Cancelar escaneos en curso + aviso de aislamiento de red LAN en Docker (2026-09-27)

Manu reporto que sus escaneos nmap de LAN (ej. 192.168.x.x) siempre terminan
en el timeout de 180s, y pidio poder cancelar un escaneo que quedo
"running". Dos cosas separadas, ambas resueltas:

- **Cancelar un escaneo pending/running**: nuevo endpoint
  `POST /scans/{id}/cancel` en `scan-service`. Cada corrida de
  `execute_scan_job` se auto-registra (via `asyncio.current_task()`) en un
  registro en memoria (`_RUNNING_SCAN_TASKS`, un solo dict de proceso --
  mismo supuesto que ya usa el scheduler de `ScanSchedule`) mientras corre;
  cancelar le pide `Task.cancel()` a esa tarea, y cada driver
  (nmap/trivy/nuclei/openvas) atrapa el `CancelledError` resultante para
  matar el subproceso en curso (nmap/trivy/nuclei) antes de re-lanzarlo --
  sin esto, el binario seguia corriendo huerfano dentro del contenedor
  aunque el job ya quedara marcado como cancelado, igual que ya pasaba con
  el timeout. El driver de OpenVAS es un caso especial: el escaneo real lo
  corre gvmd/ospd-openvas del otro lado del socket, no un subproceso local
  nuestro, asi que ademas se le manda un `stop_task` GMP best-effort al
  task remoto para no dejarlo corriendo huerfano ahi tambien. Si no hay
  ninguna tarea viva registrada para ese job (por ejemplo, quedo "running"
  huerfano de un reinicio del contenedor), se marca cancelado directamente
  en la DB -- no hay nada que matar. Nuevo estado `cancelled` en
  `ScanStatus`, cuenta como estado terminal (se puede borrar despues, igual
  que completed/failed/scanner_unavailable). En el frontend, cada fila de
  "Escaneos realizados" en estado pending/running ahora tiene un boton
  "Cancelar".
- **Aviso de aislamiento de red antes de escanear, no despues de esperar
  180s**: el timeout de nmap contra un rango LAN/oficina no es un bug --
  Docker Desktop aisla al contenedor de `scan-service` detras de NAT, y no
  hay forma confiable de darle acceso real a la LAN de la PC desde ahi
  (`network_mode: host` en Docker Desktop para Windows/Mac no expone la
  LAN real del host como en Linux nativo). La solucion real a esto ya
  existia en el producto -- el agente de "Escaneos remotos" corre FUERA de
  Docker y si llega a la LAN -- pero el usuario solo se entraba de la
  limitacion despues de esperar el timeout completo. Se agrego un aviso
  visible en el formulario "Nuevo escaneo" en cuanto se elige ambito LAN o
  MAN, explicando el aislamiento de Docker y señalando directamente a
  "Escaneos remotos" como la forma correcta de escanear la red real.

Verificacion antes de commitear: 68 tests en scan-service (62 existentes +
6 nuevos de la logica de cancelacion, sin DB ni drivers reales) todos en
verde, import-sanity de `app.main` confirmando que `POST /scans/{id}/cancel`
queda bien registrado, `tsc --noEmit` limpio y `npm run build` exitoso en
el frontend completo.

**Paso manual pendiente para Manu**: solo hace falta reconstruir
`scan-service` y `frontend` -- `docker compose build scan-service frontend`
y despues `docker compose up -d scan-service frontend`. Nota: cancelar un
escaneo de agente remoto ("Escaneos remotos") todavia no esta soportado --
esos corren en `remote-agent/agent.py`, un proceso aparte que hace polling,
y cancelarlos requeriria cambiar ese protocolo. Quedo fuera de esta corrida.
