"""Driver de OpenVAS/GVM: escaneo real de vulnerabilidades via Greenbone
Vulnerability Management (protocolo GMP), en modo deteccion (el motor
openvas-scanner/ospd-openvas corre NVTs de deteccion, nunca payloads de
explotacion activa).

Requiere el stack de GVM (gvmd + ospd-openvas + su propia base de datos y
feed de NVTs, ver docker-compose.yml seccion "OpenVAS/GVM") accesible via
el socket unix de gvmd, y credenciales GMP (GVM_USER/GVM_PASSWORD, ver
.env.example -- se crean con el comando de bootstrap documentado en
README.md/STATUS.md). Si el binario gvm-cli no esta instalado o no hay
credenciales configuradas, el driver reporta 'scanner_unavailable' /
un error claro en vez de fallar silenciosamente.

Flujo GMP real (a diferencia de la version anterior de este driver, que
solo hacia una consulta `get_vulns` sin autenticar y sin disparar ningun
escaneo):
  1. Descubre dinamicamente scanner_id / config_id / port_list_id via
     get_scanners / get_configs / get_port_lists, en vez de hardcodear
     UUIDs "bien conocidos" -- esos UUIDs pueden faltar en instalaciones
     nuevas o de arquitectura dividida (ospd-openvas) como esta (ver
     https://github.com/admirito/gvm-containers/issues/60).
  2. create_target -> create_task -> start_task.
  3. Poll de get_tasks hasta que el status sea terminal (Done/Stopped/
     Interrupted) o se agote GVM_SCAN_TIMEOUT_SECONDS.
  4. get_results del task para traer los hallazgos.
"""
import asyncio
import os
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape
from app.scanners.base import ScannerDriver, ScanResult

_SEVERITY_THRESHOLDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)

# Preferencias de nombre para el descubrimiento dinamico (en orden). Si
# ninguna preferencia matchea, se usa el primer item devuelto por gvmd --
# mejor un escaneo con la config/scanner/port_list "que sea" que fallar
# el job por completo.
_CONFIG_NAME_PREFERENCES = ("full and fast",)
_SCANNER_NAME_PREFERENCES = ("openvas default", "openvas")
_PORT_LIST_NAME_PREFERENCES = ("all iana assigned tcp and udp", "all iana assigned tcp", "all tcp")

_TERMINAL_TASK_STATUSES = {"Done", "Stopped", "Interrupted"}
_DEFAULT_POLL_INTERVAL = 15
_DEFAULT_SCAN_TIMEOUT = int(os.getenv("GVM_SCAN_TIMEOUT_SECONDS", "1500"))


def _severity_from_cvss(cvss: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if cvss >= threshold:
            return label
    return "info"


def _gvm_cmd(socket_path: str, user: str, password: str, xml: str) -> list[str]:
    """Funcion pura: construye el comando gvm-cli. Las credenciales van
    como flags globales -- gvm-cli se autentica solo, sin necesidad de
    mandar un <authenticate/> manual."""
    return [
        "gvm-cli", "--gmp-username", user, "--gmp-password", password,
        "socket", "--socketpath", socket_path, "--xml", xml,
    ]


def _find_id_by_name(xml_text: str, item_tag: str, preferences: tuple[str, ...]) -> str | None:
    """Busca en una respuesta get_configs/get_scanners/get_port_lists el id
    del item cuyo <name> matchea (case-insensitive, substring) alguna de
    las preferencias en orden; si ninguna matchea, devuelve el primer id
    disponible. None si la lista viene vacia o el XML es invalido."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    items = []
    for item in root.findall(f".//{item_tag}"):
        item_id = item.get("id")
        name_el = item.find("name")
        name = name_el.text if name_el is not None and name_el.text else ""
        if item_id:
            items.append((item_id, name))

    if not items:
        return None

    for pref in preferences:
        for item_id, name in items:
            if pref in name.lower():
                return item_id

    return items[0][0]


def _parse_response_id(xml_text: str) -> str | None:
    """Los *_response de gvm-cli (create_target_response, create_task_response)
    traen el id del recurso creado como atributo del elemento raiz."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    return root.get("id") or None


def _response_status_ok(xml_text: str) -> bool:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    status = root.get("status") or ""
    return status.startswith("2")


def _build_create_target_xml(name: str, hosts: str, port_list_id: str) -> str:
    return (
        f"<create_target><name>{_xml_escape(name)}</name>"
        f"<hosts>{_xml_escape(hosts)}</hosts>"
        f"<port_list id='{port_list_id}'/></create_target>"
    )


def _build_create_task_xml(name: str, target_id: str, config_id: str, scanner_id: str) -> str:
    return (
        f"<create_task><name>{_xml_escape(name)}</name>"
        f"<target id='{target_id}'/><config id='{config_id}'/>"
        f"<scanner id='{scanner_id}'/></create_task>"
    )


def _parse_task_status(xml_text: str) -> tuple[str, int] | None:
    """Parsea la respuesta de get_tasks (con un solo <task/>, filtrado por
    id) y devuelve (status, progress). None si no se pudo parsear."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    task = root.find(".//task")
    if task is None:
        return None
    status_el = task.find("status")
    progress_el = task.find("progress")
    status = status_el.text if status_el is not None and status_el.text else "Unknown"
    try:
        progress = int(progress_el.text) if progress_el is not None and progress_el.text else 0
    except ValueError:
        progress = 0
    return status, progress


def _parse_gmp_results(xml_text: str) -> list[dict]:
    """Parsea una respuesta get_results (findall .//result) a la forma
    comun de findings del proyecto."""
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for result in root.findall(".//result"):
        name_el = result.find("name")
        severity_el = result.find("severity")
        host_el = result.find("host")
        port_el = result.find("port")
        desc_el = result.find("description")
        nvt_el = result.find("nvt")
        cve_el = nvt_el.find("cve") if nvt_el is not None else None
        try:
            cvss = float(severity_el.text) if severity_el is not None and severity_el.text else 0.0
        except ValueError:
            cvss = 0.0
        host = host_el.text if host_el is not None and host_el.text else ""
        findings.append(
            {
                "title": name_el.text if name_el is not None and name_el.text else "hallazgo OpenVAS",
                "description": (desc_el.text or "")[:1000] if desc_el is not None else "",
                "severity": _severity_from_cvss(cvss),
                "cve_id": cve_el.text if cve_el is not None and cve_el.text and cve_el.text != "NOCVE" else None,
                "service": f"{host}:{port_el.text}" if port_el is not None and port_el.text else host or None,
            }
        )
    return findings


class OpenVasDriver(ScannerDriver):
    binary_name = "gvm-cli"

    async def run(self, target: str, options: dict) -> ScanResult:
        if not self.is_available():
            return ScanResult(
                raw_output="",
                error="gvm-cli no esta disponible en este contenedor (falta el paquete gvm-tools). "
                "El job queda marcado como scanner_unavailable.",
            )

        socket_path = options.get("gvm_socket") or os.getenv("GVM_SOCKET_PATH") or "/run/gvmd/gvmd.sock"
        user = options.get("gvm_user") or os.getenv("GVM_USER") or ""
        password = options.get("gvm_password") or os.getenv("GVM_PASSWORD") or ""
        if not user or not password:
            return ScanResult(
                raw_output="",
                error="Faltan credenciales GMP (GVM_USER/GVM_PASSWORD). Corre el bootstrap de gvmd "
                "documentado en README.md/STATUS.md y completa esas variables en .env.",
            )

        async def gvm_query(xml: str, timeout: int = 60) -> tuple[int, str, str]:
            cmd = _gvm_cmd(socket_path, user, password, xml)
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except FileNotFoundError:
                return -1, "", "gvm-cli no esta instalado en este contenedor"
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return -1, "", f"timeout ({timeout}s) hablando con gvmd"
            except asyncio.CancelledError:
                # Ver nmap.py: mata el gvm-cli que estaba esperando en vez de
                # dejarlo huerfano. Esto NO detiene el escaneo del lado de
                # gvmd/ospd-openvas -- eso lo maneja el except de mas abajo
                # (best-effort stop_task).
                if proc is not None:
                    proc.kill()
                    await proc.wait()
                raise
            return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

        # task_id se completa en el paso 2 -- se declara antes del try para
        # que el except CancelledError de mas abajo sepa si ya existe un
        # task GVM real corriendo (y haya que pedirle stop_task) o si la
        # cancelacion llego antes de crear ninguno.
        task_id: str | None = None
        try:
            # -- 1. Descubrimiento dinamico de config/scanner/port_list ----
            rc, out, err = await gvm_query("<get_configs/>")
            if rc != 0:
                return ScanResult(raw_output=out, error=f"no se pudo consultar get_configs: {err[:1000]}")
            config_id = _find_id_by_name(out, "config", _CONFIG_NAME_PREFERENCES)

            rc, out, err = await gvm_query("<get_scanners/>")
            if rc != 0:
                return ScanResult(raw_output=out, error=f"no se pudo consultar get_scanners: {err[:1000]}")
            scanner_id = _find_id_by_name(out, "scanner", _SCANNER_NAME_PREFERENCES)

            rc, out, err = await gvm_query("<get_port_lists/>")
            if rc != 0:
                return ScanResult(raw_output=out, error=f"no se pudo consultar get_port_lists: {err[:1000]}")
            port_list_id = _find_id_by_name(out, "port_list", _PORT_LIST_NAME_PREFERENCES)

            if not (config_id and scanner_id and port_list_id):
                return ScanResult(
                    raw_output="",
                    error=(
                        "gvmd no tiene configuradas las entidades minimas para escanear "
                        f"(config={config_id}, scanner={scanner_id}, port_list={port_list_id}). "
                        "Puede que el feed de NVTs todavia no termino de sincronizar la primera vez "
                        "-- ver README.md/STATUS.md sobre el tiempo de sincronizacion inicial."
                    ),
                )

            # -- 2. create_target / create_task / start_task ----------------
            task_name = f"sentinelops-{target}-{int(time.time())}"
            rc, out, err = await gvm_query(_build_create_target_xml(task_name, target, port_list_id))
            if rc != 0 or not _response_status_ok(out):
                return ScanResult(raw_output=out, error=f"no se pudo crear el target GVM: {err[:1000] or out[:1000]}")
            target_id = _parse_response_id(out)
            if not target_id:
                return ScanResult(raw_output=out, error="create_target no devolvio un id de target")

            rc, out, err = await gvm_query(_build_create_task_xml(task_name, target_id, config_id, scanner_id))
            if rc != 0 or not _response_status_ok(out):
                return ScanResult(raw_output=out, error=f"no se pudo crear el task GVM: {err[:1000] or out[:1000]}")
            task_id = _parse_response_id(out)
            if not task_id:
                return ScanResult(raw_output=out, error="create_task no devolvio un id de task")

            rc, out, err = await gvm_query(f"<start_task task_id='{task_id}'/>")
            if rc != 0:
                return ScanResult(raw_output=out, error=f"no se pudo iniciar el task GVM: {err[:1000]}")

            # -- 3. Poll hasta terminal o timeout ----------------------------
            deadline = time.monotonic() + _DEFAULT_SCAN_TIMEOUT
            last_status, last_progress = "Requested", 0
            while time.monotonic() < deadline:
                await asyncio.sleep(_DEFAULT_POLL_INTERVAL)
                rc, out, err = await gvm_query(f"<get_tasks task_id='{task_id}'/>")
                if rc != 0:
                    continue  # error transitorio consultando estado -- reintenta en el proximo ciclo
                parsed = _parse_task_status(out)
                if parsed is None:
                    continue
                last_status, last_progress = parsed
                if last_status in _TERMINAL_TASK_STATUSES:
                    break
            else:
                return ScanResult(
                    raw_output="",
                    error=(
                        f"timeout esperando que termine el escaneo GVM ({_DEFAULT_SCAN_TIMEOUT}s, "
                        f"ultimo estado visto: {last_status} {last_progress}%). El escaneo puede seguir "
                        "corriendo en gvmd -- subir GVM_SCAN_TIMEOUT_SECONDS si el target es grande."
                    ),
                )

            if last_status != "Done":
                return ScanResult(raw_output="", error=f"el escaneo GVM termino en estado '{last_status}', no 'Done'")

            # -- 4. get_results -----------------------------------------------
            rc, out, err = await gvm_query(f"<get_results task_id='{task_id}' filter='rows=1000'/>", timeout=120)
            if rc != 0:
                return ScanResult(raw_output=out, error=f"no se pudieron obtener los resultados: {err[:1000]}")

            return ScanResult(raw_output=out, findings=_parse_gmp_results(out))
        except asyncio.CancelledError:
            # A diferencia de nmap/trivy/nuclei (un solo subproceso local
            # nuestro), aca el escaneo real lo corre gvmd/ospd-openvas del
            # otro lado del socket -- matar el gvm-cli que estaba esperando
            # (ya lo hizo gvm_query arriba) NO detiene ese escaneo remoto.
            # Si ya se llego a crear un task GVM, se le pide stop_task
            # best-effort antes de propagar la cancelacion, para no dejar
            # un escaneo real corriendo en gvmd huerfano de un job que en
            # nuestra DB ya va a quedar 'cancelled'. Nunca debe tapar el
            # CancelledError original: cualquier error de esta limpieza
            # solo se ignora.
            if task_id:
                try:
                    await gvm_query(f"<stop_task task_id='{task_id}'/>", timeout=15)
                except Exception:  # noqa: BLE001 -- best-effort
                    pass
            raise
