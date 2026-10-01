"""Driver de Nmap: descubrimiento de hosts/puertos/servicios y deteccion de
version (-sV) + scripts de deteccion segura (-sC, categoria 'default' y
'safe'). NUNCA se ejecuta con --script vuln en modo exploit ni con scripts
de la categoria 'exploit'/'intrusive'.

Soporta dos modos via options['mode']:
  - 'full' (default, comportamiento historico): -sV -sC --script default,safe,
    --host-timeout 30s, timeout total de proceso 180s. Mas lento pero mas
    completo -- deteccion de version + scripts NSE seguros sobre 1000 puertos
    (top-1000 default de nmap si no se especifica -p/--top-ports).
  - 'fast': sin -sC/--script (elimina el mayor costo de tiempo), -sV se
    mantiene, --top-ports 100 si el usuario no especifico puertos/--top-ports
    propios, --host-timeout mas corto (10s) y timeout total de proceso mas
    corto (60s). Pensado para un primer pantallazo rapido.
"""
import asyncio
import xml.etree.ElementTree as ET
from app.scanners.base import ScannerDriver, ScanResult

# Flags permitidos explicitamente. Cualquier opcion fuera de esta lista se
# ignora: evita que un `options` arbitrario inyecte flags de explotacion.
_ALLOWED_EXTRA_FLAGS = {"-p", "-Pn", "-6", "--top-ports"}

_FAST_HOST_TIMEOUT = "10s"
_FAST_PROC_TIMEOUT = 60
_FULL_HOST_TIMEOUT = "30s"
_FULL_PROC_TIMEOUT = 180


def _build_nmap_cmd(target: str, options: dict) -> tuple[list[str], int, str]:
    """Construye el comando de nmap y el timeout de proceso segun el modo.
    Funcion pura (sin I/O) para poder testearla sin ejecutar nmap de verdad."""
    mode = options.get("mode") if options.get("mode") in ("fast", "full") else "full"
    ports = options.get("ports")
    has_explicit_ports = isinstance(ports, str) and ports.replace(",", "").replace("-", "").isdigit()

    if mode == "fast":
        # -T5 (el timing mas agresivo de nmap) + sin -sC/--script: el
        # costo de los scripts NSE (aun los 'safe') es lo que mas
        # tarda en escaneos de red completos. -sV se mantiene porque
        # es relativamente barato y da informacion util (que servicio
        # corre en cada puerto abierto).
        cmd = ["nmap", "-T5", "--host-timeout", _FAST_HOST_TIMEOUT, "-sV", "-oX", "-", target]
        if has_explicit_ports:
            cmd[1:1] = ["-p", ports]
        else:
            # Sin puertos explicitos, limitamos a los 100 mas comunes
            # en vez del top-1000 default -- reduce drasticamente el
            # tiempo sin perder los servicios mas relevantes.
            cmd[1:1] = ["--top-ports", "100"]
        return cmd, _FAST_PROC_TIMEOUT, mode

    # -T4 (timing agresivo) y --host-timeout acotan cuanto se puede
    # tardar un host que no responde -- sin esto, escanear un rango
    # /24 entero donde casi nada contesta (tipico si el rango no es
    # realmente accesible desde este contenedor, ver nota mas abajo)
    # podia comerse el timeout entero de 600s por cada host lento en
    # vez de descartarlo rapido y seguir.
    cmd = [
        "nmap", "-T4", "--host-timeout", _FULL_HOST_TIMEOUT,
        "-sV", "-sC", "--script", "default,safe", "-oX", "-", target,
    ]
    if has_explicit_ports:
        cmd[1:1] = ["-p", ports]
    return cmd, _FULL_PROC_TIMEOUT, mode


class NmapDriver(ScannerDriver):
    binary_name = "nmap"

    async def run(self, target: str, options: dict) -> ScanResult:
        cmd, proc_timeout, mode = _build_nmap_cmd(target, options)

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=proc_timeout)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="nmap no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            # Sin este kill(), el proceso de nmap sigue corriendo en
            # segundo plano dentro del contenedor aunque el job ya haya
            # quedado marcado como fallido -- no rompe nada, pero
            # desperdicia CPU indefinidamente en cada timeout.
            proc.kill()
            await proc.wait()
            return ScanResult(
                raw_output="",
                error=(
                    f"timeout de escaneo ({proc_timeout}s, modo {mode}) -- si el target es un rango de LAN/oficina "
                    "(ej. 192.168.x.x), recorda que este escaneo corre DENTRO del contenedor "
                    "Docker, no en la red real de la PC: Docker Desktop aisla al contenedor "
                    "detras de NAT, asi que no llega a los dispositivos de tu LAN salvo que "
                    "el propio Docker corra con acceso a esa red -- usa 'Escaneos remotos' "
                    "con un agente para escanear la LAN real."
                ),
            )
        except asyncio.CancelledError:
            # El usuario cancelo el escaneo desde la UI (POST
            # /scans/{id}/cancel). Igual que en el timeout: sin este kill(),
            # nmap sigue corriendo huerfano dentro del contenedor aunque el
            # job ya haya quedado marcado como cancelado. Se relanza para
            # que execute_scan_job se entere y escriba el estado final.
            if proc is not None:
                proc.kill()
                await proc.wait()
            raise

        raw = stdout.decode(errors="replace")
        if proc.returncode != 0:
            return ScanResult(raw_output=raw, error=stderr.decode(errors="replace")[:2000])

        return ScanResult(raw_output=raw, findings=_parse_nmap_xml(raw))


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else "desconocido"
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            svc_name = service.get("name", "") if service is not None else ""
            svc_product = service.get("product", "") if service is not None else ""
            svc_version = service.get("version", "") if service is not None else ""
            findings.append(
                {
                    "title": f"Puerto abierto {port.get('portid')}/{port.get('protocol')} ({svc_name}) en {address}",
                    "description": f"{svc_product} {svc_version}".strip(),
                    "severity": "info",
                    "port": int(port.get("portid")),
                    "service": svc_name,
                }
            )
    return findings
