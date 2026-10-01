"""Driver de Trivy: analisis de vulnerabilidades conocidas (CVE) en imagenes
de contenedor, sistemas de archivos y manifiestos de dependencias. Es
puramente de deteccion: compara paquetes instalados contra bases de datos
de CVEs publicas, nunca ejecuta codigo contra el objetivo.

La base de datos de CVEs se descarga UNA VEZ al construir la imagen
(ver Dockerfile: `trivy image --download-db-only`) y se persiste despues
en el volumen nombrado `trivy_cache` (ver docker-compose.yml) montado en
TRIVY_CACHE_DIR. Un job periodico (ver app/services.py::refresh_trivy_db,
registrado en app/main.py) la refresca en segundo plano cada 24hs. Por
eso cada escaneo individual corre con --skip-db-update: sin esto, Trivy
intentaba bajar la DB completa (varios cientos de MB) en CADA escaneo,
que era la causa principal de que trivy "tardara mucho"."""
import asyncio
import json
import os
from app.scanners.base import ScannerDriver, ScanResult

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

TRIVY_CACHE_DIR = os.getenv("TRIVY_CACHE_DIR", "/root/.cache/trivy")


def _build_trivy_cmd(target: str, options: dict, cache_dir: str = TRIVY_CACHE_DIR) -> list[str]:
    """Funcion pura (sin I/O) para poder testear la construccion del comando
    sin ejecutar trivy de verdad."""
    mode = options.get("mode", "image")
    subcommand = "fs" if mode == "fs" else "image"
    return [
        "trivy", subcommand,
        "--format", "json", "--quiet", "--timeout", "8m",
        "--cache-dir", cache_dir,
        "--skip-db-update", "--skip-java-db-update",
        target,
    ]


class TrivyDriver(ScannerDriver):
    binary_name = "trivy"

    async def run(self, target: str, options: dict) -> ScanResult:
        cmd = _build_trivy_cmd(target, options)

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=540)
        except FileNotFoundError:
            return ScanResult(raw_output="", error="trivy no esta instalado en este contenedor")
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ScanResult(raw_output="", error="timeout de escaneo (540s)")
        except asyncio.CancelledError:
            # Ver nmap.py: sin este kill(), trivy sigue corriendo huerfano
            # dentro del contenedor aunque el job ya haya quedado cancelado.
            if proc is not None:
                proc.kill()
                await proc.wait()
            raise

        raw = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        if proc.returncode not in (0, 1):
            if "--skip-db-update" in err or "database is not initialized" in err.lower() or "no such file" in err.lower():
                # La cache esta vacia (primer arranque antes de que corra
                # el refresh periodico, o volumen recien creado) --
                # reintentamos una sola vez permitiendo que trivy baje la
                # DB, en vez de fallar el escaneo directamente.
                fallback_cmd = [c for c in cmd if c not in ("--skip-db-update", "--skip-java-db-update")]
                proc2 = None
                try:
                    proc2 = await asyncio.create_subprocess_exec(
                        *fallback_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    stdout2, stderr2 = await asyncio.wait_for(proc2.communicate(), timeout=540)
                except asyncio.TimeoutError:
                    proc2.kill()
                    await proc2.wait()
                    return ScanResult(raw_output="", error="timeout de escaneo (540s, incluyo descarga inicial de la DB)")
                except asyncio.CancelledError:
                    if proc2 is not None:
                        proc2.kill()
                        await proc2.wait()
                    raise
                raw2 = stdout2.decode(errors="replace")
                if proc2.returncode not in (0, 1):
                    return ScanResult(raw_output=raw2, error=stderr2.decode(errors="replace")[:2000])
                return ScanResult(raw_output=raw2, findings=_parse_trivy_json(raw2))
            return ScanResult(raw_output=raw, error=err[:2000])

        return ScanResult(raw_output=raw, findings=_parse_trivy_json(raw))


def _parse_trivy_json(raw_json: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(raw_json) if raw_json.strip() else {}
    except json.JSONDecodeError:
        return findings

    for result in data.get("Results", []) or []:
        target_name = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "title": f"{vuln.get('VulnerabilityID', 'CVE-desconocido')} en {vuln.get('PkgName', '')} ({target_name})",
                    "description": (vuln.get("Title") or vuln.get("Description") or "")[:1000],
                    "severity": _SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info"),
                    "cve_id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                }
            )
    return findings
