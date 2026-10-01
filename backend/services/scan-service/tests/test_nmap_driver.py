"""Tests para app/scanners/nmap.py::_parse_nmap_xml (normalizacion de la
salida XML de nmap a findings), sin ejecutar nmap de verdad -- se le pasa
un XML de ejemplo tal como lo devolveria `nmap -oX -`."""
from app.scanners.nmap import _ALLOWED_EXTRA_FLAGS, _build_nmap_cmd, _parse_nmap_xml

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="192.168.1.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="filtered"/>
        <service name="ms-wbt-server"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_only_open_ports_are_reported():
    findings = _parse_nmap_xml(_SAMPLE_XML)
    ports_found = {f["port"] for f in findings}
    assert ports_found == {22, 443}  # 80 (closed) y 3389 (filtered) quedan afuera


def test_finding_shape_and_content():
    findings = _parse_nmap_xml(_SAMPLE_XML)
    ssh_finding = next(f for f in findings if f["port"] == 22)
    assert ssh_finding["service"] == "ssh"
    assert "OpenSSH" in ssh_finding["description"]
    assert "192.168.1.10" in ssh_finding["title"]
    assert ssh_finding["severity"] == "info"  # descubrimiento, no vulnerabilidad


def test_host_with_no_open_ports_contributes_nothing():
    findings = _parse_nmap_xml(_SAMPLE_XML)
    assert not any("192.168.1.11" in f["title"] for f in findings)


def test_malformed_xml_returns_empty_list_not_exception():
    assert _parse_nmap_xml("esto no es xml valido <<<") == []


def test_empty_xml_returns_empty_list():
    assert _parse_nmap_xml("<nmaprun></nmaprun>") == []


def test_allowed_extra_flags_excludes_exploitation_related_flags():
    # Guardrail de alcance: ninguno de los flags permitidos por el driver
    # debe habilitar categorias de scripts de explotacion (ver docstring
    # del modulo y docs/architecture.md 'Fuera de alcance'). Si alguien
    # agrega '--script' o similar a este set en el futuro, este test debe
    # fallar y llamar la atencion sobre ese cambio.
    assert _ALLOWED_EXTRA_FLAGS == {"-p", "-Pn", "-6", "--top-ports"}
    assert "--script" not in _ALLOWED_EXTRA_FLAGS


def test_build_cmd_full_mode_default_keeps_historic_behavior():
    cmd, timeout, mode = _build_nmap_cmd("10.0.0.5", {})
    assert mode == "full"
    assert cmd == ["nmap", "-T4", "--host-timeout", "30s", "-sV", "-sC", "--script", "default,safe", "-oX", "-", "10.0.0.5"]
    assert timeout == 180


def test_build_cmd_fast_mode_drops_scripts_and_shrinks_ports():
    cmd, timeout, mode = _build_nmap_cmd("10.0.0.5", {"mode": "fast"})
    assert mode == "fast"
    assert "-sC" not in cmd
    assert "--script" not in cmd
    assert "--top-ports" in cmd and "100" in cmd
    assert timeout == 60


def test_build_cmd_fast_mode_with_explicit_ports_skips_top_ports():
    cmd, _, _ = _build_nmap_cmd("10.0.0.5", {"mode": "fast", "ports": "22,80,443"})
    assert "--top-ports" not in cmd
    assert "-p" in cmd and "22,80,443" in cmd


def test_build_cmd_unknown_mode_falls_back_to_full():
    _, timeout, mode = _build_nmap_cmd("10.0.0.5", {"mode": "bogus"})
    assert mode == "full"
    assert timeout == 180


def test_build_cmd_full_mode_with_explicit_ports():
    cmd, _, _ = _build_nmap_cmd("10.0.0.5", {"ports": "1-1024"})
    assert "-p" in cmd and "1-1024" in cmd
