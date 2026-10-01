"""Tests para app/scanners/openvas.py -- descubrimiento dinamico de ids,
construccion de comandos/XML y parseo de respuestas GMP, sin hablar con
un gvmd de verdad."""
from app.scanners.openvas import (
    _build_create_target_xml,
    _build_create_task_xml,
    _find_id_by_name,
    _gvm_cmd,
    _parse_gmp_results,
    _parse_response_id,
    _parse_task_status,
    _response_status_ok,
    _severity_from_cvss,
)

_GET_CONFIGS_XML = """<get_configs_response status="200" status_text="OK">
  <config id="aaa-111"><name>Discovery</name></config>
  <config id="bbb-222"><name>Full and fast</name></config>
  <config id="ccc-333"><name>Empty, static and fast</name></config>
</get_configs_response>"""

_GET_SCANNERS_XML = """<get_scanners_response status="200" status_text="OK">
  <scanner id="sc-111"><name>CVE</name></scanner>
  <scanner id="sc-222"><name>OpenVAS Default</name></scanner>
</get_scanners_response>"""

_GET_PORT_LISTS_XML = """<get_port_lists_response status="200" status_text="OK">
  <port_list id="pl-111"><name>All TCP and Nmap top 100 UDP</name></port_list>
  <port_list id="pl-222"><name>All IANA assigned TCP and UDP</name></port_list>
</get_port_lists_response>"""


def test_gvm_cmd_includes_auth_flags_and_socket():
    cmd = _gvm_cmd("/run/gvmd/gvmd.sock", "admin", "s3cret", "<get_tasks/>")
    assert cmd == [
        "gvm-cli", "--gmp-username", "admin", "--gmp-password", "s3cret",
        "socket", "--socketpath", "/run/gvmd/gvmd.sock", "--xml", "<get_tasks/>",
    ]


def test_find_id_by_name_prefers_full_and_fast_config():
    assert _find_id_by_name(_GET_CONFIGS_XML, "config", ("full and fast",)) == "bbb-222"


def test_find_id_by_name_prefers_openvas_default_scanner():
    assert _find_id_by_name(_GET_SCANNERS_XML, "scanner", ("openvas default", "openvas")) == "sc-222"


def test_find_id_by_name_prefers_all_iana_port_list():
    assert _find_id_by_name(
        _GET_PORT_LISTS_XML, "port_list", ("all iana assigned tcp and udp", "all tcp")
    ) == "pl-222"


def test_find_id_by_name_falls_back_to_first_when_no_match():
    assert _find_id_by_name(_GET_CONFIGS_XML, "config", ("no existe esta config",)) == "aaa-111"


def test_find_id_by_name_returns_none_on_empty_list():
    empty = '<get_configs_response status="200"></get_configs_response>'
    assert _find_id_by_name(empty, "config", ("full and fast",)) is None


def test_find_id_by_name_returns_none_on_malformed_xml():
    assert _find_id_by_name("no es xml <<<", "config", ("full and fast",)) is None


def test_build_create_target_xml_escapes_and_embeds_port_list():
    xml = _build_create_target_xml("mi target & cia", "10.0.0.1", "pl-222")
    assert "mi target &amp; cia" in xml
    assert "<hosts>10.0.0.1</hosts>" in xml
    assert "port_list id='pl-222'" in xml


def test_build_create_task_xml_embeds_all_ids():
    xml = _build_create_task_xml("t1", "target-1", "config-1", "scanner-1")
    assert "target id='target-1'" in xml
    assert "config id='config-1'" in xml
    assert "scanner id='scanner-1'" in xml


def test_parse_response_id_extracts_id_attribute():
    xml = '<create_target_response status="201" id="tgt-999"/>'
    assert _parse_response_id(xml) == "tgt-999"


def test_parse_response_id_none_when_missing():
    assert _parse_response_id('<create_target_response status="400"/>') is None


def test_response_status_ok_true_for_2xx():
    assert _response_status_ok('<create_target_response status="201"/>') is True


def test_response_status_ok_false_for_4xx():
    assert _response_status_ok('<create_target_response status="400"/>') is False


def test_response_status_ok_false_on_malformed_xml():
    assert _response_status_ok("no es xml") is False


def test_parse_task_status_extracts_status_and_progress():
    xml = """<get_tasks_response><task id="t1">
        <status>Running</status><progress>42</progress>
    </task></get_tasks_response>"""
    assert _parse_task_status(xml) == ("Running", 42)


def test_parse_task_status_none_when_no_task():
    assert _parse_task_status("<get_tasks_response></get_tasks_response>") is None


def test_severity_from_cvss_thresholds():
    assert _severity_from_cvss(9.5) == "critical"
    assert _severity_from_cvss(7.0) == "high"
    assert _severity_from_cvss(4.0) == "medium"
    assert _severity_from_cvss(0.5) == "low"
    assert _severity_from_cvss(0.0) == "info"


def test_parse_gmp_results_extracts_findings():
    xml = """<get_results_response><result>
        <name>SSL/TLS debil</name>
        <severity>7.5</severity>
        <host>10.0.0.5</host>
        <port>443/tcp</port>
        <description>Cipher suite debil detectado</description>
        <nvt><cve>CVE-2024-9999</cve></nvt>
    </result></get_results_response>"""
    findings = _parse_gmp_results(xml)
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "SSL/TLS debil"
    assert f["severity"] == "high"
    assert f["cve_id"] == "CVE-2024-9999"
    assert f["service"] == "10.0.0.5:443/tcp"


def test_parse_gmp_results_nocve_maps_to_none():
    xml = """<get_results_response><result>
        <name>hallazgo generico</name>
        <severity>2.0</severity>
        <nvt><cve>NOCVE</cve></nvt>
    </result></get_results_response>"""
    findings = _parse_gmp_results(xml)
    assert findings[0]["cve_id"] is None


def test_parse_gmp_results_empty_on_malformed_xml():
    assert _parse_gmp_results("no es xml <<<") == []
