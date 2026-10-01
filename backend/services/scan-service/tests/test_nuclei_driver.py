"""Tests para app/scanners/nuclei.py -- construccion de comando y parseo
de JSONL, sin ejecutar nuclei de verdad."""
import json
from app.scanners.nuclei import _build_nuclei_cmd, _parse_nuclei_jsonl

_SAMPLE_JSONL = "\n".join([
    json.dumps({
        "template-id": "cve-2023-0001",
        "info": {
            "name": "Ejemplo CVE",
            "description": "descripcion de ejemplo",
            "severity": "high",
            "classification": {"cve-id": ["CVE-2023-0001"]},
        },
        "matched-at": "https://10.0.0.5:443",
    }),
    json.dumps({
        "template-id": "tech-detect",
        "info": {"name": "Tech fingerprint", "severity": "info"},
        "matched-at": "https://10.0.0.5:443",
    }),
])


def test_build_cmd_includes_disable_update_check():
    cmd = _build_nuclei_cmd("https://10.0.0.5", {})
    assert "-duc" in cmd
    assert "dos,fuzz,intrusive" in cmd


def test_build_cmd_sanitizes_tags():
    cmd = _build_nuclei_cmd("https://10.0.0.5", {"tags": "cve, exposed-panels; rm -rf"})
    assert "-tags" in cmd
    tags_value = cmd[cmd.index("-tags") + 1]
    assert "rm" not in tags_value and ";" not in tags_value
    assert "cve" in tags_value


def test_build_cmd_no_tags_omits_flag():
    cmd = _build_nuclei_cmd("https://10.0.0.5", {})
    assert "-tags" not in cmd


def test_parse_jsonl_extracts_findings_with_cve():
    findings = _parse_nuclei_jsonl(_SAMPLE_JSONL)
    assert len(findings) == 2
    cve_finding = next(f for f in findings if f["cve_id"] == "CVE-2023-0001")
    assert cve_finding["severity"] == "high"
    assert cve_finding["title"] == "Ejemplo CVE"


def test_parse_jsonl_finding_without_cve_has_none():
    findings = _parse_nuclei_jsonl(_SAMPLE_JSONL)
    tech_finding = next(f for f in findings if f["title"] == "Tech fingerprint")
    assert tech_finding["cve_id"] is None
    assert tech_finding["severity"] == "info"


def test_parse_jsonl_skips_malformed_lines():
    raw = _SAMPLE_JSONL + "\nno es json valido\n"
    findings = _parse_nuclei_jsonl(raw)
    assert len(findings) == 2


def test_parse_jsonl_empty_returns_empty_list():
    assert _parse_nuclei_jsonl("") == []
