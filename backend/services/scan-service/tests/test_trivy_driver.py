"""Tests para app/scanners/trivy.py -- construccion de comando y parseo de
JSON, sin ejecutar trivy de verdad."""
import json
from app.scanners.trivy import _build_trivy_cmd, _parse_trivy_json

_SAMPLE_JSON = json.dumps({
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.4)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "Title": "openssl: buffer overflow",
                    "Severity": "CRITICAL",
                    "InstalledVersion": "3.0.1",
                    "FixedVersion": "3.0.2",
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "libc",
                    "Description": "desc sin title",
                    "Severity": "UNKNOWN",
                    "InstalledVersion": "1.0",
                    "FixedVersion": None,
                },
            ],
        }
    ]
})


def test_build_cmd_defaults_to_image_mode_with_skip_flags():
    cmd = _build_trivy_cmd("alpine:3.18", {}, cache_dir="/root/.cache/trivy")
    assert cmd[0:2] == ["trivy", "image"]
    assert "--skip-db-update" in cmd
    assert "--skip-java-db-update" in cmd
    assert "--cache-dir" in cmd and "/root/.cache/trivy" in cmd
    assert cmd[-1] == "alpine:3.18"


def test_build_cmd_fs_mode():
    cmd = _build_trivy_cmd("/src", {"mode": "fs"}, cache_dir="/cache")
    assert cmd[0:2] == ["trivy", "fs"]
    assert cmd[-1] == "/src"


def test_parse_trivy_json_extracts_findings():
    findings = _parse_trivy_json(_SAMPLE_JSON)
    assert len(findings) == 2
    critical = next(f for f in findings if f["cve_id"] == "CVE-2024-1234")
    assert critical["severity"] == "critical"
    assert critical["package"] == "openssl"
    assert "openssl" in critical["title"]


def test_parse_trivy_json_unknown_severity_maps_to_info():
    findings = _parse_trivy_json(_SAMPLE_JSON)
    unknown = next(f for f in findings if f["cve_id"] == "CVE-2024-5678")
    assert unknown["severity"] == "info"
    assert "desc sin title" in unknown["description"]


def test_parse_trivy_json_malformed_returns_empty():
    assert _parse_trivy_json("no es json <<<") == []


def test_parse_trivy_json_empty_string_returns_empty():
    assert _parse_trivy_json("") == []
