"""Tests de la logica pura de app/services.py -- sin git/gitleaks/trivy
real, sin red, sin DB (_clone_repo/_run_gitleaks/_run_trivy_fs/
run_repo_scan, que si hacen I/O, quedan fuera de este archivo a
proposito)."""
import json

from app.services import (
    build_authenticated_clone_url,
    build_trivy_fs_vuln_cmd,
    classify_gitleaks_severity,
    parse_gitleaks_report,
    parse_trivy_vuln_json,
    redact_secret_match,
    redact_url,
    should_create_secret_finding,
    validate_repo_url,
)
from app.models import SecretSeverity


class TestValidateRepoUrl:
    def test_https_url_is_valid(self):
        assert validate_repo_url("https://github.com/acme/repo.git") is True

    def test_http_url_is_invalid(self):
        assert validate_repo_url("http://github.com/acme/repo.git") is False

    def test_ssh_url_is_invalid(self):
        assert validate_repo_url("git@github.com:acme/repo.git") is False

    def test_ssh_scheme_url_is_invalid(self):
        assert validate_repo_url("ssh://git@github.com/acme/repo.git") is False

    def test_empty_url_is_invalid(self):
        assert validate_repo_url("") is False


class TestBuildAuthenticatedCloneUrl:
    def test_with_token_inserts_x_access_token(self):
        result = build_authenticated_clone_url("https://github.com/acme/repo.git", "ghp_abc123")
        assert result == "https://x-access-token:ghp_abc123@github.com/acme/repo.git"

    def test_without_token_returns_url_unchanged(self):
        url = "https://github.com/acme/repo.git"
        assert build_authenticated_clone_url(url, None) == url

    def test_empty_token_returns_url_unchanged(self):
        url = "https://github.com/acme/repo.git"
        assert build_authenticated_clone_url(url, "") == url


class TestRedactUrl:
    def test_redacts_token_before_host(self):
        url = "https://x-access-token:ghp_supersecret@github.com/acme/repo.git"
        result = redact_url(url)
        assert "ghp_supersecret" not in result
        assert result == "https://***@github.com/acme/repo.git"

    def test_url_without_credentials_is_unchanged(self):
        url = "https://github.com/acme/repo.git"
        assert redact_url(url) == url

    def test_redacts_credentials_embedded_in_longer_message(self):
        message = "fatal: no se pudo clonar https://x-access-token:secretvalue@github.com/acme/repo.git: not found"
        result = redact_url(message)
        assert "secretvalue" not in result
        assert "***@github.com" in result

    def test_empty_string_is_unchanged(self):
        assert redact_url("") == ""


class TestRedactSecretMatch:
    def test_short_secret_is_fully_masked(self):
        assert redact_secret_match("abc") == "••••"

    def test_exactly_six_chars_is_fully_masked(self):
        assert redact_secret_match("abcdef") == "••••"

    def test_long_secret_keeps_first_three_and_last_two(self):
        raw = "AKIAIOSFODNN7EXAMPLE"
        result = redact_secret_match(raw)
        assert result.startswith("AKI")
        assert result.endswith("LE")
        assert raw not in result
        assert raw[3:-2] not in result

    def test_padding_capped_at_twenty(self):
        raw = "a" * 100
        result = redact_secret_match(raw)
        # 3 primeros + relleno (cap 20) + 2 ultimos
        assert result == "aaa" + ("•" * 20) + "aa"
        assert raw not in result

    def test_empty_secret_is_fully_masked(self):
        assert redact_secret_match("") == "••••"


class TestClassifyGitleaksSeverity:
    def test_private_key_is_critical(self):
        assert classify_gitleaks_severity("private-key") == SecretSeverity.critical

    def test_aws_is_critical(self):
        assert classify_gitleaks_severity("aws-access-key-id") == SecretSeverity.critical

    def test_gcp_is_critical(self):
        assert classify_gitleaks_severity("gcp-service-account") == SecretSeverity.critical

    def test_azure_is_critical(self):
        assert classify_gitleaks_severity("azure-storage-key") == SecretSeverity.critical

    def test_generic_service_account_is_critical(self):
        assert classify_gitleaks_severity("some-service-account-rule") == SecretSeverity.critical

    def test_token_is_high(self):
        assert classify_gitleaks_severity("github-pat-token") == SecretSeverity.high

    def test_api_key_is_high(self):
        assert classify_gitleaks_severity("stripe-api-key") == SecretSeverity.high

    def test_apikey_is_high(self):
        assert classify_gitleaks_severity("generic-apikey") == SecretSeverity.high

    def test_secret_is_high(self):
        assert classify_gitleaks_severity("jwt-secret") == SecretSeverity.high

    def test_password_is_high(self):
        assert classify_gitleaks_severity("basic-auth-password") == SecretSeverity.high

    def test_generic_is_high(self):
        assert classify_gitleaks_severity("generic-credential") == SecretSeverity.high

    def test_unknown_rule_is_medium(self):
        assert classify_gitleaks_severity("some-unrelated-rule") == SecretSeverity.medium

    def test_is_case_insensitive(self):
        assert classify_gitleaks_severity("AWS-Access-Key") == SecretSeverity.critical


class TestParseGitleaksReport:
    def test_valid_json_with_findings(self):
        raw = json.dumps(
            [
                {
                    "RuleID": "aws-access-key",
                    "Description": "AWS Access Key",
                    "File": "config/settings.py",
                    "StartLine": 42,
                    "Commit": "abc123",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                }
            ]
        )
        result = parse_gitleaks_report(raw)
        assert len(result) == 1
        item = result[0]
        assert item["rule_id"] == "aws-access-key"
        assert item["description"] == "AWS Access Key"
        assert item["file_path"] == "config/settings.py"
        assert item["start_line"] == 42
        assert item["commit_hash"] == "abc123"
        assert item["severity"] == SecretSeverity.critical
        assert "AKIAIOSFODNN7EXAMPLE" not in item["match_redacted"]
        assert "Secret" not in item
        assert "Match" not in item

    def test_empty_list_returns_empty(self):
        assert parse_gitleaks_report("[]") == []

    def test_empty_string_returns_empty(self):
        assert parse_gitleaks_report("") == []

    def test_invalid_json_returns_empty_without_raising(self):
        assert parse_gitleaks_report("not json at all {{{") == []

    def test_non_list_json_returns_empty(self):
        assert parse_gitleaks_report(json.dumps({"not": "a list"})) == []

    def test_falls_back_to_match_when_secret_missing(self):
        raw = json.dumps(
            [{"RuleID": "generic-secret", "File": "a.py", "StartLine": 1, "Match": "password=hunter22"}]
        )
        result = parse_gitleaks_report(raw)
        assert "hunter22" not in result[0]["match_redacted"]


class TestBuildTrivyFsVulnCmd:
    def test_builds_expected_command(self):
        cmd = build_trivy_fs_vuln_cmd("/tmp/repo", "/root/.cache/trivy")
        assert cmd == [
            "trivy", "fs",
            "--scanners", "vuln",
            "--format", "json", "--quiet", "--timeout", "8m",
            "--cache-dir", "/root/.cache/trivy",
            "--skip-db-update", "--skip-java-db-update",
            "/tmp/repo",
        ]


class TestParseTrivyVulnJson:
    _SAMPLE = json.dumps(
        {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.15",
                            "FixedVersion": "4.17.21",
                            "Severity": "HIGH",
                            "Title": "Prototype pollution in lodash",
                        },
                        {
                            "VulnerabilityID": "CVE-2022-9999",
                            "PkgName": "requests",
                            "InstalledVersion": "2.20.0",
                            "FixedVersion": "",
                            "Severity": "CRITICAL",
                            "Description": "Some vuln description",
                        },
                    ],
                }
            ]
        }
    )

    def test_parses_findings_with_repo_in_title(self):
        result = parse_trivy_vuln_json(self._SAMPLE, "acme-backend")
        assert len(result) == 2
        first = result[0]
        assert first["title"] == "CVE-2023-1234 en lodash (repo: acme-backend)"
        assert first["severity"] == "high"
        assert first["cve_id"] == "CVE-2023-1234"
        assert first["package"] == "lodash"
        assert first["installed_version"] == "4.17.15"
        assert first["fixed_version"] == "4.17.21"
        assert first["description"] == "Prototype pollution in lodash"

    def test_maps_critical_severity_and_falls_back_to_description(self):
        result = parse_trivy_vuln_json(self._SAMPLE, "acme-backend")
        second = result[1]
        assert second["severity"] == "critical"
        assert second["description"] == "Some vuln description"

    def test_empty_string_returns_empty(self):
        assert parse_trivy_vuln_json("", "repo") == []

    def test_invalid_json_returns_empty(self):
        assert parse_trivy_vuln_json("not json", "repo") == []

    def test_no_results_key_returns_empty(self):
        assert parse_trivy_vuln_json(json.dumps({}), "repo") == []

    def test_unknown_severity_maps_to_info(self):
        raw = json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x", "Severity": "WEIRD"}]}]})
        result = parse_trivy_vuln_json(raw, "repo")
        assert result[0]["severity"] == "info"


class TestShouldCreateSecretFinding:
    def test_empty_list_creates_new_finding(self):
        assert should_create_secret_finding([]) is True

    def test_last_acknowledged_allows_new_finding(self):
        findings = [{"is_acknowledged": False}, {"is_acknowledged": True}]
        assert should_create_secret_finding(findings) is True

    def test_last_not_acknowledged_blocks_new_finding(self):
        findings = [{"is_acknowledged": True}, {"is_acknowledged": False}]
        assert should_create_secret_finding(findings) is False
