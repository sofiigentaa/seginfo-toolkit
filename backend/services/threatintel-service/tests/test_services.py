"""Tests de la logica pura de threatintel-service (sin DB, sin red real) --
is_private_or_reserved_ip, is_cache_fresh, parse_abuseipdb_response y
_combine_results. El resto (clientes HTTP, lookup_ip/lookup_batch) hace
I/O real (red y DB) y no se testea aca, igual que _notify_soar en
siem-service."""
from datetime import datetime, timedelta, timezone

from app.services import (
    is_private_or_reserved_ip,
    is_cache_fresh,
    parse_abuseipdb_response,
    _combine_results,
)


class TestIsPrivateOrReservedIp:
    def test_private_ipv4_is_private(self):
        assert is_private_or_reserved_ip("10.0.0.1") is True

    def test_public_ipv4_is_not_private(self):
        assert is_private_or_reserved_ip("8.8.8.8") is False

    def test_loopback_is_private(self):
        assert is_private_or_reserved_ip("127.0.0.1") is True

    def test_link_local_is_private(self):
        assert is_private_or_reserved_ip("169.254.1.1") is True

    def test_other_private_ranges(self):
        assert is_private_or_reserved_ip("172.16.0.5") is True
        assert is_private_or_reserved_ip("192.168.1.1") is True

    def test_invalid_ip_is_treated_as_private(self):
        # Una IP invalida nunca se manda a una API externa -- se trata
        # igual que una privada/reservada, no como un error.
        assert is_private_or_reserved_ip("no-es-una-ip") is True

    def test_empty_string_is_treated_as_private(self):
        assert is_private_or_reserved_ip("") is True


class TestIsCacheFresh:
    def test_fresh_when_not_yet_expired(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        ttl = now + timedelta(hours=1)
        assert is_cache_fresh(ttl, now) is True

    def test_stale_when_already_expired(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        ttl = now - timedelta(hours=1)
        assert is_cache_fresh(ttl, now) is False

    def test_exactly_at_the_boundary_is_considered_expired(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert is_cache_fresh(now, now) is False


class TestParseAbuseipdbResponse:
    def test_score_above_threshold_is_malicious(self):
        body = {"data": {"abuseConfidenceScore": 87, "reports": [{"categories": [18, 22]}]}}
        parsed = parse_abuseipdb_response(body)
        assert parsed["is_malicious"] is True
        assert parsed["score"] == 87
        assert "Brute-Force" in parsed["categories"]
        assert "SSH" in parsed["categories"]

    def test_score_below_threshold_is_not_malicious(self):
        body = {"data": {"abuseConfidenceScore": 10, "reports": []}}
        parsed = parse_abuseipdb_response(body)
        assert parsed["is_malicious"] is False
        assert parsed["score"] == 10
        assert parsed["categories"] == []

    def test_custom_threshold_is_respected(self):
        body = {"data": {"abuseConfidenceScore": 60, "reports": []}}
        assert parse_abuseipdb_response(body, malicious_score_threshold=75)["is_malicious"] is False
        assert parse_abuseipdb_response(body, malicious_score_threshold=50)["is_malicious"] is True

    def test_unknown_category_id_falls_back_to_numeric_string(self):
        body = {"data": {"abuseConfidenceScore": 90, "reports": [{"categories": [999]}]}}
        parsed = parse_abuseipdb_response(body)
        assert parsed["categories"] == ["999"]

    def test_empty_or_malformed_response_does_not_explode(self):
        assert parse_abuseipdb_response({})["is_malicious"] is False
        assert parse_abuseipdb_response({"data": "no-es-un-dict"})["is_malicious"] is False
        assert parse_abuseipdb_response({"data": {}})["score"] == 0
        assert parse_abuseipdb_response({"data": {"abuseConfidenceScore": "no-es-un-numero"}})["score"] == 0


class TestCombineResults:
    def test_no_source_configured_or_available_means_could_not_check(self):
        assert _combine_results("8.8.8.8", [])["is_malicious"] is None

    def test_all_sources_could_not_check_means_final_could_not_check(self):
        results = [{"source": "abuseipdb", "is_malicious": None, "score": None, "categories": []}]
        combined = _combine_results("8.8.8.8", results)
        assert combined["is_malicious"] is None
        assert combined["source"] == "abuseipdb"

    def test_any_source_flagging_malicious_wins(self):
        results = [
            {"source": "abuseipdb", "is_malicious": False, "score": 5, "categories": []},
            {"source": "misp", "is_malicious": True, "score": None, "categories": []},
        ]
        combined = _combine_results("1.2.3.4", results)
        assert combined["is_malicious"] is True
        assert combined["source"] == "abuseipdb+misp"

    def test_score_is_the_highest_available(self):
        results = [
            {"source": "abuseipdb", "is_malicious": True, "score": 40, "categories": []},
        ]
        assert _combine_results("1.2.3.4", results)["score"] == 40

    def test_categories_are_merged_without_duplicates(self):
        results = [
            {"source": "abuseipdb", "is_malicious": True, "score": 90, "categories": ["SSH", "Brute-Force"]},
        ]
        combined = _combine_results("1.2.3.4", results)
        assert combined["categories"] == ["SSH", "Brute-Force"]

    def test_sources_that_could_not_check_are_excluded_from_final_source(self):
        results = [
            {"source": "abuseipdb", "is_malicious": True, "score": 90, "categories": []},
            {"source": "misp", "is_malicious": None, "score": None, "categories": []},
        ]
        combined = _combine_results("1.2.3.4", results)
        assert combined["source"] == "abuseipdb"
