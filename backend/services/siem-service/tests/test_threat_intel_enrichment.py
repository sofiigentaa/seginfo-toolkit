"""Tests de las funciones puras que enriquecen una alerta con threat intel
(ver app/services.py::_enrich_alert_with_threat_intel) -- sin DB ni red
real, igual que test_alert_update.py en este mismo paquete. La llamada a
threatintel-service en si (httpx.AsyncClient, best-effort con try/except
httpx.HTTPError) no se testea aca por la misma razon que _notify_soar no
se testea: es I/O real."""
from app.services import _extract_ips_from_event, _malicious_ips_from_lookup


class TestExtractIpsFromEvent:
    def test_extracts_source_and_dest_ip(self):
        event = {"source": {"ip": "1.2.3.4"}, "destination": {"ip": "5.6.7.8"}}
        assert _extract_ips_from_event(event) == ["1.2.3.4", "5.6.7.8"]

    def test_deduplicates_when_source_and_dest_are_the_same(self):
        event = {"source": {"ip": "1.2.3.4"}, "destination": {"ip": "1.2.3.4"}}
        assert _extract_ips_from_event(event) == ["1.2.3.4"]

    def test_skips_empty_ips(self):
        event = {"source": {"ip": ""}, "destination": {"ip": "5.6.7.8"}}
        assert _extract_ips_from_event(event) == ["5.6.7.8"]

    def test_no_ips_at_all_returns_empty_list(self):
        assert _extract_ips_from_event({}) == []
        assert _extract_ips_from_event({"source": {"ip": ""}, "destination": {"ip": ""}}) == []

    def test_missing_source_or_destination_key_does_not_explode(self):
        assert _extract_ips_from_event({"destination": {"ip": "5.6.7.8"}}) == ["5.6.7.8"]


class TestMaliciousIpsFromLookup:
    def test_keeps_only_malicious_ips(self):
        results = [
            {"ip": "1.2.3.4", "is_malicious": True, "score": 90, "source": "abuseipdb", "categories": ["SSH"]},
            {"ip": "10.0.0.1", "is_malicious": False, "score": None, "source": "internal", "categories": []},
        ]
        malicious = _malicious_ips_from_lookup(results)
        assert list(malicious.keys()) == ["1.2.3.4"]
        assert malicious["1.2.3.4"]["score"] == 90

    def test_excludes_ips_that_could_not_be_checked(self):
        # is_malicious=None ("no se pudo chequear") no es lo mismo que
        # is_malicious=False ("se cheque y esta limpia") -- ninguno de
        # los dos debe terminar en Alert.threat_intel.
        results = [{"ip": "1.2.3.4", "is_malicious": None, "score": None, "source": "abuseipdb", "categories": []}]
        assert _malicious_ips_from_lookup(results) == {}

    def test_no_malicious_ips_returns_empty_dict(self):
        assert _malicious_ips_from_lookup([]) == {}

    def test_ip_key_itself_is_not_duplicated_inside_the_value(self):
        results = [{"ip": "1.2.3.4", "is_malicious": True, "score": 90, "source": "abuseipdb", "categories": []}]
        malicious = _malicious_ips_from_lookup(results)
        assert "ip" not in malicious["1.2.3.4"]
