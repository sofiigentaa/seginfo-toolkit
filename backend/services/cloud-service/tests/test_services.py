"""Tests de la logica pura de app/services.py -- sin boto3 real, sin red,
sin DB (discover_ec2_instances/discover_security_groups/discover_s3_buckets/
run_account_sync, que si hacen I/O, quedan fuera de este archivo a
proposito)."""
from app.services import (
    bucket_is_public,
    bucket_public_access_block_blocks_all,
    classify_security_group_finding,
    diff_external_ids,
    extract_public_ingress_rules,
    is_public_cidr,
    mask_access_key_id,
    normalize_ec2_instance,
    should_create_finding,
)
from app.models import FindingSeverity


class TestIsPublicCidr:
    def test_ipv4_open_world_is_public(self):
        assert is_public_cidr("0.0.0.0/0") is True

    def test_ipv6_open_world_is_public(self):
        assert is_public_cidr("::/0") is True

    def test_specific_cidr_is_not_public(self):
        assert is_public_cidr("10.0.0.0/8") is False
        assert is_public_cidr("203.0.113.5/32") is False


class TestExtractPublicIngressRules:
    def test_rule_open_to_specific_port(self):
        sg = {
            "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            ]
        }
        assert extract_public_ingress_rules(sg) == [
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}
        ]

    def test_all_protocols_rule_has_none_ports(self):
        sg = {"IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        assert extract_public_ingress_rules(sg) == [
            {"protocol": "-1", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"}
        ]

    def test_non_public_cidr_is_excluded(self):
        sg = {
            "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
            ]
        }
        assert extract_public_ingress_rules(sg) == []

    def test_ipv6_public_range_is_included(self):
        sg = {
            "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
            ]
        }
        assert extract_public_ingress_rules(sg) == [
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "::/0"}
        ]

    def test_no_permissions_returns_empty(self):
        assert extract_public_ingress_rules({}) == []


class TestClassifySecurityGroupFinding:
    def test_no_public_rules_is_none(self):
        assert classify_security_group_finding([]) is None

    def test_all_protocols_open_is_critical(self):
        rules = [{"protocol": "-1", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"}]
        severity, detail = classify_security_group_finding(rules)
        assert severity == FindingSeverity.critical
        assert "0.0.0.0/0" in detail

    def test_risky_port_22_is_critical(self):
        rules = [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}]
        severity, _ = classify_security_group_finding(rules)
        assert severity == FindingSeverity.critical

    def test_risky_port_in_range_is_critical(self):
        rules = [{"protocol": "tcp", "from_port": 20, "to_port": 25, "cidr": "0.0.0.0/0"}]
        severity, _ = classify_security_group_finding(rules)
        assert severity == FindingSeverity.critical

    def test_non_risky_port_open_to_world_is_medium(self):
        rules = [{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr": "0.0.0.0/0"}]
        severity, _ = classify_security_group_finding(rules)
        assert severity == FindingSeverity.medium


class TestNormalizeEc2Instance:
    def test_extracts_name_from_tags(self):
        raw = {
            "InstanceId": "i-123",
            "Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "Name", "Value": "web-1"}],
            "State": {"Name": "running"},
            "InstanceType": "t3.micro",
            "PrivateIpAddress": "10.0.0.5",
            "PublicIpAddress": "1.2.3.4",
        }
        result = normalize_ec2_instance(raw)
        assert result["instance_id"] == "i-123"
        assert result["name"] == "web-1"
        assert result["state"] == "running"
        assert result["instance_type"] == "t3.micro"
        assert result["private_ip"] == "10.0.0.5"
        assert result["public_ip"] == "1.2.3.4"

    def test_missing_name_tag_defaults_to_empty_string(self):
        raw = {"InstanceId": "i-456", "State": {"Name": "stopped"}}
        result = normalize_ec2_instance(raw)
        assert result["name"] == ""
        assert result["private_ip"] == ""
        assert result["public_ip"] == ""
        assert result["launch_time"] == ""


class TestBucketPublicAccessBlockBlocksAll:
    def test_none_does_not_block(self):
        assert bucket_public_access_block_blocks_all(None) is False

    def test_all_four_flags_true_blocks(self):
        pab = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        assert bucket_public_access_block_blocks_all(pab) is True

    def test_one_flag_false_does_not_block(self):
        pab = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        }
        assert bucket_public_access_block_blocks_all(pab) is False


class TestBucketIsPublic:
    def test_blocked_by_public_access_block_overrides_public_policy(self):
        pab = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        policy_status = {"PolicyStatus": {"IsPublic": True}}
        assert bucket_is_public(policy_status, pab, []) is False

    def test_public_policy_status_without_block_is_public(self):
        policy_status = {"PolicyStatus": {"IsPublic": True}}
        assert bucket_is_public(policy_status, None, []) is True

    def test_public_via_acl_all_users_grant_without_policy(self):
        acl_grants = [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]
        assert bucket_is_public(None, None, acl_grants) is True

    def test_private_bucket_is_not_public(self):
        policy_status = {"PolicyStatus": {"IsPublic": False}}
        acl_grants = [{"Grantee": {"URI": "id=some-other-account"}, "Permission": "READ"}]
        assert bucket_is_public(policy_status, None, acl_grants) is False


class TestDiffExternalIds:
    def test_new_and_removed_ids(self):
        previous = {"a", "b"}
        current = {"b", "c"}
        new_ids, removed_ids = diff_external_ids(previous, current)
        assert new_ids == {"c"}
        assert removed_ids == {"a"}

    def test_no_changes(self):
        ids = {"a", "b"}
        new_ids, removed_ids = diff_external_ids(ids, ids)
        assert new_ids == set()
        assert removed_ids == set()


class TestShouldCreateFinding:
    def test_empty_list_creates_new_finding(self):
        assert should_create_finding([]) is True

    def test_last_acknowledged_allows_new_finding(self):
        findings = [{"is_acknowledged": False}, {"is_acknowledged": True}]
        assert should_create_finding(findings) is True

    def test_last_not_acknowledged_blocks_new_finding(self):
        findings = [{"is_acknowledged": True}, {"is_acknowledged": False}]
        assert should_create_finding(findings) is False


class TestMaskAccessKeyId:
    def test_long_key_shows_first_and_last_four(self):
        assert mask_access_key_id("AKIAIOSFODNN7WXYZ") == "AKIA…WXYZ"

    def test_short_key_is_fully_masked(self):
        assert mask_access_key_id("abc") == "••••"

    def test_exactly_eight_chars_is_masked_normally(self):
        assert mask_access_key_id("ABCDEFGH") == "ABCD…EFGH"
