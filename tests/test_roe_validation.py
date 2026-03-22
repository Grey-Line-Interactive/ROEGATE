"""
Tests for the ROE specification validator.

Validates that the validator correctly catches invalid specs, produces
appropriate warnings, and accepts valid specs.
"""

from __future__ import annotations

import pytest
from typing import Any

from src.roe_spec.validator import validate_roe_file, validate_roe_spec


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_spec() -> dict[str, Any]:
    """A minimal valid ROE spec."""
    return {
        "metadata": {
            "engagement_id": "ENG-2024-001",
            "created": "2024-01-10T09:00:00Z",
            "approved_by": "John Smith, CISO",
        },
        "schedule": {
            "valid_from": "2024-01-15T00:00:00Z",
            "valid_until": "2030-12-31T23:59:59Z",
        },
        "scope": {
            "in_scope": {
                "networks": [{"cidr": "10.0.0.0/24", "ports": [80, 443]}],
            },
            "out_of_scope": {
                "networks": [{"cidr": "10.0.2.0/24", "reason": "Production DB"}],
            },
        },
        "actions": {
            "allowed": [{"category": "reconnaissance"}],
            "denied": [
                {"category": "denial_of_service", "reason": "No DoS"},
                {"category": "social_engineering", "reason": "No phishing"},
                {"category": "data_exfiltration", "reason": "No exfil"},
                {"category": "lateral_movement", "reason": "No pivoting"},
                {"category": "privilege_escalation", "reason": "No privesc"},
            ],
        },
        "emergency": {
            "kill_switch": True,
            "max_consecutive_denials": 3,
        },
        "constraints": {
            "no_persistent_changes": True,
        },
    }


# ---------------------------------------------------------------------------
# Schema validation (Level 1)
# ---------------------------------------------------------------------------

class TestSchemaValidation:

    def test_valid_spec_passes(self, valid_spec):
        result = validate_roe_spec(valid_spec)
        assert result.valid

    def test_missing_required_section_metadata(self, valid_spec):
        del valid_spec["metadata"]
        result = validate_roe_spec(valid_spec)
        assert not result.valid
        assert any("metadata" in i.message for i in result.errors)

    def test_missing_required_section_scope(self, valid_spec):
        del valid_spec["scope"]
        result = validate_roe_spec(valid_spec)
        assert not result.valid
        assert any("scope" in i.message for i in result.errors)

    def test_missing_required_section_actions(self, valid_spec):
        del valid_spec["actions"]
        result = validate_roe_spec(valid_spec)
        assert not result.valid
        assert any("actions" in i.message for i in result.errors)

    def test_missing_required_section_schedule(self, valid_spec):
        del valid_spec["schedule"]
        result = validate_roe_spec(valid_spec)
        assert not result.valid
        assert any("schedule" in i.message for i in result.errors)

    def test_missing_metadata_engagement_id(self, valid_spec):
        del valid_spec["metadata"]["engagement_id"]
        result = validate_roe_spec(valid_spec)
        assert not result.valid

    def test_invalid_engagement_id_format(self, valid_spec):
        valid_spec["metadata"]["engagement_id"] = "INVALID-FORMAT"
        result = validate_roe_spec(valid_spec)
        assert not result.valid

    def test_unknown_category_enum_fails(self, valid_spec):
        valid_spec["actions"]["allowed"].append({"category": "banana_testing"})
        result = validate_roe_spec(valid_spec)
        assert not result.valid
        assert any("UNKNOWN_CATEGORY" in i.code for i in result.errors)

    def test_not_a_dict_fails(self):
        result = validate_roe_spec("not a dict")
        assert not result.valid
        assert any("NOT_A_DICT" in i.code for i in result.errors)


# ---------------------------------------------------------------------------
# CIDR validation
# ---------------------------------------------------------------------------

class TestCIDRValidation:

    def test_valid_cidr_passes(self, valid_spec):
        result = validate_roe_spec(valid_spec)
        assert not any("INVALID_CIDR" in i.code for i in result.issues)

    def test_invalid_cidr_octet_fails(self, valid_spec):
        valid_spec["scope"]["in_scope"]["networks"] = [
            {"cidr": "999.999.999.999/32"}
        ]
        result = validate_roe_spec(valid_spec)
        assert any("INVALID_CIDR" in i.code for i in result.errors)

    def test_invalid_cidr_prefix_fails(self, valid_spec):
        valid_spec["scope"]["in_scope"]["networks"] = [
            {"cidr": "10.0.0.0/33"}
        ]
        result = validate_roe_spec(valid_spec)
        assert any("INVALID_CIDR" in i.code for i in result.errors)

    def test_ipv6_cidr_passes(self, valid_spec):
        valid_spec["scope"]["in_scope"]["networks"] = [
            {"cidr": "::1/128"}
        ]
        result = validate_roe_spec(valid_spec)
        assert not any("INVALID_CIDR" in i.code for i in result.issues)


# ---------------------------------------------------------------------------
# Port validation
# ---------------------------------------------------------------------------

class TestPortValidation:

    def test_port_in_range_passes(self, valid_spec):
        result = validate_roe_spec(valid_spec)
        assert not any("INVALID_PORT" in i.code for i in result.issues)

    def test_port_zero_fails(self, valid_spec):
        valid_spec["scope"]["in_scope"]["networks"][0]["ports"] = [0]
        result = validate_roe_spec(valid_spec)
        assert any("INVALID_PORT" in i.code for i in result.errors)

    def test_port_too_high_fails(self, valid_spec):
        valid_spec["scope"]["in_scope"]["networks"][0]["ports"] = [70000]
        result = validate_roe_spec(valid_spec)
        assert any("INVALID_PORT" in i.code for i in result.errors)

    def test_port_range_start_greater_than_end_fails(self, valid_spec):
        valid_spec["scope"]["in_scope"]["networks"][0]["port_ranges"] = [
            {"start": 8080, "end": 80}
        ]
        result = validate_roe_spec(valid_spec)
        assert any("INVALID_PORT_RANGE" in i.code for i in result.errors)


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

class TestDomainValidation:

    def test_empty_domain_pattern_fails(self, valid_spec):
        valid_spec["scope"]["in_scope"]["domains"] = [{"pattern": ""}]
        result = validate_roe_spec(valid_spec)
        assert any("EMPTY_DOMAIN_PATTERN" in i.code for i in result.errors)


# ---------------------------------------------------------------------------
# Timezone validation
# ---------------------------------------------------------------------------

class TestTimezoneValidation:

    def test_valid_timezone_passes(self, valid_spec):
        valid_spec["schedule"]["timezone"] = "America/New_York"
        result = validate_roe_spec(valid_spec)
        assert not any("INVALID_TIMEZONE" in i.code for i in result.issues)

    def test_utc_passes(self, valid_spec):
        valid_spec["schedule"]["timezone"] = "UTC"
        result = validate_roe_spec(valid_spec)
        assert not any("INVALID_TIMEZONE" in i.code for i in result.issues)

    def test_invalid_timezone_fails(self, valid_spec):
        valid_spec["schedule"]["timezone"] = "Fake/Timezone"
        result = validate_roe_spec(valid_spec)
        assert any("INVALID_TIMEZONE" in i.code for i in result.errors)


# ---------------------------------------------------------------------------
# Schedule validation
# ---------------------------------------------------------------------------

class TestScheduleValidation:

    def test_valid_from_after_valid_until_fails(self, valid_spec):
        valid_spec["schedule"]["valid_from"] = "2030-01-01T00:00:00Z"
        valid_spec["schedule"]["valid_until"] = "2020-01-01T00:00:00Z"
        result = validate_roe_spec(valid_spec)
        assert any("SCHEDULE_INVALID_RANGE" in i.code for i in result.errors)

    def test_allowed_hours_invalid_format_fails(self, valid_spec):
        valid_spec["schedule"]["allowed_hours"] = "25:00-30:00"
        result = validate_roe_spec(valid_spec)
        assert any("INVALID_HOURS_FORMAT" in i.code for i in result.errors)

    def test_midnight_wrap_info(self, valid_spec):
        valid_spec["schedule"]["allowed_hours"] = "22:00-06:00"
        result = validate_roe_spec(valid_spec)
        assert any("MIDNIGHT_WRAP_HOURS" in i.code for i in result.issues)


# ---------------------------------------------------------------------------
# Match criteria validation
# ---------------------------------------------------------------------------

class TestMatchCriteriaValidation:

    def test_empty_match_dict_no_warning(self, valid_spec):
        """Empty match dict is fine — it means match on category alone."""
        valid_spec["actions"]["denied"].append({
            "category": "exploitation",
            "match": {},
        })
        result = validate_roe_spec(valid_spec)
        assert not any("UNKNOWN_MATCH_KEYS" in i.code for i in result.warnings)

    def test_unknown_match_keys_warns(self, valid_spec):
        """Match criteria with only unrecognized keys triggers warning."""
        valid_spec["actions"]["denied"].append({
            "category": "exploitation",
            "match": {"destination_not_in": "scope.in_scope.networks"},
        })
        result = validate_roe_spec(valid_spec)
        assert any("UNKNOWN_MATCH_KEYS" in i.code for i in result.warnings)


# ---------------------------------------------------------------------------
# Coverage warnings (Level 3)
# ---------------------------------------------------------------------------

class TestCoverageWarnings:

    def test_no_emergency_section_warns(self, valid_spec):
        del valid_spec["emergency"]
        result = validate_roe_spec(valid_spec)
        assert any("MISSING_EMERGENCY" in i.code for i in result.warnings)

    def test_kill_switch_disabled_warns(self, valid_spec):
        valid_spec["emergency"]["kill_switch"] = False
        result = validate_roe_spec(valid_spec)
        assert any("KILL_SWITCH_DISABLED" in i.code for i in result.warnings)

    def test_no_denied_actions_warns(self, valid_spec):
        valid_spec["actions"]["denied"] = []
        result = validate_roe_spec(valid_spec)
        assert any("EMPTY_DENIED_ACTIONS" in i.code for i in result.warnings)

    def test_missing_constraints_warns(self, valid_spec):
        del valid_spec["constraints"]
        result = validate_roe_spec(valid_spec)
        assert any("MISSING_CONSTRAINTS" in i.code for i in result.warnings)

    def test_missing_out_of_scope_warns(self, valid_spec):
        del valid_spec["scope"]["out_of_scope"]
        result = validate_roe_spec(valid_spec)
        assert any("MISSING_OUT_OF_SCOPE" in i.code for i in result.warnings)


# ---------------------------------------------------------------------------
# File-based validation
# ---------------------------------------------------------------------------

class TestFileValidation:

    def test_valid_local_corp_roe_passes(self):
        result = validate_roe_file("examples/local_corp_roe.yaml")
        assert result.valid

    def test_valid_localhost_webapp_roe_passes(self):
        result = validate_roe_file("examples/localhost_webapp_roe.yaml")
        assert result.valid

    def test_valid_corpsec_labs_roe_passes(self):
        result = validate_roe_file("examples/corpsec_labs_roe.yaml")
        assert result.valid

    def test_missing_file_fails(self):
        result = validate_roe_file("nonexistent_file.yaml")
        assert not result.valid
        assert any("FILE_NOT_FOUND" in i.code for i in result.errors)
