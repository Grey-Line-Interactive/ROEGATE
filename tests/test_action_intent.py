"""
Tests for src.core.action_intent — Action Intent Serialization.
"""

from __future__ import annotations

import json

from src.core.action_intent import (
    ActionCategory,
    ImpactLevel,
    DataAccessType,
    Target,
    ImpactAssessment,
    ActionIntent,
    classify_tool_call,
    PORT_SERVICE_MAP,
    TOOL_CATEGORY_MAP,
)


# ---------------------------------------------------------------------------
# ActionCategory enum
# ---------------------------------------------------------------------------

def test_action_category_reconnaissance():
    assert ActionCategory.RECONNAISSANCE.value == "reconnaissance"


def test_action_category_web_application_testing():
    assert ActionCategory.WEB_APPLICATION_TESTING.value == "web_application_testing"


def test_action_category_direct_database_access():
    assert ActionCategory.DIRECT_DATABASE_ACCESS.value == "direct_database_access"


def test_action_category_denial_of_service():
    assert ActionCategory.DENIAL_OF_SERVICE.value == "denial_of_service"


def test_action_category_other():
    assert ActionCategory.OTHER.value == "other"


def test_action_category_all_expected_values_exist():
    expected = {
        "reconnaissance", "port_scanning", "service_enumeration",
        "web_application_testing", "api_testing", "authentication_testing",
        "credential_testing", "authorization_testing", "injection_testing",
        "exploitation", "post_exploitation", "lateral_movement",
        "privilege_escalation", "data_exfiltration", "denial_of_service",
        "social_engineering", "direct_database_access", "file_access",
        "command_execution", "network_connect", "other",
    }
    actual = {member.value for member in ActionCategory}
    assert expected == actual


# ---------------------------------------------------------------------------
# ImpactLevel enum
# ---------------------------------------------------------------------------

def test_impact_level_values():
    expected = {"none", "low", "medium", "high", "critical"}
    actual = {member.value for member in ImpactLevel}
    assert expected == actual


def test_impact_level_ordering_accessible():
    assert ImpactLevel.NONE.value == "none"
    assert ImpactLevel.LOW.value == "low"
    assert ImpactLevel.CRITICAL.value == "critical"


# ---------------------------------------------------------------------------
# Target dataclass
# ---------------------------------------------------------------------------

def test_target_defaults():
    t = Target()
    assert t.host == ""
    assert t.port is None
    assert t.protocol is None
    assert t.service is None
    assert t.url is None
    assert t.domain is None


def test_target_to_dict_excludes_none():
    t = Target(host="10.0.0.1", port=443)
    d = t.to_dict()
    assert d["host"] == "10.0.0.1"
    assert d["port"] == 443
    assert "protocol" not in d
    assert "service" not in d
    assert "url" not in d
    assert "domain" not in d


def test_target_to_dict_full():
    t = Target(
        host="10.0.0.1",
        port=443,
        protocol="tcp",
        service="https",
        url="https://example.com",
        domain="example.com",
    )
    d = t.to_dict()
    assert len(d) == 6
    assert d["domain"] == "example.com"


# ---------------------------------------------------------------------------
# ImpactAssessment dataclass
# ---------------------------------------------------------------------------

def test_impact_assessment_defaults():
    ia = ImpactAssessment()
    assert ia.data_access == DataAccessType.NONE
    assert ia.service_disruption == ImpactLevel.NONE
    assert ia.reversibility == "full"
    assert ia.estimated_severity == ImpactLevel.LOW
    assert ia.record_count_estimate is None


def test_impact_assessment_to_dict():
    ia = ImpactAssessment(
        data_access=DataAccessType.READ,
        service_disruption=ImpactLevel.MEDIUM,
        reversibility="partial",
        estimated_severity=ImpactLevel.HIGH,
        record_count_estimate=100,
    )
    d = ia.to_dict()
    assert d["data_access"] == "read"
    assert d["service_disruption"] == "medium"
    assert d["reversibility"] == "partial"
    assert d["estimated_severity"] == "high"
    assert d["record_count_estimate"] == 100


def test_impact_assessment_to_dict_omits_none_record_count():
    ia = ImpactAssessment()
    d = ia.to_dict()
    assert "record_count_estimate" not in d


# ---------------------------------------------------------------------------
# ActionIntent dataclass
# ---------------------------------------------------------------------------

def test_action_intent_creation():
    intent = ActionIntent(
        tool="nmap",
        category=ActionCategory.PORT_SCANNING,
        description="Port scan test target",
        target=Target(host="10.0.0.1", port=80),
    )
    assert intent.tool == "nmap"
    assert intent.category == ActionCategory.PORT_SCANNING
    assert intent.target.host == "10.0.0.1"
    assert intent.intent_id  # auto-generated UUID


def test_action_intent_to_dict():
    intent = ActionIntent(
        tool="curl",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
        description="XSS test",
        target=Target(host="10.0.0.50", port=443),
        justification="Testing for reflected XSS",
    )
    d = intent.to_dict()
    assert d["action"]["tool"] == "curl"
    assert d["action"]["category"] == "web_application_testing"
    assert d["action"]["subcategory"] == "xss"
    assert d["target"]["host"] == "10.0.0.50"
    assert d["target"]["port"] == 443
    assert d["agent_justification"] == "Testing for reflected XSS"
    assert "intent_id" in d
    assert "timestamp" in d


def test_action_intent_to_json():
    intent = ActionIntent(
        tool="nmap",
        category=ActionCategory.PORT_SCANNING,
        target=Target(host="10.0.0.1"),
    )
    j = intent.to_json()
    parsed = json.loads(j)
    assert parsed["action"]["tool"] == "nmap"
    # JSON should be deterministic (sorted keys)
    assert j == json.dumps(parsed, sort_keys=True, separators=(",", ":"))


def test_action_intent_auto_fields():
    intent = ActionIntent()
    assert len(intent.intent_id) > 0
    assert len(intent.timestamp) > 0


# ---------------------------------------------------------------------------
# classify_tool_call()
# ---------------------------------------------------------------------------

def test_classify_nmap_is_port_scanning():
    intent = classify_tool_call("nmap", target_host="10.0.0.1")
    assert intent.category == ActionCategory.PORT_SCANNING
    assert intent.tool == "nmap"
    assert intent.target.host == "10.0.0.1"


def test_classify_psql_is_direct_database_access():
    intent = classify_tool_call("psql", target_host="10.0.2.1")
    assert intent.category == ActionCategory.DIRECT_DATABASE_ACCESS
    assert intent.tool == "psql"


def test_classify_curl_is_web_application_testing():
    intent = classify_tool_call("curl", target_host="10.0.0.50")
    assert intent.category == ActionCategory.WEB_APPLICATION_TESTING
    assert intent.tool == "curl"


def test_classify_with_database_port_5432():
    intent = classify_tool_call("nmap", target_host="10.0.0.1", target_port=5432)
    assert intent.category == ActionCategory.DIRECT_DATABASE_ACCESS
    assert intent.target.service == "postgresql"
    assert intent.target.port == 5432


def test_classify_with_database_port_3306():
    intent = classify_tool_call("nmap", target_host="10.0.0.1", target_port=3306)
    assert intent.category == ActionCategory.DIRECT_DATABASE_ACCESS
    assert intent.target.service == "mysql"
    assert intent.target.port == 3306


def test_classify_with_web_port_no_override():
    """Web ports do NOT override the tool-based classification because
    DIRECT_DATABASE_ACCESS and COMMAND_EXECUTION take precedence."""
    intent = classify_tool_call("nmap", target_host="10.0.0.1", target_port=80)
    # PORT_SERVICE_MAP has port 80 -> WEB_APPLICATION_TESTING, but override
    # only happens for DIRECT_DATABASE_ACCESS or COMMAND_EXECUTION.
    assert intent.category == ActionCategory.PORT_SCANNING


def test_classify_unknown_tool():
    intent = classify_tool_call("custom_tool", target_host="10.0.0.1")
    assert intent.category == ActionCategory.OTHER


def test_classify_extra_kwargs_stored():
    intent = classify_tool_call("nmap", target_host="10.0.0.1", ports="1-1000")
    assert intent.parameters["ports"] == "1-1000"


# ---------------------------------------------------------------------------
# PORT_SERVICE_MAP
# ---------------------------------------------------------------------------

def test_port_service_map_contains_postgres():
    assert 5432 in PORT_SERVICE_MAP
    service, cat = PORT_SERVICE_MAP[5432]
    assert service == "postgresql"
    assert cat == ActionCategory.DIRECT_DATABASE_ACCESS


def test_port_service_map_contains_mysql():
    assert 3306 in PORT_SERVICE_MAP
    service, cat = PORT_SERVICE_MAP[3306]
    assert service == "mysql"
    assert cat == ActionCategory.DIRECT_DATABASE_ACCESS


def test_port_service_map_contains_ssh():
    assert 22 in PORT_SERVICE_MAP
    service, cat = PORT_SERVICE_MAP[22]
    assert service == "ssh"
    assert cat == ActionCategory.COMMAND_EXECUTION


def test_port_service_map_contains_http():
    assert 80 in PORT_SERVICE_MAP
    service, cat = PORT_SERVICE_MAP[80]
    assert service == "http"
    assert cat == ActionCategory.WEB_APPLICATION_TESTING


def test_port_service_map_contains_ftp():
    assert 21 in PORT_SERVICE_MAP
    service, cat = PORT_SERVICE_MAP[21]
    assert service == "ftp"
    assert cat == ActionCategory.FILE_ACCESS
