"""
Tests for src.core.rule_engine — Deterministic Rule Engine.
"""

from __future__ import annotations

from src.core.action_intent import (
    ActionCategory,
    ImpactLevel,
    ImpactAssessment,
)
from src.core.rule_engine import RuleEngine, RuleVerdict


# ---------------------------------------------------------------------------
# In-scope checks
# ---------------------------------------------------------------------------

def test_in_scope_ip_allowed_port_is_allowed(sample_roe_spec, make_intent):
    """An in-scope IP on an allowed port should be HARD_ALLOW or NEEDS_EVALUATION."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
    )
    result = engine.evaluate(intent)
    assert result.verdict in (RuleVerdict.HARD_ALLOW, RuleVerdict.NEEDS_EVALUATION)


def test_in_scope_ip_with_allowed_category_is_hard_allow(sample_roe_spec, make_intent):
    """An in-scope IP + allowed category should produce HARD_ALLOW."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_ALLOW


# ---------------------------------------------------------------------------
# Out-of-scope checks — IP
# ---------------------------------------------------------------------------

def test_out_of_scope_ip_is_hard_deny(sample_roe_spec, make_intent):
    """An out-of-scope IP should produce HARD_DENY."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="curl",
        host="10.0.2.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY
    assert any("out-of-scope" in r.description.lower() or "out of scope" in r.description.lower()
               for r in result.matched_rules)


def test_out_of_scope_payment_network_is_hard_deny(sample_roe_spec, make_intent):
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="nmap",
        host="10.0.3.1",
        port=None,
        category=ActionCategory.PORT_SCANNING,
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY


# ---------------------------------------------------------------------------
# Out-of-scope checks — Domain
# ---------------------------------------------------------------------------

def test_out_of_scope_domain_is_hard_deny(sample_roe_spec, make_intent):
    """A domain matching an out-of-scope pattern should produce HARD_DENY."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="curl",
        host="staging.payments.corp.local",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        domain="staging.payments.corp.local",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY


def test_out_of_scope_internal_domain_is_hard_deny(sample_roe_spec, make_intent):
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="curl",
        host="wiki.internal.corp.local",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        domain="wiki.internal.corp.local",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY


# ---------------------------------------------------------------------------
# Denied action categories
# ---------------------------------------------------------------------------

def test_denied_action_dos_is_hard_deny(sample_roe_spec, make_intent):
    """Denial of service is always denied."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="hping3",
        host="10.0.0.50",
        port=80,
        category=ActionCategory.DENIAL_OF_SERVICE,
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY
    assert any("denial_of_service" in r.matched_value for r in result.matched_rules)


def test_denied_action_direct_db_access_is_hard_deny(sample_roe_spec, make_intent):
    """Direct database access is denied."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="psql",
        host="10.0.0.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        service="postgresql",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY


def test_denied_action_lateral_movement_is_hard_deny(sample_roe_spec, make_intent):
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="ssh",
        host="10.0.0.50",
        port=22,
        category=ActionCategory.LATERAL_MOVEMENT,
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY


# ---------------------------------------------------------------------------
# Allowed action categories
# ---------------------------------------------------------------------------

def test_allowed_reconnaissance_with_in_scope_target(sample_roe_spec, make_intent):
    """Reconnaissance against an in-scope target with matching subcategory should be allowed."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="nmap",
        host="10.0.0.50",
        port=None,
        category=ActionCategory.RECONNAISSANCE,
        subcategory="port_scan",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_ALLOW


def test_allowed_web_application_testing(sample_roe_spec, make_intent):
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="sql_injection",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_ALLOW


# ---------------------------------------------------------------------------
# Out-of-scope services
# ---------------------------------------------------------------------------

def test_out_of_scope_service_database_is_hard_deny(sample_roe_spec, make_intent):
    """Targeting a database service type should be HARD_DENY."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="psql",
        host="10.0.0.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        service="database",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY


def test_out_of_scope_service_via_protocol(sample_roe_spec, make_intent):
    """Targeting a service matching an out-of-scope protocol should be HARD_DENY."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="psql",
        host="10.0.0.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        service="postgresql",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY


# ---------------------------------------------------------------------------
# Requires approval
# ---------------------------------------------------------------------------

def test_requires_approval_exploitation_critical(sample_roe_spec, make_intent):
    """Exploitation with critical severity should require human approval."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="metasploit",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.EXPLOITATION,
        severity=ImpactLevel.CRITICAL,
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.NEEDS_HUMAN


# ---------------------------------------------------------------------------
# Unknown / ambiguous targets
# ---------------------------------------------------------------------------

def test_unknown_target_no_host_needs_human_or_evaluation(sample_roe_spec, make_intent):
    """An intent with no target host or domain triggers the 'any' requires_approval
    rule (condition: target.host not in scope.in_scope), which yields NEEDS_HUMAN
    because an empty host cannot be confirmed as in-scope."""
    engine = RuleEngine(sample_roe_spec)
    intent = make_intent(
        tool="custom_tool",
        host="",
        port=None,
        category=ActionCategory.OTHER,
    )
    result = engine.evaluate(intent)
    # The 'any' category requires_approval rule with "target.host not in scope"
    # catches this because an empty host is not confirmable as in-scope.
    assert result.verdict in (RuleVerdict.NEEDS_HUMAN, RuleVerdict.NEEDS_EVALUATION)
