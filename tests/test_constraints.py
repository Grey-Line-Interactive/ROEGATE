"""
Tests for constraints evaluation in the deterministic Rule Engine.

The constraints check sits between approval gates (check 6) and the final
in-scope/allowed check (check 8). It enforces global ROE constraints like
no_persistent_changes and no_production_data_storage.
"""

from __future__ import annotations

from src.core.action_intent import (
    ActionCategory,
    DataAccessType,
    ImpactLevel,
    ImpactAssessment,
)
from src.core.rule_engine import RuleEngine, RuleVerdict


# ---------------------------------------------------------------------------
# Helpers — ROE specs with constraints
# ---------------------------------------------------------------------------

def _roe_with_constraints(**constraint_overrides):
    """Build a minimal ROE spec with specific constraints."""
    constraints = {
        "max_concurrent_connections": 10,
        "global_rate_limit": "200 requests/second",
    }
    constraints.update(constraint_overrides)
    return {
        "metadata": {"engagement_id": "ENG-TEST", "client": "Test", "version": 1},
        "schedule": {
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2030-12-31T23:59:59Z",
            "timezone": "UTC",
            "blackout_dates": [],
        },
        "scope": {
            "in_scope": {
                "networks": [
                    {"cidr": "10.0.0.0/24", "ports": [80, 443]},
                ],
                "domains": [],
            },
            "out_of_scope": {"networks": [], "domains": [], "services": []},
        },
        "actions": {
            "allowed": [
                {"category": "reconnaissance", "methods": ["port_scan"]},
                {"category": "web_application_testing", "methods": ["sql_injection", "xss"]},
            ],
            "denied": [],
            "requires_approval": [],
        },
        "constraints": constraints,
    }


# ---------------------------------------------------------------------------
# no_persistent_changes: blocks irreversible actions
# ---------------------------------------------------------------------------

def test_no_persistent_changes_blocks_irreversible(make_intent):
    """When no_persistent_changes is true, actions with reversibility='none' are HARD_DENY."""
    spec = _roe_with_constraints(no_persistent_changes=True)
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    intent.impact.reversibility = "none"
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY
    assert any("no persistent changes" in r.description for r in result.matched_rules)
    assert any(r.rule_type == "constraint" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# no_persistent_changes: blocks write data_access
# ---------------------------------------------------------------------------

def test_no_persistent_changes_blocks_write_access(make_intent):
    """When no_persistent_changes is true, actions with data_access=WRITE are HARD_DENY."""
    spec = _roe_with_constraints(no_persistent_changes=True)
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    intent.impact.data_access = DataAccessType.WRITE
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY
    assert any("write" in r.description for r in result.matched_rules)


def test_no_persistent_changes_blocks_delete_access(make_intent):
    """When no_persistent_changes is true, actions with data_access=DELETE are HARD_DENY."""
    spec = _roe_with_constraints(no_persistent_changes=True)
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    intent.impact.data_access = DataAccessType.DELETE
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY
    assert any("delete" in r.description for r in result.matched_rules)


# ---------------------------------------------------------------------------
# no_production_data_storage: blocks DATA_EXFILTRATION
# ---------------------------------------------------------------------------

def test_no_production_data_storage_blocks_exfiltration(make_intent):
    """When no_production_data_storage is true, DATA_EXFILTRATION actions are HARD_DENY."""
    spec = _roe_with_constraints(no_production_data_storage=True)
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="custom",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.DATA_EXFILTRATION,
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_DENY
    assert any("no production data storage" in r.description for r in result.matched_rules)
    assert any(r.rule_path == "constraints.no_production_data_storage" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# Constraints pass when satisfied
# ---------------------------------------------------------------------------

def test_constraints_pass_when_satisfied(make_intent):
    """An action that satisfies all constraints should not be blocked by the constraints check."""
    spec = _roe_with_constraints(
        no_persistent_changes=True,
        no_production_data_storage=True,
    )
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="nmap",
        host="10.0.0.50",
        port=None,
        category=ActionCategory.RECONNAISSANCE,
        subcategory="port_scan",
    )
    # Default impact: reversibility="full", data_access=NONE, category is not DATA_EXFILTRATION
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_ALLOW


def test_read_access_allowed_with_no_persistent_changes(make_intent):
    """Read-only actions should pass the no_persistent_changes constraint."""
    spec = _roe_with_constraints(no_persistent_changes=True)
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    intent.impact.data_access = DataAccessType.READ
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_ALLOW


# ---------------------------------------------------------------------------
# Missing constraints section doesn't cause errors
# ---------------------------------------------------------------------------

def test_missing_constraints_section_no_error(make_intent):
    """A ROE spec with no constraints section should not crash the engine."""
    spec = _roe_with_constraints()
    # Remove constraints entirely
    del spec["constraints"]
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="nmap",
        host="10.0.0.50",
        port=None,
        category=ActionCategory.RECONNAISSANCE,
        subcategory="port_scan",
    )
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_ALLOW


def test_empty_constraints_section_no_error(make_intent):
    """A ROE spec with an empty constraints dict should not crash the engine."""
    spec = _roe_with_constraints()
    spec["constraints"] = {}
    engine = RuleEngine(spec)
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="sql_injection",
    )
    # Should still work -- no constraints to violate
    result = engine.evaluate(intent)
    assert result.verdict == RuleVerdict.HARD_ALLOW
