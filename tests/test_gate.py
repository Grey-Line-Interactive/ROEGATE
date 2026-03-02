"""
Tests for src.gate.gate — ROE Gate Orchestrator.
"""

from __future__ import annotations

import json

from src.core.action_intent import ActionCategory, ImpactLevel
from src.gate.gate import ROEGate, GateDecision, GateResult
from tests.helpers import MockLLMProvider


# ---------------------------------------------------------------------------
# Full pipeline: ALLOW
# ---------------------------------------------------------------------------

def test_pipeline_in_scope_web_test_allow(gate_with_mock, make_intent):
    """In-scope web test against allowed category should produce ALLOW with a token."""
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    result = gate_with_mock.evaluate(intent)
    assert result.decision == GateDecision.ALLOW
    assert result.token is not None
    assert result.token.signature.startswith("hmac-sha256:")
    assert result.token.intent_id == intent.intent_id


# ---------------------------------------------------------------------------
# Full pipeline: DENY
# ---------------------------------------------------------------------------

def test_pipeline_out_of_scope_db_access_deny(gate_with_mock, make_intent):
    """Out-of-scope database access should produce DENY."""
    intent = make_intent(
        tool="psql",
        host="10.0.2.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
    )
    result = gate_with_mock.evaluate(intent)
    assert result.decision == GateDecision.DENY
    assert result.token is None
    assert result.denial_count >= 1


# ---------------------------------------------------------------------------
# Repeated denials -> HALT
# ---------------------------------------------------------------------------

def test_pipeline_repeated_denials_halt(sample_roe_spec, make_intent):
    """Three consecutive denials should halt the session."""
    provider = MockLLMProvider(verdict="ALLOW", confidence=0.9)
    gate = ROEGate(
        roe_spec=sample_roe_spec,
        llm_provider=provider,
        max_consecutive_denials=3,
    )

    # Send 3 denied requests (out of scope)
    for i in range(3):
        intent = make_intent(
            tool="psql",
            host="10.0.2.50",
            port=5432,
            category=ActionCategory.DIRECT_DATABASE_ACCESS,
            session="halt-test-session",
        )
        result = gate.evaluate(intent)

    assert result.decision == GateDecision.HALT
    assert "HALTED" in result.reasoning.upper()


def test_session_halt_persists(sample_roe_spec, make_intent):
    """After halt, further requests from the same session should still be HALT."""
    provider = MockLLMProvider(verdict="ALLOW", confidence=0.9)
    gate = ROEGate(
        roe_spec=sample_roe_spec,
        llm_provider=provider,
        max_consecutive_denials=3,
    )

    # Trigger halt
    for i in range(3):
        intent = make_intent(
            tool="psql",
            host="10.0.2.50",
            port=5432,
            category=ActionCategory.DIRECT_DATABASE_ACCESS,
            session="persist-halt",
        )
        gate.evaluate(intent)

    # Even a valid request should be halted now
    valid_intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        session="persist-halt",
    )
    result = gate.evaluate(valid_intent)
    assert result.decision == GateDecision.HALT


# ---------------------------------------------------------------------------
# Resume session
# ---------------------------------------------------------------------------

def test_resume_session_clears_halt(sample_roe_spec, make_intent):
    provider = MockLLMProvider(verdict="ALLOW", confidence=0.9)
    gate = ROEGate(
        roe_spec=sample_roe_spec,
        llm_provider=provider,
        max_consecutive_denials=3,
    )

    # Trigger halt
    for i in range(3):
        intent = make_intent(
            tool="psql",
            host="10.0.2.50",
            port=5432,
            category=ActionCategory.DIRECT_DATABASE_ACCESS,
            session="resume-test",
        )
        gate.evaluate(intent)

    # Resume
    gate.resume_session("resume-test")

    # Should work again
    valid_intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
        session="resume-test",
    )
    result = gate.evaluate(valid_intent)
    assert result.decision == GateDecision.ALLOW


# ---------------------------------------------------------------------------
# Emergency halt
# ---------------------------------------------------------------------------

def test_emergency_halt(gate_with_mock, make_intent):
    gate_with_mock.emergency_halt()
    intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    # After emergency halt, the signer raises RuntimeError in sign_action.
    # The rule engine and judge still evaluate first; only the signing step
    # will fail. However, `verify_token` should also reject.
    # We need to check that the gate handles this. Since the gate calls
    # signer.sign_action which raises RuntimeError, we expect the gate
    # to propagate that or handle it.
    try:
        result = gate_with_mock.evaluate(intent)
        # If the gate catches the error, it should deny
        assert result.decision in (GateDecision.DENY, GateDecision.HALT)
    except RuntimeError:
        # If the gate doesn't catch RuntimeError from signer, that's also
        # a valid enforcement mechanism
        pass
    finally:
        gate_with_mock.signer.resume()


# ---------------------------------------------------------------------------
# GateResult serialization
# ---------------------------------------------------------------------------

def test_gate_result_to_dict():
    result = GateResult(
        decision=GateDecision.DENY,
        reasoning="Out of scope",
        denial_count=2,
    )
    d = result.to_dict()
    assert d["decision"] == "DENY"
    assert d["reasoning"] == "Out of scope"
    assert d["denial_count"] == 2
    assert "evaluated_at" in d


def test_gate_result_to_agent_response_hides_internals():
    """to_agent_response should not include internal evaluation details."""
    result = GateResult(
        decision=GateDecision.ALLOW,
        reasoning="Approved",
    )
    response = result.to_agent_response()
    assert response["decision"] == "ALLOW"
    assert response["reasoning"] == "Approved"
    # Should NOT contain rule_engine or judge keys at the top level
    assert "rule_engine" not in response
    assert "judge" not in response


def test_gate_result_to_agent_response_deny_includes_denied_because(gate_with_mock, make_intent):
    """Denied responses should include denied_because for the agent."""
    intent = make_intent(
        tool="psql",
        host="10.0.2.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
    )
    result = gate_with_mock.evaluate(intent)
    assert result.decision == GateDecision.DENY
    response = result.to_agent_response()
    assert "denied_because" in response
    assert isinstance(response["denied_because"], list)
    assert len(response["denied_because"]) > 0


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def test_get_stats(gate_with_mock, make_intent):
    # Make one allowed call
    allow_intent = make_intent(
        tool="curl",
        host="10.0.0.50",
        port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
    )
    gate_with_mock.evaluate(allow_intent)

    # Make one denied call
    deny_intent = make_intent(
        tool="psql",
        host="10.0.2.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
    )
    gate_with_mock.evaluate(deny_intent)

    stats = gate_with_mock.get_stats()
    assert stats["total_evaluations"] >= 2
    assert stats["total_allows"] >= 1
    assert stats["total_denials"] >= 1
    assert "roe_hash" in stats


def test_denial_count_increments(gate_with_mock, make_intent):
    deny_intent = make_intent(
        tool="psql",
        host="10.0.2.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        session="denial-count-test",
    )

    r1 = gate_with_mock.evaluate(deny_intent)
    assert r1.denial_count == 1

    deny_intent2 = make_intent(
        tool="psql",
        host="10.0.2.50",
        port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        session="denial-count-test",
    )
    r2 = gate_with_mock.evaluate(deny_intent2)
    assert r2.denial_count == 2
