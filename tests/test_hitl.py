"""Tests for Human-in-the-Loop (HITL) approval system."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

import pytest

from src.core.action_intent import (
    ActionCategory,
    ActionIntent,
    DataAccessType,
    ImpactAssessment,
    ImpactLevel,
    Target,
)
from src.gate.gate import GateDecision, GateResult, ROEGate
from src.service.gate_api import ApprovalStore, PendingApproval


# ── Fixtures ─────────────────────────────────────────────────────────────────

# Minimal ROE spec with a requires_approval rule
_ROE_SPEC = {
    "metadata": {
        "engagement_id": "HITL-TEST-001",
        "client": "Test Corp",
        "created": "2024-01-01T00:00:00Z",
        "approved_by": "Operator",
        "version": 1,
    },
    "schedule": {
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_until": "2030-12-31T23:59:59Z",
        "timezone": "UTC",
    },
    "scope": {
        "in_scope": {
            "networks": [
                {"cidr": "10.0.0.0/24", "description": "Web tier", "ports": [80, 443]},
            ],
            "domains": [],
        },
        "out_of_scope": {
            "networks": [
                {"cidr": "192.168.1.0/24", "reason": "Production"},
            ],
            "domains": [],
            "services": [],
        },
    },
    "actions": {
        "allowed": [
            {"category": "reconnaissance", "methods": ["port_scan"]},
        ],
        "denied": [],
        "requires_approval": [
            {
                "category": "any",
                "condition": "target.host not in scope.in_scope",
                "approver": "human_operator",
                "timeout": "5m",
            },
        ],
    },
    "constraints": {},
}


class MockJudge:
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return json.dumps({
            "verdict": "ALLOW",
            "confidence": 0.95,
            "reasoning": "Mock judge: allowed",
            "roe_clauses_cited": [],
        })


def _make_intent(host: str = "172.16.0.1", session: str = "test-session") -> ActionIntent:
    """Create an intent targeting an out-of-scope host (triggers NEEDS_HUMAN)."""
    return ActionIntent(
        agent_session=session,
        engagement_id="HITL-TEST-001",
        tool="nmap",
        category=ActionCategory.RECONNAISSANCE,
        subcategory="port_scan",
        description="Scan host",
        target=Target(host=host, port=80, protocol="tcp"),
        parameters={"-sT": True},
        impact=ImpactAssessment(
            data_access=DataAccessType.NONE,
            estimated_severity=ImpactLevel.LOW,
        ),
        justification="Testing",
    )


def _make_in_scope_intent(session: str = "test-session") -> ActionIntent:
    """Create an intent targeting an in-scope host."""
    return ActionIntent(
        agent_session=session,
        engagement_id="HITL-TEST-001",
        tool="nmap",
        category=ActionCategory.RECONNAISSANCE,
        subcategory="port_scan",
        description="Scan in-scope host",
        target=Target(host="10.0.0.5", port=80, protocol="tcp"),
        parameters={"-sT": True},
        impact=ImpactAssessment(
            data_access=DataAccessType.NONE,
            estimated_severity=ImpactLevel.LOW,
        ),
        justification="Testing",
    )


# ── Gate Core HITL Tests ─────────────────────────────────────────────────────


class TestGateHITLOff:
    """With HITL disabled (default), NEEDS_HUMAN → DENY."""

    def _make_gate(self) -> ROEGate:
        return ROEGate(
            roe_spec=_ROE_SPEC,
            llm_provider=MockJudge(),
            human_in_the_loop=False,
        )

    def test_out_of_scope_denied(self):
        gate = self._make_gate()
        result = gate.evaluate(_make_intent())
        assert result.decision == GateDecision.DENY
        assert "HITL disabled" in result.reasoning

    def test_denial_counted(self):
        gate = self._make_gate()
        result = gate.evaluate(_make_intent())
        assert result.denial_count == 1

    def test_consecutive_denials_trigger_halt(self):
        gate = self._make_gate()
        gate.max_consecutive_denials = 3
        for i in range(3):
            result = gate.evaluate(_make_intent())
        assert result.decision == GateDecision.HALT
        assert "AGENT HALTED" in result.reasoning

    def test_in_scope_still_allowed(self):
        gate = self._make_gate()
        result = gate.evaluate(_make_in_scope_intent())
        assert result.decision == GateDecision.ALLOW


class TestGateHITLOn:
    """With HITL enabled, NEEDS_HUMAN → ESCALATE."""

    def _make_gate(self) -> ROEGate:
        return ROEGate(
            roe_spec=_ROE_SPEC,
            llm_provider=MockJudge(),
            human_in_the_loop=True,
        )

    def test_out_of_scope_escalated(self):
        gate = self._make_gate()
        result = gate.evaluate(_make_intent())
        assert result.decision == GateDecision.ESCALATE
        assert "human approval" in result.reasoning.lower()

    def test_in_scope_still_allowed(self):
        gate = self._make_gate()
        result = gate.evaluate(_make_in_scope_intent())
        assert result.decision == GateDecision.ALLOW


# ── ApprovalStore Tests ──────────────────────────────────────────────────────


class TestApprovalStore:
    def _make_approval(self, approval_id: str = "test-123", timeout: int = 300) -> PendingApproval:
        return PendingApproval(
            approval_id=approval_id,
            intent_dict={"action": {"tool": "nmap"}},
            gate_result_dict={"decision": "ESCALATE"},
            tool="nmap",
            target_host="172.16.0.1",
            category="reconnaissance",
            reasoning="Test reason",
            timeout_seconds=timeout,
        )

    def test_add_and_get(self):
        store = ApprovalStore()
        approval = self._make_approval()
        store.add(approval)
        fetched = store.get("test-123")
        assert fetched is not None
        assert fetched.approval_id == "test-123"
        assert fetched.status == "pending"

    def test_get_nonexistent(self):
        store = ApprovalStore()
        assert store.get("nonexistent") is None

    def test_resolve_approve(self):
        store = ApprovalStore()
        store.add(self._make_approval())
        resolved = store.resolve("test-123", approved=True, token_dict={"token_id": "t1"})
        assert resolved is not None
        assert resolved.status == "approved"
        assert resolved.token_dict == {"token_id": "t1"}

    def test_resolve_deny(self):
        store = ApprovalStore()
        store.add(self._make_approval())
        resolved = store.resolve("test-123", approved=False)
        assert resolved is not None
        assert resolved.status == "denied"
        assert resolved.token_dict is None

    def test_double_resolve(self):
        store = ApprovalStore()
        store.add(self._make_approval())
        store.resolve("test-123", approved=True, token_dict={"token_id": "t1"})
        # Second resolve returns the already-resolved approval
        second = store.resolve("test-123", approved=False)
        assert second is not None
        assert second.status == "approved"  # unchanged

    def test_get_all_pending(self):
        store = ApprovalStore()
        store.add(self._make_approval("a1"))
        store.add(self._make_approval("a2"))
        store.add(self._make_approval("a3"))
        store.resolve("a2", approved=True)
        pending = store.get_all_pending()
        assert len(pending) == 2
        assert {a.approval_id for a in pending} == {"a1", "a3"}

    def test_expired_approval(self):
        store = ApprovalStore()
        approval = self._make_approval(timeout=0)  # immediately expires
        # Backdate created_at
        approval.created_at = "2020-01-01T00:00:00+00:00"
        store.add(approval)
        fetched = store.get("test-123")
        assert fetched is not None
        assert fetched.status == "timeout"

    def test_expired_not_in_pending(self):
        store = ApprovalStore()
        approval = self._make_approval(timeout=0)
        approval.created_at = "2020-01-01T00:00:00+00:00"
        store.add(approval)
        pending = store.get_all_pending()
        assert len(pending) == 0

    def test_thread_safety(self):
        store = ApprovalStore()
        errors: list[Exception] = []

        def add_approvals():
            try:
                for i in range(50):
                    store.add(self._make_approval(f"thread-{i}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_approvals) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# ── PendingApproval Tests ────────────────────────────────────────────────────


class TestPendingApproval:
    def test_to_dict(self):
        approval = PendingApproval(
            approval_id="abc",
            intent_dict={},
            gate_result_dict={},
            tool="nmap",
            target_host="10.0.0.1",
            category="reconnaissance",
            reasoning="Test",
        )
        d = approval.to_dict()
        assert d["approval_id"] == "abc"
        assert d["tool"] == "nmap"
        assert d["status"] == "pending"
        assert d["token"] is None

    def test_is_expired_false(self):
        approval = PendingApproval(
            approval_id="abc",
            intent_dict={},
            gate_result_dict={},
            tool="nmap",
            target_host="10.0.0.1",
            category="reconnaissance",
            reasoning="Test",
            timeout_seconds=300,
        )
        assert not approval.is_expired

    def test_is_expired_true(self):
        approval = PendingApproval(
            approval_id="abc",
            intent_dict={},
            gate_result_dict={},
            tool="nmap",
            target_host="10.0.0.1",
            category="reconnaissance",
            reasoning="Test",
            timeout_seconds=0,
            created_at="2020-01-01T00:00:00+00:00",
        )
        assert approval.is_expired


# ── Blocked Tools Tests ──────────────────────────────────────────────────────


class TestBlockedTools:
    """Verify that network reconnaissance tools are in the blocked list."""

    def test_ping_blocked_in_hook(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "bash_gate_hook",
            "/Volumes/DRIVE/roe_agent_gate/.claude/hooks/bash_gate_hook.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        expected = {"ping", "ping6", "fping", "traceroute", "traceroute6",
                    "mtr", "hping3", "arping", "tcpdump", "tshark", "nping"}
        assert expected.issubset(mod.KNOWN_NETWORK_TOOLS)

    def test_ping_blocked_in_agent(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "agent",
            "/Volumes/DRIVE/roe_agent_gate/examples/claude_code_pentest_agent.py",
        )
        mod = importlib.util.module_from_spec(spec)
        # Don't execute the module (it has side effects), just read the source
        import ast
        with open("/Volumes/DRIVE/roe_agent_gate/examples/claude_code_pentest_agent.py") as f:
            source = f.read()
        for tool in ["ping", "ping6", "fping", "traceroute", "traceroute6",
                      "mtr", "hping3", "arping", "tcpdump", "tshark", "nping"]:
            assert f'"{tool}"' in source, f"{tool} not found in KNOWN_NETWORK_TOOLS"
