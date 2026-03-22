"""Tests for compliance report generation."""

from __future__ import annotations

import json
import uuid
from typing import Optional

import pytest

from src.audit.logger import AuditEvent
from src.audit.compliance import (
    ComplianceReport,
    ComplianceReportGenerator,
    ReportSection,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _make_event(
    event_type: str = "action_evaluation",
    decision: str = "ALLOW",
    tool_name: str = "nmap",
    target: str = "192.168.1.0/24",
    in_scope: bool = True,
    token_issued: bool = True,
    denial_count: int = 0,
    judge: Optional[dict] = None,
    timestamp: str = "2026-01-15T10:00:00+00:00",
) -> AuditEvent:
    """Build a mock AuditEvent for testing."""
    details: dict = {}
    if event_type == "action_evaluation":
        details = {
            "intent": {"tool_name": tool_name, "target": target},
            "decision": decision,
            "reasoning": f"Mock reasoning for {decision}",
            "rule_engine": {"in_scope": in_scope, "matched_rules": []},
            "judge": judge if judge is not None else {"decision": decision},
            "token_issued": token_issued,
            "denial_count": denial_count,
        }
    elif event_type == "emergency_halt":
        details = {"triggered_by": "operator"}
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        event_type=event_type,
        details=details,
    )


def _clean_events() -> list[AuditEvent]:
    """A set of clean audit events — everything in scope and properly gated."""
    return [
        _make_event(decision="ALLOW", tool_name="nmap", target="192.168.1.0/24",
                     timestamp="2026-01-15T10:00:00+00:00"),
        _make_event(decision="ALLOW", tool_name="nikto", target="192.168.1.10",
                     timestamp="2026-01-15T10:05:00+00:00"),
        _make_event(decision="DENY", tool_name="sqlmap", target="10.0.0.1",
                     in_scope=False, token_issued=False,
                     timestamp="2026-01-15T10:10:00+00:00"),
        _make_event(decision="DENY", tool_name="sqlmap", target="10.0.0.1",
                     in_scope=False, token_issued=False, denial_count=2,
                     timestamp="2026-01-15T10:11:00+00:00"),
        _make_event(decision="ESCALATE", tool_name="metasploit", target="192.168.1.10",
                     token_issued=False,
                     timestamp="2026-01-15T10:15:00+00:00"),
        _make_event(event_type="emergency_halt",
                     timestamp="2026-01-15T10:20:00+00:00"),
    ]


_ROE_SPEC = {
    "metadata": {"engagement_name": "ACME Corp Pentest Q1 2026"},
    "scope": {
        "targets": [
            {"host": "192.168.1.0/24"},
            {"host": "192.168.1.10"},
        ],
    },
}

_ENGAGEMENT_ID = "test-engagement-001"


# ── SOC 2 Tests ──────────────────────────────────────────────────────────

class TestSOC2Report:
    def test_soc2_all_compliant(self):
        """Clean data produces an all-compliant SOC 2 report."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()

        assert report.report_type == "SOC2"
        assert report.engagement_id == _ENGAGEMENT_ID
        assert len(report.sections) == 7

        for section in report.sections:
            assert section.status == "COMPLIANT", (
                f"{section.control_id} should be COMPLIANT, got {section.status}"
            )

    def test_soc2_out_of_scope_allow_non_compliant(self):
        """An out-of-scope ALLOW makes CC6.6 NON_COMPLIANT."""
        events = [
            _make_event(
                decision="ALLOW",
                tool_name="nmap",
                target="10.99.99.99",
                in_scope=False,
                token_issued=True,
            ),
        ]
        gen = ComplianceReportGenerator(events, _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()

        cc6_6 = next(s for s in report.sections if s.control_id == "CC6.6")
        assert cc6_6.status == "NON_COMPLIANT"
        assert any("WARNING" in e for e in cc6_6.evidence)

    def test_soc2_all_control_ids_present(self):
        """All 7 SOC 2 control IDs are present in the report."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()

        expected_ids = {"CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.8", "CC7.2", "CC7.3"}
        actual_ids = {s.control_id for s in report.sections}
        assert actual_ids == expected_ids

    def test_soc2_emergency_halt_evidence(self):
        """CC6.8 captures emergency halt evidence."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()

        cc6_8 = next(s for s in report.sections if s.control_id == "CC6.8")
        assert cc6_8.status == "COMPLIANT"
        assert any("exercised" in e for e in cc6_8.evidence)

    def test_soc2_consecutive_denial_tracking(self):
        """CC7.3 reports consecutive denial counts."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()

        cc7_3 = next(s for s in report.sections if s.control_id == "CC7.3")
        assert any("consecutive" in e.lower() for e in cc7_3.evidence)


# ── PCI-DSS Tests ────────────────────────────────────────────────────────

class TestPCIDSSReport:
    def test_pci_dss_generation(self):
        """PCI-DSS report generates with correct type and sections."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_pci_dss()

        assert report.report_type == "PCI-DSS"
        assert report.engagement_id == _ENGAGEMENT_ID
        assert len(report.sections) == 5

    def test_pci_dss_all_control_ids_present(self):
        """All 5 PCI-DSS control IDs are present in the report."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_pci_dss()

        expected_ids = {"6.5", "10.1", "10.2", "10.5", "11.3"}
        actual_ids = {s.control_id for s in report.sections}
        assert actual_ids == expected_ids

    def test_pci_dss_penetration_testing_evidence(self):
        """11.3 references engagement name and target count from ROE spec."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_pci_dss()

        sec_11_3 = next(s for s in report.sections if s.control_id == "11.3")
        assert any("ACME" in e for e in sec_11_3.evidence)
        assert any("2" in e and "target" in e.lower() for e in sec_11_3.evidence)


# ── Serialization Tests ──────────────────────────────────────────────────

class TestSerialization:
    def test_to_json(self):
        """Report serializes to valid JSON with all expected fields."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()
        json_str = ComplianceReportGenerator.to_json(report)

        data = json.loads(json_str)
        assert data["report_type"] == "SOC2"
        assert data["engagement_id"] == _ENGAGEMENT_ID
        assert len(data["sections"]) == 7
        assert all(
            {"title", "control_id", "description", "evidence", "status"}
            <= set(s.keys())
            for s in data["sections"]
        )

    def test_to_text(self):
        """Report serializes to human-readable text."""
        gen = ComplianceReportGenerator(_clean_events(), _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()
        text = ComplianceReportGenerator.to_text(report)

        assert "SOC2 Compliance Report" in text
        assert _ENGAGEMENT_ID in text
        assert "[PASS]" in text
        assert "CC6.1" in text


# ── Edge Cases ───────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_audit_log(self):
        """Empty audit log generates a valid report with NOT_APPLICABLE statuses."""
        gen = ComplianceReportGenerator([], _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_soc2()

        assert report.report_type == "SOC2"
        assert len(report.sections) == 7
        for section in report.sections:
            assert section.status == "NOT_APPLICABLE"

    def test_empty_audit_log_pci(self):
        """Empty audit log generates a valid PCI-DSS report."""
        gen = ComplianceReportGenerator([], _ROE_SPEC, _ENGAGEMENT_ID)
        report = gen.generate_pci_dss()

        assert report.report_type == "PCI-DSS"
        assert len(report.sections) == 5
        for section in report.sections:
            assert section.status == "NOT_APPLICABLE"
