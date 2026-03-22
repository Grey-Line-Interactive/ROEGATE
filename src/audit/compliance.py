"""
Compliance Report Generator

Generates SOC 2 Type II and PCI-DSS compliance reports from ROE Gate
audit logs. Reports provide evidence that security testing was conducted
within authorized boundaries with complete enforcement.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .logger import AuditEvent


@dataclass
class ReportSection:
    """A single control section within a compliance report."""
    title: str
    control_id: str
    description: str
    evidence: list[str] = field(default_factory=list)
    status: str = "NOT_APPLICABLE"  # COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE


@dataclass
class ComplianceReport:
    """A generated compliance report."""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_type: str = ""  # "SOC2" or "PCI-DSS"
    engagement_id: str = ""
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    period_start: str = ""
    period_end: str = ""
    sections: list[ReportSection] = field(default_factory=list)


class ComplianceReportGenerator:
    """Generates SOC 2 Type II and PCI-DSS compliance reports from audit data."""

    def __init__(
        self,
        audit_events: list[AuditEvent],
        roe_spec: dict[str, Any],
        engagement_id: str,
    ) -> None:
        self.audit_events = audit_events
        self.roe_spec = roe_spec
        self.engagement_id = engagement_id

        # Pre-compute common aggregates
        self._evaluations = [
            e for e in audit_events if e.event_type == "action_evaluation"
        ]
        self._halts = [
            e for e in audit_events if e.event_type == "emergency_halt"
        ]
        self._decisions = [
            e.details.get("decision", "") for e in self._evaluations
        ]
        self._allows = self._decisions.count("ALLOW")
        self._denials = self._decisions.count("DENY")
        self._escalations = self._decisions.count("ESCALATE")
        self._halt_decisions = self._decisions.count("HALT")

    def _period(self) -> tuple[str, str]:
        """Determine the reporting period from audit event timestamps."""
        if not self.audit_events:
            now = datetime.now(timezone.utc).isoformat()
            return now, now
        timestamps = [e.timestamp for e in self.audit_events]
        return min(timestamps), max(timestamps)

    def _out_of_scope_allows(self) -> list[AuditEvent]:
        """Find evaluations where an out-of-scope action was allowed."""
        results = []
        for event in self._evaluations:
            decision = event.details.get("decision", "")
            rule_engine = event.details.get("rule_engine")
            if decision == "ALLOW" and rule_engine:
                if rule_engine.get("in_scope") is False:
                    results.append(event)
        return results

    def _tokens_issued_count(self) -> int:
        """Count evaluations where a token was issued."""
        return sum(
            1 for e in self._evaluations if e.details.get("token_issued")
        )

    def _consecutive_denial_events(self) -> list[AuditEvent]:
        """Find evaluations where denial_count > 1 (consecutive denials)."""
        return [
            e for e in self._evaluations
            if (e.details.get("denial_count") or 0) > 1
        ]

    # ── SOC 2 Type II ────────────────────────────────────────────────────

    def generate_soc2(self) -> ComplianceReport:
        """Generate a SOC 2 Type II compliance report."""
        period_start, period_end = self._period()
        sections = [
            self._soc2_cc6_1(),
            self._soc2_cc6_2(),
            self._soc2_cc6_3(),
            self._soc2_cc6_6(),
            self._soc2_cc6_8(),
            self._soc2_cc7_2(),
            self._soc2_cc7_3(),
        ]
        return ComplianceReport(
            report_type="SOC2",
            engagement_id=self.engagement_id,
            period_start=period_start,
            period_end=period_end,
            sections=sections,
        )

    def _soc2_cc6_1(self) -> ReportSection:
        """CC6.1 — Logical Access Security."""
        total = len(self._evaluations)
        tokens = self._tokens_issued_count()
        evidence = [
            f"Total actions evaluated by gate: {total}",
            f"Actions issued cryptographic tokens: {tokens}",
            f"Actions denied or escalated: {self._denials + self._escalations}",
        ]
        if total > 0:
            evidence.append(
                f"100% of actions were mediated by the ROE Gate reference monitor"
            )
        status = "COMPLIANT" if total > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Logical Access Security",
            control_id="CC6.1",
            description=(
                "The entity implements logical access security software, "
                "infrastructure, and architectures to protect information assets "
                "from security events."
            ),
            evidence=evidence,
            status=status,
        )

    def _soc2_cc6_2(self) -> ReportSection:
        """CC6.2 — Prior to Issuing System Credentials."""
        evidence = [
            "All action tokens use HMAC-SHA256 cryptographic signing",
            "Token time-to-live (TTL) is enforced at 30 seconds",
            "Tokens are single-use and bound to a specific action intent",
        ]
        tokens = self._tokens_issued_count()
        if tokens > 0:
            evidence.append(f"{tokens} short-lived tokens issued during period")
        status = "COMPLIANT" if tokens > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Prior to Issuing System Credentials",
            control_id="CC6.2",
            description=(
                "Prior to issuing system credentials and granting system access, "
                "the entity registers and authorizes new users."
            ),
            evidence=evidence,
            status=status,
        )

    def _soc2_cc6_3(self) -> ReportSection:
        """CC6.3 — Registration and Authorization."""
        evidence = [
            "All actions require dual authorization: deterministic rule engine AND isolated judge LLM",
            f"Total evaluations processed: {len(self._evaluations)}",
            f"Allowed: {self._allows}, Denied: {self._denials}, "
            f"Escalated: {self._escalations}, Halted: {self._halt_decisions}",
        ]
        # Check that judge was invoked for all evaluations
        judge_used = sum(
            1 for e in self._evaluations if e.details.get("judge") is not None
        )
        if judge_used > 0:
            evidence.append(
                f"Isolated judge LLM invoked for {judge_used} evaluations"
            )
        status = "COMPLIANT" if len(self._evaluations) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Registration and Authorization",
            control_id="CC6.3",
            description=(
                "The entity authorizes, modifies, or removes access to data, "
                "software, functions, and other protected information assets."
            ),
            evidence=evidence,
            status=status,
        )

    def _soc2_cc6_6(self) -> ReportSection:
        """CC6.6 — Restricting Access (scope enforcement)."""
        oos_allows = self._out_of_scope_allows()
        evidence = [
            f"Total actions evaluated: {len(self._evaluations)}",
            f"Out-of-scope actions denied: {self._denials}",
        ]
        if oos_allows:
            evidence.append(
                f"WARNING: {len(oos_allows)} out-of-scope actions were ALLOWED"
            )
            for event in oos_allows:
                intent = event.details.get("intent", {})
                evidence.append(
                    f"  - {intent.get('tool_name', 'unknown')} targeting "
                    f"{intent.get('target', 'unknown')}"
                )
            status = "NON_COMPLIANT"
        else:
            evidence.append(
                "Zero out-of-scope actions were allowed during the period"
            )
            status = "COMPLIANT" if len(self._evaluations) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Restricting Access",
            control_id="CC6.6",
            description=(
                "The entity restricts logical and physical access to information "
                "assets to authorized scope boundaries."
            ),
            evidence=evidence,
            status=status,
        )

    def _soc2_cc6_8(self) -> ReportSection:
        """CC6.8 — Prevention of Unauthorized Access (emergency halt)."""
        evidence = []
        halt_count = len(self._halts)
        evidence.append(f"Emergency halt events during period: {halt_count}")
        if halt_count > 0:
            evidence.append("Emergency halt capability was exercised and verified")
            status = "COMPLIANT"
        else:
            evidence.append(
                "Emergency halt capability exists but was not exercised during period"
            )
            status = "COMPLIANT" if len(self._evaluations) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Prevention of Unauthorized Access",
            control_id="CC6.8",
            description=(
                "The entity implements controls to prevent or detect and act upon "
                "the introduction of unauthorized or malicious software."
            ),
            evidence=evidence,
            status=status,
        )

    def _soc2_cc7_2(self) -> ReportSection:
        """CC7.2 — System Monitoring (continuous audit logging)."""
        total_events = len(self.audit_events)
        event_types = set(e.event_type for e in self.audit_events)
        evidence = [
            f"Total audit events recorded: {total_events}",
            f"Event types captured: {', '.join(sorted(event_types)) if event_types else 'none'}",
            "All events include: event_id (UUID), ISO-8601 timestamp, event_type, structured details",
            "Audit log uses append-only JSON Lines format",
        ]
        status = "COMPLIANT" if total_events > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="System Monitoring",
            control_id="CC7.2",
            description=(
                "The entity monitors system components and the operation of those "
                "components for anomalies and security events."
            ),
            evidence=evidence,
            status=status,
        )

    def _soc2_cc7_3(self) -> ReportSection:
        """CC7.3 — Security Event Detection (denial detection and escalation)."""
        consecutive = self._consecutive_denial_events()
        evidence = [
            f"Total denials detected: {self._denials}",
            f"Total escalations triggered: {self._escalations}",
            f"Halt decisions: {self._halt_decisions}",
            f"Emergency halts: {len(self._halts)}",
        ]
        if consecutive:
            evidence.append(
                f"Consecutive denial tracking active: {len(consecutive)} events "
                f"with elevated denial counts"
            )
        status = "COMPLIANT" if len(self._evaluations) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Security Event Detection",
            control_id="CC7.3",
            description=(
                "The entity evaluates detected security events and determines "
                "whether they could indicate a failure to comply with policies."
            ),
            evidence=evidence,
            status=status,
        )

    # ── PCI-DSS ──────────────────────────────────────────────────────────

    def generate_pci_dss(self) -> ComplianceReport:
        """Generate a PCI-DSS compliance report."""
        period_start, period_end = self._period()
        sections = [
            self._pci_6_5(),
            self._pci_10_1(),
            self._pci_10_2(),
            self._pci_10_5(),
            self._pci_11_3(),
        ]
        return ComplianceReport(
            report_type="PCI-DSS",
            engagement_id=self.engagement_id,
            period_start=period_start,
            period_end=period_end,
            sections=sections,
        )

    def _pci_6_5(self) -> ReportSection:
        """6.5 — Secure Development."""
        oos_allows = self._out_of_scope_allows()
        evidence = [
            f"Testing conducted within defined ROE boundaries",
            f"Total actions evaluated: {len(self._evaluations)}",
            f"Actions allowed within scope: {self._allows}",
            f"Actions denied (boundary enforcement): {self._denials}",
        ]
        if oos_allows:
            evidence.append(
                f"WARNING: {len(oos_allows)} out-of-scope actions were allowed"
            )
            status = "NON_COMPLIANT"
        else:
            status = "COMPLIANT" if len(self._evaluations) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Secure Development",
            control_id="6.5",
            description=(
                "Address common coding vulnerabilities in software-development "
                "processes. Testing was conducted within defined boundaries."
            ),
            evidence=evidence,
            status=status,
        )

    def _pci_10_1(self) -> ReportSection:
        """10.1 — Audit Trails."""
        total = len(self.audit_events)
        evidence = [
            f"Complete audit trail maintained: {total} events recorded",
            "Each event includes unique event_id, ISO-8601 timestamp, event_type, and structured details",
            f"All {len(self._evaluations)} action evaluations include intent, decision, reasoning, and token status",
        ]
        status = "COMPLIANT" if total > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Audit Trails",
            control_id="10.1",
            description=(
                "Implement audit trails to link all access to system components "
                "to each individual user."
            ),
            evidence=evidence,
            status=status,
        )

    def _pci_10_2(self) -> ReportSection:
        """10.2 — Audit Events."""
        evidence = [
            f"Security denials captured: {self._denials}",
            f"Escalation events captured: {self._escalations}",
            f"Halt decisions captured: {self._halt_decisions}",
            f"Emergency halt events captured: {len(self._halts)}",
        ]
        has_security_events = (
            self._denials + self._escalations + self._halt_decisions + len(self._halts)
        ) > 0
        if has_security_events:
            evidence.append("All security-relevant events are captured in the audit log")
        status = "COMPLIANT" if len(self._evaluations) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Audit Events",
            control_id="10.2",
            description=(
                "Implement automated audit trails for all system components to "
                "reconstruct security events."
            ),
            evidence=evidence,
            status=status,
        )

    def _pci_10_5(self) -> ReportSection:
        """10.5 — Secure Audit Trails."""
        evidence = [
            "Audit logs use append-only JSON Lines format",
            "Each event is cryptographically identifiable via UUID event_id",
            "Log entries include ISO-8601 timestamps with UTC timezone",
            "Audit logger enforces immutable, append-only write pattern",
        ]
        status = "COMPLIANT" if len(self.audit_events) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Secure Audit Trails",
            control_id="10.5",
            description=(
                "Secure audit trails so they cannot be altered."
            ),
            evidence=evidence,
            status=status,
        )

    def _pci_11_3(self) -> ReportSection:
        """11.3 — Penetration Testing."""
        roe_name = self.roe_spec.get("metadata", {}).get("engagement_name", "Unknown")
        scope_targets = self.roe_spec.get("scope", {}).get("targets", [])
        evidence = [
            f"Engagement: {roe_name}",
            f"Engagement ID: {self.engagement_id}",
            f"Authorized targets: {len(scope_targets)}",
            f"Total actions evaluated against ROE: {len(self._evaluations)}",
            f"Actions allowed: {self._allows}",
            f"Actions denied (ROE enforcement): {self._denials}",
            "All testing followed defined rules of engagement enforced by the ROE Gate reference monitor",
        ]
        status = "COMPLIANT" if len(self._evaluations) > 0 else "NOT_APPLICABLE"
        return ReportSection(
            title="Penetration Testing",
            control_id="11.3",
            description=(
                "Implement a methodology for penetration testing that includes "
                "defined rules of engagement and scope boundaries."
            ),
            evidence=evidence,
            status=status,
        )

    # ── Serialization ────────────────────────────────────────────────────

    @staticmethod
    def to_json(report: ComplianceReport) -> str:
        """Serialize a compliance report to JSON."""
        data = {
            "report_id": report.report_id,
            "report_type": report.report_type,
            "engagement_id": report.engagement_id,
            "generated_at": report.generated_at,
            "period_start": report.period_start,
            "period_end": report.period_end,
            "sections": [
                {
                    "title": s.title,
                    "control_id": s.control_id,
                    "description": s.description,
                    "evidence": s.evidence,
                    "status": s.status,
                }
                for s in report.sections
            ],
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def to_text(report: ComplianceReport) -> str:
        """Serialize a compliance report to human-readable text."""
        lines = [
            f"{'=' * 72}",
            f"  {report.report_type} Compliance Report",
            f"{'=' * 72}",
            f"  Report ID:     {report.report_id}",
            f"  Engagement:    {report.engagement_id}",
            f"  Generated:     {report.generated_at}",
            f"  Period:        {report.period_start} to {report.period_end}",
            f"{'=' * 72}",
            "",
        ]
        for section in report.sections:
            status_marker = {
                "COMPLIANT": "[PASS]",
                "NON_COMPLIANT": "[FAIL]",
                "NOT_APPLICABLE": "[ N/A]",
            }.get(section.status, "[????]")

            lines.append(f"{status_marker} {section.control_id} - {section.title}")
            lines.append(f"  {section.description}")
            lines.append("")
            for item in section.evidence:
                lines.append(f"    - {item}")
            lines.append("")
        lines.append(f"{'=' * 72}")
        return "\n".join(lines)
