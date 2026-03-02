"""
Audit Logger

Every decision the ROE Gate makes is logged to an immutable audit trail.
This provides:
- Complete accountability for every action allowed or denied
- Evidence for compliance reporting
- Forensic data if an incident occurs
- Proof that the ROE was enforced throughout the engagement
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


logger = logging.getLogger("roe_gate.audit")


@dataclass
class AuditEvent:
    """A single audit log entry."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = ""  # "action_evaluation", "emergency_halt", "session_resumed", etc.
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "details": self.details,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """Append-only audit logger for ROE Gate decisions.

    Writes to both a structured log file and Python's logging system.
    The log file uses JSON Lines format (one JSON object per line) for
    easy ingestion by log analysis tools.
    """

    def __init__(
        self,
        engagement_id: str,
        log_dir: str | Path | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self._events: list[AuditEvent] = []

        # Set up file logging if a directory is provided
        self._log_file: Path | None = None
        if log_dir:
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)
            self._log_file = log_path / f"audit_{engagement_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"

    def log(self, event: AuditEvent) -> None:
        """Record an audit event."""
        self._events.append(event)

        # Log to Python logging
        log_level = logging.WARNING if "deny" in event.event_type.lower() or "halt" in event.event_type.lower() else logging.INFO
        logger.log(
            log_level,
            "[%s] %s | %s",
            self.engagement_id,
            event.event_type,
            event.details.get("decision", event.details.get("triggered_by", "")),
        )

        # Append to log file
        if self._log_file:
            with open(self._log_file, "a") as f:
                f.write(event.to_json() + "\n")

    def get_events(
        self,
        event_type: str | None = None,
        since: str | None = None,
    ) -> list[AuditEvent]:
        """Query audit events."""
        events = self._events
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if since:
            events = [e for e in events if e.timestamp >= since]
        return events

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all audit events for reporting."""
        evaluations = [e for e in self._events if e.event_type == "action_evaluation"]
        decisions = [e.details.get("decision", "") for e in evaluations]

        return {
            "engagement_id": self.engagement_id,
            "total_events": len(self._events),
            "total_evaluations": len(evaluations),
            "allows": decisions.count("ALLOW"),
            "denials": decisions.count("DENY"),
            "escalations": decisions.count("ESCALATE"),
            "halts": decisions.count("HALT"),
            "emergency_halts": len([e for e in self._events if e.event_type == "emergency_halt"]),
        }
