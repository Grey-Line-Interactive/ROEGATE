"""
Tests for src.audit.logger — Audit Logger.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.audit.logger import AuditEvent, AuditLogger


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------

def test_audit_event_creation():
    event = AuditEvent(
        event_type="action_evaluation",
        details={"decision": "ALLOW", "tool": "curl"},
    )
    assert event.event_type == "action_evaluation"
    assert event.details["decision"] == "ALLOW"
    assert event.event_id  # auto-generated UUID
    assert event.timestamp  # auto-generated timestamp


def test_audit_event_to_dict():
    event = AuditEvent(
        event_type="emergency_halt",
        details={"triggered_by": "operator"},
    )
    d = event.to_dict()
    assert d["event_type"] == "emergency_halt"
    assert d["details"]["triggered_by"] == "operator"
    assert "event_id" in d
    assert "timestamp" in d


def test_audit_event_to_json():
    event = AuditEvent(
        event_type="action_evaluation",
        details={"decision": "DENY", "reason": "out of scope"},
    )
    j = event.to_json()
    parsed = json.loads(j)
    assert parsed["event_type"] == "action_evaluation"
    assert parsed["details"]["decision"] == "DENY"


# ---------------------------------------------------------------------------
# AuditLogger.log() and get_events()
# ---------------------------------------------------------------------------

def test_audit_logger_log_stores_events():
    logger = AuditLogger(engagement_id="ENG-001")
    event = AuditEvent(event_type="action_evaluation", details={"decision": "ALLOW"})
    logger.log(event)
    assert len(logger._events) == 1
    assert logger._events[0] is event


def test_audit_logger_get_events_no_filter():
    logger = AuditLogger(engagement_id="ENG-001")
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "ALLOW"}))
    logger.log(AuditEvent(event_type="emergency_halt", details={"triggered_by": "operator"}))
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "DENY"}))

    events = logger.get_events()
    assert len(events) == 3


def test_audit_logger_get_events_with_type_filter():
    logger = AuditLogger(engagement_id="ENG-001")
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "ALLOW"}))
    logger.log(AuditEvent(event_type="emergency_halt", details={"triggered_by": "operator"}))
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "DENY"}))

    events = logger.get_events(event_type="action_evaluation")
    assert len(events) == 2
    assert all(e.event_type == "action_evaluation" for e in events)


def test_audit_logger_get_events_with_unknown_type():
    logger = AuditLogger(engagement_id="ENG-001")
    logger.log(AuditEvent(event_type="action_evaluation", details={}))

    events = logger.get_events(event_type="nonexistent_type")
    assert len(events) == 0


# ---------------------------------------------------------------------------
# AuditLogger.get_summary()
# ---------------------------------------------------------------------------

def test_audit_logger_get_summary():
    logger = AuditLogger(engagement_id="ENG-001")
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "ALLOW"}))
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "ALLOW"}))
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "DENY"}))
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "ESCALATE"}))
    logger.log(AuditEvent(event_type="emergency_halt", details={"triggered_by": "operator"}))

    summary = logger.get_summary()
    assert summary["engagement_id"] == "ENG-001"
    assert summary["total_events"] == 5
    assert summary["total_evaluations"] == 4
    assert summary["allows"] == 2
    assert summary["denials"] == 1
    assert summary["escalations"] == 1
    assert summary["emergency_halts"] == 1


# ---------------------------------------------------------------------------
# File logging
# ---------------------------------------------------------------------------

def test_file_logging_writes_json_lines(tmp_path):
    """Audit logger should write JSON Lines to a file when log_dir is provided."""
    logger = AuditLogger(engagement_id="ENG-FILE-TEST", log_dir=str(tmp_path))

    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "ALLOW"}))
    logger.log(AuditEvent(event_type="action_evaluation", details={"decision": "DENY"}))
    logger.log(AuditEvent(event_type="emergency_halt", details={"triggered_by": "test"}))

    # Find the log file
    log_files = list(tmp_path.glob("audit_ENG-FILE-TEST_*.jsonl"))
    assert len(log_files) == 1

    log_file = log_files[0]
    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 3

    # Each line should be valid JSON
    for line in lines:
        parsed = json.loads(line)
        assert "event_id" in parsed
        assert "timestamp" in parsed
        assert "event_type" in parsed
        assert "details" in parsed

    # Verify content
    first = json.loads(lines[0])
    assert first["event_type"] == "action_evaluation"
    assert first["details"]["decision"] == "ALLOW"
