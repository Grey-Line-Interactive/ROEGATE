"""
Tests for src.service.alerting — Slack and Webhook Alerting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from unittest.mock import patch, MagicMock, call

from src.service.alerting import (
    AlertEvent,
    AlertLevel,
    AlertManager,
    SlackAlerter,
    WebhookAlerter,
    gate_result_to_alert,
)


# ---------------------------------------------------------------------------
# Fake domain objects for gate_result_to_alert tests
# ---------------------------------------------------------------------------

class _FakeDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HALT = "HALT"
    ESCALATE = "ESCALATE"


@dataclass
class _FakeTarget:
    host: str = ""


class _FakeCategory(str, Enum):
    WEB = "web_application_testing"


@dataclass
class _FakeIntent:
    intent_id: str = "intent-001"
    tool: str = "curl"
    category: _FakeCategory = field(default_factory=lambda: _FakeCategory.WEB)
    target: _FakeTarget = field(default_factory=_FakeTarget)


@dataclass
class _FakeGateResult:
    decision: _FakeDecision = field(default_factory=lambda: _FakeDecision.ALLOW)
    reasoning: str = "Approved"
    denial_count: int = 0


# ---------------------------------------------------------------------------
# AlertEvent
# ---------------------------------------------------------------------------

def test_alert_event_creation():
    event = AlertEvent(
        level=AlertLevel.WARNING,
        event_type="gate_deny",
        summary="DENY: nmap -> 10.0.0.1",
        details={"tool": "nmap"},
    )
    assert event.level == AlertLevel.WARNING
    assert event.event_type == "gate_deny"
    assert event.summary == "DENY: nmap -> 10.0.0.1"
    assert event.details == {"tool": "nmap"}
    assert event.timestamp  # non-empty


def test_alert_event_serialization():
    event = AlertEvent(
        level=AlertLevel.CRITICAL,
        event_type="gate_halt",
        summary="HALT: sqlmap -> db.example.com",
        details={"decision": "HALT", "denial_count": 3},
        timestamp="2026-03-01T00:00:00+00:00",
    )
    d = event.to_dict()
    assert d["level"] == "CRITICAL"
    assert d["event_type"] == "gate_halt"
    assert d["summary"] == "HALT: sqlmap -> db.example.com"
    assert d["details"]["denial_count"] == 3
    assert d["timestamp"] == "2026-03-01T00:00:00+00:00"

    # to_json round-trips through JSON correctly
    parsed = json.loads(event.to_json())
    assert parsed == d


# ---------------------------------------------------------------------------
# SlackAlerter
# ---------------------------------------------------------------------------

@patch("src.service.alerting.urllib.request.urlopen")
def test_slack_alerter_sends_formatted_message(mock_urlopen):
    alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
    event = AlertEvent(
        level=AlertLevel.WARNING,
        event_type="gate_deny",
        summary="DENY: nmap -> 10.0.0.1",
        details={"decision": "DENY", "tool": "nmap"},
        timestamp="2026-03-01T12:00:00+00:00",
    )
    # Call the synchronous method directly so we don't need to join threads
    alerter._send_sync(event)

    mock_urlopen.assert_called_once()
    req = mock_urlopen.call_args[0][0]
    assert req.full_url == "https://hooks.slack.com/test"
    assert req.get_header("Content-type") == "application/json"

    body = json.loads(req.data.decode("utf-8"))
    assert "attachments" in body
    attachment = body["attachments"][0]
    # DENY -> red color
    assert attachment["color"] == "#cc0000"
    assert "DENY: nmap -> 10.0.0.1" in attachment["title"]
    assert "WARNING" in attachment["footer"]


@patch("src.service.alerting.urllib.request.urlopen")
def test_slack_alerter_allow_uses_green(mock_urlopen):
    alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
    event = AlertEvent(
        level=AlertLevel.INFO,
        event_type="gate_allow",
        summary="ALLOW: curl -> api.example.com",
        details={"decision": "ALLOW"},
    )
    alerter._send_sync(event)

    body = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
    assert body["attachments"][0]["color"] == "#2eb886"


# ---------------------------------------------------------------------------
# WebhookAlerter
# ---------------------------------------------------------------------------

@patch("src.service.alerting.urllib.request.urlopen")
def test_webhook_alerter_sends_json_payload(mock_urlopen):
    alerter = WebhookAlerter(
        url="https://siem.example.com/api/events",
        headers={"Authorization": "Bearer tok123"},
    )
    event = AlertEvent(
        level=AlertLevel.INFO,
        event_type="gate_allow",
        summary="ALLOW: curl -> api.example.com",
    )
    alerter._send_sync(event)

    mock_urlopen.assert_called_once()
    req = mock_urlopen.call_args[0][0]
    assert req.full_url == "https://siem.example.com/api/events"
    assert req.get_header("Content-type") == "application/json"
    assert req.get_header("Authorization") == "Bearer tok123"
    # No signature header when no secret
    assert req.get_header("X-roe-signature") is None

    body = json.loads(req.data.decode("utf-8"))
    assert body["event_type"] == "gate_allow"


@patch("src.service.alerting.urllib.request.urlopen")
def test_webhook_alerter_hmac_signing(mock_urlopen):
    secret = "my-test-secret"
    alerter = WebhookAlerter(
        url="https://siem.example.com/api/events",
        secret=secret,
    )
    event = AlertEvent(
        level=AlertLevel.WARNING,
        event_type="gate_deny",
        summary="DENY: sqlmap -> db.example.com",
        details={"decision": "DENY"},
        timestamp="2026-03-01T00:00:00+00:00",
    )
    alerter._send_sync(event)

    req = mock_urlopen.call_args[0][0]
    sig_header = req.get_header("X-roe-signature")
    assert sig_header is not None
    assert sig_header.startswith("sha256=")

    # Verify the HMAC matches
    expected = hmac.new(
        secret.encode("utf-8"),
        event.to_json().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert sig_header == f"sha256={expected}"


# ---------------------------------------------------------------------------
# AlertManager — dispatch and level filtering
# ---------------------------------------------------------------------------

def test_alert_manager_dispatches_to_all_alerters():
    manager = AlertManager()
    sent_a: list[AlertEvent] = []
    sent_b: list[AlertEvent] = []

    alerter_a = MagicMock()
    alerter_a.send = lambda e: sent_a.append(e)
    alerter_b = MagicMock()
    alerter_b.send = lambda e: sent_b.append(e)

    manager.register(alerter_a, min_level=AlertLevel.INFO)
    manager.register(alerter_b, min_level=AlertLevel.INFO)

    event = AlertEvent(
        level=AlertLevel.WARNING,
        event_type="gate_deny",
        summary="test",
    )
    manager.alert(event)

    assert len(sent_a) == 1
    assert len(sent_b) == 1
    assert sent_a[0] is event
    assert sent_b[0] is event


def test_alert_manager_respects_min_level():
    manager = AlertManager()
    info_events: list[AlertEvent] = []
    critical_events: list[AlertEvent] = []

    info_alerter = MagicMock()
    info_alerter.send = lambda e: info_events.append(e)
    critical_alerter = MagicMock()
    critical_alerter.send = lambda e: critical_events.append(e)

    manager.register(info_alerter, min_level=AlertLevel.INFO)
    manager.register(critical_alerter, min_level=AlertLevel.CRITICAL)

    # INFO event — only info_alerter should fire
    info_event = AlertEvent(level=AlertLevel.INFO, event_type="gate_allow", summary="allow")
    manager.alert(info_event)
    assert len(info_events) == 1
    assert len(critical_events) == 0

    # WARNING event — only info_alerter should fire
    warn_event = AlertEvent(level=AlertLevel.WARNING, event_type="gate_deny", summary="deny")
    manager.alert(warn_event)
    assert len(info_events) == 2
    assert len(critical_events) == 0

    # CRITICAL event — both should fire
    crit_event = AlertEvent(level=AlertLevel.CRITICAL, event_type="gate_halt", summary="halt")
    manager.alert(crit_event)
    assert len(info_events) == 3
    assert len(critical_events) == 1


# ---------------------------------------------------------------------------
# AlertManager.from_config
# ---------------------------------------------------------------------------

def test_from_config_builds_manager():
    config = {
        "slack": {
            "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
            "min_level": "WARNING",
        },
        "webhooks": [
            {
                "url": "https://siem.example.com/api",
                "headers": {"Authorization": "Bearer abc"},
                "secret": "s3cret",
                "min_level": "INFO",
            },
            {
                "url": "https://other.example.com/hook",
            },
        ],
    }
    manager = AlertManager.from_config(config)

    # Should have 3 alerters: 1 Slack + 2 webhooks
    assert len(manager._alerters) == 3

    slack_alerter, slack_level = manager._alerters[0]
    assert isinstance(slack_alerter, SlackAlerter)
    assert slack_alerter.webhook_url == "https://hooks.slack.com/services/T00/B00/xxx"
    assert slack_level == AlertLevel.WARNING

    wh1_alerter, wh1_level = manager._alerters[1]
    assert isinstance(wh1_alerter, WebhookAlerter)
    assert wh1_alerter.url == "https://siem.example.com/api"
    assert wh1_alerter.headers == {"Authorization": "Bearer abc"}
    assert wh1_alerter.secret == "s3cret"
    assert wh1_level == AlertLevel.INFO

    wh2_alerter, wh2_level = manager._alerters[2]
    assert isinstance(wh2_alerter, WebhookAlerter)
    assert wh2_alerter.url == "https://other.example.com/hook"
    assert wh2_level == AlertLevel.INFO  # default


def test_from_config_empty():
    manager = AlertManager.from_config({})
    assert len(manager._alerters) == 0


# ---------------------------------------------------------------------------
# gate_result_to_alert
# ---------------------------------------------------------------------------

def test_gate_result_to_alert_allow():
    intent = _FakeIntent(tool="curl", target=_FakeTarget(host="api.example.com"))
    result = _FakeGateResult(decision=_FakeDecision.ALLOW, reasoning="Approved")

    event = gate_result_to_alert(intent, result)
    assert event.level == AlertLevel.INFO
    assert event.event_type == "gate_allow"
    assert "ALLOW" in event.summary
    assert "curl" in event.summary
    assert "api.example.com" in event.summary
    assert event.details["decision"] == "ALLOW"
    assert event.details["tool"] == "curl"
    assert event.details["reasoning"] == "Approved"


def test_gate_result_to_alert_deny():
    intent = _FakeIntent(tool="nmap", target=_FakeTarget(host="10.0.0.1"))
    result = _FakeGateResult(
        decision=_FakeDecision.DENY,
        reasoning="Out of scope",
        denial_count=2,
    )

    event = gate_result_to_alert(intent, result)
    assert event.level == AlertLevel.WARNING
    assert event.event_type == "gate_deny"
    assert event.details["denial_count"] == 2


def test_gate_result_to_alert_halt():
    intent = _FakeIntent(tool="sqlmap", target=_FakeTarget(host="db.internal"))
    result = _FakeGateResult(decision=_FakeDecision.HALT, reasoning="Too many denials")

    event = gate_result_to_alert(intent, result)
    assert event.level == AlertLevel.CRITICAL
    assert event.event_type == "gate_halt"


def test_gate_result_to_alert_escalate():
    intent = _FakeIntent(tool="metasploit", target=_FakeTarget(host="target.com"))
    result = _FakeGateResult(decision=_FakeDecision.ESCALATE, reasoning="Needs human review")

    event = gate_result_to_alert(intent, result)
    assert event.level == AlertLevel.WARNING
    assert event.event_type == "gate_escalate"


# ---------------------------------------------------------------------------
# AlertLevel ordering
# ---------------------------------------------------------------------------

def test_alert_level_ordering():
    assert AlertLevel.INFO < AlertLevel.WARNING
    assert AlertLevel.WARNING < AlertLevel.CRITICAL
    assert AlertLevel.CRITICAL >= AlertLevel.WARNING
    assert AlertLevel.INFO <= AlertLevel.INFO
    assert not (AlertLevel.INFO > AlertLevel.WARNING)
