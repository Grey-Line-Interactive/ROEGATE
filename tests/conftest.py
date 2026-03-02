"""
Shared test fixtures for the ROE Agent Gate test suite.
"""

from __future__ import annotations

import pytest
from typing import Any

from src.core.action_intent import (
    ActionIntent,
    ActionCategory,
    Target,
    ImpactAssessment,
    ImpactLevel,
    DataAccessType,
)
from src.core.judge import JudgeVerdict
from src.crypto.signer import ActionSigner, compute_roe_hash
from src.gate.gate import ROEGate

from tests.helpers import MockLLMProvider


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_roe_spec() -> dict[str, Any]:
    """A minimal but realistic ROE spec matching the acme_corp_roe.yaml structure."""
    return {
        "metadata": {
            "engagement_id": "ENG-2024-001",
            "client": "Acme Corp",
            "created": "2024-01-10T09:00:00Z",
            "approved_by": "John Smith, CISO",
            "version": 1,
        },
        "schedule": {
            "valid_from": "2024-01-15T00:00:00Z",
            "valid_until": "2030-12-31T23:59:59Z",
            "timezone": "UTC",
            "blackout_dates": [],
        },
        "scope": {
            "in_scope": {
                "networks": [
                    {
                        "cidr": "10.0.0.0/24",
                        "description": "Web application subnet",
                        "ports": [80, 443, 8080, 8443],
                    },
                    {
                        "cidr": "10.0.1.0/24",
                        "description": "API services subnet",
                        "ports": [443, 8443],
                    },
                ],
                "domains": [
                    {"pattern": "*.app.corp.local", "include_subdomains": True},
                    {"pattern": "api.corp.local"},
                    {"pattern": "auth.corp.local"},
                ],
            },
            "out_of_scope": {
                "networks": [
                    {"cidr": "10.0.2.0/24", "reason": "Production database tier"},
                    {"cidr": "10.0.3.0/24", "reason": "Payment processing"},
                    {"cidr": "10.0.4.0/24", "reason": "Internal corporate network"},
                ],
                "domains": [
                    {"pattern": "*.payments.corp.local", "reason": "PCI DSS scope"},
                    {"pattern": "*.internal.corp.local", "reason": "Internal tooling"},
                    {"pattern": "*.prod-db.corp.local", "reason": "Production databases"},
                ],
                "services": [
                    {
                        "type": "database",
                        "protocols": ["postgresql", "mysql", "mongodb", "redis"],
                        "reason": "No direct database access authorized",
                    },
                    {"type": "email", "reason": "No email system testing"},
                    {"type": "ssh", "reason": "No SSH access authorized"},
                ],
            },
        },
        "actions": {
            "allowed": [
                {
                    "category": "reconnaissance",
                    "methods": [
                        "port_scan",
                        "service_enumeration",
                        "dns_enumeration",
                    ],
                    "constraints": {
                        "rate_limit": "100 requests/second",
                        "scan_type": "tcp_connect_only",
                    },
                },
                {
                    "category": "web_application_testing",
                    "methods": [
                        "sql_injection",
                        "xss",
                        "csrf",
                        "authentication_bypass",
                    ],
                    "constraints": {
                        "targets": ["https://app.corp.local/*"],
                        "max_payload_size": "10KB",
                    },
                },
                {
                    "category": "api_testing",
                },
                {
                    "category": "authentication_testing",
                },
            ],
            "denied": [
                {
                    "category": "denial_of_service",
                    "reason": "No DoS/DDoS testing of any kind",
                },
                {
                    "category": "social_engineering",
                    "reason": "No phishing, vishing, or pretexting",
                },
                {
                    "category": "direct_database_access",
                    "reason": "No direct connections to any database service",
                    "match": {
                        "ports": [5432, 3306, 27017, 6379, 1433, 1521],
                        "protocols": ["postgresql", "mysql", "mongodb", "redis"],
                    },
                },
                {
                    "category": "lateral_movement",
                    "reason": "No pivoting to other network segments",
                },
                {
                    "category": "privilege_escalation",
                    "reason": "No privilege escalation",
                },
            ],
            "requires_approval": [
                {
                    "category": "exploitation",
                    "condition": "impact_assessment.estimated_severity == 'critical'",
                    "approver": "human_operator",
                    "timeout": "5m",
                },
                {
                    "category": "any",
                    "condition": "target.host not in scope.in_scope",
                    "approver": "human_operator",
                    "timeout": "5m",
                },
            ],
        },
        "constraints": {
            "max_concurrent_connections": 10,
            "global_rate_limit": "200 requests/second",
        },
    }


@pytest.fixture
def mock_llm_provider() -> MockLLMProvider:
    """A mock LLM provider that returns ALLOW with confidence 0.9."""
    return MockLLMProvider(
        verdict="ALLOW",
        confidence=0.9,
        reasoning="Mock evaluation: action complies with ROE.",
    )


@pytest.fixture
def make_intent():
    """Factory function to create ActionIntent objects easily."""

    def _make(
        tool: str = "curl",
        host: str = "10.0.0.50",
        port: int | None = 443,
        category: ActionCategory = ActionCategory.WEB_APPLICATION_TESTING,
        subcategory: str = "",
        domain: str | None = None,
        service: str | None = None,
        protocol: str | None = None,
        session: str = "test-session",
        engagement: str = "ENG-2024-001",
        severity: ImpactLevel = ImpactLevel.LOW,
        description: str = "Test action",
        justification: str = "Testing",
    ) -> ActionIntent:
        intent = ActionIntent(
            tool=tool,
            category=category,
            subcategory=subcategory,
            description=description,
            justification=justification,
            agent_session=session,
            engagement_id=engagement,
            target=Target(
                host=host,
                port=port,
                domain=domain,
                service=service,
                protocol=protocol,
            ),
            impact=ImpactAssessment(
                estimated_severity=severity,
            ),
        )
        return intent

    return _make


@pytest.fixture
def signer() -> ActionSigner:
    """An ActionSigner instance with a fixed key."""
    return ActionSigner(
        signing_key=b"test-signing-key-for-unit-tests!",
        token_ttl_seconds=30,
    )


@pytest.fixture
def roe_hash(sample_roe_spec) -> str:
    """Computed hash from the sample ROE spec."""
    return compute_roe_hash(sample_roe_spec)


@pytest.fixture
def gate_with_mock(sample_roe_spec, mock_llm_provider) -> ROEGate:
    """ROEGate instance with mock provider."""
    return ROEGate(
        roe_spec=sample_roe_spec,
        llm_provider=mock_llm_provider,
        signing_key=b"test-signing-key-for-unit-tests!",
        token_ttl_seconds=30,
        max_consecutive_denials=3,
    )
