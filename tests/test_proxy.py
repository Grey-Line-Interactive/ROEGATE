"""
Tests for src.tools.proxy — Tool Proxy.
"""

from __future__ import annotations

from src.core.action_intent import ActionCategory, ImpactLevel, DataAccessType
from src.crypto.signer import ActionSigner, compute_roe_hash
from src.gate.gate import ROEGate
from src.tools.executor import ToolExecutor
from src.tools.proxy import ToolProxy, ProxiedToolResult
from tests.helpers import MockLLMProvider


# ---------------------------------------------------------------------------
# Helper to build a full proxy stack
# ---------------------------------------------------------------------------

def _make_proxy(
    sample_roe_spec,
    verdict="ALLOW",
    confidence=0.9,
    dry_run=True,
):
    provider = MockLLMProvider(verdict=verdict, confidence=confidence)
    signing_key = b"test-proxy-signing-key-12345678!"
    gate = ROEGate(
        roe_spec=sample_roe_spec,
        llm_provider=provider,
        signing_key=signing_key,
        token_ttl_seconds=30,
        max_consecutive_denials=3,
    )
    executor = ToolExecutor(
        signer=gate.signer,
        roe_hash=gate.roe_hash,
        dry_run=dry_run,
    )
    proxy = ToolProxy(
        gate=gate,
        executor=executor,
        agent_session="proxy-test-session",
        engagement_id="ENG-2024-001",
    )
    return proxy


# ---------------------------------------------------------------------------
# Execute tool with allowed action (dry_run)
# ---------------------------------------------------------------------------

def test_proxy_execute_allowed_action(sample_roe_spec):
    proxy = _make_proxy(sample_roe_spec, verdict="ALLOW", confidence=0.9)
    result = proxy.execute_tool(
        tool="curl",
        args=["-v", "https://app.corp.local"],
        target_host="10.0.0.50",
        target_port=443,
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="xss",
        description="Test XSS on app",
        justification="Looking for reflected XSS",
    )
    assert result.allowed is True
    assert result.decision == "ALLOW"
    assert "DRY RUN" in result.output


# ---------------------------------------------------------------------------
# Execute tool with denied action
# ---------------------------------------------------------------------------

def test_proxy_execute_denied_action(sample_roe_spec):
    proxy = _make_proxy(sample_roe_spec, verdict="ALLOW", confidence=0.9)
    result = proxy.execute_tool(
        tool="psql",
        args=["-h", "10.0.2.50", "-p", "5432"],
        target_host="10.0.2.50",
        target_port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        description="Direct DB access",
        justification="Testing database",
    )
    assert result.allowed is False
    assert result.decision == "DENY"
    assert result.reasoning  # should have a reason


# ---------------------------------------------------------------------------
# get_agent_tools returns expected keys
# ---------------------------------------------------------------------------

def test_get_agent_tools_keys(sample_roe_spec):
    proxy = _make_proxy(sample_roe_spec)
    tools = proxy.get_agent_tools()
    expected_keys = {"nmap_scan", "curl_request", "sql_client", "shell_command"}
    assert set(tools.keys()) == expected_keys
    # Each should be callable
    for name, func in tools.items():
        assert callable(func)


# ---------------------------------------------------------------------------
# _build_intent creates correct ActionIntent
# ---------------------------------------------------------------------------

def test_build_intent_creates_correct_intent(sample_roe_spec):
    proxy = _make_proxy(sample_roe_spec)
    intent = proxy._build_intent(
        tool="nmap",
        args=["-sT", "-p", "80,443", "10.0.0.50"],
        target_host="10.0.0.50",
        target_port=None,
        target_domain=None,
        target_url=None,
        category=ActionCategory.RECONNAISSANCE,
        subcategory="port_scan",
        description="Port scan of target",
        impact_severity=ImpactLevel.LOW,
        data_access=DataAccessType.NONE,
        justification="Initial recon",
    )
    assert intent.tool == "nmap"
    assert intent.category == ActionCategory.RECONNAISSANCE
    assert intent.subcategory == "port_scan"
    assert intent.target.host == "10.0.0.50"
    assert intent.agent_session == "proxy-test-session"
    assert intent.engagement_id == "ENG-2024-001"
    assert intent.description == "Port scan of target"
    assert intent.justification == "Initial recon"
    assert intent.parameters["command_args"] == ["-sT", "-p", "80,443", "10.0.0.50"]


def test_build_intent_auto_classifies_tool(sample_roe_spec):
    """When no explicit category is given, _build_intent should auto-classify."""
    proxy = _make_proxy(sample_roe_spec)
    intent = proxy._build_intent(
        tool="nmap",
        args=["-sT", "10.0.0.50"],
        target_host="10.0.0.50",
        target_port=None,
        target_domain=None,
        target_url=None,
        category=None,  # no override
        subcategory="",
        description="",
        impact_severity=ImpactLevel.LOW,
        data_access=DataAccessType.NONE,
        justification="",
    )
    # nmap should auto-classify as PORT_SCANNING
    assert intent.category == ActionCategory.PORT_SCANNING


def test_build_intent_sets_domain_and_url(sample_roe_spec):
    proxy = _make_proxy(sample_roe_spec)
    intent = proxy._build_intent(
        tool="curl",
        args=["-v", "https://app.corp.local/login"],
        target_host="10.0.0.50",
        target_port=443,
        target_domain="app.corp.local",
        target_url="https://app.corp.local/login",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="",
        description="Test login page",
        impact_severity=ImpactLevel.LOW,
        data_access=DataAccessType.NONE,
        justification="",
    )
    assert intent.target.domain == "app.corp.local"
    assert intent.target.url == "https://app.corp.local/login"
