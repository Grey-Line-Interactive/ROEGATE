"""
Tests for src.tools.executor — Signature-Enforcing Execution Proxy.
"""

from __future__ import annotations

import time

from src.crypto.signer import ActionSigner, compute_roe_hash
from src.tools.executor import ToolExecutor, ExecutionResult


# ---------------------------------------------------------------------------
# Helper to create a signed token for tests
# ---------------------------------------------------------------------------

def _make_token(signer, roe_hash, tool="curl"):
    return signer.sign_action(
        intent_id="intent-exec-test",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={"verdict": "ALLOW", "confidence": 0.9},
        permitted_action={"tool": tool, "category": "web_application_testing"},
    )


# ---------------------------------------------------------------------------
# Execute with valid token in dry_run mode
# ---------------------------------------------------------------------------

def test_execute_dry_run_valid_token(signer, roe_hash):
    executor = ToolExecutor(
        signer=signer,
        roe_hash=roe_hash,
        dry_run=True,
    )
    token = _make_token(signer, roe_hash, tool="curl")
    result = executor.execute(token=token, tool="curl", args=["-v", "https://example.com"])
    assert result.success is True
    assert "DRY RUN" in result.stdout
    assert "curl" in result.stdout
    assert result.token_id == token.token_id


# ---------------------------------------------------------------------------
# Rejects invalid signature
# ---------------------------------------------------------------------------

def test_execute_rejects_invalid_signature(signer, roe_hash):
    executor = ToolExecutor(
        signer=signer,
        roe_hash=roe_hash,
        dry_run=True,
    )
    token = _make_token(signer, roe_hash, tool="curl")
    # Forge the signature
    token.signature = "hmac-sha256:0000000000000000000000000000"
    result = executor.execute(token=token, tool="curl", args=[])
    assert result.success is False
    assert "signature" in result.error.lower() or "verification failed" in result.error.lower()


# ---------------------------------------------------------------------------
# Rejects expired token
# ---------------------------------------------------------------------------

def test_execute_rejects_expired_token(roe_hash):
    short_signer = ActionSigner(
        signing_key=b"test-key-for-executor-expiry!!!",
        token_ttl_seconds=0,
    )
    executor = ToolExecutor(
        signer=short_signer,
        roe_hash=roe_hash,
        dry_run=True,
    )
    token = _make_token(short_signer, roe_hash, tool="curl")
    time.sleep(0.1)
    result = executor.execute(token=token, tool="curl", args=[])
    assert result.success is False
    assert "expired" in result.error.lower()


# ---------------------------------------------------------------------------
# Rejects replayed token (used twice)
# ---------------------------------------------------------------------------

def test_execute_rejects_replayed_token(signer, roe_hash):
    executor = ToolExecutor(
        signer=signer,
        roe_hash=roe_hash,
        dry_run=True,
    )
    token = _make_token(signer, roe_hash, tool="curl")

    # First use should succeed
    result1 = executor.execute(token=token, tool="curl", args=[])
    assert result1.success is True

    # Second use (replay) should fail
    result2 = executor.execute(token=token, tool="curl", args=[])
    assert result2.success is False
    assert "replay" in result2.error.lower() or "already been used" in result2.error.lower()


# ---------------------------------------------------------------------------
# Rejects tool mismatch
# ---------------------------------------------------------------------------

def test_execute_rejects_tool_mismatch(signer, roe_hash):
    executor = ToolExecutor(
        signer=signer,
        roe_hash=roe_hash,
        dry_run=True,
    )
    token = _make_token(signer, roe_hash, tool="curl")
    # Try to execute a different tool than what was authorized
    result = executor.execute(token=token, tool="nmap", args=[])
    assert result.success is False
    assert "mismatch" in result.error.lower()


# ---------------------------------------------------------------------------
# Rejects tool not in whitelist
# ---------------------------------------------------------------------------

def test_execute_rejects_tool_not_in_whitelist(signer, roe_hash):
    executor = ToolExecutor(
        signer=signer,
        roe_hash=roe_hash,
        allowed_tools={"nmap", "nikto"},
        dry_run=True,
    )
    token = _make_token(signer, roe_hash, tool="curl")
    result = executor.execute(token=token, tool="curl", args=[])
    assert result.success is False
    assert "not in" in result.error.lower() or "allowed tools" in result.error.lower()


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats(signer, roe_hash):
    executor = ToolExecutor(
        signer=signer,
        roe_hash=roe_hash,
        dry_run=True,
    )
    token = _make_token(signer, roe_hash, tool="curl")
    executor.execute(token=token, tool="curl", args=[])

    stats = executor.get_stats()
    assert stats["total_executions"] == 1
    assert stats["unique_tokens_used"] == 1
