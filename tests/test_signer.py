"""
Tests for src.crypto.signer — Cryptographic Action Signing.
"""

from __future__ import annotations

import time

from src.crypto.signer import ActionSigner, ActionToken, compute_roe_hash


# ---------------------------------------------------------------------------
# Token creation (sign_action)
# ---------------------------------------------------------------------------

def test_sign_action_returns_token(signer, roe_hash):
    token = signer.sign_action(
        intent_id="intent-001",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={"verdict": "ALLOW", "confidence": 0.9},
        permitted_action={"tool": "curl", "category": "web_application_testing"},
    )
    assert isinstance(token, ActionToken)
    assert token.intent_id == "intent-001"
    assert token.engagement_id == "ENG-2024-001"
    assert token.roe_hash == roe_hash
    assert token.signature.startswith("hmac-sha256:")
    assert token.verdict == "ALLOW"
    assert token.token_id.startswith("tok_")


def test_sign_action_sets_expiry(signer, roe_hash):
    token = signer.sign_action(
        intent_id="intent-002",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "nmap"},
    )
    assert token.expires_at != ""
    assert token.created_at != ""


# ---------------------------------------------------------------------------
# Token verification (verify_token)
# ---------------------------------------------------------------------------

def test_verify_valid_token(signer, roe_hash):
    token = signer.sign_action(
        intent_id="intent-003",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid, reason = signer.verify_token(token, roe_hash)
    assert is_valid is True
    assert "valid" in reason.lower()


def test_expired_token_rejected():
    """A token with TTL=0 should expire immediately."""
    short_signer = ActionSigner(
        signing_key=b"test-key-for-expiry-test!!!!!!!",
        token_ttl_seconds=0,
    )
    roe_hash = "sha256:abc123"
    token = short_signer.sign_action(
        intent_id="intent-expire",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    # Wait a tiny bit for the token to expire
    time.sleep(0.1)
    is_valid, reason = short_signer.verify_token(token, roe_hash)
    assert is_valid is False
    assert "expired" in reason.lower()


def test_wrong_roe_hash_rejected(signer, roe_hash):
    token = signer.sign_action(
        intent_id="intent-wrong-hash",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid, reason = signer.verify_token(token, "sha256:totally_different_hash")
    assert is_valid is False
    assert "hash mismatch" in reason.lower()


def test_forged_signature_rejected(signer, roe_hash):
    token = signer.sign_action(
        intent_id="intent-forged",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    # Tamper with the signature
    token.signature = "hmac-sha256:0000000000000000000000000000000000000000"
    is_valid, reason = signer.verify_token(token, roe_hash)
    assert is_valid is False
    assert "signature" in reason.lower()


# ---------------------------------------------------------------------------
# Token revocation
# ---------------------------------------------------------------------------

def test_revoked_token_rejected(signer, roe_hash):
    token = signer.sign_action(
        intent_id="intent-revoke",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    signer.revoke_token(token.token_id)
    is_valid, reason = signer.verify_token(token, roe_hash)
    assert is_valid is False
    assert "revoked" in reason.lower()


# ---------------------------------------------------------------------------
# Emergency halt
# ---------------------------------------------------------------------------

def test_emergency_halt_blocks_new_tokens(signer, roe_hash):
    signer.emergency_halt()
    try:
        import pytest
        with pytest.raises(RuntimeError, match="Emergency halt"):
            signer.sign_action(
                intent_id="intent-halted",
                engagement_id="ENG-2024-001",
                roe_hash=roe_hash,
                rule_engine_result="HARD_ALLOW",
                judge_result={},
                permitted_action={"tool": "curl"},
            )
    finally:
        signer.resume()


def test_emergency_halt_blocks_verification(signer, roe_hash):
    token = signer.sign_action(
        intent_id="intent-halt-verify",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    signer.emergency_halt()
    is_valid, reason = signer.verify_token(token, roe_hash)
    assert is_valid is False
    assert "halt" in reason.lower()
    signer.resume()


def test_resume_after_halt(signer, roe_hash):
    signer.emergency_halt()
    signer.resume()
    # After resume, signing should work again
    token = signer.sign_action(
        intent_id="intent-after-resume",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid, reason = signer.verify_token(token, roe_hash)
    assert is_valid is True


# ---------------------------------------------------------------------------
# compute_roe_hash
# ---------------------------------------------------------------------------

def test_compute_roe_hash_deterministic(sample_roe_spec):
    h1 = compute_roe_hash(sample_roe_spec)
    h2 = compute_roe_hash(sample_roe_spec)
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_compute_roe_hash_changes_with_different_input(sample_roe_spec):
    h1 = compute_roe_hash(sample_roe_spec)
    modified_spec = dict(sample_roe_spec)
    modified_spec["metadata"] = dict(sample_roe_spec["metadata"])
    modified_spec["metadata"]["engagement_id"] = "ENG-DIFFERENT-999"
    h2 = compute_roe_hash(modified_spec)
    assert h1 != h2
