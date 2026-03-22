"""
Tests for src.crypto.ed25519_signer — Ed25519 Asymmetric Action Signing.
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.crypto.ed25519_signer import Ed25519ActionSigner, Ed25519Verifier
from src.crypto.signer import ActionToken


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ed25519_signer() -> Ed25519ActionSigner:
    """An Ed25519ActionSigner with auto-generated key pair."""
    return Ed25519ActionSigner(token_ttl_seconds=30)


@pytest.fixture
def ed25519_roe_hash() -> str:
    return "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


# ---------------------------------------------------------------------------
# Key pair generation
# ---------------------------------------------------------------------------

def test_key_pair_generation():
    """Signer generates a new key pair when none is provided."""
    signer = Ed25519ActionSigner()
    pub_bytes = signer.get_public_key_bytes()
    assert len(pub_bytes) == 32  # Ed25519 public keys are 32 bytes


def test_key_pair_with_provided_key():
    """Signer accepts an externally-provided private key."""
    key = Ed25519PrivateKey.generate()
    signer = Ed25519ActionSigner(private_key=key)
    pub_bytes = signer.get_public_key_bytes()
    expected = key.public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    assert pub_bytes == expected


# ---------------------------------------------------------------------------
# Sign and verify round-trip
# ---------------------------------------------------------------------------

def test_sign_and_verify_roundtrip(ed25519_signer, ed25519_roe_hash):
    """A freshly signed token must verify successfully."""
    token = ed25519_signer.sign_action(
        intent_id="intent-001",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={"verdict": "ALLOW", "confidence": 0.9},
        permitted_action={"tool": "curl", "category": "web_application_testing"},
    )
    is_valid, reason = ed25519_signer.verify_token(token, ed25519_roe_hash)
    assert is_valid is True
    assert "valid" in reason.lower()


# ---------------------------------------------------------------------------
# Signature format
# ---------------------------------------------------------------------------

def test_signature_format_is_ed25519_base64(ed25519_signer, ed25519_roe_hash):
    """Signature must be in the format 'ed25519:{base64}'."""
    token = ed25519_signer.sign_action(
        intent_id="intent-002",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "nmap"},
    )
    assert token.signature.startswith("ed25519:")
    import base64
    sig_b64 = token.signature[len("ed25519:"):]
    sig_bytes = base64.b64decode(sig_b64)
    assert len(sig_bytes) == 64  # Ed25519 signatures are 64 bytes


# ---------------------------------------------------------------------------
# Invalid signature rejected
# ---------------------------------------------------------------------------

def test_invalid_signature_rejected(ed25519_signer, ed25519_roe_hash):
    """A forged/tampered signature must be rejected."""
    token = ed25519_signer.sign_action(
        intent_id="intent-003",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    import base64
    fake_sig = base64.b64encode(b"\x00" * 64).decode("ascii")
    token.signature = f"ed25519:{fake_sig}"
    is_valid, reason = ed25519_signer.verify_token(token, ed25519_roe_hash)
    assert is_valid is False
    assert "signature" in reason.lower()


# ---------------------------------------------------------------------------
# Expired token rejected
# ---------------------------------------------------------------------------

def test_expired_token_rejected():
    """A token with TTL=0 should expire immediately."""
    signer = Ed25519ActionSigner(token_ttl_seconds=0)
    roe_hash = "sha256:abc123"
    token = signer.sign_action(
        intent_id="intent-expire",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    time.sleep(0.1)
    is_valid, reason = signer.verify_token(token, roe_hash)
    assert is_valid is False
    assert "expired" in reason.lower()


# ---------------------------------------------------------------------------
# ROE hash mismatch rejected
# ---------------------------------------------------------------------------

def test_roe_hash_mismatch_rejected(ed25519_signer, ed25519_roe_hash):
    """A token verified against a different ROE hash must be rejected."""
    token = ed25519_signer.sign_action(
        intent_id="intent-hash",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid, reason = ed25519_signer.verify_token(token, "sha256:totally_different_hash")
    assert is_valid is False
    assert "hash mismatch" in reason.lower()


# ---------------------------------------------------------------------------
# Replay prevention (revocation)
# ---------------------------------------------------------------------------

def test_replay_prevention_via_revocation(ed25519_signer, ed25519_roe_hash):
    """A revoked token must not be accepted even if signature is valid."""
    token = ed25519_signer.sign_action(
        intent_id="intent-revoke",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    # Token should be valid before revocation
    is_valid, _ = ed25519_signer.verify_token(token, ed25519_roe_hash)
    assert is_valid is True

    # Revoke and re-check
    ed25519_signer.revoke_token(token.token_id)
    is_valid, reason = ed25519_signer.verify_token(token, ed25519_roe_hash)
    assert is_valid is False
    assert "revoked" in reason.lower()


# ---------------------------------------------------------------------------
# Emergency halt
# ---------------------------------------------------------------------------

def test_emergency_halt_blocks_signing(ed25519_signer, ed25519_roe_hash):
    """Emergency halt must prevent new tokens from being signed."""
    ed25519_signer.emergency_halt()
    try:
        with pytest.raises(RuntimeError, match="Emergency halt"):
            ed25519_signer.sign_action(
                intent_id="intent-halted",
                engagement_id="ENG-2024-001",
                roe_hash=ed25519_roe_hash,
                rule_engine_result="HARD_ALLOW",
                judge_result={},
                permitted_action={"tool": "curl"},
            )
    finally:
        ed25519_signer.resume()


def test_emergency_halt_blocks_verification(ed25519_signer, ed25519_roe_hash):
    """Emergency halt must reject verification of existing tokens."""
    token = ed25519_signer.sign_action(
        intent_id="intent-halt-verify",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    ed25519_signer.emergency_halt()
    is_valid, reason = ed25519_signer.verify_token(token, ed25519_roe_hash)
    assert is_valid is False
    assert "halt" in reason.lower()
    ed25519_signer.resume()


def test_resume_after_halt(ed25519_signer, ed25519_roe_hash):
    """After resume, signing and verification should work again."""
    ed25519_signer.emergency_halt()
    ed25519_signer.resume()
    token = ed25519_signer.sign_action(
        intent_id="intent-resume",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid, reason = ed25519_signer.verify_token(token, ed25519_roe_hash)
    assert is_valid is True


# ---------------------------------------------------------------------------
# Public key export / import
# ---------------------------------------------------------------------------

def test_public_key_pem_export(ed25519_signer):
    """Public key PEM export should produce a valid PEM string."""
    pem = ed25519_signer.get_public_key_pem()
    assert "BEGIN PUBLIC KEY" in pem
    assert "END PUBLIC KEY" in pem


def test_public_key_bytes_export(ed25519_signer):
    """Raw public key bytes must be 32 bytes for Ed25519."""
    raw = ed25519_signer.get_public_key_bytes()
    assert isinstance(raw, bytes)
    assert len(raw) == 32


# ---------------------------------------------------------------------------
# Ed25519Verifier (public-key only)
# ---------------------------------------------------------------------------

def test_verifier_can_verify(ed25519_signer, ed25519_roe_hash):
    """A verifier created from the signer must be able to verify tokens."""
    token = ed25519_signer.sign_action(
        intent_id="intent-verifier",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    verifier = ed25519_signer.create_verifier()
    is_valid, reason = verifier.verify_token(token, ed25519_roe_hash)
    assert is_valid is True
    assert "valid" in reason.lower()


def test_verifier_cannot_sign():
    """An Ed25519Verifier must not have a sign_action method."""
    signer = Ed25519ActionSigner()
    verifier = signer.create_verifier()
    assert not hasattr(verifier, "sign_action")


def test_verifier_rejects_forged_token(ed25519_signer, ed25519_roe_hash):
    """Verifier must reject a token with a tampered signature."""
    token = ed25519_signer.sign_action(
        intent_id="intent-verifier-forge",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    verifier = ed25519_signer.create_verifier()

    import base64
    fake_sig = base64.b64encode(b"\xff" * 64).decode("ascii")
    token.signature = f"ed25519:{fake_sig}"
    is_valid, reason = verifier.verify_token(token, ed25519_roe_hash)
    assert is_valid is False
    assert "signature" in reason.lower()


# ---------------------------------------------------------------------------
# from_private_key_pem round-trip
# ---------------------------------------------------------------------------

def test_from_private_key_pem_roundtrip():
    """Exporting a private key to PEM and reimporting it must produce
    a signer that verifies tokens signed by the original."""
    original = Ed25519ActionSigner(token_ttl_seconds=30)
    roe_hash = "sha256:roundtrip_test"

    # Export private key PEM
    from cryptography.hazmat.primitives import serialization
    pem = original._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Re-import
    restored = Ed25519ActionSigner.from_private_key_pem(pem, token_ttl_seconds=30)

    # Sign with original, verify with restored
    token = original.sign_action(
        intent_id="intent-pem-roundtrip",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid, reason = restored.verify_token(token, roe_hash)
    assert is_valid is True

    # Sign with restored, verify with original
    token2 = restored.sign_action(
        intent_id="intent-pem-roundtrip-2",
        engagement_id="ENG-2024-001",
        roe_hash=roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid2, reason2 = original.verify_token(token2, roe_hash)
    assert is_valid2 is True


def test_from_private_key_pem_wrong_type():
    """Loading a non-Ed25519 PEM must raise TypeError."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    # Generate an EC key (not Ed25519)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    with pytest.raises(TypeError, match="Ed25519"):
        Ed25519ActionSigner.from_private_key_pem(pem)


# ---------------------------------------------------------------------------
# Cross-signer verification fails (different key pair)
# ---------------------------------------------------------------------------

def test_different_signer_rejects_token(ed25519_roe_hash):
    """A token signed by one signer must be rejected by a different signer."""
    signer_a = Ed25519ActionSigner(token_ttl_seconds=30)
    signer_b = Ed25519ActionSigner(token_ttl_seconds=30)

    token = signer_a.sign_action(
        intent_id="intent-cross",
        engagement_id="ENG-2024-001",
        roe_hash=ed25519_roe_hash,
        rule_engine_result="HARD_ALLOW",
        judge_result={},
        permitted_action={"tool": "curl"},
    )
    is_valid, reason = signer_b.verify_token(token, ed25519_roe_hash)
    assert is_valid is False
    assert "signature" in reason.lower()
