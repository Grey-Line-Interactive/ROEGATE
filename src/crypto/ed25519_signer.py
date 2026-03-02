"""
Ed25519 Asymmetric Action Signing

Enterprise-grade asymmetric signing for action tokens. Unlike HMAC-SHA256
(symmetric, shared secret), Ed25519 uses a private/public key pair:
- Private key: held ONLY by the Gate Service (signs tokens)
- Public key: can be distributed to verifiers (auditors, SIEM, compliance)

This means external systems can verify that tokens were legitimately issued
by the Gate without needing access to the signing key.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from src.crypto.signer import ActionToken


class Ed25519Verifier:
    """Verification-only Ed25519 token verifier.

    Holds only the public key -- can verify tokens but cannot sign them.
    Distribute this to auditors, SIEM systems, or compliance tooling.
    """

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        token_ttl_seconds: int = 30,
    ) -> None:
        self._public_key = public_key
        self.token_ttl = timedelta(seconds=token_ttl_seconds)
        self._revoked_tokens: set[str] = set()
        self._emergency_halt: bool = False

    def verify_token(
        self,
        token: ActionToken,
        expected_roe_hash: str,
    ) -> tuple[bool, str]:
        """Verify a token's Ed25519 signature, expiration, and ROE binding.

        Args:
            token: The token to verify.
            expected_roe_hash: The current ROE hash to verify against.

        Returns:
            Tuple of (is_valid, reason).
        """
        if self._emergency_halt:
            return False, "Emergency halt is active"

        if token.token_id in self._revoked_tokens:
            return False, f"Token {token.token_id} has been revoked"

        if token.is_expired:
            return False, f"Token expired at {token.expires_at}"

        if token.roe_hash != expected_roe_hash:
            return False, (
                f"ROE hash mismatch: token has {token.roe_hash}, "
                f"expected {expected_roe_hash}"
            )

        # Verify Ed25519 signature
        if not token.signature.startswith("ed25519:"):
            return False, "Signature is not Ed25519 format"

        sig_b64 = token.signature[len("ed25519:"):]
        try:
            sig_bytes = base64.b64decode(sig_b64)
        except Exception:
            return False, "Invalid base64 in signature"

        payload = _get_signing_payload(token)
        try:
            self._public_key.verify(sig_bytes, payload.encode("utf-8"))
        except InvalidSignature:
            return False, "Signature verification failed"

        return True, "Token is valid"

    def revoke_token(self, token_id: str) -> None:
        """Revoke a specific token."""
        self._revoked_tokens.add(token_id)

    def emergency_halt(self) -> None:
        """Activate emergency halt."""
        self._emergency_halt = True

    def resume(self) -> None:
        """Deactivate emergency halt."""
        self._emergency_halt = False
        self._revoked_tokens.clear()

    def get_public_key_pem(self) -> str:
        """Export the public key in PEM format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def get_public_key_bytes(self) -> bytes:
        """Export raw public key bytes (32 bytes)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


class Ed25519ActionSigner:
    """Ed25519 asymmetric action signer.

    Generates and verifies signed action tokens using Ed25519 key pairs.
    The private key is created at Gate startup and NEVER leaves the Gate service.
    The public key can be freely distributed for verification.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        token_ttl_seconds: int = 30,
    ) -> None:
        """Initialize the signer.

        Args:
            private_key: Ed25519 private key. Generated randomly if not provided.
            token_ttl_seconds: How long tokens are valid (default: 30 seconds).
        """
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self.token_ttl = timedelta(seconds=token_ttl_seconds)
        self._revoked_tokens: set[str] = set()
        self._emergency_halt: bool = False

    def sign_action(
        self,
        intent_id: str,
        engagement_id: str,
        roe_hash: str,
        rule_engine_result: str,
        judge_result: dict[str, Any],
        permitted_action: dict[str, Any],
        constraints: dict[str, Any] | None = None,
    ) -> ActionToken:
        """Create an Ed25519-signed action token.

        Args:
            intent_id: The ActionIntent ID this token authorizes.
            engagement_id: The engagement this belongs to.
            roe_hash: Hash of the ROE specification.
            rule_engine_result: The Rule Engine's verdict string.
            judge_result: The Judge LLM's result dictionary.
            permitted_action: Exactly what action is authorized.
            constraints: Execution constraints (timeouts, limits, etc.).

        Returns:
            A signed ActionToken with ed25519 signature.

        Raises:
            RuntimeError: If emergency halt is active.
        """
        if self._emergency_halt:
            raise RuntimeError("Emergency halt is active. No tokens can be issued.")

        now = datetime.now(timezone.utc)
        expires = now + self.token_ttl

        token = ActionToken(
            intent_id=intent_id,
            engagement_id=engagement_id,
            roe_hash=roe_hash,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            verdict="ALLOW",
            rule_engine_result=rule_engine_result,
            judge_result=judge_result,
            permitted_action=permitted_action,
            constraints=constraints or {},
        )

        payload = _get_signing_payload(token)
        sig_bytes = self._private_key.sign(payload.encode("utf-8"))
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        token.signature = f"ed25519:{sig_b64}"
        return token

    def verify_token(
        self,
        token: ActionToken,
        expected_roe_hash: str,
    ) -> tuple[bool, str]:
        """Verify a token's signature, expiration, and ROE binding.

        Args:
            token: The token to verify.
            expected_roe_hash: The current ROE hash to verify against.

        Returns:
            Tuple of (is_valid, reason).
        """
        if self._emergency_halt:
            return False, "Emergency halt is active"

        if token.token_id in self._revoked_tokens:
            return False, f"Token {token.token_id} has been revoked"

        if token.is_expired:
            return False, f"Token expired at {token.expires_at}"

        if token.roe_hash != expected_roe_hash:
            return False, (
                f"ROE hash mismatch: token has {token.roe_hash}, "
                f"expected {expected_roe_hash}"
            )

        if not token.signature.startswith("ed25519:"):
            return False, "Signature is not Ed25519 format"

        sig_b64 = token.signature[len("ed25519:"):]
        try:
            sig_bytes = base64.b64decode(sig_b64)
        except Exception:
            return False, "Invalid base64 in signature"

        payload = _get_signing_payload(token)
        try:
            self._public_key.verify(sig_bytes, payload.encode("utf-8"))
        except InvalidSignature:
            return False, "Signature verification failed"

        return True, "Token is valid"

    def revoke_token(self, token_id: str) -> None:
        """Revoke a specific token."""
        self._revoked_tokens.add(token_id)

    def emergency_halt(self) -> None:
        """Activate emergency halt. No new tokens will be issued and all
        existing tokens are effectively invalidated."""
        self._emergency_halt = True

    def resume(self) -> None:
        """Deactivate emergency halt."""
        self._emergency_halt = False
        self._revoked_tokens.clear()

    def get_public_key_pem(self) -> str:
        """Export the public key in PEM format (for distribution to auditors)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def get_public_key_bytes(self) -> bytes:
        """Export raw public key bytes (32 bytes)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @classmethod
    def from_private_key_pem(cls, pem: str, token_ttl_seconds: int = 30) -> Ed25519ActionSigner:
        """Create a signer from a PEM-encoded private key.

        Args:
            pem: PEM-encoded Ed25519 private key.
            token_ttl_seconds: How long tokens are valid.

        Returns:
            An Ed25519ActionSigner initialized with the given key.
        """
        private_key = serialization.load_pem_private_key(
            pem.encode("utf-8"),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError(f"Expected Ed25519 private key, got {type(private_key).__name__}")
        return cls(private_key=private_key, token_ttl_seconds=token_ttl_seconds)

    def create_verifier(self) -> Ed25519Verifier:
        """Create a verification-only instance with just the public key.

        This is what you'd distribute to auditors, SIEM systems, or
        compliance tooling -- they can verify tokens but cannot forge them.
        """
        return Ed25519Verifier(
            public_key=self._public_key,
            token_ttl_seconds=int(self.token_ttl.total_seconds()),
        )


def _get_signing_payload(token: ActionToken) -> str:
    """Get the canonical string to sign.

    Includes all fields except the signature itself, in a deterministic order.
    Same logic as ActionSigner._get_signing_payload for consistency.
    """
    payload = {
        "token_id": token.token_id,
        "intent_id": token.intent_id,
        "engagement_id": token.engagement_id,
        "roe_hash": token.roe_hash,
        "created_at": token.created_at,
        "expires_at": token.expires_at,
        "verdict": token.verdict,
        "rule_engine_result": token.rule_engine_result,
        "judge_result": token.judge_result,
        "permitted_action": token.permitted_action,
        "constraints": token.constraints,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
