"""
Cryptographic Action Signing

When an action passes both the Rule Engine and Judge LLM, the Gate produces a
cryptographically signed Action Token. This token is the ONLY way an action can
be executed against a target system.

Key properties:
- The signing key is held by the Gate service, NOT accessible to the agent
- Tokens are short-lived (configurable TTL, default 30 seconds)
- Tokens are action-specific (cannot be reused for different actions)
- Tokens are ROE-bound (include the ROE spec hash; if ROE changes, tokens invalidate)
- Tokens are unforgeable (HMAC-SHA256 or Ed25519 signatures)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any


@dataclass
class ActionToken:
    """A cryptographically signed authorization token for a specific action.

    This token is what the Tool Executor checks before running any action.
    Without a valid token, nothing executes.
    """
    token_id: str = field(default_factory=lambda: f"tok_{uuid.uuid4().hex[:12]}")
    intent_id: str = ""
    engagement_id: str = ""
    roe_hash: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: str = ""
    verdict: str = "ALLOW"
    rule_engine_result: str = ""
    judge_result: dict[str, Any] = field(default_factory=dict)
    permitted_action: dict[str, Any] = field(default_factory=dict)
    constraints: dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "intent_id": self.intent_id,
            "engagement_id": self.engagement_id,
            "roe_hash": self.roe_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "verdict": self.verdict,
            "rule_engine_result": self.rule_engine_result,
            "judge_result": self.judge_result,
            "permitted_action": self.permitted_action,
            "constraints": self.constraints,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @property
    def is_expired(self) -> bool:
        """Check if this token has expired."""
        if not self.expires_at:
            return True
        expiry = datetime.fromisoformat(self.expires_at)
        return datetime.now(timezone.utc) > expiry


def compute_roe_hash(roe_spec: dict[str, Any]) -> str:
    """Compute a SHA-256 hash of the ROE specification.

    This hash is embedded in every action token. If the ROE is modified
    after the engagement starts, all tokens become invalid because the
    hash won't match.
    """
    canonical = json.dumps(roe_spec, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class ActionSigner:
    """Cryptographic action signer.

    Generates and verifies signed action tokens. The signing key is created
    at Gate startup and NEVER leaves the Gate service.
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        token_ttl_seconds: int = 30,
    ) -> None:
        """Initialize the signer.

        Args:
            signing_key: HMAC signing key. Generated randomly if not provided.
            token_ttl_seconds: How long tokens are valid (default: 30 seconds).
        """
        self.signing_key = signing_key or secrets.token_bytes(32)
        self.token_ttl = timedelta(seconds=token_ttl_seconds)
        # Track issued tokens for revocation
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
        """Create a signed action token.

        Args:
            intent_id: The ActionIntent ID this token authorizes.
            engagement_id: The engagement this belongs to.
            roe_hash: Hash of the ROE specification.
            rule_engine_result: The Rule Engine's verdict string.
            judge_result: The Judge LLM's result dictionary.
            permitted_action: Exactly what action is authorized.
            constraints: Execution constraints (timeouts, limits, etc.).

        Returns:
            A signed ActionToken.

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

        # Compute HMAC-SHA256 signature over the token payload
        # The signature covers everything except the signature field itself
        payload = self._get_signing_payload(token)
        signature = hmac.new(
            self.signing_key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        token.signature = f"hmac-sha256:{signature}"
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
        # Check emergency halt
        if self._emergency_halt:
            return False, "Emergency halt is active"

        # Check revocation
        if token.token_id in self._revoked_tokens:
            return False, f"Token {token.token_id} has been revoked"

        # Check expiration
        if token.is_expired:
            return False, f"Token expired at {token.expires_at}"

        # Check ROE hash binding
        if token.roe_hash != expected_roe_hash:
            return False, (
                f"ROE hash mismatch: token has {token.roe_hash}, "
                f"expected {expected_roe_hash}"
            )

        # Verify signature
        payload = self._get_signing_payload(token)
        expected_sig = hmac.new(
            self.signing_key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        actual_sig = token.signature.replace("hmac-sha256:", "")
        if not hmac.compare_digest(expected_sig, actual_sig):
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
        """Deactivate emergency halt. Requires explicit call — cannot be
        done by the agent."""
        self._emergency_halt = False
        self._revoked_tokens.clear()

    @staticmethod
    def _get_signing_payload(token: ActionToken) -> str:
        """Get the canonical string to sign.

        Includes all fields except the signature itself, in a deterministic order.
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
