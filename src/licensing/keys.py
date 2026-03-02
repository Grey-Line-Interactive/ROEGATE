"""License key generation, parsing, and verification."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def _require_cryptography() -> None:
    """Raise ImportError if the cryptography package is not installed."""
    if not _HAS_CRYPTOGRAPHY:
        raise ImportError(
            "The 'cryptography' package is required for license key operations. "
            "Install it with: pip install cryptography"
        )


class LicenseError(Exception):
    """Raised when license validation fails."""

    pass


def generate_key_pair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 key pair for license signing.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as bytes.
    """
    _require_cryptography()
    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def generate_license_key(private_key_pem: bytes, payload: dict) -> str:
    """Create a signed license key string.

    Args:
        private_key_pem: Ed25519 private key in PEM format.
        payload: License payload dict (must include 'tier').

    Returns:
        License key string in format: ROE-{TIER}-{base64_payload}.{base64_signature}
    """
    _require_cryptography()
    tier = payload.get("tier", "community").upper()

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(payload_json.encode())
    signature_b64 = base64.urlsafe_b64encode(signature).decode()

    return f"ROE-{tier}-{payload_b64}.{signature_b64}"


def parse_license_key(key_string: str) -> tuple[dict, bytes]:
    """Split a license key into payload and signature.

    Args:
        key_string: License key string.

    Returns:
        Tuple of (payload_dict, signature_bytes).

    Raises:
        ValueError: If the key format is invalid.
    """
    key_string = key_string.strip()

    if not key_string.startswith("ROE-"):
        raise ValueError("License key must start with 'ROE-'")

    # Strip the ROE- prefix
    remainder = key_string[4:]

    # Find the tier prefix (second segment before the next dash)
    dash_idx = remainder.find("-")
    if dash_idx == -1:
        raise ValueError("Invalid license key format: missing tier segment")

    # Everything after "ROE-{TIER}-" is "{base64_payload}.{base64_signature}"
    body = remainder[dash_idx + 1 :]

    dot_idx = body.rfind(".")
    if dot_idx == -1:
        raise ValueError("Invalid license key format: missing signature separator")

    payload_b64 = body[:dot_idx]
    signature_b64 = body[dot_idx + 1 :]

    try:
        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        payload = json.loads(payload_json)
    except Exception as e:
        raise ValueError(f"Invalid license key payload: {e}")

    try:
        signature = base64.urlsafe_b64decode(signature_b64)
    except Exception as e:
        raise ValueError(f"Invalid license key signature: {e}")

    return payload, signature


def verify_license_key(key_string: str, public_key_pem: bytes) -> dict:
    """Verify a license key's signature and check expiry.

    Args:
        key_string: License key string.
        public_key_pem: Ed25519 public key in PEM format.

    Returns:
        The verified payload dict.

    Raises:
        LicenseError: If signature is invalid or license has expired.
    """
    try:
        payload, signature = parse_license_key(key_string)
    except ValueError as e:
        raise LicenseError(f"Invalid license key format: {e}")

    # Reconstruct the canonical payload JSON for verification
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    # Load the public key and verify signature
    _require_cryptography()
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(signature, payload_json.encode())
    except Exception:
        raise LicenseError("License key signature verification failed")

    # Check expiry
    expires_at = payload.get("expires_at")
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expiry:
                raise LicenseError(
                    f"License expired on {expires_at}. "
                    "Please contact sales@roegate.io to renew."
                )
        except LicenseError:
            raise
        except Exception as e:
            raise LicenseError(f"Invalid expiry date in license: {e}")

    return payload
