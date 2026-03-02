"""Runtime license validator — checks license key on startup and gates features."""

import functools
import os
from http import HTTPStatus
from pathlib import Path
from typing import Optional

from src.licensing.keys import LicenseError, verify_license_key
from src.licensing.tiers import FEATURE_TIERS, Tier

# Vendor public key for verifying license signatures.
# The corresponding private key is in _vendor_private_key.pem (development only).
_VENDOR_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyt1acNjO89hS7ZG1M3SLpCNeFrGxR/dHrb7j+WBjQ3Y=
-----END PUBLIC KEY-----
"""

# Cached state
_active_tier: Optional[Tier] = None
_license_payload: Optional[dict] = None


def _load_license_key() -> Optional[str]:
    """Load license key from environment or filesystem.

    Priority:
        1. ROE_GATE_LICENSE_KEY environment variable
        2. ~/.roe-gate/license.key file
        3. ./license.key file in current directory
        4. None (no key found)
    """
    # 1. Environment variable
    env_key = os.environ.get("ROE_GATE_LICENSE_KEY")
    if env_key:
        return env_key.strip()

    # 2. Home directory
    home_key = Path.home() / ".roe-gate" / "license.key"
    if home_key.exists():
        return home_key.read_text().strip()

    # 3. Current directory
    local_key = Path("license.key")
    if local_key.exists():
        return local_key.read_text().strip()

    return None


def get_active_tier() -> Tier:
    """Get the active license tier, loading and validating the key if needed.

    Returns COMMUNITY if no valid key is found.
    """
    global _active_tier, _license_payload

    if _active_tier is not None:
        return _active_tier

    key_string = _load_license_key()
    if not key_string:
        _active_tier = Tier.COMMUNITY
        _license_payload = None
        return _active_tier

    try:
        payload = verify_license_key(key_string, _VENDOR_PUBLIC_KEY)
        tier_name = payload.get("tier", "community").upper()
        _active_tier = Tier[tier_name]
        _license_payload = payload
    except (LicenseError, KeyError):
        _active_tier = Tier.COMMUNITY
        _license_payload = None

    return _active_tier


def is_tier_active(tier: Tier) -> bool:
    """Check if the active tier is at or above the given tier."""
    return get_active_tier() >= tier


def is_feature_available(feature: str) -> bool:
    """Check if a feature is available under the current license tier."""
    required_tier = FEATURE_TIERS.get(feature)
    if required_tier is None:
        return False
    return is_tier_active(required_tier)


def reset_tier_cache() -> None:
    """Clear the cached tier and payload. Useful for testing."""
    global _active_tier, _license_payload
    _active_tier = None
    _license_payload = None


def require_tier(minimum_tier: Tier):
    """Decorator for HTTP handler methods that require a minimum license tier.

    When the active tier is below minimum_tier, calls
    self._send_error(HTTPStatus.PAYMENT_REQUIRED, message) and returns None.
    """

    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            current = get_active_tier()
            if current < minimum_tier:
                self._send_error(
                    HTTPStatus.PAYMENT_REQUIRED,
                    f"This feature requires a {minimum_tier.name} license "
                    f"(current: {current.name}). "
                    "Contact sales@roegate.io to upgrade.",
                )
                return None
            return method(self, *args, **kwargs)

        return wrapper

    return decorator
