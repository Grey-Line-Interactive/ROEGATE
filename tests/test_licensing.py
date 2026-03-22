"""Tests for the ROE Gate licensing module."""

import pytest

from src.licensing.keys import (
    LicenseError,
    generate_key_pair,
    generate_license_key,
    parse_license_key,
    verify_license_key,
)
from src.licensing.tiers import FEATURE_TIERS, Tier
from src.licensing.validator import (
    get_active_tier,
    is_feature_available,
    is_tier_active,
    require_tier,
    reset_tier_cache,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vendor_keys():
    """Generate a fresh Ed25519 key pair for tests."""
    private_pem, public_pem = generate_key_pair()
    return private_pem, public_pem


@pytest.fixture
def valid_pro_payload():
    """A valid PRO-tier license payload that expires far in the future."""
    return {
        "license_id": "LIC-TEST-001",
        "customer": "Test Corp",
        "tier": "pro",
        "issued_at": "2024-01-15T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "max_agents": 10,
    }


@pytest.fixture
def valid_pro_key(vendor_keys, valid_pro_payload):
    """A signed PRO license key string."""
    private_pem, _ = vendor_keys
    return generate_license_key(private_pem, valid_pro_payload)


@pytest.fixture(autouse=True)
def clean_license_state(monkeypatch):
    """Reset license cache and clear env var before each test."""
    reset_tier_cache()
    monkeypatch.delenv("ROE_GATE_LICENSE_KEY", raising=False)


# ---------------------------------------------------------------------------
# Tier ordering
# ---------------------------------------------------------------------------

class TestTiers:
    def test_tier_ordering(self):
        """COMMUNITY < PRO < ENTERPRISE < MSSP."""
        assert Tier.COMMUNITY < Tier.PRO < Tier.ENTERPRISE < Tier.MSSP

    def test_tier_values(self):
        assert Tier.COMMUNITY == 0
        assert Tier.PRO == 1
        assert Tier.ENTERPRISE == 2
        assert Tier.MSSP == 3

    def test_feature_tiers_community_features(self):
        """All community features map to Tier.COMMUNITY."""
        community_features = [
            "gate_pipeline", "rule_engine", "local_judge", "hmac_signing",
            "ed25519_signing", "single_roe", "mcp_tools", "cli_integration",
            "hitl", "dashboard",
        ]
        for feat in community_features:
            assert FEATURE_TIERS[feat] == Tier.COMMUNITY, f"{feat} should be COMMUNITY"

    def test_feature_tiers_all_community(self):
        """All features map to Tier.COMMUNITY (open source transition)."""
        for feat, tier in FEATURE_TIERS.items():
            assert tier == Tier.COMMUNITY, f"{feat} should be COMMUNITY"


# ---------------------------------------------------------------------------
# Key generation and parsing
# ---------------------------------------------------------------------------

class TestKeys:
    def test_generate_key_pair(self):
        """generate_key_pair returns valid PEM-encoded keys."""
        private_pem, public_pem = generate_key_pair()
        assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_generate_license_key_format(self, vendor_keys, valid_pro_payload):
        """License key starts with ROE-{TIER}- prefix."""
        private_pem, _ = vendor_keys
        key = generate_license_key(private_pem, valid_pro_payload)
        assert key.startswith("ROE-PRO-")
        # Must have a dot separating payload and signature
        assert "." in key[len("ROE-PRO-"):]

    def test_generate_license_key_enterprise(self, vendor_keys):
        """Enterprise tier key starts with ROE-ENTERPRISE-."""
        private_pem, _ = vendor_keys
        payload = {"tier": "enterprise", "license_id": "E-001",
                    "expires_at": "2099-12-31T23:59:59Z"}
        key = generate_license_key(private_pem, payload)
        assert key.startswith("ROE-ENTERPRISE-")

    def test_parse_license_key(self, valid_pro_key, valid_pro_payload):
        """parse_license_key extracts the correct payload."""
        payload, signature = parse_license_key(valid_pro_key)
        assert payload["license_id"] == valid_pro_payload["license_id"]
        assert payload["customer"] == valid_pro_payload["customer"]
        assert payload["tier"] == "pro"
        assert len(signature) == 64  # Ed25519 signatures are 64 bytes

    def test_parse_license_key_bad_prefix(self):
        """Rejects keys without ROE- prefix."""
        with pytest.raises(ValueError, match="must start with 'ROE-'"):
            parse_license_key("INVALID-KEY-STRING")

    def test_parse_license_key_no_signature(self):
        """Rejects keys without a signature separator."""
        with pytest.raises(ValueError):
            parse_license_key("ROE-PRO-payloadonly")

    def test_verify_license_key_valid(self, vendor_keys, valid_pro_key, valid_pro_payload):
        """Valid key verifies and returns correct payload."""
        _, public_pem = vendor_keys
        payload = verify_license_key(valid_pro_key, public_pem)
        assert payload["license_id"] == valid_pro_payload["license_id"]
        assert payload["tier"] == "pro"

    def test_verify_license_key_tampered(self, vendor_keys, valid_pro_key):
        """Tampered payload fails signature verification."""
        _, public_pem = vendor_keys
        # Replace a character in the payload portion to tamper with it
        parts = valid_pro_key.split(".")
        payload_part = parts[0]
        # Flip a character in the base64 payload
        tampered = payload_part[:-1] + ("A" if payload_part[-1] != "A" else "B")
        tampered_key = tampered + "." + parts[1]
        with pytest.raises(LicenseError):
            verify_license_key(tampered_key, public_pem)

    def test_verify_license_key_expired(self, vendor_keys):
        """Expired key raises LicenseError."""
        private_pem, public_pem = vendor_keys
        payload = {
            "license_id": "LIC-EXPIRED",
            "tier": "pro",
            "expires_at": "2020-01-01T00:00:00Z",
        }
        key = generate_license_key(private_pem, payload)
        with pytest.raises(LicenseError, match="expired"):
            verify_license_key(key, public_pem)

    def test_verify_license_key_wrong_public_key(self, valid_pro_key):
        """Verification with a different public key fails."""
        _, other_public_pem = generate_key_pair()
        with pytest.raises(LicenseError, match="signature verification failed"):
            verify_license_key(valid_pro_key, other_public_pem)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class TestValidator:
    def test_get_active_tier_no_key(self):
        """Returns COMMUNITY when no license key is set."""
        assert get_active_tier() == Tier.COMMUNITY

    def test_get_active_tier_with_valid_pro_key(self, monkeypatch):
        """Returns PRO when a valid PRO key is in the env var."""
        # Use the project's vendor private key to generate a key
        # that the validator's embedded public key can verify.
        from pathlib import Path
        vendor_private_path = Path(__file__).resolve().parent.parent / "src" / "licensing" / "_vendor_private_key.pem"
        private_pem = vendor_private_path.read_bytes()

        payload = {
            "license_id": "LIC-TEST-PRO",
            "customer": "Test",
            "tier": "pro",
            "issued_at": "2024-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
            "max_agents": 5,
        }
        key = generate_license_key(private_pem, payload)
        monkeypatch.setenv("ROE_GATE_LICENSE_KEY", key)
        reset_tier_cache()
        assert get_active_tier() == Tier.PRO

    def test_get_active_tier_caches(self, monkeypatch):
        """Tier is cached after first call."""
        assert get_active_tier() == Tier.COMMUNITY
        # Even if we set a key now, the cached value persists
        monkeypatch.setenv("ROE_GATE_LICENSE_KEY", "ROE-PRO-fake.fake")
        assert get_active_tier() == Tier.COMMUNITY

    def test_is_tier_active_lower_tiers(self):
        """COMMUNITY tier satisfies COMMUNITY check."""
        assert is_tier_active(Tier.COMMUNITY) is True

    def test_is_tier_active_higher_tiers(self):
        """COMMUNITY tier does NOT satisfy PRO check."""
        assert is_tier_active(Tier.PRO) is False
        assert is_tier_active(Tier.ENTERPRISE) is False
        assert is_tier_active(Tier.MSSP) is False

    def test_is_feature_available_community(self):
        """Community features available without a license."""
        assert is_feature_available("gate_pipeline") is True
        assert is_feature_available("rule_engine") is True
        assert is_feature_available("dashboard") is True

    def test_is_feature_available_all_known_features(self):
        """All known features are available (open source transition)."""
        assert is_feature_available("multi_roe") is True
        assert is_feature_available("siem_logging") is True

    def test_is_feature_available_unknown_feature(self):
        """Unknown features are not available."""
        assert is_feature_available("nonexistent_feature") is False

    def test_reset_tier_cache(self):
        """reset_tier_cache clears the cached tier."""
        # Prime the cache
        get_active_tier()
        # Reset should allow re-evaluation
        reset_tier_cache()
        # After reset, it should re-evaluate (still COMMUNITY since no key)
        assert get_active_tier() == Tier.COMMUNITY


# ---------------------------------------------------------------------------
# require_tier decorator
# ---------------------------------------------------------------------------

class MockHandler:
    """Mock HTTP handler for testing require_tier decorator."""

    def __init__(self):
        self.error_sent = None

    def _send_error(self, status, message):
        self.error_sent = (status, message)

    @require_tier(Tier.PRO)
    def pro_feature(self):
        return "success"

    @require_tier(Tier.ENTERPRISE)
    def enterprise_feature(self):
        return "enterprise_success"


class TestRequireTier:
    def test_require_tier_passthrough(self):
        """Decorator is a no-op passthrough (open source transition)."""
        handler = MockHandler()
        result = handler.pro_feature()
        assert result == "success"
        assert handler.error_sent is None

    def test_require_tier_allows_sufficient(self, monkeypatch):
        """Decorator allows when active tier meets or exceeds required tier."""
        from pathlib import Path
        vendor_private_path = Path(__file__).resolve().parent.parent / "src" / "licensing" / "_vendor_private_key.pem"
        private_pem = vendor_private_path.read_bytes()

        payload = {
            "license_id": "LIC-TEST-ENT",
            "tier": "enterprise",
            "expires_at": "2099-12-31T23:59:59Z",
        }
        key = generate_license_key(private_pem, payload)
        monkeypatch.setenv("ROE_GATE_LICENSE_KEY", key)
        reset_tier_cache()

        handler = MockHandler()
        # Enterprise >= Pro, so pro_feature should work
        assert handler.pro_feature() == "success"
        assert handler.error_sent is None
        # Enterprise >= Enterprise, so enterprise_feature should work
        assert handler.enterprise_feature() == "enterprise_success"
