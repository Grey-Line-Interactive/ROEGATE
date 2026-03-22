"""Tests for the tier activation packages (roe-gate-pro, roe-gate-enterprise, roe-gate-mssp)."""

import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch

# Ensure the project root and package src dirs are importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "packages" / "roe-gate-pro" / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "packages" / "roe-gate-enterprise" / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "packages" / "roe-gate-mssp" / "src"))

from src.licensing.keys import generate_license_key, LicenseError
from src.licensing.tiers import Tier
from src.licensing import validator


def _generate_test_key(tier: str) -> str:
    """Generate a valid test license key for the given tier."""
    private_key = (PROJECT_ROOT / "src" / "licensing" / "_vendor_private_key.pem").read_bytes()
    return generate_license_key(private_key, {
        "license_id": f"TEST-{tier.upper()}-001",
        "customer": "Test Corp",
        "tier": tier,
        "issued_at": "2024-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "max_agents": 5,
    })


@pytest.fixture(autouse=True)
def reset_state():
    """Reset validator cache and clear env var before each test."""
    validator.reset_tier_cache()
    old_key = os.environ.pop("ROE_GATE_LICENSE_KEY", None)
    yield
    validator.reset_tier_cache()
    if old_key is not None:
        os.environ["ROE_GATE_LICENSE_KEY"] = old_key
    else:
        os.environ.pop("ROE_GATE_LICENSE_KEY", None)


# ---- Test activate() with valid license keys ----

class TestActivateWithValidKey:
    def test_pro_activate_with_valid_pro_key(self):
        from roe_gate_pro.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("pro")
        activate()
        assert validator._active_tier == Tier.PRO

    def test_enterprise_activate_with_valid_enterprise_key(self):
        from roe_gate_enterprise.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("enterprise")
        activate()
        assert validator._active_tier == Tier.ENTERPRISE

    def test_mssp_activate_with_valid_mssp_key(self):
        from roe_gate_mssp.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("mssp")
        activate()
        assert validator._active_tier == Tier.MSSP

    def test_higher_tier_key_activates_lower_tier_package(self):
        """An MSSP key should work to activate the Pro package."""
        from roe_gate_pro.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("mssp")
        activate()
        assert validator._active_tier == Tier.MSSP


# ---- Test activate() raises LicenseError with no key ----

class TestActivateNoKey:
    def test_pro_activate_raises_without_key(self):
        from roe_gate_pro.activate import activate
        with pytest.raises(LicenseError, match="No license key found"):
            activate()

    def test_enterprise_activate_raises_without_key(self):
        from roe_gate_enterprise.activate import activate
        with pytest.raises(LicenseError, match="No license key found"):
            activate()

    def test_mssp_activate_raises_without_key(self):
        from roe_gate_mssp.activate import activate
        with pytest.raises(LicenseError, match="No license key found"):
            activate()


# ---- Test activate() raises LicenseError with insufficient tier ----

class TestActivateInsufficientTier:
    def test_enterprise_rejects_pro_key(self):
        from roe_gate_enterprise.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("pro")
        with pytest.raises(LicenseError, match="enterprise tier is required"):
            activate()

    def test_mssp_rejects_pro_key(self):
        from roe_gate_mssp.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("pro")
        with pytest.raises(LicenseError, match="mssp tier is required"):
            activate()

    def test_mssp_rejects_enterprise_key(self):
        from roe_gate_mssp.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("enterprise")
        with pytest.raises(LicenseError, match="mssp tier is required"):
            activate()


# ---- Test cached tier is set correctly ----

class TestCachedTierSet:
    def test_activate_sets_tier_and_payload(self):
        from roe_gate_pro.activate import activate
        os.environ["ROE_GATE_LICENSE_KEY"] = _generate_test_key("pro")
        activate()
        assert validator._active_tier == Tier.PRO
        assert validator._license_payload is not None
        assert validator._license_payload["customer"] == "Test Corp"
        assert validator._license_payload["tier"] == "pro"


# ---- Test _load_license_key ----

class TestLoadLicenseKey:
    def test_load_from_env_var(self):
        from roe_gate_pro.activate import _load_license_key
        os.environ["ROE_GATE_LICENSE_KEY"] = "ROE-PRO-test-key"
        assert _load_license_key() == "ROE-PRO-test-key"

    def test_load_from_file(self, tmp_path):
        from roe_gate_pro.activate import _load_license_key
        # Create ~/.roe-gate/license.key in a temp home dir
        license_dir = tmp_path / ".roe-gate"
        license_dir.mkdir()
        license_file = license_dir / "license.key"
        license_file.write_text("ROE-PRO-from-home-file\n")
        # Patch Path.home() to return our temp dir
        with patch.object(Path, "home", return_value=tmp_path):
            result = _load_license_key()
        assert result == "ROE-PRO-from-home-file"

    def test_load_returns_none_when_no_key(self):
        from roe_gate_pro.activate import _load_license_key
        os.environ.pop("ROE_GATE_LICENSE_KEY", None)
        with patch.object(Path, "home", return_value=Path("/nonexistent/path")):
            with patch.object(Path, "exists", return_value=False):
                result = _load_license_key()
        assert result is None


# ---- Test REQUIRED_TIER is set correctly per package ----

class TestRequiredTier:
    def test_pro_required_tier(self):
        from roe_gate_pro.activate import REQUIRED_TIER
        assert REQUIRED_TIER == "pro"

    def test_enterprise_required_tier(self):
        from roe_gate_enterprise.activate import REQUIRED_TIER
        assert REQUIRED_TIER == "enterprise"

    def test_mssp_required_tier(self):
        from roe_gate_mssp.activate import REQUIRED_TIER
        assert REQUIRED_TIER == "mssp"
