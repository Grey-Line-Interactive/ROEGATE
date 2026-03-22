"""Tests for license tier gating on Gate API endpoints.

The project has transitioned to full open source — all features are available
regardless of license tier. The @require_tier decorator is now a no-op
(passthrough). Every endpoint that previously returned HTTP 402 for
insufficient tier should now return 200.

This file verifies:
  - Community-tier core endpoints still work (health, stats, audit, etc.)
  - Previously Pro-gated endpoints (roe/list, roe/add, roe/archive) return 200
  - Previously Enterprise-gated endpoints (compliance, cluster) return 200
  - Previously MSSP-gated endpoints (tenants, branding) return 200
  - Health endpoint still reports the license_tier field
"""

import json
import socket
import threading
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path

import yaml

from src.licensing.tiers import Tier
from src.licensing import validator


def _find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestTierGating(unittest.TestCase):
    """Test that gate_api.py endpoints are accessible regardless of tier."""

    @classmethod
    def setUpClass(cls):
        """Start a Gate API server for testing."""
        from src.service.gate_api import GateAPIServer

        roe_path = Path("examples/corpsec_labs_roe.yaml")
        with open(roe_path) as f:
            roe_spec = yaml.safe_load(f)["roe"]

        # Force COMMUNITY tier before server creation
        validator.reset_tier_cache()
        validator._active_tier = Tier.COMMUNITY

        cls.port = _find_free_port()
        cls.server = GateAPIServer(
            roe_spec=roe_spec,
            port=cls.port,
            judge_name="mock",
            human_in_the_loop=True,
        )
        cls.server_thread = threading.Thread(
            target=cls.server.start, daemon=True, kwargs={"blocking": True}
        )
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        """Reset tier to COMMUNITY before each test."""
        validator.reset_tier_cache()
        validator._active_tier = Tier.COMMUNITY

    def _get(self, path):
        conn = HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp.status, body

    def _post(self, path, data=None):
        conn = HTTPConnection("127.0.0.1", self.port)
        payload = json.dumps(data or {})
        conn.request(
            "POST",
            path,
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp_body = resp.read().decode()
        conn.close()
        return resp.status, resp_body

    # ── Community core endpoints: always accessible ───────────────────

    def test_community_can_access_health(self):
        """Health endpoint is available at Community tier."""
        status, body = self._get("/api/v1/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "ok")

    def test_community_can_access_stats(self):
        """Stats endpoint is available at Community tier."""
        status, _ = self._get("/api/v1/stats")
        self.assertEqual(status, 200)

    def test_community_can_access_audit(self):
        """Audit endpoint is available at Community tier."""
        status, _ = self._get("/api/v1/audit")
        self.assertEqual(status, 200)

    def test_community_can_access_public_key(self):
        """Public key endpoint is available at Community tier."""
        status, _ = self._get("/api/v1/public-key")
        self.assertEqual(status, 200)

    def test_community_can_access_approvals_pending(self):
        """HITL approvals pending endpoint is available at Community tier."""
        status, body = self._get("/api/v1/approvals/pending")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("approvals", data)

    # ── Previously Pro-gated endpoints: now accessible at any tier ────

    def test_roe_list_accessible_at_community_tier(self):
        """GET /api/v1/roe/list returns 200 at Community tier (was Pro)."""
        status, body = self._get("/api/v1/roe/list")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("roe_specs", data)

    def test_roe_add_accessible_at_community_tier(self):
        """POST /api/v1/roe/add is not tier-gated (was Pro). May return 400 for bad input."""
        status, _ = self._post("/api/v1/roe/add", {"roe_spec": {}})
        self.assertNotEqual(status, 402, "Endpoint should not be tier-gated")

    def test_roe_archive_accessible_at_community_tier(self):
        """POST /api/v1/roe/archive is not tier-gated (was Pro). May return 404 for unknown ID."""
        status, _ = self._post("/api/v1/roe/archive", {"engagement_id": "x"})
        self.assertNotEqual(status, 402, "Endpoint should not be tier-gated")

    # ── Previously Enterprise-gated endpoints: now accessible at any tier ─

    def test_compliance_soc2_accessible_at_community_tier(self):
        """GET /api/v1/compliance/soc2 returns 200 at Community tier (was Enterprise)."""
        status, _ = self._get("/api/v1/compliance/soc2")
        self.assertEqual(status, 200)

    def test_compliance_pci_dss_accessible_at_community_tier(self):
        """GET /api/v1/compliance/pci-dss returns 200 at Community tier (was Enterprise)."""
        status, _ = self._get("/api/v1/compliance/pci-dss")
        self.assertEqual(status, 200)

    def test_cluster_status_accessible_at_community_tier(self):
        """GET /api/v1/cluster/status returns 200 at Community tier (was Enterprise)."""
        status, _ = self._get("/api/v1/cluster/status")
        self.assertEqual(status, 200)

    def test_cluster_heartbeat_accessible_at_community_tier(self):
        """GET /api/v1/cluster/heartbeat returns 200 at Community tier (was Enterprise)."""
        status, _ = self._get("/api/v1/cluster/heartbeat")
        self.assertEqual(status, 200)

    # ── Previously MSSP-gated endpoints: now accessible at any tier ───

    def test_tenants_accessible_at_community_tier(self):
        """GET /api/v1/tenants returns 200 at Community tier (was MSSP)."""
        status, body = self._get("/api/v1/tenants")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("tenants", data)

    def test_tenant_create_accessible_at_community_tier(self):
        """POST /api/v1/tenants/create is not tier-gated (was MSSP). Returns 201 on success."""
        status, _ = self._post("/api/v1/tenants/create", {"name": "test"})
        self.assertIn(status, (200, 201), "Endpoint should accept requests (not tier-gated)")

    def test_branding_accessible_at_community_tier(self):
        """GET /api/v1/branding returns 200 at Community tier (was MSSP)."""
        status, _ = self._get("/api/v1/branding")
        self.assertEqual(status, 200)

    # ── Health endpoint includes license_tier ─────────────────────────

    def test_health_includes_license_tier(self):
        """Health endpoint response includes the license_tier field."""
        status, body = self._get("/api/v1/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("license_tier", data)
        self.assertEqual(data["license_tier"], "COMMUNITY")

    def test_health_shows_correct_tier_when_upgraded(self):
        """Health endpoint reflects the active tier."""
        validator.reset_tier_cache()
        validator._active_tier = Tier.PRO
        status, body = self._get("/api/v1/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["license_tier"], "PRO")

    # ── Comprehensive: every previously-gated endpoint returns 200 ────

    def test_all_feature_endpoints_accessible(self):
        """Every previously tier-gated endpoint returns 200 at Community tier.

        This is a comprehensive sweep to ensure the open-source transition
        did not leave any endpoint still returning 402.
        """
        get_endpoints = [
            # Previously Pro
            "/api/v1/roe/list",
            # Previously Enterprise
            "/api/v1/compliance/soc2",
            "/api/v1/compliance/pci-dss",
            "/api/v1/cluster/status",
            "/api/v1/cluster/heartbeat",
            # Previously MSSP
            "/api/v1/tenants",
            "/api/v1/branding",
        ]
        post_endpoints = [
            # Previously Pro
            ("/api/v1/roe/add", {"roe_spec": {}}),
            ("/api/v1/roe/archive", {"engagement_id": "x"}),
            # Previously MSSP
            ("/api/v1/tenants/create", {"name": "test"}),
        ]

        for path in get_endpoints:
            with self.subTest(method="GET", path=path):
                status, body = self._get(path)
                self.assertEqual(
                    status,
                    200,
                    f"GET {path} returned {status} (expected 200): {body}",
                )

        for path, payload in post_endpoints:
            with self.subTest(method="POST", path=path):
                status, body = self._post(path, payload)
                self.assertNotEqual(
                    status,
                    402,
                    f"POST {path} returned 402 (tier-gated — should be open): {body}",
                )


if __name__ == "__main__":
    unittest.main()
