"""License tier definitions and feature-to-tier mapping.

All features are open source and available at the COMMUNITY tier.
Tiers are retained for corporate compliance tracking — organizations
that require a commercial license can validate their key and see their
tier reported in the health endpoint.
"""

from enum import IntEnum


class Tier(IntEnum):
    """License tiers for corporate compliance tracking.

    All features are available regardless of tier. Higher tiers exist
    for organizations that require a commercial license agreement.
    """

    COMMUNITY = 0  # Open source, no key needed
    PRO = 1  # Corporate license
    ENTERPRISE = 2  # Corporate license
    MSSP = 3  # Corporate license (OEM/multi-tenant)


# Maps feature names to tiers. All features are COMMUNITY (open source).
# This mapping is retained for backward compatibility and informational queries.
FEATURE_TIERS = {
    "gate_pipeline": Tier.COMMUNITY,
    "rule_engine": Tier.COMMUNITY,
    "local_judge": Tier.COMMUNITY,
    "hmac_signing": Tier.COMMUNITY,
    "ed25519_signing": Tier.COMMUNITY,
    "single_roe": Tier.COMMUNITY,
    "mcp_tools": Tier.COMMUNITY,
    "cli_integration": Tier.COMMUNITY,
    "hitl": Tier.COMMUNITY,
    "dashboard": Tier.COMMUNITY,
    "cloud_judge": Tier.COMMUNITY,
    "multi_roe": Tier.COMMUNITY,
    "siem_logging": Tier.COMMUNITY,
    "alerting": Tier.COMMUNITY,
    "sso_rbac": Tier.COMMUNITY,
    "compliance_reports": Tier.COMMUNITY,
    "ha_clustering": Tier.COMMUNITY,
    "multi_tenant": Tier.COMMUNITY,
    "white_label": Tier.COMMUNITY,
}
