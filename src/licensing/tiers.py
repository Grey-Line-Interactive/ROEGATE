"""License tier definitions and feature-to-tier mapping."""

from enum import IntEnum


class Tier(IntEnum):
    """License tiers ordered by capability level. Higher value = more features."""

    COMMUNITY = 0  # Free, MIT-licensed, no key needed
    PRO = 1  # $2,500/mo, requires license key
    ENTERPRISE = 2  # $8,000/mo, requires license key
    MSSP = 3  # Custom pricing, requires license key


# Maps feature names to the minimum tier required.
# Community features are always available (no license needed).
FEATURE_TIERS = {
    # Community (free, MIT)
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
    # Pro ($2,500/mo)
    "multi_roe": Tier.PRO,
    "siem_logging": Tier.PRO,
    "alerting": Tier.PRO,
    "cloud_judge": Tier.COMMUNITY,
    # Enterprise ($8,000/mo)
    "sso_rbac": Tier.ENTERPRISE,
    "compliance_reports": Tier.ENTERPRISE,
    "ha_clustering": Tier.ENTERPRISE,
    # MSSP/OEM (Custom)
    "multi_tenant": Tier.MSSP,
    "white_label": Tier.MSSP,
}
