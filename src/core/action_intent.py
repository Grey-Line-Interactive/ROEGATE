"""
Action Intent Serialization

Every tool call from an agent is intercepted and serialized into a structured
Action Intent document. This is the intermediate representation that the ROE Gate
evaluates — the agent never directly describes what it wants to do to the execution
layer. Instead, this serializer translates raw tool calls into a normalized,
evaluatable format.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ActionCategory(str, Enum):
    """Taxonomy of security testing action categories.

    This taxonomy is the bridge between raw tool calls and ROE policy rules.
    The Rule Engine matches on these categories, not on raw tool names.
    """
    RECONNAISSANCE = "reconnaissance"
    PORT_SCANNING = "port_scanning"
    SERVICE_ENUMERATION = "service_enumeration"
    WEB_APPLICATION_TESTING = "web_application_testing"
    API_TESTING = "api_testing"
    AUTHENTICATION_TESTING = "authentication_testing"
    CREDENTIAL_TESTING = "credential_testing"
    AUTHORIZATION_TESTING = "authorization_testing"
    INJECTION_TESTING = "injection_testing"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    SOCIAL_ENGINEERING = "social_engineering"
    DIRECT_DATABASE_ACCESS = "direct_database_access"
    FILE_ACCESS = "file_access"
    COMMAND_EXECUTION = "command_execution"
    NETWORK_CONNECT = "network_connect"
    OTHER = "other"


class ImpactLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataAccessType(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"


@dataclass
class Target:
    """The target of an action — what system/service is being acted upon."""
    host: str = ""
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    url: str | None = None
    domain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ImpactAssessment:
    """The agent's self-declared assessment of the action's potential impact."""
    data_access: DataAccessType = DataAccessType.NONE
    service_disruption: ImpactLevel = ImpactLevel.NONE
    reversibility: str = "full"
    estimated_severity: ImpactLevel = ImpactLevel.LOW
    record_count_estimate: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {}
        result["data_access"] = self.data_access.value
        result["service_disruption"] = self.service_disruption.value
        result["reversibility"] = self.reversibility
        result["estimated_severity"] = self.estimated_severity.value
        if self.record_count_estimate is not None:
            result["record_count_estimate"] = self.record_count_estimate
        return result


@dataclass
class ActionIntent:
    """A serialized, structured representation of what an agent wants to do.

    This is the core data structure of the ROE Gate system. Every agent tool call
    is translated into an ActionIntent before evaluation. The agent never bypasses
    this — there is no direct path from agent to tool execution.
    """
    # Identity
    intent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    agent_session: str = ""
    engagement_id: str = ""

    # What the agent wants to do
    tool: str = ""                          # Raw tool name (e.g., "nmap", "curl", "psql")
    category: ActionCategory = ActionCategory.OTHER
    subcategory: str = ""                   # More specific (e.g., "sql_injection", "port_scan")
    description: str = ""                   # Human-readable description of the action

    # Where it's targeted
    target: Target = field(default_factory=Target)

    # How it will be done
    parameters: dict[str, Any] = field(default_factory=dict)

    # Impact assessment
    impact: ImpactAssessment = field(default_factory=ImpactAssessment)

    # Agent's stated reason
    justification: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for evaluation and signing."""
        return {
            "intent_id": self.intent_id,
            "timestamp": self.timestamp,
            "agent_session": self.agent_session,
            "engagement_id": self.engagement_id,
            "action": {
                "tool": self.tool,
                "category": self.category.value,
                "subcategory": self.subcategory,
                "description": self.description,
            },
            "target": self.target.to_dict(),
            "parameters": self.parameters,
            "impact_assessment": self.impact.to_dict(),
            "agent_justification": self.justification,
        }

    def to_json(self) -> str:
        """Serialize to stable JSON for hashing and signing."""
        import json
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


# ─── Tool-to-Intent Mapping ──────────────────────────────────────────────────
# This is how raw agent tool calls get classified. Each agent framework
# needs an adapter that maps its tool calls to ActionIntents.

# Common port-to-service mappings for automatic classification
PORT_SERVICE_MAP: dict[int, tuple[str, ActionCategory]] = {
    5432: ("postgresql", ActionCategory.DIRECT_DATABASE_ACCESS),
    3306: ("mysql", ActionCategory.DIRECT_DATABASE_ACCESS),
    27017: ("mongodb", ActionCategory.DIRECT_DATABASE_ACCESS),
    6379: ("redis", ActionCategory.DIRECT_DATABASE_ACCESS),
    1433: ("mssql", ActionCategory.DIRECT_DATABASE_ACCESS),
    1521: ("oracle", ActionCategory.DIRECT_DATABASE_ACCESS),
    22: ("ssh", ActionCategory.COMMAND_EXECUTION),
    23: ("telnet", ActionCategory.COMMAND_EXECUTION),
    3389: ("rdp", ActionCategory.COMMAND_EXECUTION),
    21: ("ftp", ActionCategory.FILE_ACCESS),
    445: ("smb", ActionCategory.FILE_ACCESS),
    139: ("netbios", ActionCategory.FILE_ACCESS),
    80: ("http", ActionCategory.WEB_APPLICATION_TESTING),
    443: ("https", ActionCategory.WEB_APPLICATION_TESTING),
    8080: ("http-alt", ActionCategory.WEB_APPLICATION_TESTING),
    8443: ("https-alt", ActionCategory.WEB_APPLICATION_TESTING),
}

# Tool name patterns and their default categories
TOOL_CATEGORY_MAP: dict[str, ActionCategory] = {
    "nmap": ActionCategory.PORT_SCANNING,
    "masscan": ActionCategory.PORT_SCANNING,
    "rustscan": ActionCategory.PORT_SCANNING,
    "curl": ActionCategory.WEB_APPLICATION_TESTING,
    "wget": ActionCategory.WEB_APPLICATION_TESTING,
    "httpx": ActionCategory.WEB_APPLICATION_TESTING,
    "sqlmap": ActionCategory.INJECTION_TESTING,
    "nikto": ActionCategory.WEB_APPLICATION_TESTING,
    "dirb": ActionCategory.WEB_APPLICATION_TESTING,
    "gobuster": ActionCategory.WEB_APPLICATION_TESTING,
    "ffuf": ActionCategory.WEB_APPLICATION_TESTING,
    "hydra": ActionCategory.CREDENTIAL_TESTING,
    "medusa": ActionCategory.CREDENTIAL_TESTING,
    "john": ActionCategory.CREDENTIAL_TESTING,
    "hashcat": ActionCategory.CREDENTIAL_TESTING,
    "psql": ActionCategory.DIRECT_DATABASE_ACCESS,
    "mysql": ActionCategory.DIRECT_DATABASE_ACCESS,
    "mongo": ActionCategory.DIRECT_DATABASE_ACCESS,
    "redis-cli": ActionCategory.DIRECT_DATABASE_ACCESS,
    "ssh": ActionCategory.COMMAND_EXECUTION,
    "scp": ActionCategory.FILE_ACCESS,
    "ftp": ActionCategory.FILE_ACCESS,
    "smbclient": ActionCategory.FILE_ACCESS,
    "metasploit": ActionCategory.EXPLOITATION,
    "msfconsole": ActionCategory.EXPLOITATION,
    "msfvenom": ActionCategory.EXPLOITATION,
    "burpsuite": ActionCategory.WEB_APPLICATION_TESTING,
    "nuclei": ActionCategory.WEB_APPLICATION_TESTING,
    "subfinder": ActionCategory.RECONNAISSANCE,
    "amass": ActionCategory.RECONNAISSANCE,
    "dig": ActionCategory.RECONNAISSANCE,
    "nslookup": ActionCategory.RECONNAISSANCE,
    "whois": ActionCategory.RECONNAISSANCE,
    "theHarvester": ActionCategory.RECONNAISSANCE,
}


def classify_tool_call(
    tool_name: str,
    target_host: str | None = None,
    target_port: int | None = None,
    **kwargs: Any,
) -> ActionIntent:
    """Classify a raw tool call into a structured ActionIntent.

    This is the primary entry point for the serialization layer. Agent framework
    adapters call this function to translate their tool calls into ActionIntents.
    """
    intent = ActionIntent()
    intent.tool = tool_name

    # Classify by tool name
    intent.category = TOOL_CATEGORY_MAP.get(tool_name, ActionCategory.OTHER)

    # Override classification based on target port if it indicates a specific service
    if target_port and target_port in PORT_SERVICE_MAP:
        service, port_category = PORT_SERVICE_MAP[target_port]
        # Port-based classification takes precedence for database/sensitive services
        if port_category in (
            ActionCategory.DIRECT_DATABASE_ACCESS,
            ActionCategory.COMMAND_EXECUTION,
        ):
            intent.category = port_category
            intent.target.service = service

    # Set target
    if target_host:
        intent.target.host = target_host
    if target_port:
        intent.target.port = target_port

    # Copy additional parameters
    intent.parameters = kwargs

    return intent
