#!/usr/bin/env python3
"""
ROE Gate MCP Server -- Model Context Protocol Server for Gated Penetration Testing

This is a standalone MCP (Model Context Protocol) server that communicates with
Claude Code over stdin/stdout using the JSON-RPC 2.0 protocol. It exposes
penetration testing tools that are gated by the ROE Gate Service -- a separate
HTTP API running on localhost.

Architecture Flow:
    Claude Code Agent --(stdin/stdout)--> MCP Server --(HTTP)--> Gate Service API
                                              |                        |
                                              |                   ROE Gate evaluates
                                              |                   Token signed
                                              |                        |
                                         MCP Server <--(HTTP)--< Gate Service API
                                              |                   Executor runs cmd
                                              |                   Returns result
    Claude Code Agent <--(stdin/stdout)--< MCP Server

Every tool call is serialized into an ActionIntent, sent to the Gate Service for
evaluation, and only executed if the Gate returns ALLOW with a signed token. The
MCP server itself never makes policy decisions or runs commands directly.

Usage:
    python -m src.service.mcp_server
    python -m src.service.mcp_server --gate-url http://127.0.0.1:19990
    python -m src.service.mcp_server --engagement-id ACME-2026
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
import urllib.request

# ---------------------------------------------------------------------------
# Logging -- MUST go to stderr. stdout is reserved for JSON-RPC messages.
# ---------------------------------------------------------------------------

logger = logging.getLogger("roe_gate.mcp_server")


def _configure_logging(level: int = logging.INFO) -> None:
    """Configure logging to write exclusively to stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


# ---------------------------------------------------------------------------
# Gate HTTP Client -- uses only stdlib (urllib), no external dependencies
# ---------------------------------------------------------------------------

class GateClient:
    """HTTP client for the ROE Gate Service API.

    All communication with the Gate Service goes through this client.
    The MCP server never evaluates policy or executes commands directly --
    it delegates everything to the Gate Service over HTTP.
    """

    def __init__(self, base_url: str, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        logger.info("Gate client initialized | url=%s", self.base_url)

    def _request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send an HTTP request to the Gate Service API.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: API path (e.g., "/api/v1/evaluate").
            data: Request body (will be JSON-encoded).

        Returns:
            Parsed JSON response as a dictionary.

        Raises:
            GateConnectionError: If the Gate Service is unreachable.
            GateAPIError: If the Gate Service returns an error response.
        """
        url = f"{self.base_url}{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        headers = {"Content-Type": "application/json"} if body else {}

        req = urllib.request.Request(
            url, data=body, method=method, headers=headers,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            error_body = ""
            try:
                error_body = exc.read().decode("utf-8")
            except Exception:
                pass
            logger.error(
                "Gate API error | status=%d | url=%s | body=%s",
                exc.code, url, error_body[:500],
            )
            raise GateAPIError(
                f"Gate API returned HTTP {exc.code}: {error_body[:500]}"
            ) from exc
        except URLError as exc:
            logger.error("Gate connection error | url=%s | reason=%s", url, exc.reason)
            raise GateConnectionError(
                f"Cannot connect to Gate Service at {url}: {exc.reason}"
            ) from exc

    def health(self) -> dict[str, Any]:
        """Check Gate Service health and get engagement info."""
        return self._request("GET", "/api/v1/health")

    def evaluate(self, intent: dict[str, Any]) -> dict[str, Any]:
        """Submit an ActionIntent for evaluation.

        Args:
            intent: Serialized ActionIntent dictionary.

        Returns:
            Gate evaluation response with decision, reasoning, and
            optionally a signed token.
        """
        return self._request("POST", "/api/v1/evaluate", intent)

    def execute(
        self,
        token: dict[str, Any],
        tool: str,
        args: list[str],
    ) -> dict[str, Any]:
        """Execute an approved action using a signed token.

        Args:
            token: The signed ActionToken from the evaluate response.
            tool: Tool binary name to execute.
            args: Command-line arguments for the tool.

        Returns:
            Execution result with stdout, stderr, exit code, etc.
        """
        return self._request("POST", "/api/v1/execute", {
            "token": token,
            "tool": tool,
            "args": args,
        })


class GateConnectionError(Exception):
    """Raised when the Gate Service is unreachable."""


class GateAPIError(Exception):
    """Raised when the Gate Service returns an error HTTP status."""


# ---------------------------------------------------------------------------
# Port/Tool Classification Maps (imported inline to avoid package imports
# when running as a standalone script)
# ---------------------------------------------------------------------------

# Common port-to-service mappings for automatic classification
PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {
    5432:  ("postgresql", "direct_database_access"),
    3306:  ("mysql",      "direct_database_access"),
    27017: ("mongodb",    "direct_database_access"),
    6379:  ("redis",      "direct_database_access"),
    1433:  ("mssql",      "direct_database_access"),
    1521:  ("oracle",     "direct_database_access"),
    22:    ("ssh",        "command_execution"),
    23:    ("telnet",     "command_execution"),
    3389:  ("rdp",        "command_execution"),
    21:    ("ftp",        "file_access"),
    445:   ("smb",        "file_access"),
    139:   ("netbios",    "file_access"),
    80:    ("http",       "web_application_testing"),
    443:   ("https",      "web_application_testing"),
    8080:  ("http-alt",   "web_application_testing"),
    8443:  ("https-alt",  "web_application_testing"),
}

# Tool name patterns and their default categories
TOOL_CATEGORY_MAP: dict[str, str] = {
    "nmap":         "port_scanning",
    "masscan":      "port_scanning",
    "rustscan":     "port_scanning",
    "curl":         "web_application_testing",
    "wget":         "web_application_testing",
    "httpx":        "web_application_testing",
    "sqlmap":       "injection_testing",
    "nikto":        "web_application_testing",
    "dirb":         "web_application_testing",
    "gobuster":     "web_application_testing",
    "ffuf":         "web_application_testing",
    "hydra":        "credential_testing",
    "medusa":       "credential_testing",
    "john":         "credential_testing",
    "hashcat":      "credential_testing",
    "psql":         "direct_database_access",
    "mysql":        "direct_database_access",
    "mongo":        "direct_database_access",
    "redis-cli":    "direct_database_access",
    "ssh":          "command_execution",
    "scp":          "file_access",
    "ftp":          "file_access",
    "smbclient":    "file_access",
    "metasploit":   "exploitation",
    "msfconsole":   "exploitation",
    "msfvenom":     "exploitation",
    "burpsuite":    "web_application_testing",
    "nuclei":       "web_application_testing",
    "subfinder":    "reconnaissance",
    "amass":        "reconnaissance",
    "dig":          "reconnaissance",
    "nslookup":     "reconnaissance",
    "whois":        "reconnaissance",
    "theHarvester": "reconnaissance",
}


# ---------------------------------------------------------------------------
# ActionIntent Builder Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _build_intent(
    session_id: str,
    engagement_id: str,
    tool: str,
    category: str,
    subcategory: str,
    description: str,
    target_host: str = "",
    target_port: int | None = None,
    target_protocol: str | None = None,
    target_url: str | None = None,
    target_domain: str | None = None,
    target_service: str | None = None,
    parameters: dict[str, Any] | None = None,
    data_access: str = "none",
    service_disruption: str = "none",
    reversibility: str = "full",
    estimated_severity: str = "low",
    justification: str = "",
) -> dict[str, Any]:
    """Build a serialized ActionIntent dictionary for the Gate Service API.

    This mirrors the format produced by ActionIntent.to_dict() from the core
    module, but is implemented inline to keep the MCP server self-contained
    (no package imports from the parent project).

    Args:
        session_id: Agent session identifier.
        engagement_id: Engagement identifier.
        tool: Tool binary name (e.g., "nmap", "curl").
        category: ActionCategory value string.
        subcategory: More specific classification.
        description: Human-readable description of the action.
        target_host: Target hostname or IP address.
        target_port: Target port number.
        target_protocol: Network protocol (e.g., "tcp", "https").
        target_url: Full URL target (for web tools).
        target_domain: Target domain name.
        target_service: Service name (e.g., "postgresql").
        parameters: Additional tool-specific parameters.
        data_access: Expected data access level.
        service_disruption: Expected service disruption level.
        reversibility: Whether the action is reversible.
        estimated_severity: Estimated severity of the action.
        justification: Agent's stated reason for the action.

    Returns:
        Serialized ActionIntent dictionary ready for the Gate API.
    """
    target: dict[str, Any] = {}
    if target_host:
        target["host"] = target_host
    if target_port is not None:
        target["port"] = target_port
    if target_protocol:
        target["protocol"] = target_protocol
    if target_url:
        target["url"] = target_url
    if target_domain:
        target["domain"] = target_domain
    if target_service:
        target["service"] = target_service

    return {
        "intent_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "agent_session": session_id,
        "engagement_id": engagement_id,
        "action": {
            "tool": tool,
            "category": category,
            "subcategory": subcategory,
            "description": description,
        },
        "target": target,
        "parameters": parameters or {},
        "impact_assessment": {
            "data_access": data_access,
            "service_disruption": service_disruption,
            "reversibility": reversibility,
            "estimated_severity": estimated_severity,
        },
        "agent_justification": justification,
    }


def _extract_host_from_url(url: str) -> tuple[str, int | None, str | None]:
    """Extract host, port, and domain from a URL.

    Returns:
        Tuple of (host, port, domain). Port may be None if not specified.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        domain = parsed.hostname
        return host, port, domain
    except Exception:
        return "", None, None


def _classify_tool_from_command(command: str) -> tuple[str, str]:
    """Classify a shell command by extracting the tool name and looking it up.

    Args:
        command: Full shell command string.

    Returns:
        Tuple of (tool_name, category_string).
    """
    parts = command.strip().split()
    if not parts:
        return "unknown", "other"

    # Skip common wrappers
    skip = {"sudo", "env", "timeout", "nice", "nohup", "time"}
    idx = 0
    while idx < len(parts) and parts[idx] in skip:
        idx += 1
    tool = parts[idx] if idx < len(parts) else parts[0]

    category = TOOL_CATEGORY_MAP.get(tool, "other")
    return tool, category


# ---------------------------------------------------------------------------
# Tool Definitions -- JSON Schema for each MCP tool
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "roe_nmap_scan",
        "description": (
            "Port scan a target host using nmap, gated by the ROE Gate Service. "
            "The scan will only execute if it passes Rules of Engagement evaluation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or IP address to scan",
                },
                "ports": {
                    "type": "string",
                    "description": "Port range to scan (e.g., '1-1000', '80,443,8080')",
                    "default": "1-1000",
                },
                "scan_type": {
                    "type": "string",
                    "description": "Scan type: tcp_connect or service_version",
                    "enum": ["tcp_connect", "service_version"],
                    "default": "tcp_connect",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this scan is needed (helps with ROE evaluation)",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "roe_http_request",
        "description": (
            "Send an HTTP request to a target URL, gated by the ROE Gate Service. "
            "The request will only execute if it passes Rules of Engagement evaluation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to send the request to",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method to use",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "default": "GET",
                },
                "data": {
                    "type": "string",
                    "description": "Request body data",
                },
                "headers": {
                    "type": "object",
                    "description": "Additional HTTP headers as key-value pairs",
                    "additionalProperties": {"type": "string"},
                },
                "justification": {
                    "type": "string",
                    "description": "Why this request is needed (helps with ROE evaluation)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "roe_dns_lookup",
        "description": (
            "Perform a DNS lookup for a domain, gated by the ROE Gate Service. "
            "The lookup will only execute if it passes Rules of Engagement evaluation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain name to look up",
                },
                "record_type": {
                    "type": "string",
                    "description": "DNS record type to query",
                    "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME"],
                    "default": "A",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this lookup is needed (helps with ROE evaluation)",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "roe_service_probe",
        "description": (
            "Probe a specific service on a host:port, gated by the ROE Gate Service. "
            "The probe will only execute if it passes Rules of Engagement evaluation. "
            "The action category is auto-classified based on the target port."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target host to probe",
                },
                "port": {
                    "type": "integer",
                    "description": "Target port to probe",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this probe is needed (helps with ROE evaluation)",
                },
            },
            "required": ["host", "port"],
        },
    },
    {
        "name": "roe_directory_scan",
        "description": (
            "Scan web application directories for hidden paths and files, "
            "gated by the ROE Gate Service. The scan will only execute if it "
            "passes Rules of Engagement evaluation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Base URL of the web application to scan",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist to use for directory enumeration",
                    "default": "common",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this scan is needed (helps with ROE evaluation)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "roe_sql_injection_test",
        "description": (
            "Test a URL parameter for SQL injection vulnerabilities, "
            "gated by the ROE Gate Service. The test will only execute if it "
            "passes Rules of Engagement evaluation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL containing the parameter to test",
                },
                "parameter": {
                    "type": "string",
                    "description": "Name of the URL parameter to test for SQL injection",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method to use for the test",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this test is needed (helps with ROE evaluation)",
                },
            },
            "required": ["url", "parameter"],
        },
    },
    {
        "name": "roe_shell_command",
        "description": (
            "Execute an arbitrary shell command through the ROE Gate Service. "
            "This is the escape hatch for tools not covered by the specific "
            "tools above. The command will only execute if it passes Rules of "
            "Engagement evaluation. The action category is auto-classified "
            "based on the tool name in the command."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Full shell command to execute",
                },
                "target_host": {
                    "type": "string",
                    "description": "Target host for the command (helps with ROE scoping)",
                },
                "target_port": {
                    "type": "integer",
                    "description": "Target port for the command (helps with classification)",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this command is needed (helps with ROE evaluation)",
                },
            },
            "required": ["command"],
        },
    },
]


# ---------------------------------------------------------------------------
# Tool Handlers -- build ActionIntent and route through the Gate
# ---------------------------------------------------------------------------

class ToolHandler:
    """Handles MCP tool calls by routing them through the Gate Service.

    Each tool call is:
    1. Translated into an ActionIntent dictionary
    2. Sent to POST /api/v1/evaluate on the Gate Service
    3. If ALLOW: the signed token + command are sent to POST /api/v1/execute
    4. If DENY/HALT/ESCALATE: an error message is returned to the agent
    """

    def __init__(
        self,
        gate: GateClient,
        session_id: str,
        engagement_id: str,
    ) -> None:
        self.gate = gate
        self.session_id = session_id
        self.engagement_id = engagement_id

    def handle(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call to the appropriate handler.

        Args:
            tool_name: The MCP tool name (e.g., "roe_nmap_scan").
            arguments: The tool's input arguments.

        Returns:
            MCP tool result with content array.
        """
        handlers = {
            "roe_nmap_scan": self._handle_nmap_scan,
            "roe_http_request": self._handle_http_request,
            "roe_dns_lookup": self._handle_dns_lookup,
            "roe_service_probe": self._handle_service_probe,
            "roe_directory_scan": self._handle_directory_scan,
            "roe_sql_injection_test": self._handle_sql_injection_test,
            "roe_shell_command": self._handle_shell_command,
        }

        handler = handlers.get(tool_name)
        if handler is None:
            return _tool_error(f"Unknown tool: {tool_name}")

        try:
            return handler(arguments)
        except GateConnectionError as exc:
            logger.error("Gate connection failed: %s", exc)
            return _tool_error(
                f"Cannot connect to Gate Service: {exc}\n"
                "Ensure the Gate Service is running and accessible."
            )
        except GateAPIError as exc:
            logger.error("Gate API error: %s", exc)
            return _tool_error(f"Gate Service error: {exc}")
        except Exception as exc:
            logger.exception("Unexpected error handling tool %s", tool_name)
            return _tool_error(f"Internal error: {exc}")

    # -- Individual tool handlers ------------------------------------------

    def _handle_nmap_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle roe_nmap_scan: port scan a target host."""
        target = args["target"]
        ports = args.get("ports", "1-1000")
        scan_type = args.get("scan_type", "tcp_connect")
        justification = args.get("justification", "")

        scan_flag = "-sT" if scan_type == "tcp_connect" else "-sV"
        description = f"Port scan of {target} (ports {ports}, type {scan_type})"

        intent = _build_intent(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            tool="nmap",
            category="reconnaissance",
            subcategory="port_scan",
            description=description,
            target_host=target,
            target_protocol="tcp",
            parameters={"ports": ports, "scan_type": scan_type},
            data_access="none",
            service_disruption="none",
            estimated_severity="low",
            justification=justification,
        )

        tool_cmd = "nmap"
        tool_args = [scan_flag, "-p", ports, target]
        return self._evaluate_and_execute(intent, tool_cmd, tool_args)

    def _handle_http_request(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle roe_http_request: send an HTTP request."""
        url = args["url"]
        method = args.get("method", "GET")
        data = args.get("data")
        headers = args.get("headers", {})
        justification = args.get("justification", "")

        host, port, domain = _extract_host_from_url(url)
        description = f"HTTP {method} request to {url}"

        parsed_url = urlparse(url)
        protocol = parsed_url.scheme or "http"

        intent = _build_intent(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            tool="curl",
            category="web_application_testing",
            subcategory="",
            description=description,
            target_host=host,
            target_port=port,
            target_protocol=protocol,
            target_url=url,
            target_domain=domain,
            parameters={
                "method": method,
                "data": data,
                "headers": headers,
            },
            data_access="read",
            service_disruption="none",
            estimated_severity="medium",
            justification=justification,
        )

        tool_args = ["-X", method, url]
        if data:
            tool_args.extend(["-d", data])
        if headers:
            for k, v in headers.items():
                tool_args.extend(["-H", f"{k}: {v}"])

        return self._evaluate_and_execute(intent, "curl", tool_args)

    def _handle_dns_lookup(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle roe_dns_lookup: DNS lookup for a domain."""
        domain = args["domain"]
        record_type = args.get("record_type", "A")
        justification = args.get("justification", "")

        description = f"DNS {record_type} lookup for {domain}"

        intent = _build_intent(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            tool="dig",
            category="reconnaissance",
            subcategory="dns_enumeration",
            description=description,
            target_domain=domain,
            target_host=domain,
            target_protocol="udp",
            parameters={"record_type": record_type},
            data_access="none",
            service_disruption="none",
            estimated_severity="low",
            justification=justification,
        )

        tool_args = [domain, record_type]
        return self._evaluate_and_execute(intent, "dig", tool_args)

    def _handle_service_probe(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle roe_service_probe: probe a specific service on host:port.

        The action category is auto-classified based on the target port using
        PORT_SERVICE_MAP.
        """
        host = args["host"]
        port = args["port"]
        justification = args.get("justification", "")

        # Auto-classify based on port
        service_name = None
        category = "service_enumeration"
        if port in PORT_SERVICE_MAP:
            service_name, category = PORT_SERVICE_MAP[port]

        description = f"Service probe of {host}:{port}"
        if service_name:
            description += f" ({service_name})"

        # Determine severity based on category
        severity = "low"
        data_access = "none"
        if category in ("direct_database_access", "command_execution"):
            severity = "high"
            data_access = "read"
        elif category in ("file_access",):
            severity = "medium"
            data_access = "read"

        intent = _build_intent(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            tool="nmap",
            category=category,
            subcategory="service_probe",
            description=description,
            target_host=host,
            target_port=port,
            target_protocol="tcp",
            target_service=service_name,
            parameters={},
            data_access=data_access,
            service_disruption="none",
            estimated_severity=severity,
            justification=justification,
        )

        tool_args = ["-sV", "-p", str(port), host]
        return self._evaluate_and_execute(intent, "nmap", tool_args)

    def _handle_directory_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle roe_directory_scan: scan web application directories."""
        url = args["url"]
        wordlist = args.get("wordlist", "common")
        justification = args.get("justification", "")

        host, port, domain = _extract_host_from_url(url)
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme or "http"
        description = f"Directory scan of {url} (wordlist: {wordlist})"

        intent = _build_intent(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            tool="gobuster",
            category="web_application_testing",
            subcategory="directory_enumeration",
            description=description,
            target_host=host,
            target_port=port,
            target_protocol=protocol,
            target_url=url,
            target_domain=domain,
            parameters={"wordlist": wordlist},
            data_access="none",
            service_disruption="low",
            estimated_severity="medium",
            justification=justification,
        )

        tool_args = ["dir", "-u", url, "-w", wordlist]
        return self._evaluate_and_execute(intent, "gobuster", tool_args)

    def _handle_sql_injection_test(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle roe_sql_injection_test: test a parameter for SQLi."""
        url = args["url"]
        parameter = args["parameter"]
        method = args.get("method", "GET")
        justification = args.get("justification", "")

        host, port, domain = _extract_host_from_url(url)
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme or "http"
        description = (
            f"SQL injection test on {url} parameter '{parameter}' "
            f"via {method}"
        )

        intent = _build_intent(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            tool="sqlmap",
            category="web_application_testing",
            subcategory="sql_injection",
            description=description,
            target_host=host,
            target_port=port,
            target_protocol=protocol,
            target_url=url,
            target_domain=domain,
            parameters={
                "parameter": parameter,
                "method": method,
            },
            data_access="read",
            service_disruption="low",
            estimated_severity="high",
            justification=justification,
        )

        tool_args = ["-u", url, "-p", parameter, "--method", method, "--batch"]
        return self._evaluate_and_execute(intent, "sqlmap", tool_args)

    def _handle_shell_command(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle roe_shell_command: execute an arbitrary shell command.

        The action category is auto-classified based on the tool name in the
        command using TOOL_CATEGORY_MAP.
        """
        command = args["command"]
        target_host = args.get("target_host", "")
        target_port = args.get("target_port")
        justification = args.get("justification", "")

        # Classify the tool from the command
        tool_name, category = _classify_tool_from_command(command)

        # Override classification based on target port if it indicates a
        # specific service (database, SSH, etc.)
        service_name = None
        if target_port is not None and target_port in PORT_SERVICE_MAP:
            service_name, port_category = PORT_SERVICE_MAP[target_port]
            # Port-based classification takes precedence for sensitive services
            if port_category in ("direct_database_access", "command_execution"):
                category = port_category

        description = f"Shell command: {command[:200]}"

        # Determine severity based on category
        severity_map = {
            "exploitation": "critical",
            "direct_database_access": "high",
            "command_execution": "high",
            "privilege_escalation": "high",
            "data_exfiltration": "critical",
            "injection_testing": "high",
            "credential_testing": "medium",
            "web_application_testing": "medium",
            "reconnaissance": "low",
            "port_scanning": "low",
        }
        severity = severity_map.get(category, "medium")

        data_access_map = {
            "direct_database_access": "read",
            "file_access": "read",
            "data_exfiltration": "read",
        }
        data_access = data_access_map.get(category, "none")

        intent = _build_intent(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            tool=tool_name,
            category=category,
            subcategory="",
            description=description,
            target_host=target_host,
            target_port=target_port,
            target_protocol="tcp",
            target_service=service_name,
            parameters={"raw_command": command},
            data_access=data_access,
            service_disruption="none",
            estimated_severity=severity,
            justification=justification,
        )

        # Split command into tool + args for the executor
        parts = command.strip().split()
        exec_tool = parts[0] if parts else tool_name
        exec_args = parts[1:] if len(parts) > 1 else []

        return self._evaluate_and_execute(intent, exec_tool, exec_args)

    # -- Core evaluation/execution pipeline --------------------------------

    def _evaluate_and_execute(
        self,
        intent: dict[str, Any],
        tool: str,
        args: list[str],
    ) -> dict[str, Any]:
        """Send the intent to the Gate for evaluation, then execute if allowed.

        This is the core pipeline:
        1. POST /api/v1/evaluate with the ActionIntent
        2. If ALLOW: POST /api/v1/execute with the token + tool + args
        3. Return the result as an MCP tool response

        Args:
            intent: The serialized ActionIntent dictionary.
            tool: Tool binary name for execution.
            args: Command-line arguments for the tool.

        Returns:
            MCP tool result dictionary.
        """
        logger.info(
            "Evaluating: %s %s | target=%s | category=%s",
            tool, " ".join(args[:3]),
            intent.get("target", {}).get("host", "?"),
            intent.get("action", {}).get("category", "?"),
        )

        # Step 1: Evaluate
        eval_response = self.gate.evaluate(intent)
        decision = eval_response.get("decision", "DENY")

        logger.info(
            "Gate decision: %s | reasoning=%s",
            decision, eval_response.get("reasoning", "")[:200],
        )

        # Step 2: Handle decision
        if decision == "ALLOW":
            token = eval_response.get("token")
            if not token:
                return _tool_error(
                    "Gate returned ALLOW but no token was provided. "
                    "This is an internal Gate Service error."
                )

            # Step 3: Execute
            exec_response = self.gate.execute(token, tool, args)

            success = exec_response.get("success", False)
            stdout = exec_response.get("stdout", "")
            stderr = exec_response.get("stderr", "")
            error = exec_response.get("error", "")
            exit_code = exec_response.get("exit_code", -1)

            if success:
                output_parts = []
                if stdout:
                    output_parts.append(stdout)
                if stderr:
                    output_parts.append(f"[stderr] {stderr}")
                output = "\n".join(output_parts) if output_parts else "(no output)"
                return _tool_result(output)
            else:
                error_msg = error or stderr or "Execution failed with no output"
                return _tool_error(
                    f"Command executed but failed (exit code {exit_code}): {error_msg}"
                )

        elif decision == "DENY":
            reasoning = eval_response.get("reasoning", "No reason provided")
            denied_because = eval_response.get("denied_because", [])
            denial_count = eval_response.get("denial_count", 0)

            msg_parts = [
                f"ROE Gate DENIED this action: {reasoning}",
            ]
            if denied_because:
                msg_parts.append("\nMatched rules:")
                for rule in denied_because:
                    msg_parts.append(f"  - {rule}")
            if denial_count > 0:
                msg_parts.append(
                    f"\nConsecutive denials: {denial_count}. "
                    "Repeated violations will trigger an automatic session halt."
                )
            msg_parts.append(
                "\nAdjust your approach to stay within the authorized "
                "Rules of Engagement."
            )
            return _tool_error("\n".join(msg_parts))

        elif decision == "HALT":
            reasoning = eval_response.get("reasoning", "Repeated ROE violations")
            return _tool_error(
                f"SESSION HALTED: {reasoning}\n\n"
                "Your session has been halted due to repeated Rules of Engagement "
                "violations. A human operator must review and explicitly resume "
                "your session before you can continue. Do NOT attempt further "
                "tool calls."
            )

        elif decision == "PENDING":
            # HITL mode: the Gate is holding this action for human approval.
            # Poll until the human approves, denies, or it times out.
            approval_id = eval_response.get("approval_id")
            if not approval_id:
                return _tool_error(
                    "Gate returned PENDING but no approval_id. "
                    "This is an internal Gate Service error."
                )
            logger.info(
                "Action pending human approval: %s (approval_id=%s)",
                tool, approval_id,
            )
            return self._poll_for_approval(approval_id, tool, args)

        elif decision == "ESCALATE":
            reasoning = eval_response.get("reasoning", "Action requires review")
            return _tool_error(
                f"HUMAN APPROVAL REQUIRED: {reasoning}\n\n"
                "This action requires explicit human operator approval before "
                "it can proceed. The request has been logged for review."
            )

        else:
            return _tool_error(
                f"Unexpected Gate decision: {decision}. "
                "This may indicate a Gate Service version mismatch."
            )

    def _poll_for_approval(
        self,
        approval_id: str,
        tool: str,
        args: list[str],
        poll_interval: float = 3.0,
        max_wait: float = 330.0,  # slightly longer than 5m timeout
    ) -> dict[str, Any]:
        """Poll the Gate Service for a HITL approval decision.

        Blocks until the human approves, denies, or the approval times out.
        """
        import time as _time

        start = _time.monotonic()
        last_log = start
        while (_time.monotonic() - start) < max_wait:
            try:
                status = self.gate._request(
                    "GET",
                    f"/api/v1/approvals/{approval_id}/status",
                )
            except Exception as exc:
                logger.warning("Error polling approval %s: %s", approval_id, exc)
                _time.sleep(poll_interval)
                continue

            s = status.get("status", "pending")

            if s == "approved":
                token = status.get("token")
                if not token:
                    return _tool_error(
                        "Approval was granted but no token was returned."
                    )
                # Execute the approved action
                exec_response = self.gate.execute(token, tool, args)
                success = exec_response.get("success", False)
                stdout = exec_response.get("stdout", "")
                stderr = exec_response.get("stderr", "")
                error = exec_response.get("error", "")
                exit_code = exec_response.get("exit_code", -1)

                if success:
                    output_parts = []
                    if stdout:
                        output_parts.append(stdout)
                    if stderr:
                        output_parts.append(f"[stderr] {stderr}")
                    return _tool_result(
                        "\n".join(output_parts) if output_parts else "(no output)"
                    )
                else:
                    return _tool_error(
                        f"Command executed but failed (exit code {exit_code}): "
                        f"{error or stderr or 'no output'}"
                    )

            elif s == "denied":
                return _tool_error(
                    "Action DENIED by human operator.\n\n"
                    "The operator reviewed this action and chose to deny it. "
                    "Adjust your approach to stay within the authorized ROE."
                )

            elif s == "timeout":
                return _tool_error(
                    "Approval request TIMED OUT.\n\n"
                    "No human operator responded within the timeout window. "
                    "The action has been automatically denied."
                )

            # Still pending — log progress periodically
            now = _time.monotonic()
            if now - last_log >= 30.0:
                elapsed = int(now - start)
                logger.info(
                    "Still waiting for human approval: %s (%ds elapsed)",
                    approval_id, elapsed,
                )
                last_log = now

            _time.sleep(poll_interval)

        return _tool_error(
            "Approval polling timed out. No response received from operator."
        )


# ---------------------------------------------------------------------------
# MCP Response Helpers
# ---------------------------------------------------------------------------

def _tool_result(text: str) -> dict[str, Any]:
    """Build a successful MCP tool result."""
    return {
        "content": [{"type": "text", "text": text}],
    }


def _tool_error(text: str) -> dict[str, Any]:
    """Build an error MCP tool result."""
    return {
        "content": [{"type": "text", "text": f"ERROR: {text}"}],
        "isError": True,
    }


# ---------------------------------------------------------------------------
# MCP JSON-RPC Server
# ---------------------------------------------------------------------------

class MCPServer:
    """MCP Server implementing JSON-RPC 2.0 over stdin/stdout.

    This server reads JSON-RPC messages from stdin (one per line) and writes
    JSON-RPC responses to stdout (one per line). All logging goes to stderr.

    The server handles:
    - initialize: Return server capabilities
    - notifications/initialized: Acknowledge (no response)
    - tools/list: Return tool definitions
    - tools/call: Execute a tool through the Gate Service
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "roe-gate-pentest"
    SERVER_VERSION = "0.1.0"

    def __init__(self, tool_handler: ToolHandler) -> None:
        self.tool_handler = tool_handler
        self._initialized = False

    def run(self) -> None:
        """Run the MCP server main loop.

        Reads JSON-RPC messages from stdin, dispatches them to handlers,
        and writes responses to stdout. Runs until stdin is closed or an
        unrecoverable error occurs.
        """
        logger.info(
            "MCP Server starting | name=%s | version=%s",
            self.SERVER_NAME, self.SERVER_VERSION,
        )

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Invalid JSON received: %s", exc)
                # JSON-RPC parse error
                self._write_response({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {exc}",
                    },
                })
                continue

            self._handle_message(message)

        logger.info("MCP Server shutting down (stdin closed)")

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Route a JSON-RPC message to the appropriate handler.

        Notifications (messages without an "id" field) do not receive a
        response. Request messages (with an "id" field) always receive a
        response.
        """
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {})

        logger.debug("Received: method=%s id=%s", method, msg_id)

        # Notifications (no id) -- handle but don't respond
        if msg_id is None:
            if method == "notifications/initialized":
                logger.info("Client confirmed initialization")
            elif method == "notifications/cancelled":
                logger.info("Client cancelled request: %s", params)
            else:
                logger.debug("Unhandled notification: %s", method)
            return

        # Request messages (have id) -- must respond
        if method == "initialize":
            result = self._handle_initialize(params)
        elif method == "tools/list":
            result = self._handle_tools_list(params)
        elif method == "tools/call":
            result = self._handle_tools_call(params)
        elif method == "ping":
            result = {}
        else:
            self._write_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            })
            return

        self._write_response({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result,
        })

    def _handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle the 'initialize' method.

        Returns server capabilities and protocol version. The client sends
        this as the first message to negotiate capabilities.
        """
        client_info = params.get("clientInfo", {})
        logger.info(
            "Client initializing | client=%s version=%s",
            client_info.get("name", "unknown"),
            client_info.get("version", "unknown"),
        )

        self._initialized = True

        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
            },
        }

    def _handle_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle the 'tools/list' method.

        Returns the list of available tools with their JSON Schema input
        definitions. The client uses this to understand what tools are
        available and how to call them.
        """
        logger.debug("Tools list requested")
        return {
            "tools": TOOL_DEFINITIONS,
        }

    def _handle_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle the 'tools/call' method.

        Extracts the tool name and arguments from the params, dispatches
        to the ToolHandler, and returns the result.
        """
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        logger.info("Tool call: %s | args=%s", tool_name, json.dumps(arguments)[:200])

        result = self.tool_handler.handle(tool_name, arguments)

        is_error = result.get("isError", False)
        if is_error:
            logger.warning("Tool %s returned error", tool_name)
        else:
            logger.info("Tool %s completed successfully", tool_name)

        return result

    def _write_response(self, response: dict[str, Any]) -> None:
        """Write a JSON-RPC response to stdout.

        Each response is written as a single line of JSON followed by a
        newline. This is the line-delimited JSON transport format.
        """
        line = json.dumps(response, separators=(",", ":"))
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        logger.debug("Sent response: id=%s", response.get("id"))


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the MCP server."""
    parser = argparse.ArgumentParser(
        prog="roe-gate-mcp-server",
        description=(
            "ROE Gate MCP Server -- Model Context Protocol server that "
            "provides gated penetration testing tools for Claude Code. "
            "Communicates over stdin/stdout (JSON-RPC 2.0) and routes "
            "all tool calls through the Gate Service API."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  # Start with default settings (Gate on localhost:19990)\n"
            "  python -m src.service.mcp_server\n"
            "\n"
            "  # Specify Gate URL and engagement ID\n"
            "  python -m src.service.mcp_server \\\n"
            "    --gate-url http://192.168.1.100:19990 \\\n"
            "    --engagement-id ACME-2026\n"
            "\n"
            "  # Claude Code MCP configuration (claude_desktop_config.json):\n"
            '  {\n'
            '    "mcpServers": {\n'
            '      "roe-gate-pentest": {\n'
            '        "command": "python",\n'
            '        "args": ["-m", "src.service.mcp_server",\n'
            '                 "--gate-url", "http://127.0.0.1:19990"]\n'
            "      }\n"
            "    }\n"
            "  }\n"
        ),
    )

    parser.add_argument(
        "--gate-url",
        default="http://127.0.0.1:19990",
        help="Gate Service API URL (default: http://127.0.0.1:19990)",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help=(
            "Agent session ID (default: auto-generated). Used for "
            "tracking consecutive denials and session state."
        ),
    )
    parser.add_argument(
        "--engagement-id",
        default="",
        help=(
            "Engagement ID (default: auto-detect from Gate health endpoint). "
            "Must match the engagement configured in the Gate Service."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug-level logging (to stderr)",
    )

    return parser.parse_args()


def main() -> None:
    """MCP Server entry point.

    1. Parse command-line arguments
    2. Configure logging to stderr
    3. Connect to the Gate Service
    4. Start the JSON-RPC message loop on stdin/stdout
    """
    args = _parse_args()

    # Configure logging -- always to stderr, never stdout
    log_level = logging.DEBUG if args.verbose else logging.INFO
    _configure_logging(log_level)

    # Generate session ID if not provided
    session_id = args.session_id or f"mcp-{uuid.uuid4().hex[:12]}"
    engagement_id = args.engagement_id

    # Initialize the Gate client
    gate = GateClient(args.gate_url)

    # Try to fetch engagement ID from Gate health if not provided
    if not engagement_id:
        try:
            health = gate.health()
            engagement_id = health.get("engagement_id", "")
            if engagement_id:
                logger.info(
                    "Auto-detected engagement ID from Gate: %s", engagement_id
                )
            else:
                logger.warning(
                    "Gate health endpoint did not return an engagement_id. "
                    "Proceeding without one -- the Gate may reject requests."
                )
        except (GateConnectionError, GateAPIError) as exc:
            logger.warning(
                "Could not reach Gate Service at %s: %s. "
                "The server will start but tool calls will fail until the "
                "Gate Service is available.",
                args.gate_url, exc,
            )

    logger.info(
        "MCP Server configured | gate_url=%s | session=%s | engagement=%s",
        args.gate_url, session_id, engagement_id or "(none)",
    )

    # Create the tool handler and MCP server
    tool_handler = ToolHandler(
        gate=gate,
        session_id=session_id,
        engagement_id=engagement_id,
    )
    server = MCPServer(tool_handler)

    # Run the server (blocks until stdin closes)
    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("MCP Server interrupted by operator")
    except Exception:
        logger.exception("MCP Server crashed")
        sys.exit(1)


if __name__ == "__main__":
    main()
