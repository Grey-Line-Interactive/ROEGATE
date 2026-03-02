"""Base agent provider interface for ROE Gate pentesting agents."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class AgentConfig:
    """Configuration for a pentesting agent."""
    provider: str           # "anthropic", "openai", "claude-code", "ollama"
    model: str              # Provider-specific model name
    api_key_env: str = ""   # Env var name for API key (e.g., "ANTHROPIC_API_KEY")
    base_url: str = ""      # Custom API endpoint (for self-hosted, proxies)
    max_turns: int = 50     # Maximum agent turns before stopping
    temperature: float = 0.1
    system_prompt: str = "" # Override default pentesting system prompt
    extra: dict = field(default_factory=dict)  # Provider-specific options


class AgentProvider(abc.ABC):
    """Interface for pentesting agent LLM backends.

    Each provider implements the agent loop: send messages to the LLM,
    receive tool_use requests, route them through the Gate Service,
    and return results to the LLM.

    The provider MUST route all tool calls through the Gate Service.
    The provider MUST NOT give the agent direct shell/subprocess access.
    """

    def __init__(self, config: AgentConfig, gate_url: str = "http://127.0.0.1:19990"):
        self.config = config
        self.gate_url = gate_url

    @abc.abstractmethod
    def run(self, objective: str, roe_summary: str) -> str:
        """Run the pentesting agent with the given objective.

        Args:
            objective: The pentesting task description
            roe_summary: Human-readable summary of the ROE for the system prompt

        Returns:
            The agent's final report/findings as a string
        """

    @staticmethod
    def get_default_system_prompt(roe_summary: str) -> str:
        """Generate the default pentesting system prompt."""
        return f"""You are an expert penetration tester conducting an authorized security assessment.

RULES OF ENGAGEMENT:
{roe_summary}

IMPORTANT:
- You MUST use the provided pentesting tools for ALL network operations.
- You MUST NOT attempt to bypass the ROE Gate.
- You MUST stay within the defined scope.
- If a tool call is denied, adjust your approach -- do not retry the same action.
- Document all findings with evidence.

Available tools:
- roe_nmap_scan: Port scanning (target, ports, scan_type)
- roe_http_request: HTTP requests (url, method, data, headers)
- roe_dns_lookup: DNS enumeration (domain, record_type)
- roe_service_probe: Service probing (host, port)
- roe_directory_scan: Web directory enumeration (url, wordlist)
- roe_sql_injection_test: SQL injection testing (url, parameter, method)
- roe_shell_command: General pentest command (command, target_host, target_port)

Produce a structured report of your findings."""

    @staticmethod
    def get_tool_definitions() -> list:
        """Return the 7 ROE Gate tool definitions in a provider-neutral format.

        Returns a list of dicts with: name, description, parameters (JSON Schema).
        Each provider converts these to its own format.
        """
        return [
            {
                "name": "roe_nmap_scan",
                "description": "Scan ports on a target host using nmap. All scans go through the ROE Gate for authorization.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target IP or hostname"},
                        "ports": {"type": "string", "description": "Port range (default: 1-1000)", "default": "1-1000"},
                        "scan_type": {"type": "string", "enum": ["tcp_connect", "syn", "udp"], "default": "tcp_connect"},
                        "justification": {"type": "string", "description": "Why this scan is needed"}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "roe_http_request",
                "description": "Send an HTTP request to a URL. Goes through the ROE Gate for authorization.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], "default": "GET"},
                        "data": {"type": "string", "description": "Request body"},
                        "headers": {"type": "string", "description": "JSON string of headers"},
                        "justification": {"type": "string", "description": "Why this request is needed"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "roe_dns_lookup",
                "description": "Perform DNS lookup for a domain. Goes through the ROE Gate.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain to look up"},
                        "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"], "default": "A"},
                        "justification": {"type": "string", "description": "Why this lookup is needed"}
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "roe_service_probe",
                "description": "Probe a specific service on a host:port. Goes through the ROE Gate.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Target host"},
                        "port": {"type": "integer", "description": "Target port"},
                        "justification": {"type": "string", "description": "Why this probe is needed"}
                    },
                    "required": ["host", "port"]
                }
            },
            {
                "name": "roe_directory_scan",
                "description": "Enumerate directories on a web server. Goes through the ROE Gate.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Base URL to scan"},
                        "wordlist": {"type": "string", "description": "Wordlist to use (common, big, custom)", "default": "common"},
                        "justification": {"type": "string", "description": "Why this scan is needed"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "roe_sql_injection_test",
                "description": "Test a URL parameter for SQL injection. Goes through the ROE Gate.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "parameter": {"type": "string", "description": "Parameter to test"},
                        "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                        "justification": {"type": "string", "description": "Why this test is needed"}
                    },
                    "required": ["url", "parameter"]
                }
            },
            {
                "name": "roe_shell_command",
                "description": "Run a general pentest command. Goes through the ROE Gate for authorization.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The command to run"},
                        "target_host": {"type": "string", "description": "Target host for the command"},
                        "target_port": {"type": "integer", "description": "Target port for the command"},
                        "justification": {"type": "string", "description": "Why this command is needed"}
                    },
                    "required": ["command"]
                }
            }
        ]


class ToolRouter:
    """Routes tool calls through the Gate Service API.

    This is the enforcement layer -- every tool call goes through
    evaluate + execute, ensuring the ROE is enforced regardless
    of which agent framework is driving.
    """

    def __init__(self, gate_url: str, session_id: str, engagement_id: str):
        from src.service.gate_client import GateServiceClient
        self.client = GateServiceClient(gate_url)
        self.session_id = session_id
        self.engagement_id = engagement_id

    def execute_tool(self, tool_name: str, arguments: dict) -> dict:
        """Execute a tool call through the Gate.

        Returns: {"success": bool, "output": str, "decision": str}
        """
        # Build ActionIntent from tool call
        intent = self._build_intent(tool_name, arguments)

        # Evaluate through the Gate
        result = self.client.evaluate(intent)

        if result.get("decision") == "ALLOW":
            token = result["token"]
            # Build command from tool + args
            cmd, cmd_args = self._build_command(tool_name, arguments)
            exec_result = self.client.execute(token, cmd, cmd_args)
            return {
                "success": True,
                "output": exec_result.get("stdout", "") + exec_result.get("stderr", ""),
                "decision": "ALLOW"
            }
        else:
            return {
                "success": False,
                "output": "ROE Gate DENIED: %s" % result.get("reasoning", "Unknown reason"),
                "decision": result.get("decision", "DENY")
            }

    def _build_intent(self, tool_name: str, arguments: dict) -> dict:
        """Build an ActionIntent dict from a tool call."""
        import uuid
        from datetime import datetime, timezone

        # Tool-to-category mapping (same as MCP server)
        TOOL_CATEGORIES = {
            "roe_nmap_scan": "reconnaissance",
            "roe_http_request": "web_application_testing",
            "roe_dns_lookup": "reconnaissance",
            "roe_service_probe": "reconnaissance",
            "roe_directory_scan": "web_application_testing",
            "roe_sql_injection_test": "web_application_testing",
            "roe_shell_command": "general",
        }

        # Extract target info
        target_host = arguments.get("target") or arguments.get("host") or arguments.get("domain") or ""
        if not target_host and "url" in arguments:
            from urllib.parse import urlparse
            parsed = urlparse(arguments["url"])
            target_host = parsed.hostname or ""

        target_port = arguments.get("port", arguments.get("target_port"))

        return {
            "intent_id": str(uuid.uuid4()),
            "agent_session": self.session_id,
            "engagement_id": self.engagement_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": {
                "tool": tool_name.replace("roe_", ""),
                "category": TOOL_CATEGORIES.get(tool_name, "general"),
                "subcategory": "automated_scan",
                "description": arguments.get("justification", "Agent tool call: %s" % tool_name),
            },
            "target": {
                "host": target_host,
                "port": target_port,
                "protocol": "tcp",
            },
            "parameters": {k: v for k, v in arguments.items() if k != "justification"},
            "impact_assessment": {
                "data_access": "read",
                "estimated_severity": "low",
                "reversibility": "full",
            },
            "agent_justification": arguments.get("justification", "Automated pentesting"),
        }

    def _build_command(self, tool_name: str, arguments: dict) -> tuple:
        """Build the actual command + args from tool name and arguments."""
        if tool_name == "roe_nmap_scan":
            scan_flags = {"tcp_connect": "-sT", "syn": "-sS", "udp": "-sU"}
            flag = scan_flags.get(arguments.get("scan_type", "tcp_connect"), "-sT")
            return "nmap", [flag, "-p", arguments.get("ports", "1-1000"), arguments["target"]]
        elif tool_name == "roe_http_request":
            cmd_args = ["-s", "-S"]
            if arguments.get("method", "GET") != "GET":
                cmd_args.extend(["-X", arguments["method"]])
            if arguments.get("data"):
                cmd_args.extend(["-d", arguments["data"]])
            if arguments.get("headers"):
                import json
                headers = json.loads(arguments["headers"]) if isinstance(arguments["headers"], str) else arguments["headers"]
                for k, v in headers.items():
                    cmd_args.extend(["-H", "%s: %s" % (k, v)])
            cmd_args.append(arguments["url"])
            return "curl", cmd_args
        elif tool_name == "roe_dns_lookup":
            return "dig", [arguments["domain"], arguments.get("record_type", "A")]
        elif tool_name == "roe_service_probe":
            return "nmap", ["-sV", "-p", str(arguments["port"]), arguments["host"]]
        elif tool_name == "roe_directory_scan":
            return "gobuster", ["dir", "-u", arguments["url"], "-w", "/usr/share/wordlists/%s.txt" % arguments.get("wordlist", "common")]
        elif tool_name == "roe_sql_injection_test":
            cmd_args = ["-u", arguments["url"], "-p", arguments["parameter"], "--batch"]
            if arguments.get("method") == "POST":
                cmd_args.append("--method=POST")
            return "sqlmap", cmd_args
        elif tool_name == "roe_shell_command":
            import shlex
            parts = shlex.split(arguments["command"])
            return parts[0], parts[1:]
        else:
            return arguments.get("command", "echo"), ["Unknown tool"]
