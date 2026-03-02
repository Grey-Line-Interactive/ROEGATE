"""
Tool Proxy — The Agent's Only Interface to Tools

This is what the agent sees. Instead of having access to subprocess.run(),
os.system(), socket.connect(), or any other execution primitive, the agent
gets THIS. A set of Python functions that look like tool interfaces but
route everything through the ROE Gate.

The proxy is the INTERCEPTION POINT. It:
1. Captures what the agent wants to do
2. Serializes it into an ActionIntent
3. Sends it to the Gate for evaluation
4. If approved, forwards the signed token + action to the Tool Executor
5. Returns the result (or the denial) to the agent

The agent CANNOT bypass this because:
- The agent runs in a sandboxed process (see sandbox.py)
- subprocess, os.system, socket, ctypes are all blocked in the sandbox
- The only callable functions the agent has are the ones WE provide
- Those functions all route through this proxy

This is the Reference Monitor pattern: all access to protected resources
MUST go through the reference monitor. No exceptions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..core.action_intent import (
    ActionIntent, ActionCategory, Target, ImpactAssessment,
    ImpactLevel, DataAccessType, classify_tool_call,
)
from ..gate.gate import ROEGate, GateDecision, GateResult
from .executor import ToolExecutor, ExecutionResult

logger = logging.getLogger("roe_gate.proxy")


@dataclass
class ProxiedToolResult:
    """What the agent receives back from a tool call."""
    allowed: bool
    output: str = ""
    error: str = ""
    decision: str = ""
    reasoning: str = ""
    denial_count: int = 0
    halted: bool = False

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "allowed": self.allowed,
            "decision": self.decision,
        }
        if self.allowed:
            result["output"] = self.output
        else:
            result["error"] = self.error
            result["reasoning"] = self.reasoning
            if self.denial_count > 0:
                result["denial_count"] = self.denial_count
            if self.halted:
                result["halted"] = True
        return result


class ToolProxy:
    """The gated tool interface for agents.

    This replaces direct tool access. The agent calls methods on this proxy,
    and the proxy handles the full gate → executor pipeline.

    Usage in an agent framework:

        # Instead of giving the agent subprocess access:
        #   tool = ShellTool()  # DANGEROUS: agent has raw shell
        #
        # Give it a gated proxy:
        #   proxy = ToolProxy(gate=gate, executor=executor)
        #   tools = proxy.get_agent_tools()  # Returns gated tool functions

    The agent sees these as normal tool functions. It doesn't know (and
    doesn't need to know) that every call goes through the Gate.
    """

    def __init__(
        self,
        gate: ROEGate,
        executor: ToolExecutor,
        agent_session: str,
        engagement_id: str,
    ) -> None:
        self.gate = gate
        self.executor = executor
        self.agent_session = agent_session
        self.engagement_id = engagement_id
        self._call_count = 0

    def execute_tool(
        self,
        tool: str,
        args: list[str],
        target_host: str = "",
        target_port: int | None = None,
        target_domain: str | None = None,
        target_url: str | None = None,
        category: ActionCategory | None = None,
        subcategory: str = "",
        description: str = "",
        impact_severity: ImpactLevel = ImpactLevel.LOW,
        data_access: DataAccessType = DataAccessType.NONE,
        justification: str = "",
    ) -> ProxiedToolResult:
        """Execute a tool through the ROE Gate pipeline.

        This is the primary method the agent calls. It looks like a simple
        tool execution interface, but it enforces the full ROE pipeline.

        Args:
            tool: Tool binary name (e.g., "nmap", "curl", "psql").
            args: Command-line arguments.
            target_host: Target host/IP.
            target_port: Target port.
            target_domain: Target domain name.
            target_url: Target URL (for web tools).
            category: Override auto-classification of the action category.
            subcategory: More specific classification.
            description: What the agent is trying to do.
            impact_severity: Expected impact level.
            data_access: Type of data access.
            justification: Why the agent wants to do this.

        Returns:
            ProxiedToolResult with either the tool output or a denial.
        """
        self._call_count += 1

        # ── Step 1: Serialize into ActionIntent ───────────────────
        intent = self._build_intent(
            tool=tool,
            args=args,
            target_host=target_host,
            target_port=target_port,
            target_domain=target_domain,
            target_url=target_url,
            category=category,
            subcategory=subcategory,
            description=description,
            impact_severity=impact_severity,
            data_access=data_access,
            justification=justification,
        )

        logger.info(
            "Tool call intercepted | tool=%s | target=%s | category=%s",
            tool, target_host, intent.category.value,
        )

        # ── Step 2: Send to Gate for evaluation ───────────────────
        gate_result = self.gate.evaluate(intent)

        # ── Step 3: Handle the decision ───────────────────────────
        if gate_result.decision == GateDecision.ALLOW:
            # Gate approved — execute through the Token-Verifying Executor
            exec_result = self.executor.execute(
                token=gate_result.token,
                tool=tool,
                args=args,
            )

            if exec_result.success:
                return ProxiedToolResult(
                    allowed=True,
                    output=exec_result.stdout or exec_result.stderr,
                    decision="ALLOW",
                )
            else:
                return ProxiedToolResult(
                    allowed=False,
                    error=exec_result.error or exec_result.stderr,
                    decision="ALLOW",
                    reasoning="Tool was approved but execution failed",
                )

        elif gate_result.decision == GateDecision.DENY:
            return ProxiedToolResult(
                allowed=False,
                decision="DENY",
                reasoning=gate_result.reasoning,
                denial_count=gate_result.denial_count,
            )

        elif gate_result.decision == GateDecision.HALT:
            return ProxiedToolResult(
                allowed=False,
                decision="HALT",
                reasoning=gate_result.reasoning,
                denial_count=gate_result.denial_count,
                halted=True,
            )

        else:  # ESCALATE
            return ProxiedToolResult(
                allowed=False,
                decision="ESCALATE",
                reasoning=gate_result.reasoning,
            )

    def _build_intent(
        self,
        tool: str,
        args: list[str],
        target_host: str,
        target_port: int | None,
        target_domain: str | None,
        target_url: str | None,
        category: ActionCategory | None,
        subcategory: str,
        description: str,
        impact_severity: ImpactLevel,
        data_access: DataAccessType,
        justification: str,
    ) -> ActionIntent:
        """Build an ActionIntent from the tool call parameters."""
        # Start with auto-classification
        intent = classify_tool_call(
            tool_name=tool,
            target_host=target_host,
            target_port=target_port,
        )

        # Override with explicit values if provided
        if category is not None:
            intent.category = category
        if subcategory:
            intent.subcategory = subcategory

        intent.agent_session = self.agent_session
        intent.engagement_id = self.engagement_id
        intent.description = description or f"Execute {tool} against {target_host}"
        intent.justification = justification

        # Set target details
        if target_domain:
            intent.target.domain = target_domain
        if target_url:
            intent.target.url = target_url
        if not intent.target.protocol:
            intent.target.protocol = "tcp"

        # Set impact assessment
        intent.impact = ImpactAssessment(
            data_access=data_access,
            estimated_severity=impact_severity,
        )

        # Store the full command in parameters for audit
        intent.parameters["command_args"] = args

        return intent

    def get_agent_tools(self) -> dict[str, Any]:
        """Return a dictionary of tool functions for the agent framework.

        Each function is a closure over execute_tool with pre-filled tool
        names and sensible defaults. The agent calls these instead of raw
        shell commands.

        This is how you integrate with LangChain, CrewAI, AutoGPT, etc.:
        each framework has its own tool registration mechanism, but they
        all accept Python callables.
        """
        proxy = self

        def nmap_scan(
            target: str,
            ports: str = "1-1000",
            scan_type: str = "-sT",
            justification: str = "",
        ) -> ProxiedToolResult:
            """Port scan a target (routed through ROE Gate)."""
            args = [scan_type, "-p", ports, target]
            return proxy.execute_tool(
                tool="nmap",
                args=args,
                target_host=target,
                category=ActionCategory.RECONNAISSANCE,
                subcategory="port_scan",
                description=f"Port scan of {target} ports {ports}",
                impact_severity=ImpactLevel.LOW,
                justification=justification,
            )

        def curl_request(
            url: str,
            method: str = "GET",
            data: str | None = None,
            headers: dict[str, str] | None = None,
            justification: str = "",
        ) -> ProxiedToolResult:
            """HTTP request (routed through ROE Gate)."""
            args = ["-X", method, url]
            if data:
                args.extend(["-d", data])
            if headers:
                for k, v in headers.items():
                    args.extend(["-H", f"{k}: {v}"])

            # Extract host/domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            return proxy.execute_tool(
                tool="curl",
                args=args,
                target_host=host,
                target_port=port,
                target_domain=host,
                target_url=url,
                category=ActionCategory.WEB_APPLICATION_TESTING,
                description=f"{method} {url}",
                impact_severity=ImpactLevel.MEDIUM,
                justification=justification,
            )

        def sql_client(
            tool: str,
            host: str,
            port: int,
            command: str = "",
            justification: str = "",
        ) -> ProxiedToolResult:
            """Database client (routed through ROE Gate)."""
            args = ["-h", host, "-p", str(port)]
            if command:
                args.extend(["-c", command])

            return proxy.execute_tool(
                tool=tool,
                args=args,
                target_host=host,
                target_port=port,
                category=ActionCategory.DIRECT_DATABASE_ACCESS,
                description=f"Database connection to {host}:{port}",
                impact_severity=ImpactLevel.HIGH,
                data_access=DataAccessType.READ,
                justification=justification,
            )

        def shell_command(
            command: str,
            target_host: str = "localhost",
            justification: str = "",
        ) -> ProxiedToolResult:
            """General shell command (routed through ROE Gate)."""
            parts = command.split()
            tool = parts[0] if parts else "unknown"
            args = parts[1:] if len(parts) > 1 else []

            return proxy.execute_tool(
                tool=tool,
                args=args,
                target_host=target_host,
                category=ActionCategory.COMMAND_EXECUTION,
                description=f"Shell command: {command}",
                impact_severity=ImpactLevel.MEDIUM,
                justification=justification,
            )

        return {
            "nmap_scan": nmap_scan,
            "curl_request": curl_request,
            "sql_client": sql_client,
            "shell_command": shell_command,
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_tool_calls": self._call_count,
            "gate_stats": self.gate.get_stats(),
            "executor_stats": self.executor.get_stats(),
        }
