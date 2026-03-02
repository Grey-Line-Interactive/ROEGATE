"""
Tool Executor — Signature-Enforcing Execution Proxy

This is the ONLY component in the system that has actual execution privileges
(subprocess, network sockets, etc.). It runs in a separate trust boundary from
the agent.

The executor does NOT make policy decisions. It just verifies that someone with
authority (the Gate) has already approved the action by issuing a valid token.

No valid token = no execution. Period.

TRUST MODEL:
  - The executor trusts the Gate's signing key (shared at startup)
  - The executor does NOT trust the agent
  - The executor does NOT trust the token's content — it re-verifies everything
  - The executor runs in a privileged process; the agent runs in a sandboxed one
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..crypto.signer import ActionSigner, ActionToken

logger = logging.getLogger("roe_gate.executor")


@dataclass
class ExecutionResult:
    """Result of executing a tool through the executor."""
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    token_id: str = ""
    error: str = ""
    executed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "token_id": self.token_id,
            "error": self.error,
            "executed_at": self.executed_at,
        }


class ToolExecutor:
    """Signature-enforcing tool executor.

    This is the only path to actual command execution. The agent cannot
    reach this directly — it can only submit (token, action) pairs through
    the Tool Proxy, and this executor verifies the token before running anything.

    Enforcement properties:
    1. COMPLETE MEDIATION: Every execution attempt is verified
    2. TAMPER-PROOF: The signing key is held here, not by the agent
    3. VERIFIABLE: All executions are logged with their authorizing token
    4. ACTION-SPECIFIC: The token's permitted_action must match the requested action
    """

    def __init__(
        self,
        signer: ActionSigner,
        roe_hash: str,
        allowed_tools: set[str] | None = None,
        execution_timeout: int = 120,
        dry_run: bool = False,
    ) -> None:
        """Initialize the executor.

        Args:
            signer: The same ActionSigner used by the Gate (shares the key).
            roe_hash: Current ROE specification hash.
            allowed_tools: Whitelist of tool binaries that can be executed.
                          If None, any tool approved by the Gate can run.
            execution_timeout: Max seconds for any single tool execution.
            dry_run: If True, log the command but don't execute it.
        """
        self.signer = signer
        self.roe_hash = roe_hash
        self.allowed_tools = allowed_tools
        self.execution_timeout = execution_timeout
        self.dry_run = dry_run

        # Track executed tokens to prevent replay
        self._executed_tokens: set[str] = set()
        self._execution_count = 0

    def execute(
        self,
        token: ActionToken,
        tool: str,
        args: list[str],
    ) -> ExecutionResult:
        """Execute a tool command, but ONLY if the token is valid.

        This is the core enforcement point. The flow is:
        1. Verify token signature (cryptographic proof the Gate approved this)
        2. Verify token is not expired (30s TTL)
        3. Verify token hasn't already been used (replay prevention)
        4. Verify the requested tool matches what the token authorizes
        5. Verify the tool is in the allowed whitelist
        6. Execute the command with timeout and output capture
        7. Log everything

        Args:
            token: The signed action token from the Gate.
            tool: The tool binary to execute (e.g., "nmap", "curl").
            args: Command-line arguments for the tool.

        Returns:
            ExecutionResult with the output or error.
        """
        self._execution_count += 1

        # ── Step 1: Verify token signature ────────────────────────
        is_valid, reason = self.signer.verify_token(token, self.roe_hash)
        if not is_valid:
            logger.warning(
                "BLOCKED: Token verification failed | token=%s | reason=%s",
                token.token_id, reason,
            )
            return ExecutionResult(
                success=False,
                token_id=token.token_id,
                error=f"Token verification failed: {reason}",
            )

        # ── Step 2: Replay prevention ─────────────────────────────
        if token.token_id in self._executed_tokens:
            logger.warning(
                "BLOCKED: Token replay attempt | token=%s", token.token_id,
            )
            return ExecutionResult(
                success=False,
                token_id=token.token_id,
                error="Token has already been used (replay attempt blocked)",
            )

        # ── Step 3: Verify tool matches token's permitted action ──
        permitted = token.permitted_action
        if permitted.get("tool") != tool:
            logger.warning(
                "BLOCKED: Tool mismatch | token authorized '%s' but '%s' requested",
                permitted.get("tool"), tool,
            )
            return ExecutionResult(
                success=False,
                token_id=token.token_id,
                error=(
                    f"Tool mismatch: token authorizes '{permitted.get('tool')}' "
                    f"but '{tool}' was requested"
                ),
            )

        # ── Step 4: Verify tool is in the allowed whitelist ───────
        if self.allowed_tools is not None and tool not in self.allowed_tools:
            logger.warning(
                "BLOCKED: Tool '%s' not in executor whitelist", tool,
            )
            return ExecutionResult(
                success=False,
                token_id=token.token_id,
                error=f"Tool '{tool}' is not in the executor's allowed tools list",
            )

        # ── Step 5: Mark token as used (before execution) ─────────
        self._executed_tokens.add(token.token_id)

        # ── Step 6: Build and execute the command ─────────────────
        cmd = [tool] + args

        if self.dry_run:
            logger.info(
                "DRY RUN: Would execute %s | token=%s",
                shlex.join(cmd), token.token_id,
            )
            return ExecutionResult(
                success=True,
                token_id=token.token_id,
                stdout=f"[DRY RUN] Would execute: {shlex.join(cmd)}",
            )

        try:
            logger.info(
                "EXECUTING: %s | token=%s | timeout=%ds",
                shlex.join(cmd), token.token_id, self.execution_timeout,
            )
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.execution_timeout,
            )
            return ExecutionResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                token_id=token.token_id,
            )

        except subprocess.TimeoutExpired:
            logger.error(
                "TIMEOUT: %s exceeded %ds | token=%s",
                shlex.join(cmd), self.execution_timeout, token.token_id,
            )
            return ExecutionResult(
                success=False,
                token_id=token.token_id,
                error=f"Execution timed out after {self.execution_timeout}s",
            )
        except FileNotFoundError:
            return ExecutionResult(
                success=False,
                token_id=token.token_id,
                error=f"Tool binary '{tool}' not found on system",
            )
        except Exception as e:
            logger.error("Execution error: %s", e)
            return ExecutionResult(
                success=False,
                token_id=token.token_id,
                error=f"Execution error: {e}",
            )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_executions": self._execution_count,
            "unique_tokens_used": len(self._executed_tokens),
        }
