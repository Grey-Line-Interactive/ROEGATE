"""
ROE Gate Service Client — Synchronous HTTP Client

A lightweight HTTP client for communicating with the ROE Gate Service.
Uses only Python's built-in ``urllib.request`` module -- no external
dependencies required.

This client is used by the MCP Server, Tool Proxy, and other components
that need to submit ActionIntents for evaluation or execute approved
actions through the Gate Service running as a separate process.

Usage:
    from src.service.gate_client import GateServiceClient

    client = GateServiceClient("http://127.0.0.1:19990")
    client.wait_for_ready(timeout=10.0)

    # Evaluate an intent
    result = client.evaluate(intent.to_dict())
    if result["decision"] == "ALLOW":
        token = result["token"]
        exec_result = client.execute(token, "nmap", ["-sT", "10.0.0.1"])
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any


logger = logging.getLogger("roe_gate.client")


class GateServiceError(Exception):
    """Raised when the Gate Service returns an error response."""

    def __init__(self, status_code: int, message: str, body: dict | None = None) -> None:
        self.status_code = status_code
        self.message = message
        self.body = body or {}
        super().__init__(f"HTTP {status_code}: {message}")


class GateServiceConnectionError(Exception):
    """Raised when the Gate Service is unreachable."""

    def __init__(self, url: str, cause: Exception | None = None) -> None:
        self.url = url
        self.cause = cause
        msg = f"Cannot connect to Gate Service at {url}"
        if cause:
            msg += f": {cause}"
        super().__init__(msg)


class GateServiceClient:
    """HTTP client for the ROE Gate Service API.

    This is used by the MCP Server and other components to communicate
    with the Gate Service running as a separate process.

    All methods return parsed JSON dictionaries.  On HTTP errors, a
    ``GateServiceError`` is raised with the status code and error message.
    On connection failures, a ``GateServiceConnectionError`` is raised.

    Args:
        base_url: The base URL of the Gate Service
            (default: ``http://127.0.0.1:19990``).
        timeout: Default request timeout in seconds (default: 30).
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:19990",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ── Public API ───────────────────────────────────────────────────

    def evaluate(self, intent_dict: dict) -> dict:
        """Submit an ActionIntent for evaluation.

        Args:
            intent_dict: The serialized ActionIntent (from ``ActionIntent.to_dict()``).

        Returns:
            A ``GateResult`` dictionary.  If the decision is ``ALLOW``, the
            dictionary will contain a ``token`` key with the signed
            ``ActionToken``.

        Raises:
            GateServiceError: If the server returns an HTTP error.
            GateServiceConnectionError: If the server is unreachable.
        """
        return self._post("/api/v1/evaluate", intent_dict)

    def execute(self, token_dict: dict, tool: str, args: list[str]) -> dict:
        """Execute an approved action with a valid token.

        Args:
            token_dict: The signed ActionToken dictionary (from the
                ``evaluate()`` response's ``token`` field).
            tool: The tool binary to execute (e.g., ``"nmap"``, ``"curl"``).
            args: Command-line arguments for the tool.

        Returns:
            An ``ExecutionResult`` dictionary.

        Raises:
            GateServiceError: If the server returns an HTTP error.
            GateServiceConnectionError: If the server is unreachable.
        """
        return self._post("/api/v1/execute", {
            "token": token_dict,
            "tool": tool,
            "args": args,
        })

    def get_stats(self) -> dict:
        """Get Gate and Executor statistics.

        Returns:
            A dictionary containing evaluation counts, denial counts,
            halted sessions, and executor statistics.
        """
        return self._get("/api/v1/stats")

    def get_audit(self) -> dict:
        """Get audit events and summary.

        Returns:
            A dictionary with ``events`` (list of audit event dicts) and
            ``summary`` (aggregate counts).
        """
        return self._get("/api/v1/audit")

    def halt(self) -> dict:
        """Trigger emergency halt.

        Activates the emergency halt on the Gate Service.  All in-flight
        and future token issuance is blocked until ``resume()`` is called.

        Returns:
            ``{"status": "halted"}`` on success.
        """
        return self._post("/api/v1/halt", {})

    def resume(self, session_id: str) -> dict:
        """Resume a halted session.

        Args:
            session_id: The agent session ID to resume.

        Returns:
            ``{"status": "resumed"}`` on success.
        """
        return self._post("/api/v1/resume", {"session_id": session_id})

    def health(self) -> dict:
        """Health check / readiness probe.

        Returns:
            A dictionary with ``status``, ``roe_hash``, ``engagement_id``,
            and ``uptime_seconds``.
        """
        return self._get("/api/v1/health")

    def wait_for_ready(
        self,
        timeout: float = 30.0,
        poll_interval: float = 0.5,
    ) -> bool:
        """Poll ``/health`` until the server is ready or the timeout expires.

        This is useful when starting the Gate Service as a subprocess and
        waiting for it to become available before sending requests.

        Args:
            timeout: Maximum time in seconds to wait for the server.
            poll_interval: Time in seconds between poll attempts.

        Returns:
            ``True`` if the server became ready within the timeout.

        Raises:
            GateServiceConnectionError: If the server is still unreachable
                after the timeout expires.
        """
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None

        logger.debug(
            "Waiting for Gate Service at %s (timeout=%.1fs)...",
            self.base_url, timeout,
        )

        while time.monotonic() < deadline:
            try:
                result = self.health()
                if result.get("status") == "ok":
                    logger.info(
                        "Gate Service is ready (engagement=%s, roe_hash=%s)",
                        result.get("engagement_id", "?"),
                        result.get("roe_hash", "?"),
                    )
                    return True
            except (GateServiceConnectionError, GateServiceError) as exc:
                last_error = exc
                logger.debug("Not ready yet: %s", exc)

            time.sleep(poll_interval)

        raise GateServiceConnectionError(
            self.base_url,
            cause=last_error,  # type: ignore[arg-type]
        )

    # ── HTTP transport ───────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        """Make a GET request and return the parsed JSON response.

        Args:
            path: The URL path (e.g., ``/api/v1/health``).

        Returns:
            The parsed JSON response body as a dict.

        Raises:
            GateServiceError: On HTTP 4xx/5xx responses.
            GateServiceConnectionError: If the server is unreachable.
        """
        url = self.base_url + path
        request = urllib.request.Request(url, method="GET")
        return self._do_request(request)

    def _post(self, path: str, data: dict) -> dict:
        """Make a POST request with a JSON body and return the parsed response.

        Args:
            path: The URL path (e.g., ``/api/v1/evaluate``).
            data: The request body to serialize as JSON.

        Returns:
            The parsed JSON response body as a dict.

        Raises:
            GateServiceError: On HTTP 4xx/5xx responses.
            GateServiceConnectionError: If the server is unreachable.
        """
        url = self.base_url + path
        body = json.dumps(data, default=str).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(body)),
            },
        )
        return self._do_request(request)

    def _do_request(self, request: urllib.request.Request) -> dict:
        """Execute an HTTP request and handle the response.

        Args:
            request: The prepared ``urllib.request.Request``.

        Returns:
            The parsed JSON response body.

        Raises:
            GateServiceError: On HTTP 4xx/5xx responses with a parseable body.
            GateServiceConnectionError: On connection failures or timeouts.
        """
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    # The server returned a non-JSON response.  Wrap it.
                    return {"raw_response": raw.decode("utf-8", errors="replace")}

        except urllib.error.HTTPError as exc:
            # The server returned an HTTP error (4xx or 5xx).
            body_dict: dict | None = None
            message = str(exc)
            try:
                error_body = exc.read()
                body_dict = json.loads(error_body)
                message = body_dict.get("error", message)
            except (json.JSONDecodeError, OSError):
                pass
            raise GateServiceError(exc.code, message, body_dict) from exc

        except urllib.error.URLError as exc:
            raise GateServiceConnectionError(request.full_url, cause=exc) from exc

        except OSError as exc:
            # Covers socket.timeout, ConnectionRefusedError, etc.
            raise GateServiceConnectionError(request.full_url, cause=exc) from exc

    # ── HITL Approval methods ────────────────────────────────────────

    def get_pending_approvals(self) -> dict:
        """List all pending HITL approval requests.

        Returns:
            A dictionary with ``approvals`` (list) and ``hitl_enabled`` (bool).
        """
        return self._get("/api/v1/approvals/pending")

    def get_approval_status(self, approval_id: str) -> dict:
        """Poll the status of a specific approval request.

        Args:
            approval_id: The approval request ID.

        Returns:
            The approval dict with ``status``, ``token`` (if approved), etc.
        """
        return self._get(f"/api/v1/approvals/{approval_id}/status")

    def respond_approval(self, approval_id: str, approved: bool) -> dict:
        """Approve or deny a pending approval request.

        Args:
            approval_id: The approval request ID.
            approved: ``True`` to approve, ``False`` to deny.

        Returns:
            The resolved approval dict.
        """
        return self._post(
            f"/api/v1/approvals/{approval_id}/respond",
            {"approved": approved},
        )

    # ── Convenience ──────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"GateServiceClient(base_url={self.base_url!r}, timeout={self.timeout})"
