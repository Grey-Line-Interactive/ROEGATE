#!/usr/bin/env python3
"""
ROE Gate Service — Standalone HTTP API Server

This is the heart of the Reference Monitor architecture. The Gate Service runs
as a SEPARATE PROCESS from the agent. It holds the signing keys and is the ONLY
component that can approve actions.

The server exposes a JSON API over HTTP, wrapping the existing ROEGate and
ToolExecutor classes. No external dependencies are required beyond the Python
standard library (plus PyYAML for ROE spec loading).

Endpoints:
    POST /api/v1/evaluate   - Submit an ActionIntent for evaluation
    POST /api/v1/execute    - Execute an approved action with a valid token
    GET  /api/v1/stats      - Gate statistics
    GET  /api/v1/audit      - Audit events and summary
    POST /api/v1/halt       - Trigger emergency halt
    POST /api/v1/resume     - Resume a halted session
    GET  /api/v1/health     - Health check / readiness probe

Usage:
    python -m src.service.gate_api --roe examples/acme_corp_roe.yaml
    python -m src.service.gate_api --roe my_roe.yaml --port 19990 --judge mock --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import socketserver
import sys
import time
import threading
import uuid as _uuid_mod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

# ── Project imports ──────────────────────────────────────────────────────────
# Adjust sys.path so that the project root is importable regardless of how
# this module is invoked (directly, via ``python -m``, or as an installed
# package).
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.action_intent import (
    ActionIntent,
    ActionCategory,
    Target,
    ImpactAssessment,
    ImpactLevel,
    DataAccessType,
)
from src.core.rule_engine import RuleEngine, RuleVerdict
from src.core.judge import JudgeLLM, JudgeVerdict
from src.crypto.signer import ActionSigner, ActionToken, compute_roe_hash
from src.gate.gate import ROEGate, GateDecision, GateResult
from src.tools.executor import ToolExecutor, ExecutionResult
from src.audit.logger import AuditLogger, AuditEvent
# Paid-tier modules — imported conditionally so the community edition
# works without them.  The @require_tier decorator on each endpoint
# prevents access when the module isn't available.
try:
    from src.service.alerting import AlertManager, AlertLevel, AlertEvent
except ImportError:
    AlertManager = AlertLevel = AlertEvent = None  # type: ignore[misc,assignment]

try:
    from src.service.multi_roe import MultiROEManager
except ImportError:
    MultiROEManager = None  # type: ignore[misc,assignment]

try:
    from src.audit.compliance import ComplianceReportGenerator
except ImportError:
    ComplianceReportGenerator = None  # type: ignore[misc,assignment]

try:
    from src.auth.rbac import RBACManager, Role, Permission
except ImportError:
    RBACManager = Role = Permission = None  # type: ignore[misc,assignment]

try:
    from src.service.ha import HACluster
except ImportError:
    HACluster = None  # type: ignore[misc,assignment]

try:
    from src.service.tenant import TenantManager
except ImportError:
    TenantManager = None  # type: ignore[misc,assignment]

try:
    from src.service.branding import BrandingManager, BrandingConfig
except ImportError:
    BrandingManager = BrandingConfig = None  # type: ignore[misc,assignment]
from src.licensing.tiers import Tier
from src.licensing.validator import require_tier, get_active_tier


logger = logging.getLogger("roe_gate.service")


# ── Intent / Token reconstruction helpers ────────────────────────────────────

def _reconstruct_intent(data: dict) -> ActionIntent:
    """Reconstruct an ActionIntent from its JSON dict representation.

    This reverses the ``ActionIntent.to_dict()`` serialization so that
    intents submitted over the HTTP API can be evaluated by the Gate
    exactly as if they were created in-process.

    Args:
        data: Dictionary matching the ``ActionIntent.to_dict()`` schema.

    Returns:
        A fully-populated ``ActionIntent`` instance.
    """
    action = data.get("action", {})
    target_data = data.get("target", {})
    impact_data = data.get("impact_assessment", {})

    return ActionIntent(
        intent_id=data.get("intent_id", ""),
        timestamp=data.get("timestamp", ""),
        agent_session=data.get("agent_session", ""),
        engagement_id=data.get("engagement_id", ""),
        tool=action.get("tool", ""),
        category=ActionCategory(action.get("category", "other")),
        subcategory=action.get("subcategory", ""),
        description=action.get("description", ""),
        target=Target(
            host=target_data.get("host", ""),
            port=target_data.get("port"),
            protocol=target_data.get("protocol"),
            service=target_data.get("service"),
            url=target_data.get("url"),
            domain=target_data.get("domain"),
        ),
        parameters=data.get("parameters", {}),
        impact=ImpactAssessment(
            data_access=DataAccessType(impact_data.get("data_access", "none")),
            service_disruption=ImpactLevel(impact_data.get("service_disruption", "none")),
            reversibility=impact_data.get("reversibility", "full"),
            estimated_severity=ImpactLevel(impact_data.get("estimated_severity", "low")),
            record_count_estimate=impact_data.get("record_count_estimate"),
        ),
        justification=data.get("agent_justification", ""),
    )


def _reconstruct_token(data: dict) -> ActionToken:
    """Reconstruct an ActionToken from its JSON dict representation.

    Args:
        data: Dictionary matching the ``ActionToken.to_dict()`` schema.

    Returns:
        A fully-populated ``ActionToken`` instance.
    """
    return ActionToken(
        token_id=data.get("token_id", ""),
        intent_id=data.get("intent_id", ""),
        engagement_id=data.get("engagement_id", ""),
        roe_hash=data.get("roe_hash", ""),
        created_at=data.get("created_at", ""),
        expires_at=data.get("expires_at", ""),
        verdict=data.get("verdict", ""),
        rule_engine_result=data.get("rule_engine_result", ""),
        judge_result=data.get("judge_result", {}),
        permitted_action=data.get("permitted_action", {}),
        constraints=data.get("constraints", {}),
        signature=data.get("signature", ""),
    )


# ── Human-in-the-Loop Approval Types ─────────────────────────────────────────

@dataclass
class PendingApproval:
    """A pending human-in-the-loop approval request."""
    approval_id: str
    intent_dict: dict[str, Any]
    gate_result_dict: dict[str, Any]
    tool: str
    target_host: str
    category: str
    reasoning: str
    status: str = "pending"  # pending | approved | denied | timeout
    timeout_seconds: int = 300  # 5 minutes default
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    token_dict: dict[str, Any] | None = None  # filled on approve

    @property
    def is_expired(self) -> bool:
        created = datetime.fromisoformat(self.created_at)
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        return elapsed >= self.timeout_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "tool": self.tool,
            "target_host": self.target_host,
            "category": self.category,
            "reasoning": self.reasoning,
            "status": self.status,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at,
            "token": self.token_dict,
        }


class ApprovalStore:
    """Thread-safe store for pending HITL approval requests."""

    def __init__(self) -> None:
        self._approvals: dict[str, PendingApproval] = {}
        self._lock = threading.Lock()

    def add(self, approval: PendingApproval) -> None:
        with self._lock:
            self._approvals[approval.approval_id] = approval

    def get(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            approval = self._approvals.get(approval_id)
            if approval and approval.status == "pending" and approval.is_expired:
                approval.status = "timeout"
            return approval

    def get_all_pending(self) -> list[PendingApproval]:
        with self._lock:
            result = []
            for a in self._approvals.values():
                if a.status == "pending":
                    if a.is_expired:
                        a.status = "timeout"
                    else:
                        result.append(a)
            return result

    def resolve(self, approval_id: str, approved: bool, token_dict: dict | None = None) -> PendingApproval | None:
        with self._lock:
            approval = self._approvals.get(approval_id)
            if approval is None:
                return None
            if approval.status != "pending":
                return approval  # already resolved
            if approval.is_expired:
                approval.status = "timeout"
                return approval
            approval.status = "approved" if approved else "denied"
            if approved and token_dict:
                approval.token_dict = token_dict
            return approval


# ── Threaded HTTP Server ─────────────────────────────────────────────────────

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """An ``HTTPServer`` subclass that handles each request in a new thread.

    ``ThreadingMixIn`` is used so that long-running evaluation or execution
    requests do not block health checks or other concurrent API calls.
    Daemon threads are used so that the server shuts down cleanly when the
    main thread exits.
    """

    daemon_threads = True
    allow_reuse_address = True


def _build_dashboard_html(engagement_id: str, roe_hash: str) -> str:
    """Return a self-contained HTML page for the web dashboard."""
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROE Gate Dashboard</title>
<style>
  :root {{ --bg: #0d1117; --surface: #161b22; --border: #30363d;
           --text: #e6edf3; --muted: #8b949e; --green: #3fb950;
           --red: #f85149; --yellow: #d29922; --blue: #58a6ff; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
          background: var(--bg); color: var(--text); padding: 16px; }}
  .header {{ background: var(--surface); border: 1px solid var(--border);
             border-radius: 8px; padding: 16px 20px; margin-bottom: 12px; }}
  .header h1 {{ font-size: 18px; color: var(--green); margin-bottom: 8px; }}
  .header .meta {{ font-size: 13px; color: var(--muted); }}
  .header .meta span {{ margin-right: 20px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
             margin-bottom: 12px; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 14px 18px; text-align: center; }}
  .stat .value {{ font-size: 32px; font-weight: bold; }}
  .stat .label {{ font-size: 11px; color: var(--muted); margin-top: 4px;
                  text-transform: uppercase; letter-spacing: 1px; }}
  .stat.allow .value {{ color: var(--green); }}
  .stat.deny .value {{ color: var(--red); }}
  .stat.halt .value {{ color: var(--yellow); }}
  .stat.total .value {{ color: var(--blue); }}
  .log-panel {{ background: var(--surface); border: 1px solid var(--border);
                border-radius: 8px; padding: 16px; }}
  .log-panel h2 {{ font-size: 14px; color: var(--muted); margin-bottom: 10px;
                   text-transform: uppercase; letter-spacing: 1px; }}
  .log {{ max-height: 55vh; overflow-y: auto; font-size: 13px; }}
  .log-entry {{ padding: 6px 0; border-bottom: 1px solid var(--border);
                display: flex; gap: 12px; align-items: baseline; }}
  .log-entry:last-child {{ border-bottom: none; }}
  .log-time {{ color: var(--muted); flex-shrink: 0; font-size: 12px; }}
  .log-badge {{ font-weight: bold; flex-shrink: 0; width: 72px;
                text-align: center; border-radius: 4px; padding: 1px 6px;
                font-size: 11px; }}
  .log-badge.ALLOW {{ background: #23382e; color: var(--green); }}
  .log-badge.DENY {{ background: #3d1f20; color: var(--red); }}
  .log-badge.HALT {{ background: #3d2e10; color: var(--yellow); }}
  .log-badge.ESCALATE {{ background: #2a2040; color: #bc8cff; }}
  .log-detail {{ color: var(--text); }}
  .log-detail .tool {{ color: var(--blue); }}
  .log-detail .target {{ color: var(--muted); }}
  .controls {{ display: flex; gap: 10px; margin-top: 12px; align-items: center; }}
  .controls button {{ background: var(--surface); color: var(--text);
                      border: 1px solid var(--border); border-radius: 6px;
                      padding: 8px 16px; cursor: pointer; font-family: inherit;
                      font-size: 12px; }}
  .controls button:hover {{ border-color: var(--blue); }}
  .controls button.danger {{ border-color: var(--red); color: var(--red); }}
  .controls button.danger:hover {{ background: #3d1f20; }}
  .status {{ margin-left: auto; font-size: 12px; color: var(--muted); }}
  .status .dot {{ display: inline-block; width: 8px; height: 8px;
                  border-radius: 50%; background: var(--green); margin-right: 6px; }}
  .empty {{ color: var(--muted); text-align: center; padding: 40px;
            font-style: italic; }}
  .approvals-panel {{ background: var(--surface); border: 2px solid var(--yellow);
                      border-radius: 8px; padding: 16px; margin-bottom: 12px;
                      display: none; }}
  .approvals-panel h2 {{ font-size: 14px; color: var(--yellow); margin-bottom: 10px;
                         text-transform: uppercase; letter-spacing: 1px; }}
  .approval-card {{ background: var(--bg); border: 1px solid var(--border);
                    border-radius: 6px; padding: 12px; margin-bottom: 8px; }}
  .approval-card .info {{ font-size: 13px; margin-bottom: 8px; }}
  .approval-card .info span {{ margin-right: 16px; }}
  .approval-card .info .lbl {{ color: var(--muted); }}
  .approval-card .reason {{ font-size: 12px; color: var(--muted);
                            margin-bottom: 10px; }}
  .approval-card .actions {{ display: flex; gap: 8px; }}
  .approval-card .actions button {{ padding: 6px 16px; border-radius: 4px;
                                   cursor: pointer; font-family: inherit;
                                   font-size: 12px; font-weight: bold; border: none; }}
  .btn-approve {{ background: #23382e; color: var(--green); }}
  .btn-approve:hover {{ background: #2d4a3a; }}
  .btn-deny {{ background: #3d1f20; color: var(--red); }}
  .btn-deny:hover {{ background: #4d2a2b; }}
  .approval-card .timer {{ font-size: 11px; color: var(--yellow); float: right; }}
</style>
</head>
<body>
<div class="header">
  <h1>ROE GATE &mdash; Real-Time Audit Dashboard</h1>
  <div class="meta">
    <span>Engagement: <strong>{engagement_id}</strong></span>
    <span>ROE Hash: <strong>{roe_hash[:32]}...</strong></span>
    <span id="uptime"></span>
  </div>
</div>
<div class="stats">
  <div class="stat total"><div class="value" id="s-eval">0</div><div class="label">Evaluations</div></div>
  <div class="stat allow"><div class="value" id="s-allow">0</div><div class="label">Allowed</div></div>
  <div class="stat deny"><div class="value" id="s-deny">0</div><div class="label">Denied</div></div>
  <div class="stat halt"><div class="value" id="s-halt">0</div><div class="label">Halted Sessions</div></div>
</div>
<div class="approvals-panel" id="approvals-panel">
  <h2>Pending Approvals</h2>
  <div id="approvals-list"></div>
</div>
<div class="log-panel">
  <h2>Decision Log</h2>
  <div class="log" id="log"><div class="empty">Waiting for activity...</div></div>
</div>
<div class="controls">
  <button class="danger" onclick="doHalt()">Emergency Halt</button>
  <div class="status"><span class="dot" id="dot"></span><span id="status-text">Connecting...</span></div>
</div>
<script>
const BASE = window.location.origin;
let prevEventCount = 0;

async function refresh() {{
  try {{
    const [statsRes, auditRes] = await Promise.all([
      fetch(BASE + '/api/v1/stats'),
      fetch(BASE + '/api/v1/audit'),
    ]);
    const stats = await statsRes.json();
    const audit = await auditRes.json();

    document.getElementById('s-eval').textContent = stats.total_evaluations ?? 0;
    document.getElementById('s-allow').textContent = stats.total_allows ?? 0;
    document.getElementById('s-deny').textContent = stats.total_denials ?? 0;
    document.getElementById('s-halt').textContent = (stats.halted_sessions ?? []).length;

    const events = audit.events ?? [];
    if (events.length !== prevEventCount) {{
      prevEventCount = events.length;
      const logEl = document.getElementById('log');
      if (events.length === 0) {{
        logEl.innerHTML = '<div class="empty">Waiting for activity...</div>';
      }} else {{
        logEl.innerHTML = events.slice().reverse().map(e => {{
          const d = e.details || {{}};
          const intent = d.intent || {{}};
          const action = intent.action || {{}};
          const target = intent.target || {{}};
          const t = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '';
          const dec = (d.decision || e.event_type || '').toUpperCase();
          const tool = action.tool || '';
          const host = target.host || '';
          const port = target.port || '';
          const cat = action.category || '';
          const reason = d.reasoning || '';
          const tgt = host ? (port ? host+':'+port : host) : '';
          return `<div class="log-entry">`
            + `<span class="log-time">${{t}}</span>`
            + `<span class="log-badge ${{dec}}">${{dec}}</span>`
            + `<span class="log-detail"><span class="tool">${{tool}}</span>`
            + `${{tgt ? ' &rarr; <span class="target">'+tgt+'</span>' : ''}}`
            + `${{cat ? ' ('+cat+')' : ''}}`
            + `${{reason ? '<br><span class="target" style="font-size:11px">' + reason.substring(0,120) + '</span>' : ''}}`
            + `</span></div>`;
        }}).join('');
        logEl.scrollTop = 0;
      }}
    }}

    document.getElementById('dot').style.background = '#3fb950';
    document.getElementById('status-text').textContent = 'Connected — refreshing every 2s';
  }} catch(err) {{
    document.getElementById('dot').style.background = '#f85149';
    document.getElementById('status-text').textContent = 'Connection lost';
  }}
}}

async function doHalt() {{
  if (!confirm('Trigger emergency halt? This will block ALL actions.')) return;
  await fetch(BASE + '/api/v1/halt', {{ method: 'POST',
    headers: {{'Content-Type': 'application/json'}}, body: '{{}}' }});
  refresh();
}}

async function refreshApprovals() {{
  try {{
    const res = await fetch(BASE + '/api/v1/approvals/pending');
    const data = await res.json();
    const panel = document.getElementById('approvals-panel');
    const list = document.getElementById('approvals-list');
    const approvals = data.approvals || [];
    if (!data.hitl_enabled || approvals.length === 0) {{
      panel.style.display = 'none';
      return;
    }}
    panel.style.display = 'block';
    list.innerHTML = approvals.map(a => {{
      const created = new Date(a.created_at);
      const elapsed = Math.floor((Date.now() - created.getTime()) / 1000);
      const remaining = Math.max(0, a.timeout_seconds - elapsed);
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      return `<div class="approval-card">`
        + `<span class="timer">${{mins}}:${{String(secs).padStart(2,'0')}} remaining</span>`
        + `<div class="info">`
        + `<span><span class="lbl">Tool:</span> <strong>${{a.tool}}</strong></span>`
        + `<span><span class="lbl">Target:</span> <strong>${{a.target_host}}</strong></span>`
        + `<span><span class="lbl">Category:</span> ${{a.category}}</span>`
        + `</div>`
        + `<div class="reason">${{a.reasoning}}</div>`
        + `<div class="actions">`
        + `<button class="btn-approve" onclick="respondApproval('${{a.approval_id}}', true)">APPROVE</button>`
        + `<button class="btn-deny" onclick="respondApproval('${{a.approval_id}}', false)">DENY</button>`
        + `</div></div>`;
    }}).join('');
  }} catch(err) {{}}
}}

async function respondApproval(id, approved) {{
  const action = approved ? 'APPROVE' : 'DENY';
  if (!confirm(`${{action}} this action?`)) return;
  await fetch(BASE + '/api/v1/approvals/' + id + '/respond', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{approved: approved}}),
  }});
  refreshApprovals();
}}

refresh();
refreshApprovals();
setInterval(refresh, 2000);
setInterval(refreshApprovals, 2000);
</script>
</body>
</html>"""


class GateRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the ROE Gate Service API.

    All endpoints accept and return JSON.  The handler reads the request body
    (for POST), dispatches to the appropriate handler method, and writes back
    a JSON response with appropriate status codes.

    The ``server`` attribute (set by ``HTTPServer``) is expected to be a
    ``GateAPIServer`` instance that holds references to the Gate, Executor,
    and other shared state.
    """

    # Silence the default ``BaseHTTPRequestHandler`` logging to stderr;
    # we use the ``logging`` module instead.
    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("HTTP %s", format % args)

    # ── RBAC permission mapping per endpoint ────────────────────────
    # When the RBAC module is not installed (community edition), these
    # dicts are empty and _check_rbac() returns True early anyway.

    _ENDPOINT_PERMISSIONS: dict = (
        {
            "/api/v1/evaluate": Permission.EVALUATE,
            "/api/v1/execute": Permission.EXECUTE,
            "/api/v1/stats": Permission.VIEW_STATS,
            "/api/v1/audit": Permission.VIEW_AUDIT,
            "/api/v1/halt": Permission.HALT,
            "/api/v1/resume": Permission.RESUME,
            "/api/v1/roe/list": Permission.VIEW_STATS,
            "/api/v1/roe/add": Permission.MANAGE_ROE,
            "/api/v1/roe/archive": Permission.MANAGE_ROE,
            "/api/v1/compliance/soc2": Permission.EXPORT_REPORTS,
            "/api/v1/compliance/pci-dss": Permission.EXPORT_REPORTS,
            "/api/v1/cluster/status": Permission.VIEW_STATS,
            "/api/v1/cluster/heartbeat": Permission.VIEW_STATS,
            "/api/v1/tenants": Permission.MANAGE_USERS,
            "/api/v1/tenants/create": Permission.MANAGE_USERS,
            "/api/v1/branding": Permission.VIEW_STATS,
            "/api/v1/public-key": Permission.VIEW_STATS,
            "/api/v1/approvals/pending": Permission.VIEW_STATS,
        }
        if Permission is not None
        else {}
    )

    # Approval endpoints use prefix matching (handled in _check_rbac)
    _APPROVAL_PREFIX_PERMISSIONS: dict = (
        {"/api/v1/approvals/": Permission.EVALUATE}
        if Permission is not None
        else {}
    )

    def _check_rbac(self) -> bool:
        """Check RBAC authorization if enabled. Returns True if access is granted."""
        rbac: RBACManager | None = getattr(self.server, "rbac", None)
        if rbac is None:
            return True  # RBAC not enabled, allow all

        # Health, dashboard, and ROE Creator are always public
        if self.path in ("/api/v1/health", "/dashboard", "/roe-creator"):
            return True

        permission = self._ENDPOINT_PERMISSIONS.get(self.path)
        if permission is None:
            # Check prefix-based approval endpoints
            for prefix, perm in self._APPROVAL_PREFIX_PERMISSIONS.items():
                if self.path.startswith(prefix):
                    permission = perm
                    break
        if permission is None:
            return True  # Unknown endpoints fall through to 404 handling

        api_key = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not api_key:
            self._send_error(HTTPStatus.UNAUTHORIZED, "Missing Authorization header (Bearer <api_key>)")
            return False

        allowed, reason = rbac.check_access(api_key, permission)
        if not allowed:
            self._send_error(HTTPStatus.FORBIDDEN, reason)
            return False
        return True

    # ── Routing ──────────────────────────────────────────────────────

    def do_GET(self) -> None:
        """Dispatch GET requests."""
        route_map = {
            "/api/v1/stats": self._handle_stats,
            "/api/v1/audit": self._handle_audit,
            "/api/v1/health": self._handle_health,
            "/api/v1/roe/list": self._handle_roe_list,
            "/api/v1/compliance/soc2": self._handle_compliance_soc2,
            "/api/v1/compliance/pci-dss": self._handle_compliance_pci_dss,
            "/api/v1/cluster/status": self._handle_cluster_status,
            "/api/v1/cluster/heartbeat": self._handle_cluster_heartbeat,
            "/api/v1/tenants": self._handle_tenants_list,
            "/api/v1/branding": self._handle_branding,
            "/api/v1/public-key": self._handle_public_key,
            "/api/v1/approvals/pending": self._handle_approvals_pending,
            "/dashboard": self._handle_dashboard,
            "/roe-creator": self._handle_roe_creator,
        }
        handler = route_map.get(self.path)
        # Check for parameterized approval status route: /api/v1/approvals/{id}/status
        if handler is None and self.path.startswith("/api/v1/approvals/") and self.path.endswith("/status"):
            handler = self._handle_approval_status
        if handler is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Unknown endpoint: {self.path}")
            return
        if not self._check_rbac():
            return
        try:
            handler()
        except Exception as exc:
            logger.exception("Unhandled error on GET %s", self.path)
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_POST(self) -> None:
        """Dispatch POST requests."""
        route_map = {
            "/api/v1/evaluate": self._handle_evaluate,
            "/api/v1/execute": self._handle_execute,
            "/api/v1/halt": self._handle_halt,
            "/api/v1/resume": self._handle_resume,
            "/api/v1/roe/add": self._handle_roe_add,
            "/api/v1/roe/archive": self._handle_roe_archive,
            "/api/v1/tenants/create": self._handle_tenant_create,
        }
        handler = route_map.get(self.path)
        # Check for parameterized approval respond route: /api/v1/approvals/{id}/respond
        if handler is None and self.path.startswith("/api/v1/approvals/") and self.path.endswith("/respond"):
            handler = self._handle_approval_respond
        if handler is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Unknown endpoint: {self.path}")
            return
        if not self._check_rbac():
            return
        try:
            handler()
        except Exception as exc:
            logger.exception("Unhandled error on POST %s", self.path)
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    # ── Endpoint implementations ─────────────────────────────────────

    def _handle_evaluate(self) -> None:
        """POST /api/v1/evaluate -- Evaluate an ActionIntent through the Gate."""
        body = self._read_json_body()
        if body is None:
            return  # error already sent

        try:
            intent = _reconstruct_intent(body)
        except (ValueError, KeyError) as exc:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                f"Invalid ActionIntent payload: {exc}",
            )
            return

        gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
        result = gate.evaluate(intent)

        # HITL interception: if gate returns ESCALATE and HITL is enabled,
        # create a PendingApproval and return PENDING to the caller.
        approval_store: ApprovalStore | None = getattr(self.server, "approval_store", None)
        if result.decision == GateDecision.ESCALATE and approval_store is not None:
            action = body.get("action", {})
            target = body.get("target", {})
            approval = PendingApproval(
                approval_id=_uuid_mod.uuid4().hex,
                intent_dict=body,
                gate_result_dict=result.to_dict(),
                tool=action.get("tool", "unknown"),
                target_host=target.get("host", "unknown"),
                category=action.get("category", "unknown"),
                reasoning=result.reasoning,
            )
            approval_store.add(approval)
            logger.info(
                "HITL approval created: %s | tool=%s target=%s",
                approval.approval_id, approval.tool, approval.target_host,
            )
            response = result.to_dict()
            response["decision"] = "PENDING"
            response["approval_id"] = approval.approval_id
            self._send_json(HTTPStatus.OK, response)
            return

        self._send_json(HTTPStatus.OK, result.to_dict())

    def _handle_execute(self) -> None:
        """POST /api/v1/execute -- Execute an approved action with a token."""
        body = self._read_json_body()
        if body is None:
            return

        token_data = body.get("token")
        tool = body.get("tool")
        args = body.get("args", [])

        if not token_data or not isinstance(token_data, dict):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Missing or invalid 'token' field (expected JSON object).",
            )
            return
        if not tool or not isinstance(tool, str):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Missing or invalid 'tool' field (expected non-empty string).",
            )
            return
        if not isinstance(args, list):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Invalid 'args' field (expected JSON array of strings).",
            )
            return

        try:
            token = _reconstruct_token(token_data)
        except (ValueError, KeyError) as exc:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                f"Invalid ActionToken payload: {exc}",
            )
            return

        executor: ToolExecutor = self.server.executor  # type: ignore[attr-defined]
        result = executor.execute(token, tool, [str(a) for a in args])
        self._send_json(HTTPStatus.OK, result.to_dict())

    def _handle_stats(self) -> None:
        """GET /api/v1/stats -- Return Gate and Executor statistics."""
        gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
        executor: ToolExecutor = self.server.executor  # type: ignore[attr-defined]

        stats = gate.get_stats()
        stats["executor"] = executor.get_stats()
        self._send_json(HTTPStatus.OK, stats)

    def _handle_audit(self) -> None:
        """GET /api/v1/audit -- Return audit events and summary."""
        gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
        events = gate.audit.get_events()
        summary = gate.audit.get_summary()
        self._send_json(HTTPStatus.OK, {
            "events": [e.to_dict() for e in events],
            "summary": summary,
        })

    def _handle_halt(self) -> None:
        """POST /api/v1/halt -- Trigger emergency halt."""
        gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
        gate.emergency_halt()
        logger.critical("Emergency halt triggered via API")
        self._send_json(HTTPStatus.OK, {"status": "halted"})

    def _handle_resume(self) -> None:
        """POST /api/v1/resume -- Resume a halted session."""
        body = self._read_json_body()
        if body is None:
            return

        session_id = body.get("session_id")
        if not session_id or not isinstance(session_id, str):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Missing or invalid 'session_id' field (expected non-empty string).",
            )
            return

        gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
        gate.resume_session(session_id)

        # Also resume the signer if it was in emergency halt mode
        gate.signer.resume()

        logger.info("Session '%s' resumed via API", session_id)
        self._send_json(HTTPStatus.OK, {"status": "resumed"})

    def _handle_health(self) -> None:
        """GET /api/v1/health -- Health check / readiness probe."""
        server = self.server  # type: ignore[attr-defined]
        uptime = time.monotonic() - server.start_time
        self._send_json(HTTPStatus.OK, {
            "status": "ok",
            "roe_hash": server.roe_hash,
            "engagement_id": server.engagement_id,
            "uptime_seconds": round(uptime, 2),
            "license_tier": get_active_tier().name,
        })

    def _handle_dashboard(self) -> None:
        """GET /dashboard -- Serve the web-based real-time audit dashboard."""
        server = self.server  # type: ignore[attr-defined]
        html = _build_dashboard_html(
            engagement_id=server.engagement_id,
            roe_hash=server.roe_hash,
        )
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_roe_creator(self) -> None:
        """GET /roe-creator -- Serve the ROE Creator Dashboard (Community)."""
        from src.service.roe_creator import build_roe_creator_html
        html = build_roe_creator_html()
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── Multi-ROE endpoints ────────────────────────────────────────────

    @require_tier(Tier.PRO)
    def _handle_roe_list(self) -> None:
        """GET /api/v1/roe/list -- List all loaded ROE specifications."""
        multi_roe: MultiROEManager = self.server.multi_roe  # type: ignore[attr-defined]
        entries = multi_roe.list_all()
        self._send_json(HTTPStatus.OK, {
            "roe_specs": [
                {
                    "engagement_id": e.engagement_id,
                    "client": e.client,
                    "roe_hash": e.roe_hash,
                    "status": e.status,
                    "loaded_at": e.loaded_at,
                    "file_path": e.file_path,
                }
                for e in entries
            ],
            "total": len(entries),
        })

    @require_tier(Tier.PRO)
    def _handle_roe_add(self) -> None:
        """POST /api/v1/roe/add -- Add a new ROE specification."""
        body = self._read_json_body()
        if body is None:
            return
        roe_spec = body.get("roe_spec") or body.get("roe")
        if not roe_spec or not isinstance(roe_spec, dict):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Missing or invalid 'roe_spec' field (expected JSON object with ROE spec).",
            )
            return
        multi_roe: MultiROEManager = self.server.multi_roe  # type: ignore[attr-defined]
        try:
            entry = multi_roe.add_roe(roe_spec)
        except ValueError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self._send_json(HTTPStatus.CREATED, {
            "status": "added",
            "engagement_id": entry.engagement_id,
            "roe_hash": entry.roe_hash,
        })

    @require_tier(Tier.PRO)
    def _handle_roe_archive(self) -> None:
        """POST /api/v1/roe/archive -- Archive an ROE specification."""
        body = self._read_json_body()
        if body is None:
            return
        engagement_id = body.get("engagement_id")
        if not engagement_id or not isinstance(engagement_id, str):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Missing or invalid 'engagement_id' field.",
            )
            return
        multi_roe: MultiROEManager = self.server.multi_roe  # type: ignore[attr-defined]
        try:
            multi_roe.archive(engagement_id)
        except KeyError as exc:
            self._send_error(HTTPStatus.NOT_FOUND, str(exc))
            return
        self._send_json(HTTPStatus.OK, {"status": "archived", "engagement_id": engagement_id})

    # ── Compliance endpoints ─────────────────────────────────────────

    @require_tier(Tier.ENTERPRISE)
    def _handle_compliance_soc2(self) -> None:
        """GET /api/v1/compliance/soc2 -- Generate SOC 2 Type II report."""
        gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
        events = gate.audit.get_events()
        generator = ComplianceReportGenerator(
            audit_events=events,
            roe_spec=self.server.roe_spec,  # type: ignore[attr-defined]
            engagement_id=self.server.engagement_id,  # type: ignore[attr-defined]
        )
        report = generator.generate_soc2()
        self._send_json(HTTPStatus.OK, json.loads(ComplianceReportGenerator.to_json(report)))

    @require_tier(Tier.ENTERPRISE)
    def _handle_compliance_pci_dss(self) -> None:
        """GET /api/v1/compliance/pci-dss -- Generate PCI-DSS report."""
        gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
        events = gate.audit.get_events()
        generator = ComplianceReportGenerator(
            audit_events=events,
            roe_spec=self.server.roe_spec,  # type: ignore[attr-defined]
            engagement_id=self.server.engagement_id,  # type: ignore[attr-defined]
        )
        report = generator.generate_pci_dss()
        self._send_json(HTTPStatus.OK, json.loads(ComplianceReportGenerator.to_json(report)))

    # ── HA Cluster endpoints ─────────────────────────────────────────

    @require_tier(Tier.ENTERPRISE)
    def _handle_cluster_status(self) -> None:
        """GET /api/v1/cluster/status -- HA cluster overview."""
        cluster: HACluster | None = self.server.cluster  # type: ignore[attr-defined]
        if cluster is None:
            self._send_json(HTTPStatus.OK, {"cluster": "disabled", "mode": "standalone"})
            return
        self._send_json(HTTPStatus.OK, cluster.get_cluster_status())

    @require_tier(Tier.ENTERPRISE)
    def _handle_cluster_heartbeat(self) -> None:
        """GET /api/v1/cluster/heartbeat -- This node's heartbeat."""
        cluster: HACluster | None = self.server.cluster  # type: ignore[attr-defined]
        if cluster is None:
            self._send_json(HTTPStatus.OK, {"cluster": "disabled"})
            return
        self._send_json(HTTPStatus.OK, cluster.heartbeat())

    # ── Tenant endpoints ─────────────────────────────────────────────

    @require_tier(Tier.MSSP)
    def _handle_tenants_list(self) -> None:
        """GET /api/v1/tenants -- List all tenants."""
        tm: TenantManager = self.server.tenant_manager  # type: ignore[attr-defined]
        tenants = tm.list_tenants()
        self._send_json(HTTPStatus.OK, {
            "tenants": [
                {
                    "tenant_id": t.tenant_id,
                    "name": t.name,
                    "status": t.status,
                    "created_at": t.created_at,
                    "evaluation_count": t.evaluation_count,
                }
                for t in tenants
            ],
            "total": len(tenants),
        })

    @require_tier(Tier.MSSP)
    def _handle_tenant_create(self) -> None:
        """POST /api/v1/tenants/create -- Create a new tenant."""
        body = self._read_json_body()
        if body is None:
            return
        name = body.get("name")
        if not name or not isinstance(name, str):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Missing or invalid 'name' field.",
            )
            return
        config = body.get("config", {})
        tm: TenantManager = self.server.tenant_manager  # type: ignore[attr-defined]
        tenant = tm.create_tenant(name=name, config=config)
        self._send_json(HTTPStatus.CREATED, {
            "status": "created",
            "tenant_id": tenant.tenant_id,
            "name": tenant.name,
        })

    # ── Branding endpoint ────────────────────────────────────────────

    @require_tier(Tier.MSSP)
    def _handle_branding(self) -> None:
        """GET /api/v1/branding -- Get branding configuration."""
        bm: BrandingManager = self.server.branding_manager  # type: ignore[attr-defined]
        self._send_json(HTTPStatus.OK, bm.to_dict())

    # ── Public Key endpoint (Ed25519) ────────────────────────────────

    def _handle_public_key(self) -> None:
        """GET /api/v1/public-key -- Export Ed25519 public key for auditors."""
        ed25519_signer = getattr(self.server, "ed25519_signer", None)
        if ed25519_signer is None:
            self._send_json(HTTPStatus.OK, {
                "signing_algorithm": "hmac-sha256",
                "public_key": None,
                "note": "HMAC signing does not use public/private key pairs. "
                        "Use --signing-algo ed25519 for asymmetric key distribution.",
            })
            return
        self._send_json(HTTPStatus.OK, {
            "signing_algorithm": "ed25519",
            "public_key_pem": ed25519_signer.get_public_key_pem(),
        })

    # ── HITL Approval endpoints ──────────────────────────────────────

    def _handle_approvals_pending(self) -> None:
        """GET /api/v1/approvals/pending -- List pending approval requests."""
        store: ApprovalStore | None = getattr(self.server, "approval_store", None)
        if store is None:
            self._send_json(HTTPStatus.OK, {"approvals": [], "hitl_enabled": False})
            return
        pending = store.get_all_pending()
        self._send_json(HTTPStatus.OK, {
            "approvals": [a.to_dict() for a in pending],
            "hitl_enabled": True,
        })

    def _handle_approval_status(self) -> None:
        """GET /api/v1/approvals/{id}/status -- Poll a specific approval's status."""
        # Extract approval_id from path: /api/v1/approvals/{id}/status
        parts = self.path.split("/")
        # ['', 'api', 'v1', 'approvals', '{id}', 'status']
        if len(parts) < 6:
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid approval status path")
            return
        approval_id = parts[4]

        store: ApprovalStore | None = getattr(self.server, "approval_store", None)
        if store is None:
            self._send_error(HTTPStatus.NOT_FOUND, "HITL not enabled")
            return

        approval = store.get(approval_id)
        if approval is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Approval {approval_id} not found")
            return

        self._send_json(HTTPStatus.OK, approval.to_dict())

    def _handle_approval_respond(self) -> None:
        """POST /api/v1/approvals/{id}/respond -- Approve or deny an approval request."""
        # Extract approval_id from path: /api/v1/approvals/{id}/respond
        parts = self.path.split("/")
        if len(parts) < 6:
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid approval respond path")
            return
        approval_id = parts[4]

        body = self._read_json_body()
        if body is None:
            return

        approved = body.get("approved")
        if approved is None or not isinstance(approved, bool):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Missing or invalid 'approved' field (expected boolean)",
            )
            return

        store: ApprovalStore | None = getattr(self.server, "approval_store", None)
        if store is None:
            self._send_error(HTTPStatus.NOT_FOUND, "HITL not enabled")
            return

        approval = store.get(approval_id)
        if approval is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Approval {approval_id} not found")
            return

        if approval.status != "pending":
            self._send_json(HTTPStatus.CONFLICT, {
                "error": f"Approval already resolved: {approval.status}",
                "approval": approval.to_dict(),
            })
            return

        token_dict = None
        if approved:
            # Sign a token for the approved action
            gate: ROEGate = self.server.gate  # type: ignore[attr-defined]
            intent = _reconstruct_intent(approval.intent_dict)
            token = gate.signer.sign_action(
                intent_id=intent.intent_id,
                engagement_id=intent.engagement_id,
                roe_hash=gate.roe_hash,
                rule_engine_result="NEEDS_HUMAN",
                judge_result={"verdict": "ALLOW", "reasoning": "Human operator approved"},
                permitted_action={
                    "tool": intent.tool,
                    "category": intent.category.value,
                    "target": intent.target.to_dict(),
                    "parameters": intent.parameters,
                },
                constraints={},
            )
            token_dict = token.to_dict()
            logger.info("HITL approval APPROVED: %s", approval_id)
        else:
            logger.info("HITL approval DENIED: %s", approval_id)

        resolved = store.resolve(approval_id, approved, token_dict)
        if resolved is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Approval {approval_id} not found")
            return

        self._send_json(HTTPStatus.OK, resolved.to_dict())

    # ── JSON I/O helpers ─────────────────────────────────────────────

    def _read_json_body(self) -> dict | None:
        """Read and parse the JSON request body.

        Returns the parsed dict on success, or ``None`` if the body is
        missing or invalid JSON (in which case a 400 error has already been
        sent to the client).
        """
        content_length_str = self.headers.get("Content-Length", "0")
        try:
            content_length = int(content_length_str)
        except ValueError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                f"Invalid Content-Length header: {content_length_str!r}",
            )
            return None

        if content_length == 0:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Request body is empty. Expected JSON payload.",
            )
            return None

        raw = self.rfile.read(content_length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                f"Invalid JSON: {exc}",
            )
            return None

        if not isinstance(data, dict):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Request body must be a JSON object (not an array or scalar).",
            )
            return None

        return data

    def _send_json(self, status: HTTPStatus, data: Any) -> None:
        """Send a JSON response with the given HTTP status code."""
        body = json.dumps(data, default=str, indent=2).encode("utf-8")
        self.send_response(status.value)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        """Send a JSON error response."""
        logger.warning("HTTP %d on %s %s: %s", status.value, self.command, self.path, message)
        self._send_json(status, {"error": message})

    def _send_cors_headers(self) -> None:
        """Add CORS headers for dashboard access."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(HTTPStatus.NO_CONTENT.value)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()


# ── Server factory / wrapper ─────────────────────────────────────────────────

class GateAPIServer:
    """High-level wrapper around the threaded HTTP server.

    Encapsulates initialization of the ROE Gate, ActionSigner, ToolExecutor,
    and the HTTP server itself.  Provides ``start()`` / ``stop()`` lifecycle
    methods and stores metadata for the ``/health`` endpoint.

    Args:
        roe_spec: The parsed ROE specification dict (the ``'roe'`` key from YAML).
        host: Bind address for the HTTP server.
        port: Bind port for the HTTP server.
        judge_name: Name of the judge backend (``'mock'``, ``'anthropic'``, ``'openai'``).
        dry_run: If ``True``, the ToolExecutor will log commands without running them.
        log_dir: Optional directory for audit log files.
    """

    def __init__(
        self,
        roe_spec: dict[str, Any],
        host: str = "127.0.0.1",
        port: int = 19990,
        judge_name: str = "mock",
        dry_run: bool = False,
        log_dir: str | None = None,
        alert_config: dict[str, Any] | None = None,
        signing_algo: str = "hmac",
        rbac_enabled: bool = False,
        ha_peers: list[tuple[str, int]] | None = None,
        human_in_the_loop: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.roe_spec = roe_spec
        self.roe_hash = compute_roe_hash(roe_spec)
        self.engagement_id = roe_spec.get("metadata", {}).get("engagement_id", "unknown")
        self.human_in_the_loop = human_in_the_loop

        # ── Select Judge LLM provider ────────────────────────────────
        llm_provider = self._create_judge_provider(judge_name)

        # ── Alerting (Pro+) ──────────────────────────────────────────
        self.alert_manager = None
        if alert_config and AlertManager is not None:
            self.alert_manager = AlertManager.from_config(alert_config)
            logger.info("Alerting configured with %d alerter(s)", len(self.alert_manager._alerters))

        # ── Signing algorithm selection ──────────────────────────────
        signer: ActionSigner | None = None
        self.ed25519_signer = None
        if signing_algo == "ed25519":
            try:
                from src.crypto.ed25519_signer import Ed25519ActionSigner
                self.ed25519_signer = Ed25519ActionSigner()
                signer = self.ed25519_signer  # type: ignore[assignment]
                logger.info("Using Ed25519 asymmetric signing")
            except ImportError:
                logger.error(
                    "Ed25519 signing requires the 'cryptography' package. "
                    "Install with: pip install roe-agent-gate[ed25519]"
                )
                sys.exit(1)

        # ── Initialize core components ───────────────────────────────
        self.gate = ROEGate(
            roe_spec=roe_spec,
            llm_provider=llm_provider,
            alert_manager=self.alert_manager,
            signer=signer,
            human_in_the_loop=human_in_the_loop,
        )

        # The executor shares the same signer as the gate so that token
        # verification works end-to-end.
        self.executor = ToolExecutor(
            signer=self.gate.signer,
            roe_hash=self.roe_hash,
            dry_run=dry_run,
        )

        # Optional audit log directory
        if log_dir:
            self.gate.audit._log_file = (
                Path(log_dir)
                / f"audit_{self.engagement_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
            )
            Path(log_dir).mkdir(parents=True, exist_ok=True)

        # ── RBAC (Enterprise) ────────────────────────────────────────
        self.rbac = None
        if rbac_enabled and RBACManager is not None:
            self.rbac = RBACManager()
            # Create a default admin user (API key printed at startup)
            import secrets
            admin_key = secrets.token_urlsafe(32)
            self.rbac.add_user("admin", Role.ADMIN, api_key=admin_key)
            self._admin_api_key = admin_key
            logger.info("RBAC enabled. Admin API key generated (shown in startup banner).")

        # ── Multi-ROE (Pro+) ─────────────────────────────────────────
        self.multi_roe = None
        if MultiROEManager is not None:
            self.multi_roe = MultiROEManager()
            self.multi_roe.add_roe(roe_spec)

        # ── HA Cluster (Enterprise) ──────────────────────────────────
        self.cluster = None
        if ha_peers and HACluster is not None:
            import uuid as _uuid
            node_id = f"{host}:{port}"
            self.cluster = HACluster(
                node_id=node_id, host=host, port=port, peers=ha_peers,
            )
            self.cluster.elect_leader()
            logger.info(
                "HA cluster initialized: node=%s, peers=%d",
                node_id, len(ha_peers),
            )

        # ── Tenant Manager (MSSP/OEM) ────────────────────────────────
        self.tenant_manager = TenantManager() if TenantManager is not None else None

        # ── Branding Manager (MSSP/OEM) ──────────────────────────────
        self.branding_manager = BrandingManager() if BrandingManager is not None else None

        # ── HITL Approval Store ─────────────────────────────────────
        self.approval_store: ApprovalStore | None = (
            ApprovalStore() if human_in_the_loop else None
        )

        # ── Create the HTTP server ───────────────────────────────────
        self._httpd = ThreadedHTTPServer((host, port), GateRequestHandler)

        # Attach shared state to the server instance so the request handler
        # can access it via ``self.server``.
        self._httpd.gate = self.gate  # type: ignore[attr-defined]
        self._httpd.executor = self.executor  # type: ignore[attr-defined]
        self._httpd.roe_spec = roe_spec  # type: ignore[attr-defined]
        self._httpd.roe_hash = self.roe_hash  # type: ignore[attr-defined]
        self._httpd.engagement_id = self.engagement_id  # type: ignore[attr-defined]
        self._httpd.start_time = time.monotonic()  # type: ignore[attr-defined]
        self._httpd.rbac = self.rbac  # type: ignore[attr-defined]
        self._httpd.multi_roe = self.multi_roe  # type: ignore[attr-defined]
        self._httpd.cluster = self.cluster  # type: ignore[attr-defined]
        self._httpd.tenant_manager = self.tenant_manager  # type: ignore[attr-defined]
        self._httpd.branding_manager = self.branding_manager  # type: ignore[attr-defined]
        self._httpd.ed25519_signer = self.ed25519_signer  # type: ignore[attr-defined]
        self._httpd.approval_store = self.approval_store  # type: ignore[attr-defined]

        self._server_thread: threading.Thread | None = None

    def start(self, blocking: bool = True) -> None:
        """Start the HTTP server.

        Args:
            blocking: If ``True`` (the default), serve forever on the
                current thread.  If ``False``, start in a background daemon
                thread and return immediately (useful for embedding).
        """
        if blocking:
            logger.info(
                "Gate Service listening on %s:%d (blocking mode)",
                self.host, self.port,
            )
            self._httpd.serve_forever()
        else:
            self._server_thread = threading.Thread(
                target=self._httpd.serve_forever,
                daemon=True,
                name="gate-api-server",
            )
            self._server_thread.start()
            logger.info(
                "Gate Service listening on %s:%d (background mode)",
                self.host, self.port,
            )

    def stop(self) -> None:
        """Shut down the HTTP server gracefully."""
        logger.info("Shutting down Gate Service...")
        self._httpd.shutdown()
        self._httpd.server_close()
        logger.info("Gate Service stopped.")

    @property
    def url(self) -> str:
        """Return the base URL of the running server."""
        return f"http://{self.host}:{self.port}"

    @staticmethod
    def _create_judge_provider(judge_name: str) -> Any:
        """Instantiate the requested Judge LLM provider.

        API keys are read from environment variables:
          - ``ANTHROPIC_API_KEY`` for the ``anthropic`` and ``claude-sdk`` providers
          - ``OPENAI_API_KEY`` for the ``openai`` provider
          - ``CLAUDE_CODE_OAUTH_TOKEN`` as an alternative for ``claude-sdk``

        Args:
            judge_name: One of ``'mock'``, ``'anthropic'``, ``'openai'``,
                or ``'claude-sdk'``.

        Returns:
            An LLM provider instance implementing the ``complete()`` protocol.

        Raises:
            SystemExit: If the requested provider's dependencies are not
                installed or the required API key is missing.
            ValueError: If the judge name is unrecognized.
        """
        import os

        if judge_name == "mock":
            from examples.demo import MockJudgeLLM
            return MockJudgeLLM()

        if judge_name == "anthropic":
            try:
                from src.core.providers import AnthropicProvider
            except ImportError:
                logger.error(
                    "AnthropicProvider requires the 'anthropic' package. "
                    "Install with: pip install roe-agent-gate[anthropic]"
                )
                sys.exit(1)
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                logger.error(
                    "ANTHROPIC_API_KEY environment variable is required "
                    "when using --judge anthropic"
                )
                sys.exit(1)
            return AnthropicProvider(api_key=api_key)

        if judge_name == "openai":
            try:
                from src.core.providers import OpenAIProvider
            except ImportError:
                logger.error(
                    "OpenAIProvider requires the 'openai' package. "
                    "Install with: pip install roe-agent-gate[openai]"
                )
                sys.exit(1)
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                logger.error(
                    "OPENAI_API_KEY environment variable is required "
                    "when using --judge openai"
                )
                sys.exit(1)
            return OpenAIProvider(api_key=api_key)

        if judge_name == "claude-sdk":
            try:
                from src.core.providers import ClaudeAgentSDKProvider
            except ImportError:
                logger.error(
                    "ClaudeAgentSDKProvider requires the 'claude-agent-sdk' package. "
                    "Install with: pip install claude-agent-sdk\n"
                    "Authenticate with: export ANTHROPIC_API_KEY=sk-ant-...\n"
                    "  or: export CLAUDE_CODE_OAUTH_TOKEN=... (from 'claude setup-token')"
                )
                sys.exit(1)
            # ClaudeAgentSDKProvider reads auth from env vars internally
            # (ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN)
            has_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
            if not has_key:
                logger.error(
                    "Claude Agent SDK requires authentication. Set one of:\n"
                    "  ANTHROPIC_API_KEY=sk-ant-...  (API key)\n"
                    "  CLAUDE_CODE_OAUTH_TOKEN=...   (from 'claude setup-token')"
                )
                sys.exit(1)
            return ClaudeAgentSDKProvider()

        if judge_name == "claude-cli":
            try:
                from src.core.providers import ClaudeCLIProvider
                return ClaudeCLIProvider()
            except FileNotFoundError as exc:
                logger.error("%s", exc)
                sys.exit(1)

        if judge_name == "gemini":
            from src.core.providers import GeminiProvider
            api_key = os.environ.get("GOOGLE_API_KEY", "")
            if not api_key:
                logger.error(
                    "GOOGLE_API_KEY environment variable is required "
                    "when using --judge gemini"
                )
                sys.exit(1)
            return GeminiProvider(api_key=api_key)

        if judge_name == "ollama":
            from src.core.providers import OllamaProvider
            return OllamaProvider()

        if judge_name == "bedrock":
            from src.core.providers import BedrockProvider
            return BedrockProvider()

        if judge_name == "openai-compatible":
            from src.core.providers import OpenAIProvider
            api_key = os.environ.get("OPENAI_API_KEY", "")
            base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
            if not api_key:
                logger.error(
                    "OPENAI_API_KEY environment variable is required "
                    "when using --judge openai-compatible"
                )
                sys.exit(1)
            return OpenAIProvider(api_key=api_key, base_url=base_url)

        raise ValueError(f"Unknown judge provider: {judge_name!r}")


def create_server(
    roe_spec: dict[str, Any],
    host: str = "127.0.0.1",
    port: int = 19990,
    judge_name: str = "mock",
    dry_run: bool = False,
    log_dir: str | None = None,
    alert_config: dict[str, Any] | None = None,
    signing_algo: str = "hmac",
    rbac_enabled: bool = False,
    ha_peers: list[tuple[str, int]] | None = None,
    human_in_the_loop: bool = False,
) -> GateAPIServer:
    """Convenience factory for creating a ``GateAPIServer`` instance.

    This is the primary programmatic entry point.  For command-line usage,
    see ``main()``.

    Args:
        roe_spec: Parsed ROE specification (the ``'roe'`` key from YAML).
        host: Bind address.
        port: Bind port.
        judge_name: Judge backend name.
        dry_run: Run executor in dry-run mode.
        log_dir: Optional audit log directory.
        alert_config: Optional alerting configuration dict.
        signing_algo: Signing algorithm ("hmac" or "ed25519").
        rbac_enabled: Enable role-based access control.
        ha_peers: Optional list of (host, port) tuples for HA clustering.
        human_in_the_loop: Enable human-in-the-loop approval UI.

    Returns:
        A configured but not yet started ``GateAPIServer``.
    """
    return GateAPIServer(
        roe_spec=roe_spec,
        host=host,
        port=port,
        judge_name=judge_name,
        dry_run=dry_run,
        log_dir=log_dir,
        alert_config=alert_config,
        signing_algo=signing_algo,
        rbac_enabled=rbac_enabled,
        ha_peers=ha_peers,
        human_in_the_loop=human_in_the_loop,
    )


# ── Startup banner ───────────────────────────────────────────────────────────

_BANNER = r"""
 ____   ___  _____    ____       _
|  _ \ / _ \| ____|  / ___| __ _| |_ ___
| |_) | | | |  _|   | |  _ / _` | __/ _ \
|  _ <| |_| | |___  | |_| | (_| | ||  __/
|_| \_\\___/|_____|  \____|\__,_|\__\___|
  Service v{version}
"""


def _print_startup_banner(
    roe_spec: dict[str, Any],
    roe_hash: str,
    host: str,
    port: int,
    judge_name: str,
    dry_run: bool,
    signing_algo: str = "hmac",
    rbac_enabled: bool = False,
    admin_api_key: str | None = None,
    alert_config: dict[str, Any] | None = None,
    ha_peers: list[tuple[str, int]] | None = None,
    human_in_the_loop: bool = False,
) -> None:
    """Print the startup banner with engagement information."""
    from src import __version__

    metadata = roe_spec.get("metadata", {})
    engagement_id = metadata.get("engagement_id", "unknown")
    client = metadata.get("client", "unknown")

    print(_BANNER.format(version=__version__))
    print(f"  Engagement:   {engagement_id}")
    print(f"  Client:       {client}")
    print(f"  ROE Hash:     {roe_hash}")
    print(f"  Judge:        {judge_name}")
    print(f"  Signing:      {signing_algo}")
    print(f"  License tier: {get_active_tier().name}")
    print(f"  RBAC:         {'enabled' if rbac_enabled else 'disabled'}")
    print(f"  HITL:         {'enabled (dashboard approval UI)' if human_in_the_loop else 'disabled (out-of-scope = DENY)'}")
    print(f"  Dry Run:      {dry_run}")
    print(f"  Listening on: http://{host}:{port}")

    if alert_config:
        targets = []
        if "slack" in alert_config:
            targets.append("Slack")
        if "webhooks" in alert_config:
            targets.append(f"{len(alert_config['webhooks'])} webhook(s)")
        print(f"  Alerting:     {', '.join(targets)}")

    if ha_peers:
        print(f"  HA Peers:     {len(ha_peers)}")

    print()
    print("  Core Endpoints:")
    print("    POST /api/v1/evaluate       - Evaluate an ActionIntent")
    print("    POST /api/v1/execute        - Execute an approved action")
    print("    GET  /api/v1/stats          - Gate statistics")
    print("    GET  /api/v1/audit          - Audit trail")
    print("    POST /api/v1/halt           - Emergency halt")
    print("    POST /api/v1/resume         - Resume halted session")
    print("    GET  /api/v1/health         - Health check")
    print()
    if human_in_the_loop:
        print("  HITL Approval Endpoints:")
        print("    GET  /api/v1/approvals/pending      - List pending approvals")
        print("    GET  /api/v1/approvals/{id}/status   - Poll approval status")
        print("    POST /api/v1/approvals/{id}/respond  - Approve or deny")
        print()
    print("  Pro/Enterprise Endpoints:")
    print("    GET  /api/v1/roe/list       - List loaded ROE specs")
    print("    POST /api/v1/roe/add        - Add ROE specification")
    print("    POST /api/v1/roe/archive    - Archive ROE specification")
    print("    GET  /api/v1/compliance/soc2    - SOC 2 report")
    print("    GET  /api/v1/compliance/pci-dss - PCI-DSS report")
    print("    GET  /api/v1/cluster/status     - HA cluster status")
    print("    GET  /api/v1/tenants        - List tenants")
    print("    POST /api/v1/tenants/create - Create tenant")
    print("    GET  /api/v1/branding       - Branding config")
    print("    GET  /api/v1/public-key     - Ed25519 public key")

    if rbac_enabled and admin_api_key:
        print()
        print(f"  Admin API Key: {admin_api_key}")
        print("  (Use this key in Authorization: Bearer <key> header)")

    print()
    print("  Press Ctrl+C to stop the server.")
    print()


# ── CLI entry point ──────────────────────────────────────────────────────────

def main() -> None:
    """Command-line entry point for the ROE Gate Service.

    Parses arguments, loads the ROE specification, initializes all
    components, and starts the HTTP server.
    """
    parser = argparse.ArgumentParser(
        prog="roe-gate-service",
        description=(
            "ROE Gate Service -- Standalone HTTP API for out-of-band "
            "Rules of Engagement enforcement."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m src.service.gate_api --roe examples/acme_corp_roe.yaml\n"
            "  python -m src.service.gate_api --roe my_roe.yaml --port 8080 --judge mock --dry-run\n"
            "  python -m src.service.gate_api --roe roe.yaml --judge anthropic --verbose\n"
        ),
    )
    parser.add_argument(
        "--roe",
        required=True,
        metavar="PATH",
        help="Path to the ROE YAML specification file (required).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address for the HTTP server (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=19990,
        help="Bind port for the HTTP server (default: 19990).",
    )
    parser.add_argument(
        "--judge",
        choices=[
            "mock", "anthropic", "openai", "gemini", "ollama",
            "bedrock", "openai-compatible", "claude-sdk", "claude-cli",
        ],
        default="mock",
        help="Judge LLM backend to use (default: mock).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the executor in dry-run mode (log commands, do not execute).",
    )
    parser.add_argument(
        "--log-dir",
        metavar="PATH",
        default=None,
        help="Directory for audit log files.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    parser.add_argument(
        "--slack-webhook",
        metavar="URL",
        default=None,
        help="Slack incoming webhook URL for real-time alerts.",
    )
    parser.add_argument(
        "--webhook-url",
        metavar="URL",
        default=None,
        help="Generic webhook URL for real-time alerts.",
    )
    parser.add_argument(
        "--signing-algo",
        choices=["hmac", "ed25519"],
        default="hmac",
        help="Token signing algorithm (default: hmac).",
    )
    parser.add_argument(
        "--rbac",
        action="store_true",
        help="Enable role-based access control (requires API keys for all endpoints).",
    )
    parser.add_argument(
        "--ha-peers",
        metavar="HOST:PORT",
        nargs="*",
        default=None,
        help="HA cluster peer addresses (e.g., 10.0.0.2:19990 10.0.0.3:19990).",
    )
    parser.add_argument(
        "--human-in-the-loop",
        action="store_true",
        help=(
            "Enable human-in-the-loop approval for out-of-scope actions. "
            "When enabled, actions that require human approval are held "
            "pending on the dashboard. When disabled (default), such actions "
            "are denied outright."
        ),
    )

    args = parser.parse_args()

    # ── Configure logging ────────────────────────────────────────────
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(name)-24s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Load ROE specification ───────────────────────────────────────
    roe_path = Path(args.roe)
    if not roe_path.exists():
        logger.error("ROE file not found: %s", roe_path)
        sys.exit(1)

    if roe_path.suffix not in (".yaml", ".yml"):
        logger.warning("ROE file does not have a .yaml/.yml extension: %s", roe_path)

    try:
        import yaml
    except ImportError:
        logger.error("PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    try:
        with open(roe_path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse ROE YAML: %s", exc)
        sys.exit(1)

    if not isinstance(raw, dict) or "roe" not in raw:
        logger.error(
            "Invalid ROE file: expected a top-level 'roe' key. "
            "Got keys: %s", list(raw.keys()) if isinstance(raw, dict) else type(raw).__name__,
        )
        sys.exit(1)

    roe_spec: dict[str, Any] = raw["roe"]
    roe_hash = compute_roe_hash(roe_spec)

    # ── Build alert config from CLI flags ────────────────────────────
    alert_config: dict[str, Any] | None = None
    if args.slack_webhook or args.webhook_url:
        alert_config = {}
        if args.slack_webhook:
            alert_config["slack"] = {"webhook_url": args.slack_webhook}
        if args.webhook_url:
            alert_config["webhooks"] = [{"url": args.webhook_url}]

    # ── Parse HA peers ────────────────────────────────────────────────
    ha_peers: list[tuple[str, int]] | None = None
    if args.ha_peers:
        ha_peers = []
        for peer in args.ha_peers:
            host_str, port_str = peer.rsplit(":", 1)
            ha_peers.append((host_str, int(port_str)))

    # ── Create and start the server ──────────────────────────────────
    server = create_server(
        roe_spec=roe_spec,
        host=args.host,
        port=args.port,
        judge_name=args.judge,
        dry_run=args.dry_run,
        log_dir=args.log_dir,
        alert_config=alert_config,
        signing_algo=args.signing_algo,
        rbac_enabled=args.rbac,
        ha_peers=ha_peers,
        human_in_the_loop=args.human_in_the_loop,
    )

    # ── Print startup banner ─────────────────────────────────────────
    _print_startup_banner(
        roe_spec=roe_spec,
        roe_hash=roe_hash,
        host=args.host,
        port=args.port,
        judge_name=args.judge,
        dry_run=args.dry_run,
        signing_algo=args.signing_algo,
        rbac_enabled=args.rbac,
        admin_api_key=getattr(server, '_admin_api_key', None),
        alert_config=alert_config,
        ha_peers=ha_peers,
        human_in_the_loop=args.human_in_the_loop,
    )

    # ── Signal handling for graceful shutdown ─────────────────────────
    def _handle_shutdown(signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, initiating graceful shutdown...", sig_name)
        # Run shutdown in a separate thread to avoid deadlock (the signal
        # handler runs on the main thread, which is also serving requests).
        threading.Thread(target=server.stop, daemon=True).start()

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        # Fallback in case the signal handler didn't fire (e.g. on Windows).
        pass
    finally:
        server.stop()

    logger.info("Gate Service exited.")


if __name__ == "__main__":
    main()
