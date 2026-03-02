"""
ROE Gate CLI — Command-line interface for ROE Agent Gate.

Provides utilities for validating ROE specifications, running demos,
and inspecting system configuration.

Usage:
    roe-gate validate <roe_file>
    roe-gate demo
    roe-gate info
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_yaml(path: str) -> dict[str, Any]:
    """Load and parse a YAML file, returning the parsed dictionary."""
    try:
        import yaml
    except ImportError:
        print("Error: PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    file_path = Path(path)
    if not file_path.exists():
        print(f"Error: File not found: {path}")
        sys.exit(1)

    if not file_path.suffix in (".yaml", ".yml"):
        print(f"Warning: File does not have a .yaml or .yml extension: {path}")

    with open(file_path) as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"Error: Failed to parse YAML: {e}")
            sys.exit(1)


def cmd_validate(args: argparse.Namespace) -> None:
    """Validate a ROE YAML specification file."""
    print(f"Validating: {args.roe_file}")
    print()

    data = _load_yaml(args.roe_file)

    # Check top-level 'roe' key
    if "roe" not in data:
        print("[FAIL] Missing top-level 'roe' key.")
        print("  The ROE specification must be nested under a 'roe:' key.")
        sys.exit(1)

    roe = data["roe"]
    errors: list[str] = []
    warnings: list[str] = []
    passed: list[str] = []

    # --- Required sections ---
    required_sections = ["metadata", "scope", "actions"]
    for section in required_sections:
        if section not in roe:
            errors.append(f"Missing required section: '{section}'")
        else:
            passed.append(f"Required section '{section}' is present")

    # --- Metadata checks ---
    if "metadata" in roe:
        metadata = roe["metadata"]
        for field in ("engagement_id", "client"):
            if field in metadata and metadata[field]:
                passed.append(f"metadata.{field} = {metadata[field]!r}")
            else:
                warnings.append(f"metadata.{field} is missing or empty")
        if "version" in metadata:
            passed.append(f"metadata.version = {metadata['version']}")
        else:
            warnings.append("metadata.version is not set")

    # --- Scope checks ---
    if "scope" in roe:
        scope = roe["scope"]
        if "in_scope" in scope:
            in_scope = scope["in_scope"]
            scope_types = []
            if "networks" in in_scope and in_scope["networks"]:
                scope_types.append(f"{len(in_scope['networks'])} network(s)")
            if "domains" in in_scope and in_scope["domains"]:
                scope_types.append(f"{len(in_scope['domains'])} domain(s)")
            if "services" in in_scope and in_scope["services"]:
                scope_types.append(f"{len(in_scope['services'])} service(s)")
            if scope_types:
                passed.append(f"scope.in_scope defines: {', '.join(scope_types)}")
            else:
                warnings.append("scope.in_scope has no networks, domains, or services defined")
        else:
            errors.append("scope.in_scope is missing")

        if "out_of_scope" not in scope:
            warnings.append("scope.out_of_scope is not defined (recommended)")
        else:
            passed.append("scope.out_of_scope is defined")

    # --- Actions checks ---
    if "actions" in roe:
        actions = roe["actions"]
        if "allowed" in actions and actions["allowed"]:
            categories = [a.get("category", "?") for a in actions["allowed"]]
            passed.append(f"actions.allowed: {len(categories)} categories ({', '.join(categories)})")
        else:
            warnings.append("actions.allowed is empty or missing")

        if "denied" in actions and actions["denied"]:
            categories = [d.get("category", "?") for d in actions["denied"]]
            passed.append(f"actions.denied: {len(categories)} categories ({', '.join(categories)})")
        else:
            warnings.append("actions.denied is empty or missing (recommended to explicitly deny dangerous categories)")

        if "requires_approval" in actions and actions["requires_approval"]:
            passed.append(f"actions.requires_approval: {len(actions['requires_approval'])} rule(s)")

    # --- Optional but recommended sections ---
    optional_sections = ["schedule", "data_handling", "constraints", "emergency"]
    for section in optional_sections:
        if section in roe:
            passed.append(f"Optional section '{section}' is present")
        else:
            warnings.append(f"Optional section '{section}' is not defined (recommended)")

    # --- Emergency checks ---
    if "emergency" in roe:
        emergency = roe["emergency"]
        if emergency.get("kill_switch"):
            passed.append("emergency.kill_switch is enabled")
        else:
            warnings.append("emergency.kill_switch is not enabled (strongly recommended)")
        if "max_consecutive_denials" in emergency:
            passed.append(f"emergency.max_consecutive_denials = {emergency['max_consecutive_denials']}")

    # --- Print results ---
    print(f"  Passed:   {len(passed)}")
    print(f"  Warnings: {len(warnings)}")
    print(f"  Errors:   {len(errors)}")
    print()

    if passed:
        for item in passed:
            print(f"  [PASS] {item}")
    print()

    if warnings:
        for item in warnings:
            print(f"  [WARN] {item}")
        print()

    if errors:
        for item in errors:
            print(f"  [FAIL] {item}")
        print()
        print("Validation FAILED.")
        sys.exit(1)
    else:
        print("Validation PASSED.")


def cmd_demo(args: argparse.Namespace) -> None:
    """Run the built-in demo scenario."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        print("Error: PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    from .core.action_intent import (
        ActionIntent,
        ActionCategory,
        Target,
        ImpactAssessment,
        ImpactLevel,
        DataAccessType,
    )
    from .gate.gate import ROEGate, GateDecision

    # --- ANSI color helpers ---
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def color_decision(decision: GateDecision) -> str:
        label = decision.value
        if decision == GateDecision.ALLOW:
            return f"{GREEN}{BOLD}[ALLOW]{RESET}"
        elif decision in (GateDecision.DENY, GateDecision.HALT):
            return f"{RED}{BOLD}[{label}]{RESET}"
        else:
            return f"{YELLOW}{BOLD}[{label}]{RESET}"

    def print_header(text: str) -> None:
        print(f"\n{'=' * 70}")
        print(f"  {text}")
        print(f"{'=' * 70}\n")

    # --- Mock Judge LLM ---
    class MockJudgeLLM:
        """Simulates Judge LLM behavior for the demo."""

        def complete(self, system_prompt: str, user_prompt: str) -> str:
            action_section = ""
            if "PROPOSED ACTION:" in user_prompt:
                action_section = user_prompt.split("PROPOSED ACTION:")[1].split("RULE ENGINE")[0]

            if '"category": "direct_database_access"' in action_section:
                return json.dumps({
                    "verdict": "DENY",
                    "confidence": 0.98,
                    "reasoning": (
                        "Direct database access is explicitly prohibited by the ROE. "
                        "The agent must test through the web application layer only."
                    ),
                    "roe_clauses_cited": ["actions.denied - direct_database_access"],
                })
            elif '"category": "web_application_testing"' in action_section:
                return json.dumps({
                    "verdict": "ALLOW",
                    "confidence": 0.95,
                    "reasoning": (
                        "Web application testing on in-scope domain is explicitly permitted. "
                        "The target and method are within the authorized scope."
                    ),
                    "roe_clauses_cited": [
                        "scope.in_scope.domains - *.app.corp.local",
                        "actions.allowed - web_application_testing",
                    ],
                })
            elif '"category": "reconnaissance"' in action_section:
                return json.dumps({
                    "verdict": "ALLOW",
                    "confidence": 0.92,
                    "reasoning": "Reconnaissance on in-scope network is explicitly allowed.",
                    "roe_clauses_cited": ["actions.allowed - reconnaissance"],
                })
            else:
                return json.dumps({
                    "verdict": "ESCALATE",
                    "confidence": 0.5,
                    "reasoning": "Action is ambiguous and requires human review.",
                    "roe_clauses_cited": [],
                })

    # --- Inline ROE spec (self-contained, no file dependency) ---
    roe_spec = {
        "metadata": {
            "engagement_id": "DEMO-001",
            "client": "Acme Corp",
            "created": "2024-01-10T09:00:00Z",
            "approved_by": "Demo Operator",
            "version": 1,
        },
        "schedule": {
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2030-12-31T23:59:59Z",
            "timezone": "UTC",
        },
        "scope": {
            "in_scope": {
                "networks": [
                    {"cidr": "10.0.0.0/24", "description": "Web app subnet", "ports": [80, 443, 8080, 8443]},
                    {"cidr": "10.0.1.0/24", "description": "API subnet", "ports": [443, 8443]},
                ],
                "domains": [
                    {"pattern": "*.app.corp.local", "include_subdomains": True},
                    {"pattern": "api.corp.local"},
                ],
            },
            "out_of_scope": {
                "networks": [
                    {"cidr": "10.0.2.0/24", "reason": "Production database tier"},
                    {"cidr": "10.0.3.0/24", "reason": "Payment processing (PCI DSS)"},
                ],
                "domains": [
                    {"pattern": "*.payments.corp.local", "reason": "PCI DSS scope"},
                    {"pattern": "*.prod-db.corp.local", "reason": "Production databases"},
                ],
                "services": [
                    {
                        "type": "database",
                        "protocols": ["postgresql", "mysql", "mongodb", "redis"],
                        "reason": "No direct database access authorized",
                    },
                ],
            },
        },
        "actions": {
            "allowed": [
                {
                    "category": "reconnaissance",
                    "methods": ["port_scan", "service_enumeration", "dns_enumeration"],
                    "constraints": {"rate_limit": "100 requests/second"},
                },
                {
                    "category": "web_application_testing",
                    "methods": ["sql_injection", "xss", "csrf", "authentication_bypass"],
                    "constraints": {"targets": ["https://app.corp.local/*"]},
                },
            ],
            "denied": [
                {"category": "direct_database_access", "reason": "No direct database connections",
                 "match": {"ports": [5432, 3306, 27017, 6379]}},
                {"category": "denial_of_service", "reason": "No DoS testing"},
                {"category": "data_exfiltration", "reason": "No bulk data extraction"},
                {"category": "lateral_movement", "reason": "No pivoting to other segments"},
            ],
        },
        "data_handling": {
            "pii_encountered": "hash_and_log_metadata_only",
            "credentials_found": "log_existence_only_no_values",
        },
        "constraints": {
            "max_concurrent_connections": 10,
            "no_persistent_changes": True,
        },
        "emergency": {
            "kill_switch": True,
            "max_consecutive_denials": 3,
        },
    }

    # --- Initialize the Gate ---
    print_header("ROE Agent Gate -- Interactive Demo")
    print(f"  Engagement:  {roe_spec['metadata']['engagement_id']}")
    print(f"  Client:      {roe_spec['metadata']['client']}")
    print(f"  Judge:       MockJudgeLLM (deterministic simulation)")
    print()

    gate = ROEGate(
        roe_spec=roe_spec,
        llm_provider=MockJudgeLLM(),
        token_ttl_seconds=30,
        max_consecutive_denials=3,
    )

    # --- Scenario 1: Allowed action ---
    print_header("Scenario 1: SQL Injection Test on In-Scope Web App")
    print("  The agent wants to test app.corp.local for SQL injection.")
    print("  This is an ALLOWED action on an IN-SCOPE target.")
    print()

    intent_1 = ActionIntent(
        agent_session="demo-session",
        engagement_id="DEMO-001",
        tool="curl",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="sql_injection",
        description="Testing for SQL injection in user search endpoint",
        target=Target(
            host="app.corp.local",
            port=443,
            protocol="https",
            service="https",
            domain="app.corp.local",
            url="https://app.corp.local/api/users?search=test'OR'1'='1",
        ),
        parameters={"method": "GET", "payload": "' OR '1'='1"},
        impact=ImpactAssessment(
            data_access=DataAccessType.READ,
            estimated_severity=ImpactLevel.MEDIUM,
        ),
        justification="Testing for SQL injection vulnerability",
    )

    result_1 = gate.evaluate(intent_1)
    print(f"  Decision:  {color_decision(result_1.decision)}")
    print(f"  Reasoning: {result_1.reasoning}")
    if result_1.token:
        print(f"  Token:     {result_1.token.token_id}")
    print()

    # --- Scenario 2: Denied action ---
    print_header("Scenario 2: Direct Database Access (ROE VIOLATION)")
    print("  The agent found credentials via SQLi and wants to connect to")
    print("  the production PostgreSQL database at 10.0.2.50:5432.")
    print("  This is EXPLICITLY DENIED by the ROE.")
    print()

    intent_2 = ActionIntent(
        agent_session="demo-session",
        engagement_id="DEMO-001",
        tool="psql",
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        subcategory="credential_verification",
        description="Connect to PostgreSQL using discovered credentials",
        target=Target(
            host="10.0.2.50",
            port=5432,
            protocol="tcp",
            service="postgresql",
        ),
        parameters={"username": "app_user", "credential_source": "extracted_from_sqli"},
        impact=ImpactAssessment(
            data_access=DataAccessType.READ,
            estimated_severity=ImpactLevel.HIGH,
        ),
        justification="Verifying credentials to confirm finding severity",
    )

    result_2 = gate.evaluate(intent_2)
    print(f"  Decision:        {color_decision(result_2.decision)}")
    print(f"  Reasoning:       {result_2.reasoning}")
    print(f"  Denial count:    {result_2.denial_count}")
    print()

    # --- Scenario 3: Repeated denial -> halt ---
    print_header("Scenario 3: Agent Persists -- Repeated Denial Triggers HALT")
    print("  The agent tries the same class of prohibited action twice more.")
    print(f"  After {gate.max_consecutive_denials} consecutive denials, the agent is HALTED.")
    print()

    for attempt in range(2):
        intent_n = ActionIntent(
            agent_session="demo-session",
            engagement_id="DEMO-001",
            tool="psql",
            category=ActionCategory.DIRECT_DATABASE_ACCESS,
            subcategory="enumeration",
            description=f"Attempt {attempt + 2}: enumerate database tables",
            target=Target(host="10.0.2.50", port=5432, protocol="tcp", service="postgresql"),
            parameters={"query": "SELECT * FROM information_schema.tables"},
            impact=ImpactAssessment(
                data_access=DataAccessType.READ,
                estimated_severity=ImpactLevel.HIGH,
            ),
            justification="Assessing scope of data exposure",
        )
        result_n = gate.evaluate(intent_n)
        print(f"  Attempt {attempt + 2}:  {color_decision(result_n.decision)}  (consecutive denials: {result_n.denial_count})")
        if result_n.decision == GateDecision.HALT:
            print(f"  {RED}Agent HALTED. Human operator intervention required to resume.{RESET}")

    # --- Summary ---
    print()
    print_header("Summary")
    stats = gate.get_stats()
    print(f"  Total evaluations:  {stats['total_evaluations']}")
    print(f"  Actions allowed:    {stats['total_allows']}")
    print(f"  Actions denied:     {stats['total_denials']}")
    print(f"  Sessions halted:    {stats['halted_sessions']}")
    print()
    print("  The agent could not bypass the ROE Gate. The production database")
    print("  was never contacted. After repeated violations, the agent was halted.")
    print()


def cmd_pentest(args: argparse.Namespace) -> None:
    """Run an ROE-gated pentest session using Claude Code."""
    import atexit
    import os
    import shutil
    import signal
    import subprocess
    import tempfile
    import time
    import urllib.request
    import uuid

    project_root = Path(__file__).resolve().parent.parent
    python = sys.executable

    # -- Merge config file with CLI flags --
    if args.config:
        from .agents.config import ROEGateConfig
        config = ROEGateConfig.from_yaml(args.config)
        # Config provides defaults; explicit CLI flags override
        if args.roe is None:
            args.roe = config.gate.roe
        if args.judge == "claude-cli":
            args.judge = config.judge.provider or "claude-cli"
        if args.model == "sonnet":
            args.model = config.tester.model or "sonnet"
        if args.gate_port == 19990:
            args.gate_port = config.gate.port
        if args.signing_algo == "hmac":
            args.signing_algo = config.gate.signing or "hmac"
        if not args.human_in_the_loop:
            args.human_in_the_loop = config.gate.hitl
        if not args.dry_run:
            args.dry_run = config.gate.dry_run
        if not args.dashboard:
            args.dashboard = config.gate.dashboard
        if not args.rbac:
            args.rbac = config.gate.rbac
        if not args.slack_webhook:
            args.slack_webhook = config.gate.slack_webhook or None
        if not args.webhook_url:
            args.webhook_url = config.gate.webhook_url or None

    if not args.roe:
        print("Error: --roe is required (provide via CLI or in config file under gate.roe)")
        sys.exit(1)

    # -- Verify claude CLI --
    claude_path = shutil.which("claude")
    if claude_path is None:
        print("Error: 'claude' CLI not found on $PATH.")
        print("Install Claude Code: https://docs.anthropic.com/en/docs/claude-code")
        sys.exit(1)

    # -- Load ROE spec --
    roe_data = _load_yaml(args.roe)
    if "roe" not in roe_data:
        print("Error: ROE file missing top-level 'roe' key.")
        sys.exit(1)
    roe_spec = roe_data["roe"]

    metadata = roe_spec.get("metadata", {})
    engagement_id = metadata.get("engagement_id", "UNKNOWN")
    client = metadata.get("client", "Unknown")
    session_id = f"pentest-{engagement_id}-{uuid.uuid4().hex[:8]}"
    gate_url = f"http://127.0.0.1:{args.gate_port}"

    # -- Compute ROE hash --
    from .crypto.signer import compute_roe_hash
    roe_hash = compute_roe_hash(roe_spec)

    # -- Banner --
    print()
    print("=" * 64)
    print("  ROE Gate -- Penetration Testing Session")
    print("=" * 64)
    print(f"  Engagement:  {engagement_id}")
    print(f"  Client:      {client}")
    print(f"  ROE Hash:    {roe_hash[:40]}...")
    print(f"  Judge:       {args.judge}")
    print(f"  Agent Model: {args.model}")
    print(f"  Gate Port:   {args.gate_port}")
    print(f"  Dashboard:   {gate_url}/dashboard")
    print(f"  Signing:     {args.signing_algo}")
    print(f"  RBAC:        {'yes' if args.rbac else 'no'}")
    print(f"  HITL:        {'yes (dashboard approval)' if args.human_in_the_loop else 'no (out-of-scope = DENY)'}")
    print(f"  Dry Run:     {'yes' if args.dry_run else 'no'}")
    print(f"  Session:     {session_id}")
    if args.slack_webhook:
        print(f"  Alerting:    Slack webhook configured")
    if args.webhook_url:
        print(f"  Alerting:    Webhook configured")
    print("=" * 64)

    # -- Check for stale processes on the gate port --
    gate_port = args.gate_port
    try:
        stale_check = subprocess.run(
            ["lsof", "-ti", f":{gate_port}"],
            capture_output=True, text=True, timeout=5,
        )
        stale_pids = stale_check.stdout.strip()
        if stale_pids:
            print(f"\n  Port {gate_port} is already in use (PID: {stale_pids.replace(chr(10), ', ')}).")
            print("  Killing stale process(es)...")
            for pid in stale_pids.splitlines():
                try:
                    os.kill(int(pid.strip()), signal.SIGTERM)
                except (ProcessLookupError, ValueError):
                    pass
            time.sleep(1)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # lsof not available or timed out — proceed anyway

    # -- Start Gate Service --
    print("\n  Starting Gate Service...")
    gate_cmd = [
        python, "-m", "src.service.gate_api",
        "--roe", str(Path(args.roe).resolve()),
        "--port", str(gate_port),
        "--judge", args.judge,
        "--signing-algo", args.signing_algo,
    ]
    if args.dry_run:
        gate_cmd.append("--dry-run")
    if args.rbac:
        gate_cmd.append("--rbac")
    if args.human_in_the_loop:
        gate_cmd.append("--human-in-the-loop")
    if args.slack_webhook:
        gate_cmd.extend(["--slack-webhook", args.slack_webhook])
    if args.webhook_url:
        gate_cmd.extend(["--webhook-url", args.webhook_url])

    gate_proc = subprocess.Popen(
        gate_cmd,
        cwd=str(project_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,  # own process group so Ctrl+C doesn't kill it
    )

    def _cleanup_gate():
        if gate_proc.poll() is None:
            gate_proc.terminate()
            try:
                gate_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gate_proc.kill()

    atexit.register(_cleanup_gate)

    print(f"  Gate Service PID: {gate_proc.pid}")

    # -- Wait for health --
    print(f"  Waiting for Gate Service at {gate_url}...")
    deadline = time.time() + 15
    healthy = False
    while time.time() < deadline:
        # If the subprocess already exited, don't keep polling
        if gate_proc.poll() is not None:
            break
        try:
            req = urllib.request.Request(f"{gate_url}/api/v1/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                health = json.loads(resp.read().decode())
                if health.get("status") == "ok":
                    healthy = True
                    break
        except Exception:
            pass
        time.sleep(0.5)

    if not healthy:
        print("  Error: Gate Service did not become healthy within 15 seconds.")
        # Show the gate service's stderr so the user can see the actual error
        stderr_output = ""
        if gate_proc.poll() is not None:
            stderr_output = gate_proc.stderr.read().decode(errors="replace")
        else:
            _cleanup_gate()
            stderr_output = gate_proc.stderr.read().decode(errors="replace")
        if stderr_output:
            print("\n  Gate Service output:")
            for line in stderr_output.strip().splitlines():
                print(f"    {line}")
        sys.exit(1)

    print("  Gate Service is ready.")

    # -- Open web dashboard in browser --
    if args.dashboard:
        import webbrowser
        dashboard_url = f"{gate_url}/dashboard"
        print(f"  Opening dashboard: {dashboard_url}")
        webbrowser.open(dashboard_url)

    # -- Write temp MCP config --
    mcp_config = {
        "mcpServers": {
            "roe-pentest": {
                "command": python,
                "args": [
                    "-m", "src.service.mcp_server",
                    "--gate-url", gate_url,
                    "--session-id", session_id,
                    "--engagement-id", engagement_id,
                ],
                "cwd": str(project_root),
            }
        }
    }
    mcp_tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="roe_mcp_", delete=False,
    )
    json.dump(mcp_config, mcp_tmp, indent=2)
    mcp_tmp.close()

    # -- Write temp settings (hooks) --
    hook_script = str(project_root / "src" / "hooks" / "bash_gate_hook.py")
    settings_config = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{python} {hook_script}",
                        }
                    ],
                }
            ]
        }
    }
    settings_tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="roe_settings_", delete=False,
    )
    json.dump(settings_config, settings_tmp, indent=2)
    settings_tmp.close()

    def _cleanup_temp():
        for f in (mcp_tmp.name, settings_tmp.name):
            try:
                os.unlink(f)
            except OSError:
                pass

    atexit.register(_cleanup_temp)

    # -- Build system prompt --
    system_prompt = (
        f"You are an autonomous penetration testing agent for engagement "
        f"{engagement_id} (client: {client}).\n\n"
        f"CRITICAL RULES:\n"
        f"1. You MUST use the ROE-gated MCP tools for ALL interactions with "
        f"target systems. Direct Bash commands for pentest tools (nmap, curl, "
        f"sqlmap, etc.) are BLOCKED by hooks.\n"
        f"2. Do NOT self-censor or pre-filter actions based on scope. The ROE "
        f"Gate Service is the SOLE authority on what is allowed or denied. "
        f"ALWAYS submit your intended action through the gated tools and let "
        f"the Gate decide. If the Gate denies it, report the denial to the "
        f"operator. Do NOT refuse to try an action — the Gate exists to make "
        f"that decision, not you.\n"
        f"3. If a tool call is denied by the Gate, do not retry the same action. "
        f"After 3 consecutive denials your session will be HALTED.\n\n"
        f"Available MCP tools:\n"
        f"- roe_nmap_scan: Port scanning and service discovery\n"
        f"- roe_http_request: HTTP requests to web targets\n"
        f"- roe_dns_lookup: DNS enumeration\n"
        f"- roe_service_probe: Service identification on specific ports\n"
        f"- roe_directory_scan: Web directory enumeration\n"
        f"- roe_sql_injection_test: SQL injection testing\n"
        f"- roe_shell_command: General pentest commands (all gated)\n\n"
        f"You may use Bash for local-only tasks (file manipulation, notes, "
        f"analysis scripts) but all target interaction MUST go through the "
        f"ROE-gated tools above."
    )

    # -- Launch Claude Code --
    print("\n  Launching Claude Code with ROE Gate enforcement...")
    print(f"  MCP config:  {mcp_tmp.name}")
    print(f"  Hook config: {settings_tmp.name}")
    print()
    print("-" * 64)
    print()

    claude_cmd = [
        claude_path,
        "--mcp-config", mcp_tmp.name,
        "--settings", settings_tmp.name,
        "--append-system-prompt", system_prompt,
        "--model", args.model,
    ]

    try:
        claude_result = subprocess.run(claude_cmd, cwd=str(project_root))
    except KeyboardInterrupt:
        print("\n\n  Session interrupted.")

    # -- Print summary --
    print()
    print("-" * 64)

    try:
        req = urllib.request.Request(f"{gate_url}/api/v1/stats")
        with urllib.request.urlopen(req, timeout=5) as resp:
            stats = json.loads(resp.read().decode())
        print()
        print("=" * 64)
        print("  ROE Gate -- Enforcement Summary")
        print("=" * 64)
        print(f"  Total evaluations: {stats.get('total_evaluations', '?')}")
        print(f"  Actions allowed:   {stats.get('total_allows', '?')}")
        print(f"  Actions denied:    {stats.get('total_denials', '?')}")
        print(f"  Sessions halted:   {len(stats.get('halted_sessions', []))}")
        print(f"  ROE Hash:          {roe_hash[:40]}...")
        print("=" * 64)
    except Exception:
        print("  (Could not fetch final stats from Gate Service)")

    # -- Cleanup --
    print("\n  Stopping Gate Service...")
    _cleanup_gate()
    _cleanup_temp()
    print("  Done.")


def cmd_creator(args: argparse.Namespace) -> None:
    """Launch the ROE Creator Dashboard as a standalone server."""
    import http.server
    import webbrowser

    from .service.roe_creator import build_roe_creator_html

    html_bytes = build_roe_creator_html().encode("utf-8")
    port = args.port

    class CreatorHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)

        def log_message(self, fmt, *log_args):
            # Suppress noisy per-request logging
            pass

    server = http.server.HTTPServer(("127.0.0.1", port), CreatorHandler)
    url = f"http://127.0.0.1:{port}"

    print()
    print("=" * 56)
    print("  ROE Gate -- ROE Creator Dashboard")
    print("=" * 56)
    print(f"  URL:  {url}")
    print()
    print("  Build your ROE visually, then download the YAML.")
    print("  Press Ctrl+C to stop.")
    print("=" * 56)
    print()

    if not args.no_open:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


def cmd_info(args: argparse.Namespace) -> None:
    """Print system information and available providers."""
    from . import __version__

    print(f"ROE Agent Gate v{__version__}")
    print(f"Python {sys.version}")
    print()

    # Check available providers
    print("Available LLM Providers:")
    print()

    providers = [
        ("AnthropicProvider", "anthropic", "pip install roe-agent-gate[anthropic]"),
        ("OpenAIProvider", "openai", "pip install roe-agent-gate[openai]"),
        ("ClaudeAgentSDKProvider", "claude_agent_sdk", "pip install roe-agent-gate[claude-agent-sdk]"),
        ("TransformersProvider", "transformers", "pip install roe-agent-gate[transformers]"),
        ("LlamaCppProvider", "llama_cpp", "pip install roe-agent-gate[llama-cpp]"),
    ]

    always_available = ["HybridProvider"]

    for name, module, install in providers:
        try:
            __import__(module)
            print(f"  [installed]      {name}")
        except ImportError:
            print(f"  [not installed]  {name}  ({install})")

    for name in always_available:
        print(f"  [built-in]       {name}")

    print()

    # Check core dependencies
    print("Core Dependencies:")
    print()
    core_deps = [("pyyaml", "yaml"), ("pytest", "pytest")]
    for label, module in core_deps:
        try:
            mod = __import__(module)
            version = getattr(mod, "__version__", "unknown")
            print(f"  [installed]      {label} ({version})")
        except ImportError:
            print(f"  [not installed]  {label}")

    print()


def main() -> None:
    """ROE Agent Gate CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="roe-gate",
        description="ROE Agent Gate -- Out-of-Band Rules of Engagement Enforcement for Agentic Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  roe-gate creator                                    # build a ROE visually\n"
            "  roe-gate pentest --config roe_gate_config.yaml      # launch using config file\n"
            "  roe-gate pentest --roe examples/acme_corp_roe.yaml  # launch with CLI flags\n"
            "  roe-gate pentest --config conf.yaml --dashboard     # config + CLI override\n"
            "  roe-gate validate examples/acme_corp_roe.yaml       # validate a ROE file\n"
            "  roe-gate demo                                       # see enforcement demo\n"
            "  roe-gate info                                       # show installed providers\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- validate ---
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a ROE YAML specification file",
        description="Parse and validate a ROE specification file, checking for required sections and common issues.",
    )
    validate_parser.add_argument(
        "roe_file",
        help="Path to the ROE YAML file to validate",
    )

    # --- demo ---
    subparsers.add_parser(
        "demo",
        help="Run the built-in enforcement demo",
        description=(
            "Run an interactive demo showing ROE Gate enforcement. "
            "Simulates an agent attempting allowed actions, denied actions, "
            "and repeated violations that trigger an automatic halt."
        ),
    )

    # --- pentest ---
    pentest_parser = subparsers.add_parser(
        "pentest",
        help="Launch an ROE-gated pentest session with Claude Code",
        description=(
            "Start a penetration testing session using Claude Code as the agent, "
            "with all pentest tool access gated through the ROE Gate Service. "
            "Direct Bash execution of pentest tools is blocked by PreToolUse hooks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pentest_parser.add_argument(
        "--roe", default=None,
        help="Path to the ROE YAML specification file (required unless provided in --config)",
    )
    pentest_parser.add_argument(
        "--config", default=None, metavar="FILE",
        help="Path to roe_gate_config.yaml — sets all options from a single file (CLI flags override)",
    )
    pentest_parser.add_argument(
        "--judge", default="claude-cli",
        choices=["mock", "anthropic", "openai", "claude-sdk", "claude-cli"],
        help="Judge LLM provider for ROE evaluation (default: claude-cli)",
    )
    pentest_parser.add_argument(
        "--model", default="sonnet",
        help="Claude model for the pentest agent (default: sonnet)",
    )
    pentest_parser.add_argument(
        "--gate-port", type=int, default=19990,
        help="Port for the Gate Service HTTP API (default: 19990)",
    )
    pentest_parser.add_argument(
        "--dashboard", action="store_true",
        help="Open the real-time audit dashboard in a new terminal window",
    )
    pentest_parser.add_argument(
        "--dry-run", action="store_true",
        help="Start Gate Service and print config without launching Claude Code",
    )
    pentest_parser.add_argument(
        "--slack-webhook", default=None, metavar="URL",
        help="Slack incoming webhook URL for real-time alerts",
    )
    pentest_parser.add_argument(
        "--webhook-url", default=None, metavar="URL",
        help="Generic webhook URL for real-time alerts",
    )
    pentest_parser.add_argument(
        "--signing-algo", choices=["hmac", "ed25519"], default="hmac",
        help="Token signing algorithm (default: hmac)",
    )
    pentest_parser.add_argument(
        "--rbac", action="store_true",
        help="Enable role-based access control on the Gate Service",
    )
    pentest_parser.add_argument(
        "--human-in-the-loop", action="store_true",
        help=(
            "Enable human-in-the-loop approval for out-of-scope actions. "
            "When enabled, the dashboard shows APPROVE/DENY buttons and the "
            "agent waits for a human decision. When disabled (default), "
            "out-of-scope actions are denied outright."
        ),
    )

    # --- creator / roe-creator ---
    creator_help = "Launch the ROE Creator Dashboard to build a ROE spec visually"
    creator_desc = (
        "Start a lightweight local server serving the ROE Creator Dashboard. "
        "Build your Rules of Engagement specification through a visual form "
        "interface, then download the YAML file. No existing ROE file required."
    )
    for cmd_name in ("creator", "roe-creator"):
        cp = subparsers.add_parser(cmd_name, help=creator_help, description=creator_desc)
        cp.add_argument(
            "--port", type=int, default=19990,
            help="Port for the ROE Creator server (default: 19990)",
        )
        cp.add_argument(
            "--no-open", action="store_true",
            help="Don't auto-open the browser",
        )

    # --- info ---
    subparsers.add_parser(
        "info",
        help="Print version, available providers, and system info",
        description="Display ROE Agent Gate version, installed LLM providers, and Python environment details.",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    try:
        if args.command == "validate":
            cmd_validate(args)
        elif args.command == "demo":
            cmd_demo(args)
        elif args.command == "pentest":
            cmd_pentest(args)
        elif args.command in ("creator", "roe-creator"):
            cmd_creator(args)
        elif args.command == "info":
            cmd_info(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
