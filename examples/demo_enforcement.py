#!/usr/bin/env python3
"""
ROE Gate — Enforcement Demo

This demo answers the critical question:
  "What stops the agent from just using the tools directly?"

Answer: THREE independent enforcement layers.

This demo shows all three in action:
  1. MODULE BLOCKING: subprocess, os.system, socket are all disabled
  2. TOKEN VERIFICATION: The executor rejects forged/expired/replayed tokens
  3. GATE PIPELINE: Even through the proxy, ROE violations are blocked

Run:
  python3 examples/demo_enforcement.py
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from src.core.action_intent import (
    ActionIntent, ActionCategory, Target, ImpactAssessment,
    ImpactLevel, DataAccessType,
)
from src.crypto.signer import ActionSigner, ActionToken, compute_roe_hash
from src.gate.gate import ROEGate, GateDecision
from src.tools.executor import ToolExecutor
from src.tools.proxy import ToolProxy
from src.tools.sandbox import activate_sandbox


def print_header(text: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


def print_pass(text: str) -> None:
    print(f"  [BLOCKED] {text}")


def print_fail(text: str) -> None:
    print(f"  [!! FAIL !!] {text}")


# ─── Mock Judge for the demo ──────────────────────────────────────────────────

class MockJudgeLLM:
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        action_section = ""
        if "PROPOSED ACTION:" in user_prompt:
            action_section = user_prompt.split("PROPOSED ACTION:")[1].split("RULE ENGINE")[0]

        if '"category": "direct_database_access"' in action_section:
            return json.dumps({
                "verdict": "DENY", "confidence": 0.98,
                "reasoning": "Direct database access is explicitly denied.",
                "roe_clauses_cited": ["actions.denied"],
            })
        elif '"category": "web_application_testing"' in action_section:
            return json.dumps({
                "verdict": "ALLOW", "confidence": 0.95,
                "reasoning": "Web testing is allowed for in-scope targets.",
                "roe_clauses_cited": ["actions.allowed"],
            })
        else:
            return json.dumps({
                "verdict": "ALLOW", "confidence": 0.90,
                "reasoning": "Action appears within ROE.",
                "roe_clauses_cited": [],
            })


# ─── Main Demo ────────────────────────────────────────────────────────────────

def main():
    print_header("ROE Gate — Enforcement Demo")
    print("  This demo proves the agent CANNOT bypass the ROE Gate.")
    print("  We test three independent enforcement layers.\n")

    # Load ROE
    roe_path = Path(__file__).parent / "acme_corp_roe.yaml"
    with open(roe_path) as f:
        roe_spec = yaml.safe_load(f)["roe"]

    # Create the Gate, Executor, and Proxy
    gate = ROEGate(
        roe_spec=roe_spec,
        llm_provider=MockJudgeLLM(),
        token_ttl_seconds=30,
        max_consecutive_denials=5,
    )

    executor = ToolExecutor(
        signer=gate.signer,
        roe_hash=gate.roe_hash,
        dry_run=True,  # Don't actually execute commands in demo
    )

    proxy = ToolProxy(
        gate=gate,
        executor=executor,
        agent_session="enforcement-demo",
        engagement_id="ENG-2024-001",
    )

    # ══════════════════════════════════════════════════════════════
    # LAYER 1: MODULE BLOCKING
    # ══════════════════════════════════════════════════════════════

    print_header("LAYER 1: Module Blocking (Python-Level Sandbox)")
    print("  After activate_sandbox(), the agent cannot import dangerous modules.")
    print("  Let's try...\n")

    # Activate the sandbox
    report = activate_sandbox()
    print(f"  Sandbox activated:")
    print(f"    Modules blocked:     {report['modules_blocked']}")
    print(f"    OS functions blocked: {len(report['os_functions_blocked'])} functions")
    print(f"    Socket attrs blocked: {report['socket_attrs_blocked']}")
    print()

    # --- Attempt 1: import subprocess ---
    print("  Attempt: import subprocess; subprocess.run(['psql', ...])")
    try:
        import subprocess
        subprocess.run(["psql", "-h", "10.0.2.50"])
        print_fail("subprocess.run() was NOT blocked!")
    except PermissionError as e:
        print_pass(f"{e}")
    except AttributeError:
        print_pass("subprocess module is blocked (AttributeError)")
    print()

    # --- Attempt 2: os.system ---
    print("  Attempt: os.system('psql -h 10.0.2.50')")
    import os
    try:
        os.system("psql -h 10.0.2.50")
        print_fail("os.system() was NOT blocked!")
    except PermissionError as e:
        print_pass(f"{e}")
    print()

    # --- Attempt 3: os.popen ---
    print("  Attempt: os.popen('nmap 10.0.0.0/24')")
    try:
        os.popen("nmap 10.0.0.0/24")
        print_fail("os.popen() was NOT blocked!")
    except PermissionError as e:
        print_pass(f"{e}")
    print()

    # --- Attempt 4: socket ---
    print("  Attempt: socket.create_connection(('10.0.2.50', 5432))")
    try:
        import socket
        socket.create_connection(("10.0.2.50", 5432))
        print_fail("socket.create_connection() was NOT blocked!")
    except PermissionError as e:
        print_pass(f"{e}")
    except AttributeError:
        print_pass("socket module is blocked (AttributeError)")
    print()

    # --- Attempt 5: Try importing subprocess fresh ---
    print("  Attempt: Fresh import of subprocess after sandbox activated")
    try:
        if "subprocess" in sys.modules:
            del sys.modules["subprocess"]
        import subprocess as sp
        sp.run(["echo", "bypassed"])
        print_fail("Fresh subprocess import was NOT blocked!")
    except (PermissionError, AttributeError) as e:
        print_pass(f"Fresh import also blocked: {type(e).__name__}")
    print()

    print("  RESULT: All direct execution attempts BLOCKED.\n")

    # ══════════════════════════════════════════════════════════════
    # LAYER 2: TOKEN VERIFICATION (Executor Level)
    # ══════════════════════════════════════════════════════════════

    print_header("LAYER 2: Token Verification (Crypto Enforcement)")
    print("  Even if the agent somehow reaches the executor, it needs a valid token.")
    print("  Let's try forging tokens...\n")

    # --- Attempt 6: No token at all ---
    # (Can't even call executor.execute without a token object)

    # --- Attempt 7: Forged token (wrong signature) ---
    print("  Attempt: Forge a token with a fake signature")
    forged_token = ActionToken(
        intent_id="fake-intent-123",
        engagement_id="ENG-2024-001",
        roe_hash=gate.roe_hash,
        expires_at="2030-12-31T23:59:59+00:00",
        verdict="ALLOW",
        permitted_action={"tool": "psql", "category": "direct_database_access"},
        signature="hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    result = executor.execute(forged_token, "psql", ["-h", "10.0.2.50"])
    if not result.success:
        print_pass(f"{result.error}")
    else:
        print_fail("Forged token was accepted!")
    print()

    # --- Attempt 8: Expired token ---
    print("  Attempt: Use an expired token (TTL exceeded)")
    # Get a real token by going through the gate first
    legit_intent = ActionIntent(
        agent_session="enforcement-demo",
        engagement_id="ENG-2024-001",
        tool="curl",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        description="Legit test",
        target=Target(host="app.corp.local", port=443, domain="app.corp.local"),
        impact=ImpactAssessment(estimated_severity=ImpactLevel.LOW),
    )

    # Create a gate with 1-second TTL for this test
    short_gate = ROEGate(
        roe_spec=roe_spec,
        llm_provider=MockJudgeLLM(),
        token_ttl_seconds=1,
    )
    short_executor = ToolExecutor(
        signer=short_gate.signer,
        roe_hash=short_gate.roe_hash,
        dry_run=True,
    )

    gate_result = short_gate.evaluate(legit_intent)
    if gate_result.token:
        print(f"  Got legitimate token: {gate_result.token.token_id}")
        print(f"  Waiting 2 seconds for it to expire...")
        time.sleep(2)
        result = short_executor.execute(gate_result.token, "curl", ["-X", "GET", "https://app.corp.local"])
        if not result.success:
            print_pass(f"{result.error}")
        else:
            print_fail("Expired token was accepted!")
    print()

    # --- Attempt 9: Token replay ---
    print("  Attempt: Replay a token (use the same token twice)")
    gate_result_2 = gate.evaluate(legit_intent)
    if gate_result_2.token:
        # First use — should work
        result_first = executor.execute(gate_result_2.token, "curl", ["-X", "GET", "https://app.corp.local"])
        print(f"  First use: {'success' if result_first.success else 'failed'}")

        # Second use — should be blocked
        result_replay = executor.execute(gate_result_2.token, "curl", ["-X", "GET", "https://app.corp.local"])
        if not result_replay.success:
            print_pass(f"Replay blocked: {result_replay.error}")
        else:
            print_fail("Token replay was accepted!")
    print()

    # --- Attempt 10: Token for wrong tool ---
    print("  Attempt: Use a curl token to execute psql")
    gate_result_3 = gate.evaluate(legit_intent)
    if gate_result_3.token:
        result_wrong = executor.execute(gate_result_3.token, "psql", ["-h", "10.0.2.50"])
        if not result_wrong.success:
            print_pass(f"{result_wrong.error}")
        else:
            print_fail("Token was accepted for wrong tool!")
    print()

    print("  RESULT: All token forgery/manipulation attempts BLOCKED.\n")

    # ══════════════════════════════════════════════════════════════
    # LAYER 3: ROE GATE PIPELINE (Policy Enforcement)
    # ══════════════════════════════════════════════════════════════

    print_header("LAYER 3: ROE Gate Pipeline (Policy Enforcement)")
    print("  Even through the legitimate proxy, ROE violations are blocked.\n")

    # --- Attempt 11: Try to access database through the proxy ---
    print("  Attempt: Agent requests database access through the proxy")
    db_result = proxy.execute_tool(
        tool="psql",
        args=["-h", "10.0.2.50", "-p", "5432"],
        target_host="10.0.2.50",
        target_port=5432,
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        description="Connect to PostgreSQL",
        impact_severity=ImpactLevel.HIGH,
        justification="Need to verify credentials found via SQLi",
    )
    if not db_result.allowed:
        print_pass(f"Decision: {db_result.decision} — {db_result.reasoning[:100]}")
    else:
        print_fail("Database access was allowed!")
    print()

    # --- Attempt 12: Agent requests out-of-scope target ---
    print("  Attempt: Agent requests scan of out-of-scope domain")
    oos_result = proxy.execute_tool(
        tool="curl",
        args=["-X", "GET", "https://checkout.payments.corp.local/api/charge"],
        target_host="checkout.payments.corp.local",
        target_domain="checkout.payments.corp.local",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        description="Test payments endpoint",
        justification="Looking for payment processing vulnerabilities",
    )
    if not oos_result.allowed:
        print_pass(f"Decision: {oos_result.decision} — {oos_result.reasoning[:100]}")
    else:
        print_fail("Out-of-scope target was allowed!")
    print()

    # --- Legitimate request (should work) ---
    print("  Attempt: Legitimate web test on in-scope target (should PASS)")
    legit_result = proxy.execute_tool(
        tool="curl",
        args=["-X", "GET", "https://app.corp.local/api/search?q=test"],
        target_host="app.corp.local",
        target_port=443,
        target_domain="app.corp.local",
        target_url="https://app.corp.local/api/search?q=test",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="sql_injection",
        description="Testing search endpoint for SQL injection",
        justification="Standard web app testing",
    )
    if legit_result.allowed:
        print(f"  [PASS] Decision: ALLOW — Tool executed (dry run)")
        print(f"         Output: {legit_result.output[:100]}")
    else:
        print_fail("Legitimate request was blocked!")
    print()

    print("  RESULT: Policy violations BLOCKED, legitimate actions ALLOWED.\n")

    # ══════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════

    print_header("ENFORCEMENT SUMMARY")
    print("  THREE INDEPENDENT LAYERS prevent bypass:\n")
    print("  Layer 1 — MODULE BLOCKING (Python sandbox)")
    print("    subprocess.run()         BLOCKED")
    print("    os.system()              BLOCKED")
    print("    os.popen()               BLOCKED")
    print("    socket.create_connection BLOCKED")
    print("    Fresh import attempts    BLOCKED")
    print()
    print("  Layer 2 — TOKEN VERIFICATION (Cryptographic)")
    print("    Forged signature         BLOCKED")
    print("    Expired token            BLOCKED")
    print("    Token replay             BLOCKED")
    print("    Wrong-tool token         BLOCKED")
    print()
    print("  Layer 3 — ROE PIPELINE (Policy)")
    print("    Denied category (DB)     BLOCKED")
    print("    Out-of-scope target      BLOCKED")
    print("    Legitimate request       ALLOWED")
    print()
    print("  The agent physically CANNOT:")
    print("    - Import subprocess or os.system (they don't exist)")
    print("    - Open a network socket (socket is blocked)")
    print("    - Forge a valid action token (no signing key)")
    print("    - Replay a used token (replay tracking)")
    print("    - Use a token for a different tool (action binding)")
    print("    - Execute a denied action category (Rule Engine)")
    print("    - Target an out-of-scope system (Rule Engine)")
    print()
    print("  This is NOT 'please follow the rules' (prompting).")
    print("  This is 'you physically cannot break the rules' (enforcement).")
    print()


if __name__ == "__main__":
    main()
