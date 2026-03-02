#!/usr/bin/env python3
"""
ROE Gate — Local Judge Demo (HuggingFace Transformers)

This demo runs the ROE Gate with a LOCAL model loaded directly from
HuggingFace using the transformers library. No external servers, no
cloud APIs — the model weights run on your hardware.

Prerequisites:
  pip install transformers torch pyyaml

For 4-bit quantization (recommended for 7B models on limited RAM):
  pip install bitsandbytes    # Linux/CUDA only
  # On Mac (MPS), use float16 instead — no bitsandbytes needed

Usage:
  # Default: Qwen 2.5 7B Instruct (best quality, needs ~16GB RAM or 4-bit quant)
  python3 examples/demo_local_judge.py

  # Smaller model for limited hardware (needs ~8GB RAM)
  python3 examples/demo_local_judge.py --model Qwen/Qwen2.5-3B-Instruct

  # Smallest viable option (needs ~4GB RAM)
  python3 examples/demo_local_judge.py --model meta-llama/Llama-3.2-3B-Instruct

  # With 4-bit quantization (Linux/CUDA, halves memory)
  python3 examples/demo_local_judge.py --model Qwen/Qwen2.5-7B-Instruct --4bit

  # Force CPU
  python3 examples/demo_local_judge.py --device cpu
"""

import argparse
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
from src.gate.gate import ROEGate, GateDecision


def print_header(text: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


def print_result(result, elapsed: float | None = None) -> None:
    markers = {
        "ALLOW": "[PASS]",
        "DENY": "[BLOCKED]",
        "ESCALATE": "[ESCALATE]",
        "HALT": "[!! HALT !!]",
    }
    marker = markers.get(result.decision.value, "???")
    print(f"  Decision: {marker} {result.decision.value}")
    print(f"  Reasoning: {result.reasoning[:200]}")
    if elapsed is not None:
        print(f"  Eval Time: {elapsed:.1f}s")
    if result.token:
        print(f"  Token ID: {result.token.token_id}")
    if result.judge_result:
        print(f"  Judge Confidence: {result.judge_result.confidence:.2f}")
    if result.denial_count > 0:
        print(f"  Consecutive Denials: {result.denial_count}")
    print()


def main():
    parser = argparse.ArgumentParser(description="ROE Gate Local Judge Demo")
    parser.add_argument(
        "--model", default="Qwen/Qwen2.5-3B-Instruct",
        help="HuggingFace model ID or local path (default: Qwen/Qwen2.5-3B-Instruct)"
    )
    parser.add_argument(
        "--device", default=None,
        help="Device: cpu, cuda, mps, or auto-detect (default: auto)"
    )
    parser.add_argument(
        "--4bit", dest="load_4bit", action="store_true",
        help="Use 4-bit quantization via bitsandbytes (Linux/CUDA only)"
    )
    parser.add_argument(
        "--8bit", dest="load_8bit", action="store_true",
        help="Use 8-bit quantization via bitsandbytes (Linux/CUDA only)"
    )
    args = parser.parse_args()

    print_header("ROE Gate — Local Judge Demo (HuggingFace Transformers)")
    print(f"  Model: {args.model}")
    print(f"  Device: {args.device or 'auto-detect'}")
    print(f"  4-bit quantization: {args.load_4bit}")
    print()

    # ── Load the model ────────────────────────────────────────────
    print("  Loading model (this may take a minute on first run)...")
    load_start = time.time()

    from src.core.providers import TransformersProvider
    provider = TransformersProvider(
        model_id=args.model,
        device=args.device,
        load_in_4bit=args.load_4bit,
        load_in_8bit=args.load_8bit,
        temperature=0.1,
        max_new_tokens=512,
    )

    load_time = time.time() - load_start
    print(f"  Model loaded in {load_time:.1f}s")
    print()

    # ── Load ROE spec ─────────────────────────────────────────────
    roe_path = Path(__file__).parent / "acme_corp_roe.yaml"
    with open(roe_path) as f:
        roe_spec = yaml.safe_load(f)["roe"]

    gate = ROEGate(
        roe_spec=roe_spec,
        llm_provider=provider,
        token_ttl_seconds=30,
        judge_confidence_threshold=0.7,
        max_consecutive_denials=3,
    )
    print(f"  ROE loaded: {roe_spec['metadata']['engagement_id']}")

    # ── Scenario 1: Legitimate test (needs Judge) ────────────────
    print_header("Scenario 1: SQL Injection Test — In Scope (Judge Evaluates)")
    print("  This is in scope + allowed category, so the Rule Engine says HARD_ALLOW.")
    print("  The Judge then does semantic validation.")
    print("  Waiting for local model...")

    intent_1 = ActionIntent(
        agent_session="session-001",
        engagement_id="ENG-2024-001",
        tool="curl",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        subcategory="sql_injection",
        description="Testing for SQL injection in user search endpoint",
        target=Target(
            host="app.acme.com", port=443, protocol="https",
            domain="app.acme.com",
        ),
        parameters={"method": "GET", "payload": "' OR '1'='1"},
        impact=ImpactAssessment(
            data_access=DataAccessType.READ,
            estimated_severity=ImpactLevel.MEDIUM,
        ),
    )

    t0 = time.time()
    result_1 = gate.evaluate(intent_1)
    print_result(result_1, time.time() - t0)

    # ── Scenario 2: DB access (Rule Engine catches — NO Judge call)
    print_header("Scenario 2: Direct DB Access — BLOCKED by Rule Engine")
    print("  Rule Engine catches this instantly. Judge is NEVER called.")

    intent_2 = ActionIntent(
        agent_session="session-001",
        engagement_id="ENG-2024-001",
        tool="psql",
        category=ActionCategory.DIRECT_DATABASE_ACCESS,
        description="Connect to PostgreSQL with discovered credentials",
        target=Target(
            host="10.0.2.50", port=5432, protocol="tcp",
            service="postgresql",
        ),
        impact=ImpactAssessment(estimated_severity=ImpactLevel.HIGH),
    )

    t0 = time.time()
    result_2 = gate.evaluate(intent_2)
    print_result(result_2, time.time() - t0)

    # ── Scenario 3: Out-of-scope domain (Rule Engine catches) ────
    print_header("Scenario 3: Out-of-Scope Domain — BLOCKED by Rule Engine")

    intent_3 = ActionIntent(
        agent_session="session-002",
        engagement_id="ENG-2024-001",
        tool="curl",
        category=ActionCategory.WEB_APPLICATION_TESTING,
        description="Testing payments endpoint",
        target=Target(
            host="checkout.payments.acme.com", port=443,
            domain="checkout.payments.acme.com",
        ),
    )

    t0 = time.time()
    result_3 = gate.evaluate(intent_3)
    print_result(result_3, time.time() - t0)

    # ── Scenario 4: Recon scan (needs Judge) ─────────────────────
    print_header("Scenario 4: Port Scan — In Scope (Judge Evaluates)")
    print("  Waiting for local model...")

    intent_4 = ActionIntent(
        agent_session="session-002",
        engagement_id="ENG-2024-001",
        tool="nmap",
        category=ActionCategory.RECONNAISSANCE,
        subcategory="port_scan",
        description="TCP connect scan of web application subnet",
        target=Target(host="10.0.0.1", protocol="tcp"),
        parameters={"scan_type": "tcp_connect", "ports": "80,443,8080"},
        impact=ImpactAssessment(estimated_severity=ImpactLevel.LOW),
    )

    t0 = time.time()
    result_4 = gate.evaluate(intent_4)
    print_result(result_4, time.time() - t0)

    # ── Summary ──────────────────────────────────────────────────
    print_header("Summary")
    stats = gate.get_stats()
    print(f"  Total Evaluations: {stats['total_evaluations']}")
    print(f"  Allowed:           {stats['total_allows']}")
    print(f"  Denied:            {stats['total_denials']}")
    print(f"  Model:             {args.model}")
    print()
    print("  The Rule Engine handled the obvious violations WITHOUT any LLM call.")
    print("  The local model was only needed for the ambiguous cases (2 of 4).")
    print("  Zero cloud dependencies. Zero API costs. Fully on-device.")
    print()


if __name__ == "__main__":
    main()
