"""
Tests for src.core.judge — Judge LLM Isolated Semantic Evaluator.
"""

from __future__ import annotations

import json

from src.core.judge import JudgeLLM, JudgeVerdict, JudgeResult, JUDGE_SYSTEM_PROMPT
from tests.helpers import MockLLMProvider


# ---------------------------------------------------------------------------
# JudgeLLM with mock providers
# ---------------------------------------------------------------------------

def test_judge_allow_with_high_confidence(sample_roe_spec):
    provider = MockLLMProvider(verdict="ALLOW", confidence=0.95)
    judge = JudgeLLM(llm_provider=provider, confidence_threshold=0.8)
    result = judge.evaluate(
        roe_spec=sample_roe_spec,
        action_intent={"action": {"tool": "curl", "category": "web_application_testing"}},
        rule_engine_verdict="HARD_ALLOW",
        rule_engine_reasoning="In scope",
    )
    assert result.verdict == JudgeVerdict.ALLOW
    assert result.confidence == 0.95
    assert provider.call_count == 1


def test_judge_deny(sample_roe_spec):
    provider = MockLLMProvider(verdict="DENY", confidence=0.9)
    judge = JudgeLLM(llm_provider=provider, confidence_threshold=0.8)
    result = judge.evaluate(
        roe_spec=sample_roe_spec,
        action_intent={"action": {"tool": "psql", "category": "direct_database_access"}},
        rule_engine_verdict="NEEDS_EVALUATION",
        rule_engine_reasoning="Ambiguous",
    )
    assert result.verdict == JudgeVerdict.DENY
    assert result.confidence == 0.9


def test_judge_escalate(sample_roe_spec):
    provider = MockLLMProvider(verdict="ESCALATE", confidence=0.7)
    judge = JudgeLLM(llm_provider=provider, confidence_threshold=0.8)
    result = judge.evaluate(
        roe_spec=sample_roe_spec,
        action_intent={"action": {"tool": "nmap"}},
        rule_engine_verdict="NEEDS_EVALUATION",
        rule_engine_reasoning="Unclear scope",
    )
    assert result.verdict == JudgeVerdict.ESCALATE


# ---------------------------------------------------------------------------
# Confidence thresholding
# ---------------------------------------------------------------------------

def test_allow_with_low_confidence_becomes_escalate(sample_roe_spec):
    """ALLOW with confidence below threshold should be upgraded to ESCALATE."""
    provider = MockLLMProvider(verdict="ALLOW", confidence=0.7)
    judge = JudgeLLM(
        llm_provider=provider,
        confidence_threshold=0.8,
        auto_escalate_below=0.6,
    )
    result = judge.evaluate(
        roe_spec=sample_roe_spec,
        action_intent={"action": {"tool": "curl"}},
        rule_engine_verdict="HARD_ALLOW",
        rule_engine_reasoning="In scope",
    )
    assert result.verdict == JudgeVerdict.ESCALATE
    assert "insufficient confidence" in result.reasoning.lower()


def test_auto_escalate_below_threshold(sample_roe_spec):
    """ALLOW with very low confidence should trigger auto-escalate."""
    provider = MockLLMProvider(verdict="ALLOW", confidence=0.3)
    judge = JudgeLLM(
        llm_provider=provider,
        confidence_threshold=0.8,
        auto_escalate_below=0.6,
    )
    result = judge.evaluate(
        roe_spec=sample_roe_spec,
        action_intent={"action": {"tool": "curl"}},
        rule_engine_verdict="HARD_ALLOW",
        rule_engine_reasoning="In scope",
    )
    assert result.verdict == JudgeVerdict.ESCALATE
    assert "very low confidence" in result.reasoning.lower() or "auto-escalating" in result.reasoning.lower()


def test_deny_with_low_confidence_stays_deny(sample_roe_spec):
    """DENY with low confidence should stay DENY (threshold only upgrades ALLOW)."""
    provider = MockLLMProvider(verdict="DENY", confidence=0.5)
    judge = JudgeLLM(
        llm_provider=provider,
        confidence_threshold=0.8,
        auto_escalate_below=0.6,
    )
    result = judge.evaluate(
        roe_spec=sample_roe_spec,
        action_intent={"action": {"tool": "curl"}},
        rule_engine_verdict="NEEDS_EVALUATION",
        rule_engine_reasoning="Ambiguous",
    )
    assert result.verdict == JudgeVerdict.DENY


# ---------------------------------------------------------------------------
# _parse_response
# ---------------------------------------------------------------------------

def test_parse_response_valid_json():
    provider = MockLLMProvider()
    judge = JudgeLLM(llm_provider=provider)
    raw = json.dumps({
        "verdict": "ALLOW",
        "confidence": 0.95,
        "reasoning": "Action is within scope.",
        "roe_clauses_cited": ["scope.in_scope.networks[0]"],
    })
    result = judge._parse_response(raw)
    assert result.verdict == JudgeVerdict.ALLOW
    assert result.confidence == 0.95
    assert result.reasoning == "Action is within scope."
    assert "scope.in_scope.networks[0]" in result.roe_clauses_cited


def test_parse_response_markdown_code_block():
    """Judge sometimes wraps JSON in markdown code blocks."""
    provider = MockLLMProvider()
    judge = JudgeLLM(llm_provider=provider)
    raw = """```json
{
  "verdict": "DENY",
  "confidence": 0.85,
  "reasoning": "Target is out of scope.",
  "roe_clauses_cited": ["scope.out_of_scope"]
}
```"""
    result = judge._parse_response(raw)
    assert result.verdict == JudgeVerdict.DENY
    assert result.confidence == 0.85


def test_parse_response_invalid_json_becomes_escalate():
    """Unparseable response should default to ESCALATE."""
    provider = MockLLMProvider()
    judge = JudgeLLM(llm_provider=provider)
    raw = "This is not valid JSON at all."
    result = judge._parse_response(raw)
    assert result.verdict == JudgeVerdict.ESCALATE
    assert result.confidence == 0.0
    assert "failed to parse" in result.reasoning.lower()


# ---------------------------------------------------------------------------
# _build_evaluation_prompt
# ---------------------------------------------------------------------------

def test_build_evaluation_prompt_includes_roe_and_intent(sample_roe_spec):
    provider = MockLLMProvider()
    judge = JudgeLLM(llm_provider=provider)
    intent_dict = {"action": {"tool": "curl", "category": "web_application_testing"}}
    prompt = judge._build_evaluation_prompt(
        roe_spec=sample_roe_spec,
        action_intent=intent_dict,
        rule_engine_verdict="HARD_ALLOW",
        rule_engine_reasoning="In scope and allowed",
    )
    assert "RULES OF ENGAGEMENT SPECIFICATION" in prompt
    assert "PROPOSED ACTION" in prompt
    assert "curl" in prompt
    assert "web_application_testing" in prompt
    assert "HARD_ALLOW" in prompt
    assert "In scope and allowed" in prompt
    # ROE spec should be in the prompt
    assert "ENG-2024-001" in prompt


def test_judge_calls_provider_with_system_prompt(sample_roe_spec):
    provider = MockLLMProvider()
    judge = JudgeLLM(llm_provider=provider)
    judge.evaluate(
        roe_spec=sample_roe_spec,
        action_intent={"action": {"tool": "curl"}},
        rule_engine_verdict="HARD_ALLOW",
        rule_engine_reasoning="OK",
    )
    assert provider.last_system_prompt == JUDGE_SYSTEM_PROMPT
