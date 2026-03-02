"""
Shared test helpers for the ROE Agent Gate test suite.

This module exists so that test files can import MockLLMProvider directly,
since pytest's conftest.py cannot be imported as a regular module.
"""

from __future__ import annotations

import json
from typing import Any


class MockLLMProvider:
    """A configurable mock LLM provider for testing.

    Returns a pre-configured JSON response that the Judge will parse.
    """

    def __init__(
        self,
        verdict: str = "ALLOW",
        confidence: float = 0.9,
        reasoning: str = "Mock evaluation: action complies with ROE.",
        roe_clauses_cited: list[str] | None = None,
    ) -> None:
        self.verdict = verdict
        self.confidence = confidence
        self.reasoning = reasoning
        self.roe_clauses_cited = roe_clauses_cited or ["scope.in_scope"]
        self.call_count = 0
        self.last_system_prompt: str = ""
        self.last_user_prompt: str = ""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.call_count += 1
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        return json.dumps({
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "roe_clauses_cited": self.roe_clauses_cited,
        })
