"""
ROE Gate — Out-of-Band Rules of Engagement Enforcement for Agentic Security Testing

A mandatory, out-of-band enforcement architecture that implements the Reference Monitor
pattern for LLM-based autonomous security testing agents.

The agent never directly executes actions. Every action passes through the ROE Gate,
which evaluates it against a formal ROE specification using a dual-evaluation pipeline
(deterministic rules + isolated LLM judge) and cryptographic action signing.
"""

__version__ = "0.1.0"

from .core import (
    ActionIntent, ActionCategory, Target, ImpactAssessment, classify_tool_call,
    RuleEngine, RuleVerdict, RuleEngineResult,
    JudgeLLM, JudgeVerdict, JudgeResult, LLMProvider,
    TransformersProvider, LlamaCppProvider, AnthropicProvider, OpenAIProvider, HybridProvider,
)
from .gate import ROEGate, GateDecision, GateResult
from .crypto import ActionSigner, ActionToken, compute_roe_hash
from .tools import ToolExecutor, ExecutionResult, ToolProxy, ProxiedToolResult, activate_sandbox, create_sandboxed_agent_runtime
from .audit import AuditLogger, AuditEvent

__all__ = [
    # Version
    "__version__",
    # Core
    "ActionIntent", "ActionCategory", "Target", "ImpactAssessment", "classify_tool_call",
    "RuleEngine", "RuleVerdict", "RuleEngineResult",
    "JudgeLLM", "JudgeVerdict", "JudgeResult", "LLMProvider",
    # Providers
    "TransformersProvider", "LlamaCppProvider", "AnthropicProvider", "OpenAIProvider", "HybridProvider",
    # Gate
    "ROEGate", "GateDecision", "GateResult",
    # Crypto
    "ActionSigner", "ActionToken", "compute_roe_hash",
    # Tools
    "ToolExecutor", "ExecutionResult", "ToolProxy", "ProxiedToolResult",
    "activate_sandbox", "create_sandboxed_agent_runtime",
    # Audit
    "AuditLogger", "AuditEvent",
]
