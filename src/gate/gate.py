"""
ROE Gate — The Orchestrator

This is the main entry point for the ROE Gate system. It orchestrates the full
evaluation pipeline:

1. Receive Action Intent from the agent (via Tool Proxy)
2. Run Deterministic Rule Engine
3. If not HARD_DENY: Run Isolated Judge LLM
4. If approved: Generate signed Action Token
5. Return result to the Tool Proxy

The Gate runs as an independent service/process. The agent communicates with it
over an authenticated API. The agent has no direct access to the Gate's internals,
signing keys, or configuration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from ..core.action_intent import ActionIntent
from ..core.rule_engine import RuleEngine, RuleVerdict, RuleEngineResult
from ..core.judge import JudgeLLM, JudgeVerdict, JudgeResult, LLMProvider
from ..crypto.signer import ActionSigner, ActionToken, compute_roe_hash
from ..audit.logger import AuditLogger, AuditEvent


logger = logging.getLogger("roe_gate")


class GateDecision(str, Enum):
    """Final decision from the Gate."""
    ALLOW = "ALLOW"           # Action approved, token issued
    DENY = "DENY"             # Action blocked
    ESCALATE = "ESCALATE"     # Requires human operator decision
    HALT = "HALT"             # Agent halted due to repeated violations


@dataclass
class GateResult:
    """The complete result of a Gate evaluation."""
    decision: GateDecision
    token: ActionToken | None = None
    rule_engine_result: RuleEngineResult | None = None
    judge_result: JudgeResult | None = None
    reasoning: str = ""
    denial_count: int = 0
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "decision": self.decision.value,
            "reasoning": self.reasoning,
            "denial_count": self.denial_count,
            "evaluated_at": self.evaluated_at,
        }
        if self.token:
            result["token"] = self.token.to_dict()
        if self.rule_engine_result:
            result["rule_engine"] = self.rule_engine_result.to_dict()
        if self.judge_result:
            result["judge"] = self.judge_result.to_dict()
        return result

    def to_agent_response(self) -> dict[str, Any]:
        """Generate a response suitable for sending back to the agent.

        IMPORTANT: This does NOT include internal evaluation details or
        signing keys. The agent only sees the decision and the token (if allowed).
        """
        response: dict[str, Any] = {
            "decision": self.decision.value,
            "reasoning": self.reasoning,
        }
        if self.token:
            response["token"] = self.token.to_dict()
        if self.decision == GateDecision.DENY:
            # Give the agent enough info to understand why, but not enough
            # to craft a bypass
            if self.rule_engine_result:
                response["denied_because"] = [
                    r.description for r in self.rule_engine_result.matched_rules
                ]
        return response


class ROEGate:
    """The ROE Gate — main orchestrator for action evaluation.

    This is the heart of the system. It coordinates the Rule Engine, Judge LLM,
    and Crypto Signer to produce a final decision on every agent action.
    """

    def __init__(
        self,
        roe_spec: dict[str, Any],
        llm_provider: LLMProvider,
        signing_key: bytes | None = None,
        token_ttl_seconds: int = 30,
        judge_confidence_threshold: float = 0.8,
        max_consecutive_denials: int = 3,
        human_approval_callback: Callable[[ActionIntent, str], bool] | None = None,
        alert_manager: Any | None = None,
        signer: ActionSigner | None = None,
        human_in_the_loop: bool = False,
    ) -> None:
        """Initialize the ROE Gate.

        Args:
            roe_spec: The parsed ROE specification (the 'roe' key from YAML).
            llm_provider: LLM backend for the Judge.
            signing_key: HMAC signing key. Auto-generated if not provided.
                Ignored if ``signer`` is provided.
            token_ttl_seconds: Action token TTL.
                Ignored if ``signer`` is provided.
            judge_confidence_threshold: Below this, Judge ALLOW becomes ESCALATE.
            max_consecutive_denials: Halt agent after this many denials.
            human_approval_callback: Called when human approval is needed.
                Receives (intent, reason) and returns True/False.
            alert_manager: Optional AlertManager for Slack/webhook notifications.
            signer: Optional pre-configured signer (HMAC or Ed25519). If provided,
                ``signing_key`` and ``token_ttl_seconds`` are ignored.
            human_in_the_loop: When True, NEEDS_HUMAN verdicts return ESCALATE
                (allowing the API layer to present approval UI). When False
                (default), NEEDS_HUMAN verdicts are treated as DENY.
        """
        self.roe_spec = roe_spec
        self.roe_hash = compute_roe_hash(roe_spec)

        # Initialize components
        self.rule_engine = RuleEngine(roe_spec)
        self.judge = JudgeLLM(
            llm_provider=llm_provider,
            confidence_threshold=judge_confidence_threshold,
        )
        if signer is not None:
            self.signer = signer
        else:
            self.signer = ActionSigner(
                signing_key=signing_key,
                token_ttl_seconds=token_ttl_seconds,
            )
        self.audit = AuditLogger(engagement_id=roe_spec.get("metadata", {}).get("engagement_id", "unknown"))
        self.alert_manager = alert_manager

        self.max_consecutive_denials = max_consecutive_denials
        self.human_approval_callback = human_approval_callback
        self.human_in_the_loop = human_in_the_loop

        # State tracking
        self._consecutive_denials: dict[str, int] = {}  # session -> count
        self._halted_sessions: set[str] = set()
        self._total_evaluations = 0
        self._total_denials = 0
        self._total_allows = 0

        logger.info(
            "ROE Gate initialized | engagement=%s | roe_hash=%s",
            roe_spec.get("metadata", {}).get("engagement_id", "unknown"),
            self.roe_hash,
        )

    def evaluate(self, intent: ActionIntent) -> GateResult:
        """Evaluate an action intent through the full pipeline.

        This is the main entry point. Every agent action goes through here.

        Args:
            intent: The serialized action intent.

        Returns:
            GateResult with the decision and (optionally) a signed token.
        """
        self._total_evaluations += 1
        session = intent.agent_session

        # ── Pre-check: Is this session halted? ────────────────────
        if session in self._halted_sessions:
            result = GateResult(
                decision=GateDecision.HALT,
                reasoning=(
                    f"Session {session} has been halted due to repeated ROE violations. "
                    "Human operator intervention required to resume."
                ),
                denial_count=self._consecutive_denials.get(session, 0),
            )
            self._log_evaluation(intent, result)
            return result

        # ── Stage 1: Deterministic Rule Engine ────────────────────
        re_result = self.rule_engine.evaluate(intent)

        if re_result.verdict == RuleVerdict.HARD_DENY:
            self._total_denials += 1
            self._record_denial(session)
            result = GateResult(
                decision=GateDecision.DENY,
                rule_engine_result=re_result,
                reasoning=re_result.reasoning,
                denial_count=self._consecutive_denials.get(session, 0),
            )
            # Check if we need to halt the agent
            if self._should_halt(session):
                result.decision = GateDecision.HALT
                result.reasoning += (
                    f" | AGENT HALTED: {self._consecutive_denials[session]} "
                    f"consecutive denials (threshold: {self.max_consecutive_denials})"
                )
                self._halted_sessions.add(session)
            self._log_evaluation(intent, result)
            return result

        if re_result.verdict == RuleVerdict.NEEDS_HUMAN:
            return self._handle_human_approval(intent, re_result)

        # ── Stage 2: Judge LLM (Isolated Semantic Evaluation) ────
        judge_result = self.judge.evaluate(
            roe_spec=self.roe_spec,
            action_intent=intent.to_dict(),
            rule_engine_verdict=re_result.verdict.value,
            rule_engine_reasoning=re_result.reasoning,
        )

        if judge_result.verdict == JudgeVerdict.DENY:
            self._total_denials += 1
            self._record_denial(session)
            result = GateResult(
                decision=GateDecision.DENY,
                rule_engine_result=re_result,
                judge_result=judge_result,
                reasoning=f"Judge LLM denied: {judge_result.reasoning}",
                denial_count=self._consecutive_denials.get(session, 0),
            )
            if self._should_halt(session):
                result.decision = GateDecision.HALT
                result.reasoning += " | AGENT HALTED: repeated violations"
                self._halted_sessions.add(session)
            self._log_evaluation(intent, result)
            return result

        if judge_result.verdict == JudgeVerdict.ESCALATE:
            return self._handle_human_approval(
                intent, re_result, judge_result
            )

        # ── Stage 3: Approved — Generate Signed Token ─────────────
        self._total_allows += 1
        self._reset_denial_count(session)

        token = self.signer.sign_action(
            intent_id=intent.intent_id,
            engagement_id=intent.engagement_id,
            roe_hash=self.roe_hash,
            rule_engine_result=re_result.verdict.value,
            judge_result=judge_result.to_dict(),
            permitted_action={
                "tool": intent.tool,
                "category": intent.category.value,
                "target": intent.target.to_dict(),
                "parameters": intent.parameters,
            },
            constraints=self._extract_constraints(intent),
        )

        result = GateResult(
            decision=GateDecision.ALLOW,
            token=token,
            rule_engine_result=re_result,
            judge_result=judge_result,
            reasoning="Action approved by Rule Engine and Judge LLM",
            denial_count=0,
        )
        self._log_evaluation(intent, result)
        return result

    def verify_token(self, token: ActionToken) -> tuple[bool, str]:
        """Verify an action token before execution.

        Called by the Tool Executor to verify that a token is valid
        before executing the authorized action.
        """
        return self.signer.verify_token(token, self.roe_hash)

    def emergency_halt(self) -> None:
        """Activate emergency halt — stops ALL agent activity immediately."""
        self.signer.emergency_halt()
        logger.critical("EMERGENCY HALT activated — all agent activity stopped")
        self.audit.log(AuditEvent(
            event_type="emergency_halt",
            details={"triggered_by": "operator"},
        ))

        # Send critical alert
        if self.alert_manager is not None:
            from ..service.alerting import AlertLevel, AlertEvent as _AlertEvent
            self.alert_manager.alert(_AlertEvent(
                level=AlertLevel.CRITICAL,
                event_type="emergency_halt",
                summary="EMERGENCY HALT activated — all agent activity stopped",
                details={"triggered_by": "operator"},
            ))

    def resume_session(self, session: str) -> None:
        """Resume a halted session. Requires operator action."""
        self._halted_sessions.discard(session)
        self._consecutive_denials.pop(session, None)
        logger.info("Session %s resumed by operator", session)

    def get_stats(self) -> dict[str, Any]:
        """Get Gate statistics."""
        return {
            "total_evaluations": self._total_evaluations,
            "total_allows": self._total_allows,
            "total_denials": self._total_denials,
            "halted_sessions": list(self._halted_sessions),
            "roe_hash": self.roe_hash,
        }

    # ─── Private Methods ──────────────────────────────────────────────────

    def _handle_human_approval(
        self,
        intent: ActionIntent,
        re_result: RuleEngineResult,
        judge_result: JudgeResult | None = None,
    ) -> GateResult:
        """Handle actions that require human operator approval."""
        reason = re_result.reasoning
        if judge_result:
            reason += f" | Judge: {judge_result.reasoning}"

        if self.human_approval_callback:
            approved = self.human_approval_callback(intent, reason)
            if approved:
                self._total_allows += 1
                self._reset_denial_count(intent.agent_session)
                token = self.signer.sign_action(
                    intent_id=intent.intent_id,
                    engagement_id=intent.engagement_id,
                    roe_hash=self.roe_hash,
                    rule_engine_result=re_result.verdict.value,
                    judge_result=judge_result.to_dict() if judge_result else {},
                    permitted_action={
                        "tool": intent.tool,
                        "category": intent.category.value,
                        "target": intent.target.to_dict(),
                        "parameters": intent.parameters,
                    },
                    constraints=self._extract_constraints(intent),
                )
                result = GateResult(
                    decision=GateDecision.ALLOW,
                    token=token,
                    rule_engine_result=re_result,
                    judge_result=judge_result,
                    reasoning="Action approved by human operator",
                )
                self._log_evaluation(intent, result)
                return result

        # No callback or human denied
        self._total_denials += 1

        if self.human_in_the_loop:
            # HITL ON: Return ESCALATE so the API layer can create a
            # PendingApproval and present APPROVE/DENY UI to the operator.
            result = GateResult(
                decision=GateDecision.ESCALATE,
                rule_engine_result=re_result,
                judge_result=judge_result,
                reasoning=f"Action requires human approval: {reason}",
            )
            self._log_evaluation(intent, result)
            return result

        # HITL OFF (default): Treat as a hard denial. Out-of-scope or
        # otherwise unapproved actions are simply blocked.
        session = intent.agent_session
        self._record_denial(session)
        result = GateResult(
            decision=GateDecision.DENY,
            rule_engine_result=re_result,
            judge_result=judge_result,
            reasoning=f"Action denied (requires human approval, HITL disabled): {reason}",
            denial_count=self._consecutive_denials.get(session, 0),
        )
        if self._should_halt(session):
            result.decision = GateDecision.HALT
            result.reasoning += (
                f" | AGENT HALTED: {self._consecutive_denials[session]} "
                f"consecutive denials (threshold: {self.max_consecutive_denials})"
            )
            self._halted_sessions.add(session)
        self._log_evaluation(intent, result)
        return result

    def _record_denial(self, session: str) -> None:
        """Record a denial for consecutive-denial tracking."""
        self._consecutive_denials[session] = (
            self._consecutive_denials.get(session, 0) + 1
        )

    def _reset_denial_count(self, session: str) -> None:
        """Reset denial count after a successful action."""
        self._consecutive_denials.pop(session, None)

    def _should_halt(self, session: str) -> bool:
        """Check if the agent should be halted due to repeated denials."""
        count = self._consecutive_denials.get(session, 0)
        return count >= self.max_consecutive_denials

    def _extract_constraints(self, intent: ActionIntent) -> dict[str, Any]:
        """Extract execution constraints from the ROE for this action."""
        constraints: dict[str, Any] = {}
        for allowed in self.roe_spec.get("actions", {}).get("allowed", []):
            if allowed.get("category") == intent.category.value:
                if "constraints" in allowed:
                    constraints.update(allowed["constraints"])
        # Add global constraints
        global_constraints = self.roe_spec.get("constraints", {})
        if global_constraints:
            constraints["global"] = global_constraints
        return constraints

    def _log_evaluation(self, intent: ActionIntent, result: GateResult) -> None:
        """Log the evaluation to the audit trail and dispatch alerts."""
        self.audit.log(AuditEvent(
            event_type="action_evaluation",
            details={
                "intent": intent.to_dict(),
                "decision": result.decision.value,
                "reasoning": result.reasoning,
                "rule_engine": result.rule_engine_result.to_dict() if result.rule_engine_result else None,
                "judge": result.judge_result.to_dict() if result.judge_result else None,
                "token_issued": result.token is not None,
                "denial_count": result.denial_count,
            },
        ))

        # Dispatch alert to Slack/webhooks if configured
        if self.alert_manager is not None:
            from ..service.alerting import gate_result_to_alert
            self.alert_manager.alert(gate_result_to_alert(intent, result))
