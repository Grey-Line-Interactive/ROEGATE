"""
Deterministic Rule Engine

The first evaluation layer in the ROE Gate. This engine performs purely deterministic,
binary checks against the ROE specification. No LLM, no probability, no reasoning.

Same input = same output, every time.

If the ROE says port 5432 is denied, connecting to port 5432 is HARD_DENY. Period.
"""

from __future__ import annotations

import ipaddress
import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .action_intent import ActionIntent, ActionCategory, DataAccessType


class RuleVerdict(str, Enum):
    """The four possible outcomes of the deterministic rule engine."""
    HARD_DENY = "HARD_DENY"       # Unambiguous violation. Blocked. No appeal.
    HARD_ALLOW = "HARD_ALLOW"     # Clearly within scope and permitted. Still goes to Judge.
    NEEDS_EVALUATION = "NEEDS_EVALUATION"  # Ambiguous. Requires Judge LLM.
    NEEDS_HUMAN = "NEEDS_HUMAN"   # Matches a requires_approval condition.


@dataclass
class MatchedRule:
    """A record of which ROE rule matched and why."""
    rule_type: str          # "scope", "action_denied", "action_allowed", "schedule", etc.
    rule_path: str          # Path in the ROE spec (e.g., "scope.out_of_scope.networks[0]")
    description: str        # Human-readable explanation
    matched_value: str      # What was matched (e.g., "10.0.2.50 in 10.0.2.0/24")


@dataclass
class RuleEngineResult:
    """The output of the deterministic rule engine."""
    verdict: RuleVerdict
    matched_rules: list[MatchedRule] = field(default_factory=list)
    reasoning: str = ""
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "matched_rules": [
                {
                    "rule_type": r.rule_type,
                    "rule_path": r.rule_path,
                    "description": r.description,
                    "matched_value": r.matched_value,
                }
                for r in self.matched_rules
            ],
            "reasoning": self.reasoning,
            "checked_at": self.checked_at,
        }


class RuleEngine:
    """Deterministic ROE rule evaluation engine.

    This engine takes a parsed ROE specification and evaluates ActionIntents
    against it using purely deterministic logic. No machine learning, no
    probability, no ambiguity.
    """

    def __init__(self, roe_spec: dict[str, Any]) -> None:
        """Initialize with a parsed ROE specification.

        Args:
            roe_spec: The parsed ROE-SL document (the 'roe' key from the YAML).
        """
        self.spec = roe_spec
        self._parse_scope()
        self._parse_actions()
        self._parse_schedule()
        self._parse_constraints()

    def _parse_scope(self) -> None:
        """Pre-parse scope definitions into efficient lookup structures."""
        scope = self.spec.get("scope", {})

        # Parse in-scope networks
        self.in_scope_networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, list[int] | None]] = []
        for net in scope.get("in_scope", {}).get("networks", []):
            network = ipaddress.ip_network(net["cidr"], strict=False)
            ports = net.get("ports")
            self.in_scope_networks.append((network, ports))

        # Parse out-of-scope networks
        self.out_of_scope_networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        for net in scope.get("out_of_scope", {}).get("networks", []):
            network = ipaddress.ip_network(net["cidr"], strict=False)
            reason = net.get("reason", "Out of scope")
            self.out_of_scope_networks.append((network, reason))

        # Parse in-scope domains
        self.in_scope_domains: list[dict[str, Any]] = scope.get("in_scope", {}).get("domains", [])

        # Parse out-of-scope domains
        self.out_of_scope_domains: list[dict[str, Any]] = scope.get("out_of_scope", {}).get("domains", [])

        # Parse out-of-scope services
        self.out_of_scope_services: list[dict[str, Any]] = scope.get("out_of_scope", {}).get("services", [])

    def _parse_actions(self) -> None:
        """Pre-parse action rules."""
        actions = self.spec.get("actions", {})
        self.allowed_actions: list[dict[str, Any]] = actions.get("allowed", [])
        self.denied_actions: list[dict[str, Any]] = actions.get("denied", [])
        self.approval_actions: list[dict[str, Any]] = actions.get("requires_approval", [])

    @staticmethod
    def _parse_iso_datetime(s: str) -> datetime:
        """Parse ISO 8601 datetime string, handling 'Z' suffix and naive datetimes."""
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _parse_schedule(self) -> None:
        """Pre-parse schedule constraints."""
        schedule = self.spec.get("schedule", {})
        self.valid_from = (
            self._parse_iso_datetime(schedule["valid_from"])
            if "valid_from" in schedule else None
        )
        self.valid_until = (
            self._parse_iso_datetime(schedule["valid_until"])
            if "valid_until" in schedule else None
        )
        self.allowed_hours = schedule.get("allowed_hours")
        self.timezone_str = schedule.get("timezone", "UTC")
        self.blackout_dates = schedule.get("blackout_dates", [])

    def _parse_constraints(self) -> None:
        """Pre-parse global constraints from the ROE spec."""
        constraints = self.spec.get("constraints", {})
        self.no_persistent_changes: bool = bool(constraints.get("no_persistent_changes", False))
        self.no_production_data_storage: bool = bool(constraints.get("no_production_data_storage", False))

    def evaluate(self, intent: ActionIntent) -> RuleEngineResult:
        """Evaluate an ActionIntent against the ROE specification.

        This is the main entry point. It runs all checks in order of severity.

        Args:
            intent: The serialized action intent to evaluate.

        Returns:
            RuleEngineResult with the verdict and matched rules.
        """
        matched_rules: list[MatchedRule] = []

        # ── Check 1: Schedule ──────────────────────────────────────
        schedule_result = self._check_schedule()
        if schedule_result:
            return RuleEngineResult(
                verdict=RuleVerdict.HARD_DENY,
                matched_rules=[schedule_result],
                reasoning=f"Action denied: {schedule_result.description}",
            )

        # ── Check 2: Out-of-scope target (network) ────────────────
        oos_network = self._check_out_of_scope_network(intent)
        if oos_network:
            matched_rules.append(oos_network)

        # ── Check 3: Out-of-scope target (domain) ─────────────────
        oos_domain = self._check_out_of_scope_domain(intent)
        if oos_domain:
            matched_rules.append(oos_domain)

        # ── Check 4: Out-of-scope service ─────────────────────────
        oos_service = self._check_out_of_scope_service(intent)
        if oos_service:
            matched_rules.append(oos_service)

        # ── Check 5: Denied action category ───────────────────────
        denied_action = self._check_denied_actions(intent)
        if denied_action:
            matched_rules.append(denied_action)

        # If ANY out-of-scope or denied rule matched, HARD_DENY
        if matched_rules:
            reasons = "; ".join(r.description for r in matched_rules)
            return RuleEngineResult(
                verdict=RuleVerdict.HARD_DENY,
                matched_rules=matched_rules,
                reasoning=f"Action denied: {reasons}",
            )

        # ── Check 6: Requires human approval ──────────────────────
        approval_match = self._check_requires_approval(intent)
        if approval_match:
            return RuleEngineResult(
                verdict=RuleVerdict.NEEDS_HUMAN,
                matched_rules=[approval_match],
                reasoning=f"Action requires human approval: {approval_match.description}",
            )

        # ── Check 7: Constraints ──────────────────────────────────
        constraint_violation = self._check_constraints(intent)
        if constraint_violation:
            return RuleEngineResult(
                verdict=RuleVerdict.HARD_DENY,
                matched_rules=[constraint_violation],
                reasoning=f"Action denied: {constraint_violation.description}",
            )

        # ── Check 8: In-scope and allowed ─────────────────────────
        in_scope = self._check_in_scope(intent)
        allowed = self._check_allowed_actions(intent)

        if in_scope and allowed:
            rules = [r for r in [in_scope, allowed] if r]
            return RuleEngineResult(
                verdict=RuleVerdict.HARD_ALLOW,
                matched_rules=rules,
                reasoning="Action is within scope and matches an allowed category",
            )

        # ── Default: Needs semantic evaluation ────────────────────
        return RuleEngineResult(
            verdict=RuleVerdict.NEEDS_EVALUATION,
            matched_rules=[],
            reasoning="Action is not clearly denied or allowed; requires semantic evaluation",
        )

    # ─── Individual Check Methods ─────────────────────────────────────────

    def _check_schedule(self) -> MatchedRule | None:
        """Check if current time is within the allowed testing window."""
        now = datetime.now(timezone.utc)

        if self.valid_from and now < self.valid_from:
            return MatchedRule(
                rule_type="schedule",
                rule_path="schedule.valid_from",
                description=f"Engagement has not started yet (starts {self.valid_from})",
                matched_value=now.isoformat(),
            )

        if self.valid_until and now > self.valid_until:
            return MatchedRule(
                rule_type="schedule",
                rule_path="schedule.valid_until",
                description=f"Engagement has ended (ended {self.valid_until})",
                matched_value=now.isoformat(),
            )

        # Check blackout dates
        today_str = now.strftime("%Y-%m-%d")
        if today_str in self.blackout_dates:
            return MatchedRule(
                rule_type="schedule",
                rule_path="schedule.blackout_dates",
                description=f"Today ({today_str}) is a blackout date",
                matched_value=today_str,
            )

        # Check allowed hours
        if self.allowed_hours:
            match = re.match(r"(\d{2}:\d{2})-(\d{2}:\d{2})", self.allowed_hours)
            if match:
                start_str, end_str = match.groups()
                start_h, start_m = map(int, start_str.split(":"))
                end_h, end_m = map(int, end_str.split(":"))
                current_minutes = now.hour * 60 + now.minute
                start_minutes = start_h * 60 + start_m
                end_minutes = end_h * 60 + end_m
                if current_minutes < start_minutes or current_minutes > end_minutes:
                    return MatchedRule(
                        rule_type="schedule",
                        rule_path="schedule.allowed_hours",
                        description=f"Current time outside allowed hours ({self.allowed_hours})",
                        matched_value=now.strftime("%H:%M"),
                    )

        return None

    def _check_out_of_scope_network(self, intent: ActionIntent) -> MatchedRule | None:
        """Check if the target IP is in an out-of-scope network."""
        host = intent.target.host
        if not host:
            return None

        try:
            target_ip = ipaddress.ip_address(host)
        except ValueError:
            return None  # Not an IP address (might be a domain)

        for i, (network, reason) in enumerate(self.out_of_scope_networks):
            if target_ip in network:
                return MatchedRule(
                    rule_type="scope_out_of_scope",
                    rule_path=f"scope.out_of_scope.networks[{i}]",
                    description=f"Target {host} is in out-of-scope network {network}: {reason}",
                    matched_value=f"{host} in {network}",
                )

        return None

    def _check_out_of_scope_domain(self, intent: ActionIntent) -> MatchedRule | None:
        """Check if the target domain matches an out-of-scope pattern."""
        domain = intent.target.domain or intent.target.host
        if not domain:
            return None

        # Skip if it looks like an IP address
        try:
            ipaddress.ip_address(domain)
            return None
        except ValueError:
            pass

        for i, oos_domain in enumerate(self.out_of_scope_domains):
            pattern = oos_domain.get("pattern", "")
            reason = oos_domain.get("reason", "Out of scope")

            if self._domain_matches(domain, pattern):
                return MatchedRule(
                    rule_type="scope_out_of_scope",
                    rule_path=f"scope.out_of_scope.domains[{i}]",
                    description=f"Target domain {domain} matches out-of-scope pattern {pattern}: {reason}",
                    matched_value=f"{domain} matches {pattern}",
                )

        return None

    def _check_out_of_scope_service(self, intent: ActionIntent) -> MatchedRule | None:
        """Check if the action targets an out-of-scope service type."""
        for i, service in enumerate(self.out_of_scope_services):
            service_type = service.get("type", "")
            protocols = service.get("protocols", [])
            reason = service.get("reason", "Out of scope")

            # Check by service type
            if service_type and intent.target.service and intent.target.service.lower() in [
                s.lower() for s in ([service_type] if isinstance(service_type, str) else service_type)
            ]:
                return MatchedRule(
                    rule_type="scope_out_of_scope",
                    rule_path=f"scope.out_of_scope.services[{i}]",
                    description=f"Service type {intent.target.service} is out of scope: {reason}",
                    matched_value=f"service:{intent.target.service}",
                )

            # Check by protocol
            if protocols and intent.target.protocol:
                if intent.target.protocol.lower() in [p.lower() for p in protocols]:
                    return MatchedRule(
                        rule_type="scope_out_of_scope",
                        rule_path=f"scope.out_of_scope.services[{i}]",
                        description=f"Protocol {intent.target.protocol} is out of scope: {reason}",
                        matched_value=f"protocol:{intent.target.protocol}",
                    )

            # Check by protocol matching target service
            if protocols and intent.target.service:
                if intent.target.service.lower() in [p.lower() for p in protocols]:
                    return MatchedRule(
                        rule_type="scope_out_of_scope",
                        rule_path=f"scope.out_of_scope.services[{i}]",
                        description=f"Service {intent.target.service} matches out-of-scope protocol: {reason}",
                        matched_value=f"service-as-protocol:{intent.target.service}",
                    )

        return None

    def _check_denied_actions(self, intent: ActionIntent) -> MatchedRule | None:
        """Check if the action category is explicitly denied."""
        for i, denied in enumerate(self.denied_actions):
            category = denied.get("category", "")
            reason = denied.get("reason", "Denied")
            match_rules = denied.get("match", {})

            # Check category match
            category_matches = (
                category == intent.category.value
                or category == "any"
            )

            if not category_matches:
                continue

            # If there are additional match criteria, check them too
            if match_rules:
                if self._check_match_criteria(intent, match_rules):
                    return MatchedRule(
                        rule_type="action_denied",
                        rule_path=f"actions.denied[{i}]",
                        description=f"Action category '{intent.category.value}' is denied: {reason}",
                        matched_value=f"category:{intent.category.value}",
                    )
            else:
                # Category match alone is sufficient
                return MatchedRule(
                    rule_type="action_denied",
                    rule_path=f"actions.denied[{i}]",
                    description=f"Action category '{intent.category.value}' is denied: {reason}",
                    matched_value=f"category:{intent.category.value}",
                )

        return None

    def _check_requires_approval(self, intent: ActionIntent) -> MatchedRule | None:
        """Check if the action requires human approval."""
        for i, rule in enumerate(self.approval_actions):
            category = rule.get("category", "")
            condition = rule.get("condition", "")

            # Category match
            if category != "any" and category != intent.category.value:
                continue

            # Evaluate condition (simple expression evaluation)
            if self._evaluate_condition(intent, condition):
                return MatchedRule(
                    rule_type="requires_approval",
                    rule_path=f"actions.requires_approval[{i}]",
                    description=f"Action requires human approval: {condition}",
                    matched_value=f"condition:{condition}",
                )

        return None

    def _check_constraints(self, intent: ActionIntent) -> MatchedRule | None:
        """Check global constraints from the ROE spec."""
        # no_persistent_changes: block irreversible or write/delete actions
        if self.no_persistent_changes:
            if intent.impact.reversibility == "none":
                return MatchedRule(
                    rule_type="constraint",
                    rule_path="constraints.no_persistent_changes",
                    description="Action denied: no persistent changes allowed and action is irreversible",
                    matched_value=f"reversibility:{intent.impact.reversibility}",
                )
            if intent.impact.data_access in (DataAccessType.WRITE, DataAccessType.DELETE):
                return MatchedRule(
                    rule_type="constraint",
                    rule_path="constraints.no_persistent_changes",
                    description=f"Action denied: no persistent changes allowed and action has {intent.impact.data_access.value} access",
                    matched_value=f"data_access:{intent.impact.data_access.value}",
                )

        # no_production_data_storage: block data exfiltration
        if self.no_production_data_storage:
            if intent.category == ActionCategory.DATA_EXFILTRATION:
                return MatchedRule(
                    rule_type="constraint",
                    rule_path="constraints.no_production_data_storage",
                    description="Action denied: no production data storage allowed and action is data exfiltration",
                    matched_value=f"category:{intent.category.value}",
                )

        return None

    def _check_in_scope(self, intent: ActionIntent) -> MatchedRule | None:
        """Check if the target is explicitly in scope."""
        host = intent.target.host
        if not host:
            return None

        # Check IP-based scope
        try:
            target_ip = ipaddress.ip_address(host)
            for i, (network, ports) in enumerate(self.in_scope_networks):
                if target_ip in network:
                    # If ports are specified in ROE and intent has a port, verify port
                    if ports and intent.target.port:
                        if intent.target.port in ports:
                            return MatchedRule(
                                rule_type="scope_in_scope",
                                rule_path=f"scope.in_scope.networks[{i}]",
                                description=f"Target {host}:{intent.target.port} is in scope",
                                matched_value=f"{host}:{intent.target.port} in {network}",
                            )
                    elif intent.target.port is None:
                        # No port specified (e.g., port scan / recon) — IP in scope is enough
                        return MatchedRule(
                            rule_type="scope_in_scope",
                            rule_path=f"scope.in_scope.networks[{i}]",
                            description=f"Target {host} is in scope network {network}",
                            matched_value=f"{host} in {network}",
                        )
                    elif ports is None:
                        return MatchedRule(
                            rule_type="scope_in_scope",
                            rule_path=f"scope.in_scope.networks[{i}]",
                            description=f"Target {host} is in scope (all ports)",
                            matched_value=f"{host} in {network}",
                        )
        except ValueError:
            pass

        # Check domain-based scope
        domain = intent.target.domain or host
        for i, scope_domain in enumerate(self.in_scope_domains):
            pattern = scope_domain.get("pattern", "")
            excludes = scope_domain.get("exclude", [])

            if self._domain_matches(domain, pattern):
                # Check exclusions
                if not any(self._domain_matches(domain, exc) for exc in excludes):
                    return MatchedRule(
                        rule_type="scope_in_scope",
                        rule_path=f"scope.in_scope.domains[{i}]",
                        description=f"Target domain {domain} is in scope (matches {pattern})",
                        matched_value=f"{domain} matches {pattern}",
                    )

        return None

    def _check_allowed_actions(self, intent: ActionIntent) -> MatchedRule | None:
        """Check if the action category is explicitly allowed."""
        for i, allowed in enumerate(self.allowed_actions):
            category = allowed.get("category", "")
            methods = allowed.get("methods", [])

            if category == intent.category.value or category == "any":
                # If specific methods are listed, check subcategory
                if methods and intent.subcategory:
                    if intent.subcategory in methods:
                        return MatchedRule(
                            rule_type="action_allowed",
                            rule_path=f"actions.allowed[{i}]",
                            description=f"Action {intent.category.value}/{intent.subcategory} is allowed",
                            matched_value=f"category:{intent.category.value}, method:{intent.subcategory}",
                        )
                elif not methods:
                    return MatchedRule(
                        rule_type="action_allowed",
                        rule_path=f"actions.allowed[{i}]",
                        description=f"Action category {intent.category.value} is allowed",
                        matched_value=f"category:{intent.category.value}",
                    )

        return None

    # ─── Helper Methods ───────────────────────────────────────────────────

    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        """Check if a domain matches a pattern (supports wildcards).

        Also handles the common case where *.example.com should match example.com
        itself (not just subdomains).
        """
        d = domain.lower()
        p = pattern.lower()
        if fnmatch.fnmatch(d, p):
            return True
        # If pattern is *.example.com, also match example.com
        if p.startswith("*."):
            base = p[2:]
            if d == base or fnmatch.fnmatch(d, base):
                return True
        return False

    @staticmethod
    def _check_match_criteria(intent: ActionIntent, match_rules: dict[str, Any]) -> bool:
        """Check additional match criteria for a denied action rule."""
        # Check port matching
        ports = match_rules.get("ports", [])
        if ports and intent.target.port:
            if intent.target.port in ports:
                return True

        # Check protocol matching
        protocols = match_rules.get("protocols", [])
        if protocols:
            if intent.target.protocol and intent.target.protocol.lower() in [
                p.lower() for p in protocols
            ]:
                return True
            if intent.target.service and intent.target.service.lower() in [
                p.lower() for p in protocols
            ]:
                return True

        # Check record count threshold
        threshold = match_rules.get("record_count_threshold")
        if threshold and intent.impact.record_count_estimate:
            if intent.impact.record_count_estimate > threshold:
                return True

        # If no match criteria matched, check if we should match on category alone
        # (this is the case when match_rules exist but none are relevant to this intent)
        if not ports and not protocols and threshold is None:
            return True

        return False

    def _evaluate_condition(self, intent: ActionIntent, condition: str) -> bool:
        """Evaluate a simple condition expression against an ActionIntent.

        Supports basic expressions like:
        - "impact_assessment.estimated_severity == 'critical'"
        - "target.host not in scope.in_scope"

        This is intentionally limited to prevent arbitrary code execution.
        """
        if not condition:
            return True

        # Handle severity condition
        if "estimated_severity" in condition:
            for level in ["critical", "high", "medium", "low", "none"]:
                if f"== '{level}'" in condition or f"==\"{level}\"" in condition:
                    return intent.impact.estimated_severity.value == level

        # Handle "not in scope" condition — check if target is actually NOT in scope
        if "not in scope" in condition:
            in_scope = self._check_in_scope(intent)
            return in_scope is None  # Escalate only if NOT confirmed in scope

        return False
