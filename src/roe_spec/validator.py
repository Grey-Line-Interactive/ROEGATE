"""
ROE Specification Validator

Comprehensive validation of ROE specs at three levels:
1. JSON Schema validation — structural correctness against schema.yaml
2. Semantic validation — CIDR, timezone, ports, categories, schedule sanity
3. Coverage warnings — missing recommended sections, dangerous gaps
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import available_timezones

import yaml

from src.core.action_intent import ActionCategory


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ValidationIssue:
    level: str        # "error", "warning", "info"
    path: str         # ROE spec path, e.g., "scope.in_scope.networks[0].cidr"
    message: str      # Human-readable description
    code: str         # Machine-readable code, e.g., "INVALID_CIDR"


@dataclass
class ValidationResult:
    valid: bool = True
    issues: list[ValidationIssue] = field(default_factory=list)

    def add(self, level: str, path: str, message: str, code: str) -> None:
        self.issues.append(ValidationIssue(level=level, path=path, message=message, code=code))
        if level == "error":
            self.valid = False

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "warning"]


# ---------------------------------------------------------------------------
# Schema validation (Level 1)
# ---------------------------------------------------------------------------

_SCHEMA_PATH = Path(__file__).parent / "schema.yaml"
_CACHED_SCHEMA: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    global _CACHED_SCHEMA
    if _CACHED_SCHEMA is None:
        with open(_SCHEMA_PATH) as f:
            _CACHED_SCHEMA = yaml.safe_load(f)
    return _CACHED_SCHEMA


def _validate_schema(roe_spec: dict[str, Any], result: ValidationResult) -> None:
    """Level 1: Validate ROE spec against JSON Schema."""
    try:
        import jsonschema
    except ImportError:
        result.add("warning", "", "jsonschema not installed; skipping schema validation", "NO_JSONSCHEMA")
        return

    schema = _load_schema()

    # The schema expects {"roe": {...}}, but we receive the inner spec.
    # Wrap it for validation.
    wrapped = {"roe": roe_spec}

    validator_cls = jsonschema.Draft202012Validator
    validator = validator_cls(schema)

    for error in sorted(validator.iter_errors(wrapped), key=lambda e: list(e.absolute_path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        # Skip the "roe." prefix in path for cleaner output
        if path.startswith("roe."):
            path = path[4:]
        result.add("error", path, error.message, "SCHEMA_VIOLATION")


# ---------------------------------------------------------------------------
# Semantic validation (Level 2)
# ---------------------------------------------------------------------------

# All valid category values from the ActionCategory enum (excluding "any" which is rule-only)
_VALID_CATEGORIES = {cat.value for cat in ActionCategory} | {"any"}

_VALID_TIMEZONES = available_timezones()

_HOURS_RE = re.compile(r"^(\d{2}):(\d{2})-(\d{2}):(\d{2})$")


def _validate_semantics(roe_spec: dict[str, Any], result: ValidationResult) -> None:
    """Level 2: Semantic checks beyond what JSON Schema can express."""
    _validate_schedule(roe_spec.get("schedule", {}), result)
    _validate_scope(roe_spec.get("scope", {}), result)
    _validate_actions(roe_spec.get("actions", {}), result)


def _validate_schedule(schedule: dict[str, Any], result: ValidationResult) -> None:
    if not schedule:
        return

    # valid_from < valid_until
    valid_from_str = schedule.get("valid_from")
    valid_until_str = schedule.get("valid_until")
    if valid_from_str and valid_until_str:
        try:
            vf = datetime.fromisoformat(str(valid_from_str).replace("Z", "+00:00"))
            vu = datetime.fromisoformat(str(valid_until_str).replace("Z", "+00:00"))
            if vf >= vu:
                result.add(
                    "error", "schedule",
                    f"valid_from ({valid_from_str}) must be before valid_until ({valid_until_str})",
                    "SCHEDULE_INVALID_RANGE",
                )
        except (ValueError, TypeError):
            pass  # Schema validation catches format issues

    # Timezone
    tz = schedule.get("timezone")
    if tz and str(tz) not in _VALID_TIMEZONES and str(tz) != "UTC":
        result.add("error", "schedule.timezone", f"Unknown timezone: {tz!r}", "INVALID_TIMEZONE")

    # Allowed hours format
    hours = schedule.get("allowed_hours")
    if hours:
        m = _HOURS_RE.match(str(hours))
        if m:
            sh, sm, eh, em = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
            if sh > 23 or sm > 59:
                result.add(
                    "error", "schedule.allowed_hours",
                    f"Invalid start time in allowed_hours: {hours}",
                    "INVALID_HOURS_FORMAT",
                )
            if eh > 23 or em > 59:
                result.add(
                    "error", "schedule.allowed_hours",
                    f"Invalid end time in allowed_hours: {hours}",
                    "INVALID_HOURS_FORMAT",
                )
            start_minutes = sh * 60 + sm
            end_minutes = eh * 60 + em
            if start_minutes > end_minutes:
                result.add(
                    "info", "schedule.allowed_hours",
                    f"Midnight-wrap window detected ({hours}). Ensure the rule engine handles this.",
                    "MIDNIGHT_WRAP_HOURS",
                )
        elif hours:
            result.add(
                "error", "schedule.allowed_hours",
                f"Invalid allowed_hours format: {hours!r}. Expected HH:MM-HH:MM",
                "INVALID_HOURS_FORMAT",
            )


def _validate_scope(scope: dict[str, Any], result: ValidationResult) -> None:
    if not scope:
        return

    for scope_type in ("in_scope", "out_of_scope"):
        scope_def = scope.get(scope_type, {})
        if not scope_def:
            continue

        # Validate networks
        for i, net in enumerate(scope_def.get("networks", [])):
            cidr = net.get("cidr", "")
            if cidr:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError as e:
                    result.add(
                        "error", f"scope.{scope_type}.networks[{i}].cidr",
                        f"Invalid CIDR: {cidr!r} — {e}",
                        "INVALID_CIDR",
                    )

            # Validate ports
            for j, port in enumerate(net.get("ports", [])):
                if not isinstance(port, int) or port < 1 or port > 65535:
                    result.add(
                        "error", f"scope.{scope_type}.networks[{i}].ports[{j}]",
                        f"Port out of range (1-65535): {port}",
                        "INVALID_PORT",
                    )

            # Validate port ranges
            for j, pr in enumerate(net.get("port_ranges", [])):
                start = pr.get("start", 0)
                end = pr.get("end", 0)
                if start > end:
                    result.add(
                        "error", f"scope.{scope_type}.networks[{i}].port_ranges[{j}]",
                        f"Port range start ({start}) > end ({end})",
                        "INVALID_PORT_RANGE",
                    )
                for label, val in [("start", start), ("end", end)]:
                    if not isinstance(val, int) or val < 1 or val > 65535:
                        result.add(
                            "error",
                            f"scope.{scope_type}.networks[{i}].port_ranges[{j}].{label}",
                            f"Port range {label} out of range (1-65535): {val}",
                            "INVALID_PORT",
                        )

        # Validate domain patterns
        for i, dom in enumerate(scope_def.get("domains", [])):
            pattern = dom.get("pattern", "")
            if not pattern:
                result.add(
                    "error", f"scope.{scope_type}.domains[{i}].pattern",
                    "Empty domain pattern",
                    "EMPTY_DOMAIN_PATTERN",
                )


def _validate_actions(actions: dict[str, Any], result: ValidationResult) -> None:
    if not actions:
        return

    for action_type in ("allowed", "denied"):
        for i, rule in enumerate(actions.get(action_type, [])):
            category = rule.get("category", "")
            if category and category not in _VALID_CATEGORIES:
                result.add(
                    "error", f"actions.{action_type}[{i}].category",
                    f"Unknown action category: {category!r}",
                    "UNKNOWN_CATEGORY",
                )

            # Check for empty match criteria on denied actions
            if action_type == "denied":
                match_rules = rule.get("match", {})
                if isinstance(match_rules, dict) and match_rules:
                    known_keys = {"ports", "protocols", "record_count_threshold", "targets"}
                    present_keys = set(match_rules.keys())
                    recognized = present_keys & known_keys
                    if not recognized:
                        result.add(
                            "warning", f"actions.denied[{i}].match",
                            f"Match criteria contains only unrecognized keys: {present_keys}. "
                            "This may cause unexpected behavior in the rule engine.",
                            "UNKNOWN_MATCH_KEYS",
                        )

    # Validate requires_approval
    for i, rule in enumerate(actions.get("requires_approval", [])):
        category = rule.get("category", "")
        if category and category not in _VALID_CATEGORIES:
            result.add(
                "error", f"actions.requires_approval[{i}].category",
                f"Unknown action category: {category!r}",
                "UNKNOWN_CATEGORY",
            )


# ---------------------------------------------------------------------------
# Coverage analysis (Level 3)
# ---------------------------------------------------------------------------

_DANGEROUS_CATEGORIES = {
    "denial_of_service", "social_engineering", "data_exfiltration",
    "lateral_movement", "privilege_escalation",
}


def _validate_coverage(roe_spec: dict[str, Any], result: ValidationResult) -> None:
    """Level 3: Warn about missing recommended sections and dangerous gaps."""
    # Missing emergency section
    emergency = roe_spec.get("emergency")
    if not emergency:
        result.add(
            "warning", "emergency",
            "No emergency section defined. Recommended to set kill_switch and max_consecutive_denials.",
            "MISSING_EMERGENCY",
        )
    else:
        if not emergency.get("kill_switch"):
            result.add(
                "warning", "emergency.kill_switch",
                "Kill switch is not enabled. Strongly recommended.",
                "KILL_SWITCH_DISABLED",
            )

    # Missing constraints
    if not roe_spec.get("constraints"):
        result.add(
            "warning", "constraints",
            "No constraints section defined. Consider setting rate limits and persistent change controls.",
            "MISSING_CONSTRAINTS",
        )

    # Empty denied actions
    actions = roe_spec.get("actions", {})
    denied = actions.get("denied", [])
    if not denied:
        result.add(
            "warning", "actions.denied",
            "No denied actions specified. Recommended to explicitly deny dangerous categories.",
            "EMPTY_DENIED_ACTIONS",
        )
    else:
        denied_cats = {d.get("category") for d in denied}
        missing_dangerous = _DANGEROUS_CATEGORIES - denied_cats
        if missing_dangerous:
            result.add(
                "info", "actions.denied",
                f"Dangerous categories not explicitly denied: {', '.join(sorted(missing_dangerous))}. "
                "These may still be caught by scope/service checks, but explicit denial is recommended.",
                "UNDECLARED_DANGEROUS_CATEGORIES",
            )

    # Missing out_of_scope
    scope = roe_spec.get("scope", {})
    if not scope.get("out_of_scope"):
        result.add(
            "warning", "scope.out_of_scope",
            "No out_of_scope defined. Recommended to explicitly define boundaries.",
            "MISSING_OUT_OF_SCOPE",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_roe_spec(roe_spec: dict[str, Any]) -> ValidationResult:
    """Validate a ROE spec dict through all three levels.

    Args:
        roe_spec: The inner ROE spec dict (without the top-level 'roe' key).

    Returns:
        ValidationResult with valid=True if no errors found.
    """
    result = ValidationResult()

    if not isinstance(roe_spec, dict):
        result.add("error", "(root)", "ROE spec must be a dictionary", "NOT_A_DICT")
        return result

    # Level 1: Schema
    _validate_schema(roe_spec, result)

    # Level 2: Semantics
    _validate_semantics(roe_spec, result)

    # Level 3: Coverage
    _validate_coverage(roe_spec, result)

    return result


def validate_roe_file(path: str | Path) -> ValidationResult:
    """Load a YAML file and validate the ROE spec within it.

    Expects the YAML to have a top-level 'roe' key.
    """
    result = ValidationResult()
    path = Path(path)

    if not path.exists():
        result.add("error", "(file)", f"File not found: {path}", "FILE_NOT_FOUND")
        return result

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        result.add("error", "(file)", f"YAML parse error: {e}", "YAML_PARSE_ERROR")
        return result

    if not isinstance(data, dict) or "roe" not in data:
        result.add("error", "(root)", "Missing top-level 'roe' key", "MISSING_ROE_KEY")
        return result

    return validate_roe_spec(data["roe"])
