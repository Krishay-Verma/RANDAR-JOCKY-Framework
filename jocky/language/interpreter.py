"""
Interpreter for JOCKY investigations.

Walks a validated Investigation IR and executes each command through
the collector and rule allowlists. Extended to support:
  - 'let' variable bindings
  - 'if/else' conditional execution
  - Expression evaluation (literals, variables, evidence properties)

Security boundaries:
  - Variable names: strict regex allowlist (lowercase, digits, underscores)
  - Variable count: hard cap at _MAX_VARIABLES
  - Nesting depth: hard cap at _MAX_NESTING_DEPTH (prevents stack overflow)
  - Evidence property access: explicit allowlist only (no arbitrary traversal)
  - Type mismatch in comparisons: raises InterpreterError (no TypeError leak)
  - Missing collector in property access: returns safe default 0 (no crash)
"""

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from jocky.language.ir import (
    Investigation, Command,
    CollectCommand, AnalyzeCommand, ReportCommand,
    LetCommand, IfCommand,
    LiteralExpr, VarExpr, PropertyExpr,
    Condition, Expr,
)
from jocky.collectors.registry import get_collector, is_known_collector
from jocky.analysis.registry import get_rule, is_known_rule
from jocky.analysis.finding import Finding


class InterpreterError(Exception):
    """Raised when a command references an unapproved name or fails evaluation."""
    pass


@dataclass
class CollectorResult:
    target: str
    status: str          # "success" | "error"
    data: dict | None = None
    error: str | None = None


@dataclass
class InvestigationResult:
    name: str
    collector_results: list[CollectorResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    report_name: str | None = None


# ── Safety limits ──────────────────────────────────────────────────────────────

_MAX_VARIABLES    = 50
_MAX_NESTING_DEPTH = 10
_VALID_VAR_NAME   = re.compile(r"^[a-z_][a-z0-9_]*$")


# ── Evidence property allowlist ────────────────────────────────────────────────
# Maps (collector_target, property_name) to a resolver callable.
# Nothing outside this dict is reachable via a JOCKY script.

_EVIDENCE_PROPS: dict[tuple[str, str], Callable[[dict], Any]] = {
    # Original collectors
    ("processes",           "count"):     lambda d: len(d.get("processes", [])),
    ("network_connections", "count"):     lambda d: len(d.get("connections", [])),
    ("logged_in_users",     "count"):     lambda d: d.get("count", len(d.get("sessions", []))),
    ("file_hash",           "count"):     lambda d: d.get("count", 0),
    ("system_info",         "hostname"):  lambda d: d.get("hostname", ""),
    ("system_info",         "platform"):  lambda d: d.get("platform", ""),
    ("system_info",         "cpu_count"): lambda d: d.get("cpu_count", 0),
    # Extended collectors
    ("scheduled_tasks",     "count"):     lambda d: d.get("count", 0),
    ("startup_items",       "count"):     lambda d: d.get("count", 0),
    ("open_files",          "count"):     lambda d: d.get("count", 0),
    ("local_users",         "count"):     lambda d: d.get("count", 0),
    ("modules",             "count"):     lambda d: d.get("count", 0),
    ("threads",             "count"):     lambda d: d.get("count", 0),
    ("memory_regions",      "count"):     lambda d: d.get("count", 0),
}

_ALLOWED_PROPS_STR = ", ".join(
    f"{c}.{p}" for c, p in _EVIDENCE_PROPS
)


# ── Evaluation context ─────────────────────────────────────────────────────────

@dataclass
class _EvalContext:
    variables: dict[str, Any]
    evidence: dict[str, Any]


# ── Public entry point ─────────────────────────────────────────────────────────

def run_investigation(investigation: Investigation) -> InvestigationResult:
    """Execute every command in an Investigation, in order."""
    result = InvestigationResult(name=investigation.name)
    variables: dict[str, Any] = {}
    _execute_commands(investigation.commands, result, variables, depth=0)
    return result


# ── Command execution ──────────────────────────────────────────────────────────

def _execute_commands(
    commands: list[Command],
    result: InvestigationResult,
    variables: dict[str, Any],
    depth: int,
) -> None:
    if depth > _MAX_NESTING_DEPTH:
        raise InterpreterError(
            f"Maximum if-nesting depth ({_MAX_NESTING_DEPTH}) exceeded. "
            "Reduce nested if blocks."
        )
    for command in commands:
        if isinstance(command, CollectCommand):
            _run_collect(command, result)
        elif isinstance(command, AnalyzeCommand):
            _run_analyze(command, result)
        elif isinstance(command, ReportCommand):
            result.report_name = command.name
        elif isinstance(command, LetCommand):
            _run_let(command, result, variables)
        elif isinstance(command, IfCommand):
            _run_if(command, result, variables, depth)
        else:
            raise InterpreterError(
                f"Unhandled command type: {type(command).__name__}"
            )


def _run_collect(command: CollectCommand, result: InvestigationResult) -> None:
    if not is_known_collector(command.target):
        raise InterpreterError(
            f"Line {command.line}: '{command.target}' is not an approved collector"
        )
    collector_fn = get_collector(command.target)
    try:
        data = collector_fn()
        result.collector_results.append(
            CollectorResult(target=command.target, status="success", data=data)
        )
    except Exception as exc:
        result.collector_results.append(
            CollectorResult(target=command.target, status="error", error=str(exc))
        )


def _run_analyze(command: AnalyzeCommand, result: InvestigationResult) -> None:
    if not is_known_rule(command.rule):
        raise InterpreterError(
            f"Line {command.line}: '{command.rule}' is not an approved analysis rule"
        )
    rule_fn = get_rule(command.rule)
    try:
        new_findings = rule_fn(_build_evidence(result))
    except Exception as exc:  # a faulty rule must not discard collected evidence
        result.findings.append(Finding(
            rule_name=command.rule,
            severity="informational",
            summary=f"Analysis rule '{command.rule}' failed to complete",
            reason=f"{type(exc).__name__}: {exc}",
            related_evidence={"line": command.line},
        ))
        return
    result.findings.extend(new_findings)


def _run_let(
    command: LetCommand,
    result: InvestigationResult,
    variables: dict[str, Any],
) -> None:
    if not _VALID_VAR_NAME.match(command.name):
        raise InterpreterError(
            f"Line {command.line}: invalid variable name {command.name!r}. "
            "Names must start with a lowercase letter or underscore and "
            "contain only lowercase letters, digits, and underscores."
        )
    if command.name not in variables and len(variables) >= _MAX_VARIABLES:
        raise InterpreterError(
            f"Line {command.line}: variable limit ({_MAX_VARIABLES}) exceeded."
        )
    ctx = _EvalContext(variables=variables, evidence=_build_evidence(result))
    variables[command.name] = _eval_expr(command.value, ctx)


def _run_if(
    command: IfCommand,
    result: InvestigationResult,
    variables: dict[str, Any],
    depth: int,
) -> None:
    ctx = _EvalContext(variables=variables, evidence=_build_evidence(result))
    branch = (
        command.then_commands
        if _eval_condition(command.condition, ctx)
        else command.else_commands
    )
    _execute_commands(branch, result, variables, depth + 1)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_evidence(result: InvestigationResult) -> dict[str, Any]:
    return {
        cr.target: cr.data
        for cr in result.collector_results
        if cr.status == "success"
    }


# ── Expression evaluation ──────────────────────────────────────────────────────

def _eval_expr(expr: Expr, ctx: _EvalContext) -> Any:
    if isinstance(expr, LiteralExpr):
        return expr.value

    if isinstance(expr, VarExpr):
        if expr.name not in ctx.variables:
            raise InterpreterError(
                f"Undefined variable '{expr.name}'. "
                "Declare it with 'let' before use."
            )
        return ctx.variables[expr.name]

    if isinstance(expr, PropertyExpr):
        return _resolve_property(expr.collector, expr.property, ctx.evidence)

    raise InterpreterError(
        f"Unknown expression type: {type(expr).__name__}"
    )


def _resolve_property(
    collector: str, prop: str, evidence: dict[str, Any]
) -> Any:
    """
    Resolve collector.property via the strict allowlist.

    Returns 0 (safe numeric default) if the collector hasn't run or
    failed — allows condition checks on potentially uncollected evidence
    without crashing the investigation.
    """
    key = (collector, prop)
    if key not in _EVIDENCE_PROPS:
        raise InterpreterError(
            f"Unknown evidence property '{collector}.{prop}'. "
            f"Allowed properties: {_ALLOWED_PROPS_STR}"
        )
    if collector not in evidence:
        return 0
    return _EVIDENCE_PROPS[key](evidence[collector])


def _eval_condition(cond: Condition, ctx: _EvalContext) -> bool:
    left  = _eval_expr(cond.left,  ctx)
    right = _eval_expr(cond.right, ctx)

    try:
        if cond.operator == ">":  return left > right   # type: ignore[operator]
        if cond.operator == "<":  return left < right   # type: ignore[operator]
        if cond.operator == ">=": return left >= right  # type: ignore[operator]
        if cond.operator == "<=": return left <= right  # type: ignore[operator]
        if cond.operator == "==": return left == right
        if cond.operator == "!=": return left != right
    except TypeError as exc:
        raise InterpreterError(
            f"Type mismatch in condition: cannot compare "
            f"{type(left).__name__} and {type(right).__name__} "
            f"with '{cond.operator}': {exc}"
        ) from exc

    raise InterpreterError(f"Unknown operator: {cond.operator!r}")


def list_evidence_properties() -> list[str]:
    """Allowlisted `collector.property` names usable in conditions."""
    return [f"{c}.{p}" for c, p in _EVIDENCE_PROPS]
