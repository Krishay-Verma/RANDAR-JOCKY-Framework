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
import json
import contextvars
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from jocky.language.ir import (
    Investigation, Command,
    CollectCommand, AnalyzeCommand, ReportCommand,
    LetCommand, IfCommand, UserRuleCommand,
    LiteralExpr, VarExpr, PropertyExpr,
    Condition, Expr,
)
from jocky.collectors.registry import get_collector, is_known_collector
from jocky.analysis.registry import get_rule, is_known_rule
from jocky.analysis.finding import Finding
from jocky.analysis.dedup import deduplicate_findings


class InterpreterError(Exception):
    """Raised when a command references an unapproved name or fails evaluation."""
    pass


class InvestigationExecutionStopped(InterpreterError):
    """Internal control-flow exception for V1.9 runtime/cancellation limits."""

    def __init__(self, reason: str, cancelled: bool = False):
        super().__init__(reason)
        self.cancelled = cancelled


@dataclass
class CollectorResult:
    target: str
    status: str          # "success" | "error" | "cancelled" | "timeout"
    data: dict | None = None
    error: str | None = None
    duration_ms: int = 0
    record_count: int = 0
    truncated: bool = False
    resource_bytes: int = 0


@dataclass
class AnalysisResult:
    target: str
    status: str          # "success" | "error"
    finding_count: int = 0
    error: str | None = None


@dataclass
class InvestigationResult:
    name: str
    collector_results: list[CollectorResult] = field(default_factory=list)
    analysis_results: list[AnalysisResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    report_name: str | None = None
    execution_status: str = "complete"
    termination_reason: str | None = None
    elapsed_ms: int = 0
    resource_usage: dict[str, Any] = field(default_factory=dict)


# ── Safety limits ──────────────────────────────────────────────────────────────

_MAX_VARIABLES = 50
_MAX_NESTING_DEPTH = 10
_VALID_VAR_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

# V1.9 bounded execution/resource policy. These limits are deliberately
# conservative so a single collector cannot monopolize the investigator.
MAX_COLLECTOR_RUNTIME_SECONDS = 45.0

# A small number of Windows collectors legitimately need more time because
# they inspect process memory maps or parse many PE files. Keep those bounded
# separately instead of letting the generic 30-second ceiling create routine
# false timeouts on busy endpoints.
_COLLECTOR_TIMEOUTS = {
    "modules": 90.0,
    "threads": 90.0,
    "memory_regions": 90.0,
    "pe_metadata": 120.0,
    "windows_event_logs": 90.0,
    "sysmon_events": 90.0,
    "driver_inventory": 180.0,
    "services": 90.0,
    "scheduled_tasks": 90.0,
    "local_users": 60.0,
}
MAX_INVESTIGATION_RUNTIME_SECONDS = 600.0
MAX_RECORDS_PER_COLLECTOR = 10_000
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024


# ── Evidence property allowlist ────────────────────────────────────────────────
# Maps (collector_target, property_name) to a resolver callable.
# Nothing outside this dict is reachable via a JOCKY script.

_EVIDENCE_PROPS: dict[tuple[str, str], Callable[[dict], Any]] = {
    # Original collectors
    ("processes",           "count"):     lambda d: len(d.get("processes", [])),
    ("network_connections", "count"):     lambda d: len(d.get("connections", [])),
    ("network_artifacts", "count"):       lambda d: d.get("count", 0),
    ("network_artifacts", "unique_sources"): lambda d: d.get("statistics", {}).get("unique_sources", 0),
    ("network_artifacts", "unique_destinations"): lambda d: d.get("statistics", {}).get("unique_destinations", 0),
    ("network_artifacts", "unique_domains"): lambda d: d.get("statistics", {}).get("unique_domains", 0),
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
    ("driver_inventory",    "count"):     lambda d: d.get("count", 0),
    ("windows_event_logs", "count"):     lambda d: d.get("count", 0),
    ("sysmon_events",      "count"):     lambda d: d.get("count", 0),
    ("services",           "count"):     lambda d: d.get("count", 0),
    ("pe_metadata",        "count"):     lambda d: d.get("count", 0),
    ("wmi_event_subscriptions", "count"): lambda d: d.get("count", 0),
    ("ifeo_persistence", "count"): lambda d: d.get("count", 0),
    ("winlogon_persistence", "count"): lambda d: d.get("count", 0),
    ("appinit_persistence", "count"): lambda d: d.get("count", 0),
    ("com_hijack_persistence", "count"): lambda d: d.get("count", 0),
    ("bits_persistence", "count"): lambda d: d.get("count", 0),
    ("all_users_startup", "count"): lambda d: d.get("count", 0),
    ("browser_extensions", "count"): lambda d: d.get("count", 0),
    ("office_addins", "count"): lambda d: d.get("count", 0),
    ("lsa_auth_packages", "count"): lambda d: d.get("count", 0),
    ("advanced_persistence", "count"): lambda d: d.get("count", 0),
    ("clipboard_metadata", "count"): lambda d: d.get("count", 0),
    ("browser_history_metadata", "count"): lambda d: d.get("count", 0),
    ("browser_cookie_metadata", "count"): lambda d: d.get("count", 0),
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

def run_investigation(
    investigation: Investigation,
    progress_callback: Callable[[int, str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
    max_runtime_seconds: float = MAX_INVESTIGATION_RUNTIME_SECONDS,
    collector_timeout_seconds: float = MAX_COLLECTOR_RUNTIME_SECONDS,
) -> InvestigationResult:
    """Execute every command in an Investigation, in order.

    ``progress_callback`` is optional so existing callers remain unchanged.
    It receives bounded 0-100 progress plus a human-readable phase message
    after each executed command.
    """
    result = InvestigationResult(name=investigation.name)
    variables: dict[str, Any] = {}
    total = max(1, _count_commands(investigation.commands))
    started = time.monotonic()
    if progress_callback:
        progress_callback(5, f"Starting investigation: 0/{total} steps.")
    completed = [0]
    try:
        _execute_commands(
            investigation.commands, result, variables, depth=0,
            progress_callback=progress_callback, total=total, completed=completed,
            started_at=started, cancel_check=cancel_check,
            max_runtime_seconds=max_runtime_seconds,
            collector_timeout_seconds=collector_timeout_seconds,
        )
    except InvestigationExecutionStopped as exc:
        result.execution_status = "cancelled" if exc.cancelled else "partial"
        result.termination_reason = str(exc)
        if progress_callback:
            progress_callback(85, str(exc))
    else:
        if progress_callback:
            progress_callback(85, f"Investigation execution complete: {total}/{total} steps.")
    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    result.resource_usage = {
        "commands_total": total,
        "commands_completed": completed[0],
        "collector_count": len(result.collector_results),
        "successful_collectors": sum(1 for c in result.collector_results if c.status == "success"),
        "failed_collectors": sum(1 for c in result.collector_results if c.status in {"error", "timeout", "cancelled"}),
        "timed_out_collectors": sum(1 for c in result.collector_results if c.status == "timeout"),
        "cancelled_collectors": sum(1 for c in result.collector_results if c.status == "cancelled"),
        "records_collected": sum(c.record_count for c in result.collector_results),
        "evidence_bytes": sum(c.resource_bytes for c in result.collector_results),
        "truncated_collectors": sum(1 for c in result.collector_results if c.truncated),
        "elapsed_ms": result.elapsed_ms,
    }
    return result


def _count_commands(commands: list[Command]) -> int:
    """Count executable commands, including nested if/else branches."""
    total = 0
    for command in commands:
        total += 1
        if isinstance(command, IfCommand):
            total += _count_commands(command.then_commands)
            total += _count_commands(command.else_commands)
    return total


# ── Command execution ──────────────────────────────────────────────────────────

def _execute_commands(
    commands: list[Command],
    result: InvestigationResult,
    variables: dict[str, Any],
    depth: int,
    progress_callback: Callable[[int, str], None] | None = None,
    total: int = 1,
    completed: list[int] | None = None,
    started_at: float | None = None,
    cancel_check: Callable[[], bool] | None = None,
    max_runtime_seconds: float = MAX_INVESTIGATION_RUNTIME_SECONDS,
    collector_timeout_seconds: float = MAX_COLLECTOR_RUNTIME_SECONDS,
) -> None:
    if completed is None:
        completed = [0]
    if depth > _MAX_NESTING_DEPTH:
        raise InterpreterError(
            f"Maximum if-nesting depth ({_MAX_NESTING_DEPTH}) exceeded. "
            "Reduce nested if blocks."
        )
    for command in commands:
        if progress_callback:
            # Show that the active command is actually executing instead of
            # leaving the UI at the initial 5% marker during a long collector.
            active_progress = min(84, 5 + int(80 * (completed[0] + 0.25) / total))
            label = getattr(command, "target", None) or getattr(command, "rule", None) or getattr(command, "name", None) or type(command).__name__
            progress_callback(active_progress, f"Executing {label} ({completed[0]}/{total}).")
        if cancel_check and cancel_check():
            raise InvestigationExecutionStopped("Investigation cancelled by analyst.", cancelled=True)
        if started_at is not None and (time.monotonic() - started_at) > max_runtime_seconds:
            raise InvestigationExecutionStopped(
                f"Maximum investigation runtime ({max_runtime_seconds:g}s) exceeded."
            )
        if isinstance(command, CollectCommand):
            _run_collect(
                command, result, cancel_check=cancel_check,
                timeout_seconds=_collector_timeout(command.target, collector_timeout_seconds),
            )
            phase = f"Collected {command.target}"
        elif isinstance(command, AnalyzeCommand):
            _run_analyze(command, result, variables)
            phase = f"Analyzed {command.rule}"
        elif isinstance(command, ReportCommand):
            result.report_name = command.name
            phase = "Recorded report definition"
        elif isinstance(command, LetCommand):
            _run_let(command, result, variables)
            phase = f"Evaluated variable {command.name}"
        elif isinstance(command, IfCommand):
            _run_if(
                command, result, variables, depth,
                progress_callback=progress_callback, total=total, completed=completed,
                started_at=started_at, cancel_check=cancel_check,
                max_runtime_seconds=max_runtime_seconds, collector_timeout_seconds=collector_timeout_seconds,
            )
            phase = "Evaluated conditional branch"
        elif isinstance(command, UserRuleCommand):
            _run_user_rule(command, result, variables)
            phase = f"Evaluated rule {command.name}"
        else:
            raise InterpreterError(
                f"Unhandled command type: {type(command).__name__}"
            )
        completed[0] += 1
        if progress_callback:
            progress = min(85, 5 + int(80 * completed[0] / total))
            progress_callback(progress, f"{phase} ({completed[0]}/{total}).")


def _collector_timeout(target: str, default: float) -> float:
    """Return a bounded timeout appropriate for the collector surface."""
    profile = _COLLECTOR_TIMEOUTS.get(target, default)
    return max(0.1, float(profile))


def _run_collect(
    command: CollectCommand,
    result: InvestigationResult,
    cancel_check: Callable[[], bool] | None = None,
    timeout_seconds: float = MAX_COLLECTOR_RUNTIME_SECONDS,
) -> None:
    if not is_known_collector(command.target):
        raise InterpreterError(
            f"Line {command.line}: '{command.target}' is not an approved collector"
        )
    if cancel_check and cancel_check():
        raise InvestigationExecutionStopped("Investigation cancelled by analyst.", cancelled=True)
    collector_fn = get_collector(command.target)
    started = time.monotonic()
    outcome: dict[str, Any] = {}
    done = threading.Event()

    ctx = contextvars.copy_context()

    def invoke() -> None:
        try:
            outcome["data"] = ctx.run(collector_fn)
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            done.set()

    # A daemon worker prevents a stuck third-party/OS collector from keeping
    # the API process alive after the investigator has recorded a timeout.
    worker = threading.Thread(target=invoke, name=f"randar-collector-{command.target}", daemon=True)
    worker.start()
    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while not done.wait(timeout=0.05):
        if cancel_check and cancel_check():
            duration = int((time.monotonic() - started) * 1000)
            result.collector_results.append(CollectorResult(
                target=command.target, status="cancelled",
                error="Collector cancelled because the investigation was cancelled.",
                duration_ms=duration,
            ))
            return
        if time.monotonic() >= deadline:
            duration = int((time.monotonic() - started) * 1000)
            result.collector_results.append(CollectorResult(
                target=command.target, status="timeout",
                error=f"Collector exceeded its {float(timeout_seconds):g}s execution limit.",
                duration_ms=duration,
            ))
            return

    duration = int((time.monotonic() - started) * 1000)
    if "error" in outcome:
        exc = outcome["error"]
        result.collector_results.append(CollectorResult(
            target=command.target, status="error", error=str(exc), duration_ms=duration
        ))
        return

    data, truncated, records, resource_bytes = _bound_collector_data(outcome.get("data"))
    result.collector_results.append(CollectorResult(
        target=command.target, status="success", data=data, duration_ms=duration,
        record_count=records, truncated=truncated, resource_bytes=resource_bytes,
    ))


def _bound_collector_data(data: Any) -> tuple[dict | None, bool, int, int]:
    """Apply V1.9 record/size bounds while preserving an explicit audit marker."""
    if data is None:
        return None, False, 0, 0
    try:
        original = json.loads(json.dumps(data, default=str))
    except (TypeError, ValueError):
        original = {"value": str(data)}

    record_count = 0
    truncated = False

    def walk(value: Any, depth: int = 0):
        nonlocal record_count, truncated
        if depth > 20:
            return value
        if isinstance(value, list):
            out = []
            for item in value:
                if record_count >= MAX_RECORDS_PER_COLLECTOR:
                    truncated = True
                    break
                record_count += 1
                out.append(walk(item, depth + 1))
            return out
        if isinstance(value, dict):
            return {k: walk(v, depth + 1) for k, v in value.items()}
        return value

    bounded = walk(original)
    try:
        encoded = json.dumps(bounded, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        resource_bytes = len(encoded)
    except (TypeError, ValueError):
        resource_bytes = 0

    # Do not silently retain an enormous scalar/object payload. Keep metadata
    # and explicitly mark the evidence as bounded.
    if resource_bytes > MAX_EVIDENCE_BYTES:
        truncated = True
        text = json.dumps(bounded, ensure_ascii=False, default=str)
        bounded = {
            "_randar_resource_limit": {
                "truncated": True,
                "reason": "maximum evidence size exceeded",
                "max_bytes": MAX_EVIDENCE_BYTES,
                "original_bytes": resource_bytes,
            },
            "preview": text[:MAX_EVIDENCE_BYTES // 2],
        }
        resource_bytes = len(json.dumps(bounded, ensure_ascii=False).encode("utf-8"))

    if truncated and isinstance(bounded, dict):
        marker = bounded.get("_randar_resource_limit")
        if not marker:
            bounded["_randar_resource_limit"] = {
                "truncated": True,
                "max_records": MAX_RECORDS_PER_COLLECTOR,
            }
    return bounded if isinstance(bounded, dict) else {"value": bounded}, truncated, record_count, resource_bytes


def _run_analyze(command: AnalyzeCommand, result: InvestigationResult, variables: dict[str, Any]) -> None:
    if not is_known_rule(command.rule):
        raise InterpreterError(
            f"Line {command.line}: '{command.rule}' is not an approved analysis rule"
        )
    rule_fn = get_rule(command.rule)
    before = len(result.findings)
    try:
        new_findings = rule_fn(_build_evidence(result))
        if command.where is not None:
            new_findings = [f for f in new_findings if _eval_finding_condition(command.where, f, variables)]
        result.findings = deduplicate_findings(result.findings + new_findings)
        result.analysis_results.append(AnalysisResult(
            target=command.rule,
            status="success",
            finding_count=len(result.findings) - before,
        ))
    except Exception as exc:  # a faulty rule must not discard collected evidence
        result.findings.append(Finding(
            rule_name=command.rule,
            severity="informational",
            summary=f"Analysis rule '{command.rule}' failed to complete",
            reason=f"{type(exc).__name__}: {exc}",
            related_evidence={"line": command.line},
        ))
        result.analysis_results.append(AnalysisResult(
            target=command.rule,
            status="error",
            finding_count=1,
            error=f"{type(exc).__name__}: {exc}",
        ))


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
    progress_callback: Callable[[int, str], None] | None = None,
    total: int = 1,
    completed: list[int] | None = None,
    started_at: float | None = None,
    cancel_check: Callable[[], bool] | None = None,
    max_runtime_seconds: float = MAX_INVESTIGATION_RUNTIME_SECONDS,
    collector_timeout_seconds: float = MAX_COLLECTOR_RUNTIME_SECONDS,
) -> None:
    ctx = _EvalContext(variables=variables, evidence=_build_evidence(result))
    branch = (
        command.then_commands
        if _eval_condition(command.condition, ctx)
        else command.else_commands
    )
    _execute_commands(
        branch, result, variables, depth + 1,
        progress_callback=progress_callback, total=total, completed=completed,
        started_at=started_at, cancel_check=cancel_check,
        max_runtime_seconds=max_runtime_seconds, collector_timeout_seconds=collector_timeout_seconds,
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_evidence(result: InvestigationResult) -> dict[str, Any]:
    return {
        cr.target: cr.data
        for cr in result.collector_results
        if cr.status == "success"
    }


def _compare(left: Any, operator: str, right: Any) -> bool:
    try:
        if operator == "==": return left == right
        if operator == "!=": return left != right
        if operator == ">": return left > right
        if operator == "<": return left < right
        if operator == ">=": return left >= right
        if operator == "<=": return left <= right
    except TypeError:
        return False
    raise InterpreterError(f"Unsupported comparison operator {operator!r}")


def _eval_condition_tree(cond: Condition, resolver: Callable[[Expr], Any]) -> bool:
    if cond.kind == "and": return all(_eval_condition_tree(c, resolver) for c in cond.children)
    if cond.kind == "or": return any(_eval_condition_tree(c, resolver) for c in cond.children)
    if cond.kind == "not": return not _eval_condition_tree(cond.children[0], resolver)
    return _compare(resolver(cond.left), cond.operator, resolver(cond.right))


def _finding_value(finding: Finding, expr: Expr) -> Any:
    if isinstance(expr, LiteralExpr): return expr.value
    if isinstance(expr, VarExpr):
        return None  # resolved by _eval_finding_condition using the active variable scope
    ev = finding.related_evidence or {}
    c, p = expr.collector, expr.property
    aliases = {
        "process": {"name": "process_name", "pid": "pid"},
        "destination": {"address": "remote_address", "ip": "remote_address", "port": "remote_port", "is_external": "destination_is_external"},
        "source": {"address": "source", "ip": "source", "port": "source_port"},
        "module": {"name": "module_name", "path": "module_path"},
    }
    if c in aliases and p in aliases[c]:
        key = aliases[c][p]
        if key == "destination_is_external":
            import ipaddress
            value = ev.get("remote_address") or ev.get("destination")
            try: return not (ipaddress.ip_address(str(value)).is_private or ipaddress.ip_address(str(value)).is_loopback or ipaddress.ip_address(str(value)).is_link_local)
            except ValueError: return False
        return ev.get(key)
    return ev.get(p) if c in {"evidence", "finding"} else None


def _eval_finding_condition(cond: Condition, finding: Finding, variables: dict[str, Any] | None = None) -> bool:
    variables = variables or {}
    def resolve(expr):
        if isinstance(expr, VarExpr):
            if expr.name not in variables: raise InterpreterError(f"Undefined variable '{expr.name}'.")
            return variables[expr.name]
        return _finding_value(finding, expr)
    return _eval_condition_tree(cond, resolve)


def _run_user_rule(command: UserRuleCommand, result: InvestigationResult, variables: dict[str, Any]) -> None:
    matches = []
    for finding in list(result.findings):
        if _eval_finding_condition(command.condition, finding, variables):
            matches.append(finding)
    for finding in matches:
        result.findings.append(Finding(
            rule_name=command.name, severity=command.severity,
            summary=f"User-defined rule matched: {finding.summary}",
            reason=f"Analyst-authored rule '{command.name}' matched evidence from {finding.rule_name}.",
            related_evidence={"source_rule": finding.rule_name, **(finding.related_evidence or {})},
        ))

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
