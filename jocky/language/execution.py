"""V2.4 controlled in-memory execution abstraction and telemetry.

This layer does not expose arbitrary OS command execution, process injection,
API unhooking, direct syscalls, or kernel manipulation.  It routes validated
JOCKY operations through existing RANDAR collectors/rules and records an
explicit, auditable execution trace.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import platform
import time
from typing import Any

from jocky.language.compiler import host_target
from jocky.language.ir import Investigation
from jocky.language.interpreter import InvestigationResult, run_investigation

RUNTIME_VERSION = "2.4.0"
RUNTIME_MODE = "in-memory-interpreter"
SUPPORTED_ADAPTERS = frozenset({"jocky-interpreter"})


@dataclass(frozen=True)
class ExecutionEvent:
    sequence: int
    event: str
    adapter: str
    target: str
    operation: str
    status: str
    duration_ms: int = 0
    detail: str | None = None


@dataclass
class ExecutionTelemetry:
    runtime_version: str
    host_target: str
    platform: str
    process_context: str
    started_at: float
    execution_mode: str = RUNTIME_MODE
    completed_at: float | None = None
    status: str = "running"
    events: list[ExecutionEvent] = field(default_factory=list)
    resource_usage: dict[str, Any] = field(default_factory=dict)
    forensic_artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["events"] = [asdict(e) for e in self.events]
        return payload


class ExecutionAdapterError(ValueError):
    pass


def resolve_adapter(adapter: str = "jocky-interpreter") -> str:
    normalized = adapter.strip().lower()
    if normalized not in SUPPORTED_ADAPTERS:
        raise ExecutionAdapterError(
            f"Unsupported execution adapter {adapter!r}. "
            f"Expected one of: {', '.join(sorted(SUPPORTED_ADAPTERS))}."
        )
    return normalized


def execute_investigation(
    investigation: Investigation,
    *,
    adapter: str = "jocky-interpreter",
    target: str = "portable",
) -> tuple[InvestigationResult, ExecutionTelemetry]:
    """Execute a validated Investigation through a named safe adapter."""
    adapter = resolve_adapter(adapter)
    if target not in {"portable", "windows", "ubuntu"}:
        raise ExecutionAdapterError(f"Unsupported runtime target {target!r}.")

    started = time.time()
    telemetry = ExecutionTelemetry(
        runtime_version=RUNTIME_VERSION,
        host_target=host_target(),
        platform=platform.platform(aliased=True),
        process_context="randar-jocky-runtime",
        started_at=started,
    )
    sequence = 1
    telemetry.events.append(ExecutionEvent(
        sequence, "runtime.started", adapter, target, "investigation", "started"
    ))

    def progress(percent: int, message: str) -> None:
        nonlocal sequence
        sequence += 1
        telemetry.events.append(ExecutionEvent(
            sequence, "operation.progress", adapter, target, "investigation", "running",
            detail=f"{percent}% {message}",
        ))

    try:
        result = run_investigation(investigation, progress_callback=progress)
        status = result.execution_status
        sequence += 1
        telemetry.events.append(ExecutionEvent(
            sequence, "runtime.completed", adapter, target, "investigation", status,
            duration_ms=result.elapsed_ms,
            detail=f"{len(result.collector_results)} collectors; {len(result.findings)} findings",
        ))
        telemetry.status = status
        telemetry.resource_usage = result.resource_usage
        telemetry.forensic_artifacts = [
            f"collector:{item.target}" for item in result.collector_results
        ] + [
            f"finding:{finding.rule_name}" for finding in result.findings
        ]
        return result, telemetry
    except Exception as exc:
        sequence += 1
        telemetry.events.append(ExecutionEvent(
            sequence, "runtime.failed", adapter, target, "investigation", "error",
            duration_ms=int((time.time() - started) * 1000), detail=str(exc),
        ))
        telemetry.status = "error"
        raise
    finally:
        telemetry.completed_at = time.time()
