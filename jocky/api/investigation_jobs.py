"""Bounded background execution for long-running local investigations."""
from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from uuid import uuid4

from jocky.collectors.network_artifacts import set_network_source, reset_network_source
from jocky.language.interpreter import InterpreterError, run_investigation
from jocky.reports.builder import build_report
from jocky.storage.database import save_investigation
from jocky.storage.audit import audit_event

_MAX_JOBS = 64
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="jocky-investigation")
_lock = threading.Lock()
_jobs: dict[str, dict] = {}
_cancel_events: dict[str, threading.Event] = {}


def _trim_locked() -> None:
    if len(_jobs) <= _MAX_JOBS:
        return
    finished = [k for k, v in _jobs.items() if v.get("status") in {"complete", "partial", "error", "cancelled"}]
    for key in finished[: max(0, len(_jobs) - _MAX_JOBS)]:
        _jobs.pop(key, None)


def submit(investigation, script: str, network_source_id: str | None) -> str:
    job_id = uuid4().hex
    with _lock:
        _jobs[job_id] = {
            "id": job_id, "status": "queued", "progress": 0,
            "message": "Queued for execution.", "investigation_id": None,
            "error": None, "started_at": None, "finished_at": None,
            "resource_usage": {},
        }
        _cancel_events[job_id] = threading.Event()
        _trim_locked()
    _executor.submit(_worker, job_id, investigation, script, network_source_id)
    return job_id


def _update(job_id: str, **patch) -> None:
    with _lock:
        if job_id in _jobs:
            _jobs[job_id].update(patch)


def _worker(job_id, investigation, script, network_source_id):
    started_at = datetime.now(timezone.utc)
    token = set_network_source(network_source_id)
    cancel_event = _cancel_events.get(job_id, threading.Event())
    try:
        # Close the queued/cancelled race: cancellation may arrive after submit()
        # but before this worker gets scheduled. Never resurrect such a job as
        # running.
        with _lock:
            current = _jobs.get(job_id)
            if current is None:
                return
            if current.get("status") == "cancelled" or cancel_event.is_set():
                current.update(
                    status="cancelled", progress=100,
                    message="Investigation cancelled before execution.",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
                return
            current.update(status="running", progress=5, message="Starting investigation.", started_at=started_at.isoformat())

        def report_progress(progress: int, message: str) -> None:
            # Reserve the final 15% for report hashing, persistence and audit.
            _update(job_id, progress=max(5, min(85, int(progress))), message=message)

        result = run_investigation(
            investigation,
            progress_callback=report_progress,
            cancel_check=cancel_event.is_set,
        )
        if result.execution_status == "cancelled":
            _update(
                job_id, status="cancelled", progress=100,
                message=result.termination_reason or "Investigation cancelled.",
                finished_at=datetime.now(timezone.utc).isoformat(),
                resource_usage=result.resource_usage,
            )
            return
        if cancel_event.is_set():
            _update(job_id, status="cancelled", progress=100, message="Investigation cancelled before persistence.", finished_at=datetime.now(timezone.utc).isoformat(), resource_usage=result.resource_usage)
            return
        _update(job_id, progress=90, message="Building integrity-protected report.")
        finished_at = datetime.now(timezone.utc)
        script_hash = hashlib.sha256(script.encode("utf-8")).hexdigest()
        bytecode_hash = None
        try:
            from jocky.language.bytecode import compile_investigation, verify_and_load
            blob = compile_investigation(investigation); verify_and_load(blob)
            bytecode_hash = hashlib.sha256(blob).hexdigest()
        except Exception:
            pass
        report = build_report(result, started_at, finished_at, script_hash=script_hash, bytecode_hash=bytecode_hash)
        report_dict = asdict(report)
        _update(job_id, progress=95, message="Persisting investigation and provenance.")
        new_id = save_investigation(
            investigation_name=report.investigation_name,
            endpoint_hostname=report.endpoint_hostname,
            started_at=report.started_at,
            finished_at=report.finished_at,
            findings_count=len(report.findings),
            report=report_dict,
        )
        audit_event("investigation_completed", report=report, investigation_id=new_id, details={"mode": "background", "job_id": job_id})
        _update(job_id, progress=98, message="Writing audit trail.")
        final_status = "complete" if result.execution_status == "complete" else "partial"
        final_message = "Investigation completed." if final_status == "complete" else (result.termination_reason or "Investigation reached its runtime limit; partial evidence was preserved.")
        _update(job_id, status=final_status, progress=100,
                message=final_message, investigation_id=new_id,
                findings_count=len(report.findings), resource_usage=result.resource_usage,
                finished_at=datetime.now(timezone.utc).isoformat())
    except InterpreterError as exc:
        _update(job_id, status="error", progress=100, message="Investigation failed.", error=str(exc), finished_at=datetime.now(timezone.utc).isoformat())
    except Exception as exc:
        _update(job_id, status="error", progress=100, message="Investigation failed.", error=f"{type(exc).__name__}: {exc}", finished_at=datetime.now(timezone.utc).isoformat())
    finally:
        reset_network_source(token)
        with _lock:
            _cancel_events.pop(job_id, None)


def get(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def cancel(job_id: str) -> dict | None:
    """Request cancellation. A running collector is allowed to finish in its daemon worker,
    but no subsequent collector/analysis work is scheduled and its result is not persisted."""
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return None
        if job.get("status") in {"complete", "partial", "error", "cancelled"}:
            return dict(job)
        event = _cancel_events.get(job_id)
        if event:
            event.set()
        if job.get("status") == "queued":
            job.update(status="cancelled", progress=100, message="Investigation cancelled before execution.", finished_at=datetime.now(timezone.utc).isoformat())
        else:
            job.update(status="cancelling", message="Cancellation requested; stopping after the active bounded operation.")
        return dict(job)
