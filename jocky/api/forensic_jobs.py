"""Background execution for standalone forensic scans.

Forensic workspace scans must not be coupled to the lifetime of a React route or
an HTTP connection.  This module owns a bounded process-local job queue; the
worker persists the normal RANDAR investigation before publishing completion.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from uuid import uuid4

_MAX_JOBS = 32
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="randar-forensic")
_lock = threading.Lock()
_jobs: dict[str, dict] = {}
_ALLOWED = {"memory", "driver", "persistence"}


def _trim_locked() -> None:
    if len(_jobs) <= _MAX_JOBS:
        return
    finished = [
        key for key, value in _jobs.items()
        if value.get("status") in {"complete", "error"}
    ]
    for key in finished[: max(0, len(_jobs) - _MAX_JOBS)]:
        _jobs.pop(key, None)


def submit(scan_type: str) -> str:
    if scan_type not in _ALLOWED:
        raise ValueError(f"Unsupported forensic scan type: {scan_type}")
    job_id = uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        _jobs[job_id] = {
            "job_id": job_id,
            "scan_type": scan_type,
            "status": "queued",
            "message": "Queued for background execution.",
            "investigation_id": None,
            "error": None,
            "started_at": None,
            "finished_at": None,
            "created_at": now,
            "result": None,
        }
        _trim_locked()
    _executor.submit(_worker, job_id, scan_type)
    return job_id


def _update(job_id: str, **patch) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job:
            job.update(patch)


def _worker(job_id: str, scan_type: str) -> None:
    started = datetime.now(timezone.utc).isoformat()
    _update(job_id, status="running", message="Collecting forensic evidence.", started_at=started)
    try:
        # Lazy imports keep the scan route modules independent from this job
        # manager and avoid circular imports during FastAPI startup.
        if scan_type == "memory":
            from jocky.api.bytecode_routes import memory_forensics_scan
            result = memory_forensics_scan()
        elif scan_type == "driver":
            from jocky.api.driver_routes import driver_forensics_scan
            result = driver_forensics_scan()
        else:
            from jocky.api.persistence_routes import persistence_forensics_scan
            result = persistence_forensics_scan()
        finished = datetime.now(timezone.utc).isoformat()
        _update(
            job_id,
            status="complete",
            message="Forensic scan completed and was persisted as an investigation.",
            investigation_id=result.get("investigation_id"),
            finished_at=finished,
            result=result,
        )
    except Exception as exc:
        _update(
            job_id,
            status="error",
            message="Forensic scan failed.",
            error=f"{type(exc).__name__}: {exc}",
            finished_at=datetime.now(timezone.utc).isoformat(),
        )


def get(job_id: str) -> dict | None:
    with _lock:
        value = _jobs.get(job_id)
        if value is None:
            return None
        # Copy the result reference intentionally: result is immutable after the
        # worker publishes it, and this avoids mutating the job store on reads.
        return dict(value)
