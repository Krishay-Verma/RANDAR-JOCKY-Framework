"""Authenticated background-job API for standalone forensic workspaces."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from jocky.api.auth import verify_token
from jocky.api.forensic_jobs import get, submit

router = APIRouter(dependencies=[Depends(verify_token)], tags=["forensic-jobs"])


@router.post("/api/forensic-jobs/{scan_type}")
def create_forensic_job(scan_type: str) -> dict:
    if scan_type not in {"memory", "driver", "persistence"}:
        raise HTTPException(status_code=404, detail="Unknown forensic scan type.")
    return {"job_id": submit(scan_type), "scan_type": scan_type, "status": "queued"}


@router.get("/api/forensic-jobs/{job_id}")
def get_forensic_job(job_id: str) -> dict:
    job = get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Forensic job not found.")
    return job
