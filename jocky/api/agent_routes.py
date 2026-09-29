"""
API routes for remote agent management.

Two routers with different auth requirements:

  management_router  — requires investigator bearer token
    POST   /api/agents/register
    GET    /api/agents
    POST   /api/agents/{agent_id}/jobs
    GET    /api/agents/{agent_id}/jobs
    GET    /api/agents/{agent_id}/jobs/{job_id}/result

  agent_router  — requires per-agent token (scoped, cannot reach
                  investigator routes)
    GET    /api/agents/{agent_id}/jobs/pending
    POST   /api/agents/{agent_id}/jobs/{job_id}/result
    POST   /api/agents/{agent_id}/jobs/{job_id}/error
    POST   /api/agents/{agent_id}/heartbeat

Threat surface closed:
  - Compromised agent cannot read other investigations or other agents
  - Script is lexed and parsed before dispatch — malformed scripts rejected
  - Job claiming atomic — no double-dispatch under concurrent polls
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from jocky.api import agent_store
from jocky.api.auth import verify_token
from jocky.reports.report import compute_report_hash

# ── Schemas ────────────────────────────────────────────────────────────────────

class RegisterAgentRequest(BaseModel):
    hostname: str = Field(max_length=253)
    platform: str = Field(max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=200)


class HeartbeatPayload(BaseModel):
    capabilities: list[str] = Field(default_factory=list, max_length=200)


class DispatchJobRequest(BaseModel):
    script: str = Field(max_length=20_000)


class JobResultPayload(BaseModel):
    collector_results: list[dict]
    findings:          list[dict]
    report_name:       Optional[str] = None
    started_at:        str
    finished_at:       str


class JobErrorPayload(BaseModel):
    error: str


# ── Agent-token auth dependency ────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


def _require_agent_auth(
    agent_id: str,
    credentials: Annotated[
        Optional[HTTPAuthorizationCredentials],
        Depends(_bearer),
    ] = None,
) -> None:
    """
    FastAPI dependency for agent-scoped endpoints.

    Validates the per-agent token against the stored digest.
    The agent_id is injected from the route path parameter automatically.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not agent_store.verify_agent_token(agent_id, credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Management router (investigator token) ─────────────────────────────────────

management_router = APIRouter(
    dependencies=[Depends(verify_token)],
    tags=["agents"],
)


@management_router.post("/api/agents/register")
def register_agent(payload: RegisterAgentRequest) -> dict:
    """
    Register a new remote agent.
    Returns agent_id and a one-time agent token — store it immediately.
    """
    if not payload.hostname.strip():
        raise HTTPException(status_code=400, detail="hostname is required.")
    if not payload.platform.strip():
        raise HTTPException(status_code=400, detail="platform is required.")

    try:
        agent_id, token = agent_store.register_agent(
            hostname=payload.hostname.strip(),
            platform=payload.platform.strip(),
        )
        if payload.capabilities:
            agent_store.update_capabilities(agent_id, payload.capabilities)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    agent = agent_store.get_agent(agent_id)
    return {
        "agent_id":    agent_id,
        "agent_token": token,
        "capabilities": agent.capabilities if agent else [],
        "warning":     "Store this token securely — it is shown only once.",
    }


@management_router.get("/api/agents")
def list_agents() -> list[dict]:
    return agent_store.list_agents()


@management_router.get("/api/agents/{agent_id}/capabilities")
def agent_capabilities(agent_id: str) -> dict:
    agent = agent_store.get_agent(agent_id)
    if agent is None or agent.revoked_at:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return {"agent_id": agent_id, "capabilities": sorted(agent.capabilities), "last_seen": agent.last_seen}


@management_router.post("/api/agents/{agent_id}/jobs")
def dispatch_job(agent_id: str, payload: DispatchJobRequest) -> dict:
    """
    Dispatch a JOCKY script to a registered agent.
    The script is validated before being queued.
    """
    if agent_store.get_agent(agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found.")

    # Validate the script before queuing it to the agent.
    from jocky.language.lexer import LexError, tokenize
    from jocky.language.parser import ParseError, parse
    try:
        tokens = tokenize(payload.script)
        parse(tokens)
    except (LexError, ParseError) as exc:
        raise HTTPException(status_code=400, detail=f"Script error: {exc}")

    try:
        job_id = agent_store.dispatch_job(agent_id, payload.script)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job = agent_store.get_job(job_id)
    return {"job_id": job_id, "agent_id": agent_id, "status": "pending",
            "expires_at": job.expires_at if job else None, "signature": job.signature if job else None}


@management_router.get("/api/agents/{agent_id}/jobs")
def list_agent_jobs(agent_id: str) -> list[dict]:
    if agent_store.get_agent(agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return agent_store.list_jobs(agent_id=agent_id)


@management_router.get("/api/agents/{agent_id}/jobs/{job_id}/result")
def get_job_result(agent_id: str, job_id: str) -> dict:
    """Retrieve the stored result for a completed job."""
    job = agent_store.get_job(job_id)
    if job is None or job.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {
        "job_id":       job.job_id,
        "agent_id":     job.agent_id,
        "status":       job.status,
        "created_at":   job.created_at,
        "claimed_at":   job.claimed_at,
        "completed_at": job.completed_at,
        "result":       job.result,
        "error":        job.error,
    }


@management_router.delete("/api/agents/{agent_id}")
def revoke_agent(agent_id: str) -> dict:
    """Revoke an agent. Its token stops working immediately."""
    if not agent_store.delete_agent(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found.")
    return {"deleted": True}


@management_router.post("/api/agents/{agent_id}/jobs/{job_id}/cancel")
def cancel_agent_job(agent_id: str, job_id: str) -> dict:
    if not agent_store.cancel_job(agent_id, job_id):
        raise HTTPException(status_code=409, detail="Job cannot be cancelled in its current state.")
    return {"cancelled": True, "job_id": job_id}


@management_router.delete("/api/agents/{agent_id}/jobs/{job_id}")
def delete_agent_job(agent_id: str, job_id: str) -> dict:
    if not agent_store.delete_job(agent_id, job_id):
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"deleted": True}


@management_router.post("/api/agents/{agent_id}/jobs/{job_id}/import")
def import_job_result(agent_id: str, job_id: str) -> dict:
    """Persist a completed agent job as a stored investigation."""
    from jocky.storage.database import save_investigation
    job = agent_store.get_job(job_id)
    if job is None or job.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Job not found.")
    if job.status != "complete" or not job.result:
        raise HTTPException(status_code=409, detail="Job has no completed result.")
    r = job.result
    name = r.get("report_name") or f"Agent job {job_id[:8]}"
    report = {
        "investigation_name": name,
        "endpoint_hostname": str(r.get("hostname", "unknown")).upper(),
        "started_at": r["started_at"],
        "finished_at": r["finished_at"],
        "collector_results": r["collector_results"],
        "analysis_results": r.get("analysis_results", []),
        "findings": r["findings"],
        "collector_errors": [
            {"target": cr.get("target"), "error": cr.get("error")}
            for cr in r.get("collector_results", [])
            if cr.get("status") == "error"
        ],
        "report_name": r.get("report_name"),
        "script_hash": r.get("script_hash"),
        "source": {"type": "agent", "agent_id": agent_id, "job_id": job_id},
    }
    from jocky.reports.report import Report, CollectorResult, AnalysisResult, Finding
    report_model = Report(
        investigation_name=report["investigation_name"],
        endpoint_hostname=report["endpoint_hostname"],
        started_at=report["started_at"],
        finished_at=report["finished_at"],
        collector_results=[CollectorResult(**cr) for cr in report["collector_results"]],
        analysis_results=[AnalysisResult(**ar) for ar in report.get("analysis_results", [])],
        findings=[Finding(**f) for f in report["findings"]],
        collector_errors=report["collector_errors"],
        report_name=report["report_name"],
        script_hash=report["script_hash"],
        source=report["source"],
        product_name=report.get("product_name", "RANDAR"),
        product_version=report.get("product_version", "1.9.2"),
        dsl_name=report.get("dsl_name", "JOCKY"),
        dsl_version=report.get("dsl_version", "1.5"),
        bytecode_hash=report.get("bytecode_hash"),
        timeline=report.get("timeline", []),
        integrity_version=report.get("integrity_version", 1),
    )
    report["report_hash"] = compute_report_hash(report_model)
    new_id = save_investigation(
        investigation_name=name,
        endpoint_hostname=report["endpoint_hostname"],
        started_at=report["started_at"],
        finished_at=report["finished_at"],
        findings_count=len(report["findings"]),
        report=report,
    )
    return {"id": new_id}


# ── Agent router (per-agent token) ─────────────────────────────────────────────

agent_router = APIRouter(tags=["agent-operations"])


@agent_router.get("/api/agents/{agent_id}/jobs/pending")
def poll_pending_job(
    agent_id: str,
    _: None = Depends(_require_agent_auth),
) -> dict:
    """
    Agent polls this endpoint to receive its next pending job.
    Returns {"job_id": null, "script": null} when nothing is queued.
    Job is atomically marked 'running' on claim.
    """
    agent_store.touch_agent(agent_id)
    job = agent_store.claim_pending_job(agent_id)
    if job is None:
        return {"job_id": None, "script": None}
    return {"job_id": job.job_id, "script": job.script, "expires_at": job.expires_at, "nonce": job.nonce, "signature": job.signature}


@agent_router.get("/api/agents/{agent_id}/jobs/{job_id}/status")
def agent_job_status(agent_id: str, job_id: str, _: None = Depends(_require_agent_auth)) -> dict:
    job = agent_store.get_job(job_id)
    if job is None or job.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Job not found.")
    agent_store.touch_agent(agent_id)
    return {"job_id": job.job_id, "status": job.status, "expires_at": job.expires_at}


@agent_router.post("/api/agents/{agent_id}/jobs/{job_id}/result")
def submit_job_result(
    agent_id: str,
    job_id:   str,
    payload:  JobResultPayload,
    _: None = Depends(_require_agent_auth),
) -> dict:
    """Agent submits a completed investigation result."""
    agent_store.touch_agent(agent_id)

    job = agent_store.get_job(job_id)
    if job is None or job.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Job not found.")

    agent_info = agent_store.get_agent(agent_id)
    result_dict = {
        **payload.model_dump(),
        "agent_id": agent_id,
        "hostname": agent_info.hostname if agent_info else "unknown",
    }
    if not agent_store.submit_job_result(job_id, result_dict):
        raise HTTPException(
            status_code=409, detail="Job is not in 'running' state."
        )
    return {"status": "accepted", "job_id": job_id}


@agent_router.post("/api/agents/{agent_id}/jobs/{job_id}/error")
def submit_job_error(
    agent_id: str,
    job_id:   str,
    payload:  JobErrorPayload,
    _: None = Depends(_require_agent_auth),
) -> dict:
    """Agent reports that a job failed with an error."""
    agent_store.touch_agent(agent_id)

    job = agent_store.get_job(job_id)
    if job is None or job.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Job not found.")

    if not agent_store.submit_job_error(job_id, payload.error[:2000]):
        raise HTTPException(
            status_code=409, detail="Job is not in 'running' state."
        )
    return {"status": "acknowledged", "job_id": job_id}


@agent_router.post("/api/agents/{agent_id}/heartbeat")
def heartbeat(
    agent_id: str,
    payload: HeartbeatPayload | None = None,
    _: None = Depends(_require_agent_auth),
) -> dict:
    """Agent liveness ping and capability negotiation."""
    agent_store.touch_agent(agent_id, (payload.capabilities if payload else None))
    agent = agent_store.get_agent(agent_id)
    return {"status": "ok", "capabilities": sorted(agent.capabilities) if agent else []}