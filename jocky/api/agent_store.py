"""
In-memory store for registered agents and dispatched jobs.

All mutations are protected by a single threading.Lock so this is
safe under FastAPI's thread-pool executor for synchronous routes.

Security notes:
  - Agent tokens are stored as SHA-256 digests only — plaintext shown once
  - All token comparisons use hmac.compare_digest (constant-time)
  - Job claiming is atomic — two concurrent polls cannot claim the same job
  - Hard caps on agent and job counts prevent memory exhaustion
"""

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_MAX_AGENTS = 100
_MAX_JOBS   = 1000


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class RegisteredAgent:
    agent_id:      str
    hostname:      str
    platform:      str
    registered_at: str
    last_seen:     Optional[str]
    token_hash:    str        # SHA-256 hex digest — plaintext never stored


@dataclass
class AgentJob:
    job_id:       str
    agent_id:     str
    script:       str
    status:       str         # "pending" | "running" | "complete" | "failed"
    created_at:   str
    claimed_at:   Optional[str]
    completed_at: Optional[str]
    result:       Optional[dict]
    error:        Optional[str]


# ── State ──────────────────────────────────────────────────────────────────────

_lock:   threading.Lock          = threading.Lock()
_agents: dict[str, RegisteredAgent] = {}
_jobs:   dict[str, AgentJob]        = {}


# ── Agent management ───────────────────────────────────────────────────────────

def register_agent(hostname: str, platform: str) -> tuple[str, str]:
    """
    Create a new agent record.
    Returns (agent_id, plaintext_token) — token is shown to caller once only.
    """
    with _lock:
        if len(_agents) >= _MAX_AGENTS:
            raise ValueError(f"Maximum agent count ({_MAX_AGENTS}) reached.")

        agent_id = secrets.token_urlsafe(8)
        token    = secrets.token_urlsafe(32)

        _agents[agent_id] = RegisteredAgent(
            agent_id      = agent_id,
            hostname      = hostname,
            platform      = platform,
            registered_at = _now(),
            last_seen     = None,
            token_hash    = _hash(token),
        )

    return agent_id, token


def get_agent(agent_id: str) -> Optional[RegisteredAgent]:
    with _lock:
        return _agents.get(agent_id)


def list_agents() -> list[dict]:
    with _lock:
        return [
            {
                "agent_id":      a.agent_id,
                "hostname":      a.hostname,
                "platform":      a.platform,
                "registered_at": a.registered_at,
                "last_seen":     a.last_seen,
            }
            for a in _agents.values()
        ]


def verify_agent_token(agent_id: str, token: str) -> bool:
    """Constant-time token verification."""
    agent = get_agent(agent_id)
    if agent is None:
        hmac.compare_digest(_hash(token), _hash("x"))  # equalise timing
        return False
    return hmac.compare_digest(_hash(token), agent.token_hash)


def touch_agent(agent_id: str) -> None:
    """Update last_seen. Called on every authenticated agent request."""
    with _lock:
        agent = _agents.get(agent_id)
        if agent:
            agent.last_seen = _now()


# ── Job management ─────────────────────────────────────────────────────────────

def dispatch_job(agent_id: str, script: str) -> str:
    """Create a pending job for an agent. Returns job_id."""
    with _lock:
        if len(_jobs) >= _MAX_JOBS:
            # Evict the oldest finished job; never drop pending/running work.
            finished = sorted(
                (j for j in _jobs.values() if j.status in ("complete", "failed")),
                key=lambda j: j.created_at,
            )
            if not finished:
                raise ValueError(f"Maximum job count ({_MAX_JOBS}) reached.")
            del _jobs[finished[0].job_id]

        job_id = secrets.token_urlsafe(12)
        _jobs[job_id] = AgentJob(
            job_id       = job_id,
            agent_id     = agent_id,
            script       = script,
            status       = "pending",
            created_at   = _now(),
            claimed_at   = None,
            completed_at = None,
            result       = None,
            error        = None,
        )

    return job_id


def claim_pending_job(agent_id: str) -> Optional[AgentJob]:
    """
    Atomically claim the oldest pending job for this agent.
    Returns the job or None. The lock ensures only one poller wins.
    """
    with _lock:
        candidates = sorted(
            (j for j in _jobs.values()
             if j.agent_id == agent_id and j.status == "pending"),
            key=lambda j: j.created_at,
        )
        if not candidates:
            return None
        job = candidates[0]
        job.status     = "running"
        job.claimed_at = _now()
        return job


def submit_job_result(job_id: str, result: dict) -> bool:
    """Complete a job. Only a 'running' job may transition (atomic)."""
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job.status != "running":
            return False
        job.status       = "complete"
        job.completed_at = _now()
        job.result       = result
        return True


def submit_job_error(job_id: str, error: str) -> bool:
    """Fail a job. Only a 'running' job may transition (atomic)."""
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job.status != "running":
            return False
        job.status       = "failed"
        job.completed_at = _now()
        job.error        = error
        return True


def get_job(job_id: str) -> Optional[AgentJob]:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(agent_id: Optional[str] = None) -> list[dict]:
    with _lock:
        jobs = list(_jobs.values())
    if agent_id:
        jobs = [j for j in jobs if j.agent_id == agent_id]
    return [
        {
            "job_id":       j.job_id,
            "agent_id":     j.agent_id,
            "status":       j.status,
            "created_at":   j.created_at,
            "claimed_at":   j.claimed_at,
            "completed_at": j.completed_at,
            "has_result":   j.result is not None,
            "error":        j.error,
        }
        for j in sorted(jobs, key=lambda j: j.created_at, reverse=True)
    ]


def delete_agent(agent_id: str) -> bool:
    """Revoke an agent: removes it and every job it owns."""
    with _lock:
        if agent_id not in _agents:
            return False
        del _agents[agent_id]
        for jid in [j.job_id for j in _jobs.values() if j.agent_id == agent_id]:
            del _jobs[jid]
        return True


def delete_job(agent_id: str, job_id: str) -> bool:
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job.agent_id != agent_id:
            return False
        del _jobs[job_id]
        return True


# ── Helpers ────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()