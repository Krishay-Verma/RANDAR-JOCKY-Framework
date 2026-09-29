"""Persistent remote-agent registry and bounded job store for RANDAR V1.7."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_MAX_AGENTS = 100
_MAX_JOBS = 1000
_JOB_TTL_SECONDS = 3600
_ROOT = Path(__file__).resolve().parents[2]
_DB_PATH = Path(os.environ.get("RANDAR_DB_PATH") or os.environ.get("JOCKY_DB_PATH") or (_ROOT / "jocky.db"))

@dataclass
class RegisteredAgent:
    agent_id: str
    hostname: str
    platform: str
    registered_at: str
    last_seen: Optional[str]
    token_hash: str
    capabilities: list[str]
    revoked_at: Optional[str] = None

@dataclass
class AgentJob:
    job_id: str
    agent_id: str
    script: str
    status: str
    created_at: str
    claimed_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[dict]
    error: Optional[str]
    nonce: str = ""
    expires_at: str = ""
    signature: str = ""
    cancelled_at: Optional[str] = None

_lock = threading.RLock()
_agents: dict[str, RegisteredAgent] = {}
_jobs: dict[str, AgentJob] = {}
_initialized = False


def _conn():
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(_DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def init_persistence() -> None:
    global _initialized
    with _lock:
        if _initialized:
            return
        c = _conn()
        try:
            c.execute("""CREATE TABLE IF NOT EXISTS remote_agents (
                agent_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, platform TEXT NOT NULL,
                registered_at TEXT NOT NULL, last_seen TEXT, token_hash TEXT NOT NULL,
                capabilities TEXT NOT NULL DEFAULT '[]', revoked_at TEXT
            )""")
            c.commit()
            rows = c.execute("SELECT * FROM remote_agents").fetchall()
            _agents.clear()
            for r in rows:
                _agents[r["agent_id"]] = RegisteredAgent(
                    r["agent_id"], r["hostname"], r["platform"], r["registered_at"],
                    r["last_seen"], r["token_hash"], json.loads(r["capabilities"] or "[]"), r["revoked_at"]
                )
            _initialized = True
        finally:
            c.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _persist(a: RegisteredAgent) -> None:
    c = _conn()
    try:
        c.execute("""INSERT INTO remote_agents(agent_id,hostname,platform,registered_at,last_seen,token_hash,capabilities,revoked_at)
                     VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET hostname=excluded.hostname,
                     platform=excluded.platform,last_seen=excluded.last_seen,token_hash=excluded.token_hash,
                     capabilities=excluded.capabilities,revoked_at=excluded.revoked_at""",
                  (a.agent_id,a.hostname,a.platform,a.registered_at,a.last_seen,a.token_hash,json.dumps(sorted(set(a.capabilities))),a.revoked_at))
        c.commit()
    finally: c.close()


def register_agent(hostname: str, platform: str) -> tuple[str, str]:
    init_persistence()
    with _lock:
        active = sum(1 for a in _agents.values() if not a.revoked_at)
        if active >= _MAX_AGENTS:
            raise ValueError(f"Maximum agent count ({_MAX_AGENTS}) reached.")
        aid, token = secrets.token_urlsafe(8), secrets.token_urlsafe(32)
        a = RegisteredAgent(aid, hostname, platform, _now(), None, _hash(token), [])
        _agents[aid] = a
        _persist(a)
        return aid, token


def get_agent(agent_id: str) -> Optional[RegisteredAgent]:
    init_persistence()
    with _lock:
        return _agents.get(agent_id)


def list_agents(include_revoked: bool = False) -> list[dict]:
    init_persistence()
    with _lock:
        values = [a for a in _agents.values() if include_revoked or not a.revoked_at]
        return [{"agent_id":a.agent_id,"hostname":a.hostname,"platform":a.platform,
                 "registered_at":a.registered_at,"last_seen":a.last_seen,
                 "capabilities":sorted(a.capabilities),"revoked_at":a.revoked_at,
                 "status": "revoked" if a.revoked_at else ("online" if a.last_seen and _online(a.last_seen) else "offline")}
                for a in values]


def _online(last_seen: str) -> bool:
    try: return (datetime.now(timezone.utc) - datetime.fromisoformat(last_seen)).total_seconds() <= 90
    except ValueError: return False


def verify_agent_token(agent_id: str, token: str) -> bool:
    a = get_agent(agent_id)
    if a is None or a.revoked_at:
        hmac.compare_digest(_hash(token), _hash("x")); return False
    return hmac.compare_digest(_hash(token), a.token_hash)


def touch_agent(agent_id: str, capabilities: Optional[list[str]] = None) -> None:
    a = get_agent(agent_id)
    if not a or a.revoked_at: return
    with _lock:
        a.last_seen = _now()
        if capabilities is not None:
            a.capabilities = sorted(set(str(x) for x in capabilities))[:200]
        _persist(a)


def update_capabilities(agent_id: str, capabilities: list[str]) -> bool:
    a = get_agent(agent_id)
    if not a or a.revoked_at: return False
    touch_agent(agent_id, capabilities)
    return True


def _job_signature(agent: RegisteredAgent, job_id: str, nonce: str, expires_at: str) -> str:
    body = f"{job_id}|{agent.agent_id}|{nonce}|{expires_at}"
    return hmac.new(bytes.fromhex(agent.token_hash), body.encode(), hashlib.sha256).hexdigest()


def dispatch_job(agent_id: str, script: str) -> str:
    a = get_agent(agent_id)
    if not a or a.revoked_at: raise ValueError("Agent not found or revoked.")
    with _lock:
        if len(_jobs) >= _MAX_JOBS:
            finished = sorted((j for j in _jobs.values() if j.status in ("complete","failed","cancelled")), key=lambda j:j.created_at)
            if not finished: raise ValueError(f"Maximum job count ({_MAX_JOBS}) reached.")
            del _jobs[finished[0].job_id]
        jid, nonce = secrets.token_urlsafe(12), secrets.token_urlsafe(18)
        created = _now(); expires = (datetime.now(timezone.utc)+timedelta(seconds=_JOB_TTL_SECONDS)).isoformat()
        job = AgentJob(jid,agent_id,script,"pending",created,None,None,None,None,nonce,expires,_job_signature(a,jid,nonce,expires))
        _jobs[jid] = job
        return jid


def claim_pending_job(agent_id: str) -> Optional[AgentJob]:
    with _lock:
        now = datetime.now(timezone.utc)
        for j in sorted((x for x in _jobs.values() if x.agent_id==agent_id and x.status=="pending"), key=lambda x:x.created_at):
            if j.expires_at and datetime.fromisoformat(j.expires_at) <= now:
                j.status="failed"; j.error="Job expired before claim."; j.completed_at=_now(); continue
            j.status="running"; j.claimed_at=_now(); return j
        return None


def cancel_job(agent_id: str, job_id: str) -> bool:
    with _lock:
        j=_jobs.get(job_id)
        if not j or j.agent_id!=agent_id or j.status not in ("pending","running"): return False
        j.status="cancelled"; j.cancelled_at=_now(); j.completed_at=j.cancelled_at; return True


def is_cancelled(job_id: str) -> bool:
    with _lock:
        j=_jobs.get(job_id); return bool(j and j.status=="cancelled")


def submit_job_result(job_id: str, result: dict) -> bool:
    with _lock:
        j=_jobs.get(job_id)
        if not j or j.status!="running": return False
        j.status="complete"; j.completed_at=_now(); j.result=result; return True


def submit_job_error(job_id: str, error: str) -> bool:
    with _lock:
        j=_jobs.get(job_id)
        if not j or j.status!="running": return False
        j.status="failed"; j.completed_at=_now(); j.error=error[:2000]; return True


def get_job(job_id: str) -> Optional[AgentJob]:
    with _lock: return _jobs.get(job_id)


def list_jobs(agent_id: Optional[str]=None) -> list[dict]:
    with _lock: jobs=list(_jobs.values())
    if agent_id: jobs=[j for j in jobs if j.agent_id==agent_id]
    return [{"job_id":j.job_id,"agent_id":j.agent_id,"status":j.status,"created_at":j.created_at,
             "claimed_at":j.claimed_at,"completed_at":j.completed_at,"has_result":j.result is not None,
             "error":j.error,"expires_at":j.expires_at,"signature":j.signature,"cancelled_at":j.cancelled_at}
            for j in sorted(jobs,key=lambda x:x.created_at,reverse=True)]


def delete_agent(agent_id: str) -> bool:
    a=get_agent(agent_id)
    if not a: return False
    with _lock:
        a.revoked_at=_now(); _persist(a)
        for j in _jobs.values():
            if j.agent_id==agent_id and j.status in ("pending","running"): j.status="cancelled"; j.cancelled_at=_now(); j.completed_at=j.cancelled_at
    return True


def delete_job(agent_id: str, job_id: str) -> bool:
    with _lock:
        j=_jobs.get(job_id)
        if not j or j.agent_id!=agent_id: return False
        del _jobs[job_id]; return True
