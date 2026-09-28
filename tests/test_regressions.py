"""Regression tests for defects fixed in v1.0. Run: python -m pytest tests -q"""

import hashlib
import os
import tempfile

import pytest

os.environ["JOCKY_API_TOKEN_HASH"] = hashlib.sha256(b"t" * 43).hexdigest()
os.environ["JOCKY_BYTECODE_KEY"] = "k" * 40
os.environ["JOCKY_DB_PATH"] = tempfile.mktemp(suffix=".db")

from fastapi.testclient import TestClient  # noqa: E402

from jocky.analysis.rules_extended import (  # noqa: E402
    check_high_connection_processes, check_suspicious_startup_items,
)
from jocky.api import agent_store  # noqa: E402
from jocky.api.main import app  # noqa: E402
from jocky.language.lexer import LexError, tokenize  # noqa: E402
from jocky.language.parser import ParseError, parse  # noqa: E402

AUTH = {"Authorization": "Bearer " + "t" * 43}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ── language ──────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("src", [
    'investigation "a" { let x = 2\u00b2; }',            # unicode digit
    'investigation "a" { let x = ' + "9" * 5000 + "; }",  # huge literal
])
def test_lexer_rejects_hostile_numbers(src):
    with pytest.raises(LexError):
        tokenize(src)


def test_parser_bounds_nesting():
    src = 'investigation "a" {' + "if 1 == 1 {" * 50 + "}" * 50 + "}"
    with pytest.raises(ParseError):
        parse(tokenize(src))


# ── rules ─────────────────────────────────────────────────────────────────────
def test_suspicious_port_rule_uses_structured_port():
    ev = {"network_connections": {"connections": [
        {"pid": 1, "remote_port": 4444}, {"pid": 1, "remote_port": "bad"}]}}
    assert any("4444" in f.summary for f in check_high_connection_processes(ev))


def test_quoted_trusted_startup_path_not_flagged():
    ev = {"startup_items": {"items": [{
        "name": "x", "type": "registry_run_key",
        "command": '"C:\\Program Files\\App\\app.exe" --tray'}]}}
    assert check_suspicious_startup_items(ev) == []


# ── API ───────────────────────────────────────────────────────────────────────
def test_auth_required(client):
    assert client.get("/api/investigations").status_code == 401


def test_logged_in_users_count_property(client):
    s = 'investigation "t" { collect logged_in_users; let n = logged_in_users.count; report "r"; }'
    assert client.post("/api/investigations", json={"script": s}, headers=AUTH).status_code == 200


def test_crud_and_immutable_evidence(client):
    s = 'investigation "t" { collect system_info; report "r"; }'
    i = client.post("/api/investigations", json={"script": s}, headers=AUTH).json()["id"]
    r = client.patch(f"/api/investigations/{i}", headers=AUTH,
                     json={"investigation_name": "Renamed", "status": "closed", "notes": "n"})
    assert r.status_code == 200 and r.json()["status"] == "closed"
    assert r.json()["report_json"]["investigation_name"] == "t"      # evidence untouched
    assert client.patch(f"/api/investigations/{i}", headers=AUTH, json={"status": "x"}).status_code == 400
    assert client.delete(f"/api/investigations/{i}", headers=AUTH).status_code == 200
    assert client.get(f"/api/investigations/{i}", headers=AUTH).status_code == 404


def test_oversized_script_rejected(client):
    r = client.post("/api/validate", json={"script": "a" * 30_000}, headers=AUTH)
    assert r.status_code == 422


def test_bytecode_roundtrip_and_tamper(client):
    s = 'investigation "t" { collect system_info; report "r"; }'
    b = client.post("/api/bytecode/compile", json={"script": s}, headers=AUTH).json()["bytecode_b64"]
    assert client.post("/api/bytecode/disasm", json={"bytecode_b64": b}, headers=AUTH).status_code == 200
    bad = ("A" if b[10] != "A" else "B").join([b[:10], b[11:]])
    assert client.post("/api/bytecode/execute", json={"bytecode_b64": bad}, headers=AUTH).status_code == 400


# ── agent store ───────────────────────────────────────────────────────────────
def test_job_cannot_complete_twice_or_fail_after_complete():
    aid, _ = agent_store.register_agent("h", "Linux")
    jid = agent_store.dispatch_job(aid, "s")
    assert agent_store.claim_pending_job(aid).job_id == jid
    assert agent_store.submit_job_result(jid, {"ok": 1})
    assert not agent_store.submit_job_result(jid, {"ok": 2})
    assert not agent_store.submit_job_error(jid, "late")
    assert agent_store.get_job(jid).status == "complete"


def test_job_cap_evicts_finished_jobs(monkeypatch):
    monkeypatch.setattr(agent_store, "_MAX_JOBS", 3)
    agent_store._jobs.clear()
    aid, _ = agent_store.register_agent("h2", "Linux")
    ids = [agent_store.dispatch_job(aid, "s") for _ in range(3)]
    for _ in ids:
        job = agent_store.claim_pending_job(aid)
        agent_store.submit_job_result(job.job_id, {})
    agent_store.dispatch_job(aid, "s")            # would previously raise forever
    assert len(agent_store._jobs) == 3

# ── Windows injection-forensics surface ──────────────────────────────────────
def test_injection_collectors_are_registered_and_safe_on_non_windows():
    from jocky.collectors.registry import is_known_collector, get_collector
    assert is_known_collector("modules")
    assert is_known_collector("threads")
    assert is_known_collector("memory_regions")
    if os.name != "nt":
        assert get_collector("modules")()["supported"] is False
        assert get_collector("threads")()["supported"] is False
        assert get_collector("memory_regions")()["supported"] is False


def test_injection_rules_are_allowlisted():
    from jocky.analysis.registry import is_known_rule
    for name in (
        "suspicious_module_loads", "dll_sideloading",
        "process_hollowing_indicators", "reflective_load_indicators",
        "thread_hijacking_indicators", "injection_correlation",
    ):
        assert is_known_rule(name)


def test_injection_correlation_uses_independent_evidence():
    from jocky.analysis.injection_rules import rule_injection_correlation
    evidence = {
        "modules": {"modules": [{"pid": 123, "is_user_writable": True}]},
        "memory_regions": {"regions": [{"pid": 123, "is_private_executable": True}]},
    }
    findings = rule_injection_correlation(evidence)
    assert len(findings) == 1
    assert findings[0].rule_name == "injection_correlation"
    assert findings[0].related_evidence["pid"] == 123
