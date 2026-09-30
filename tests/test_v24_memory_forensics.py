from jocky.analysis.memory_forensics import build_memory_forensics, build_memory_forensics_findings
from jocky.language.execution import RUNTIME_MODE, RUNTIME_VERSION


def _evidence():
    return {
        "processes": {"processes": [{"pid": 123, "name": "sample.exe", "exe_path": r"C:\\sample.exe"}]},
        "modules": {"modules": [{"pid": 123, "module_name": "sample.exe", "is_user_writable": False}]},
        "threads": {"threads": [{"pid": 123, "process_name": "sample.exe", "thread_id": 7, "start_address": 0x1200}]},
        "memory_regions": {"supported": True, "regions": [{
            "pid": 123, "process_name": "sample.exe", "base_address": 0x1000,
            "region_size": 0x1000, "protect": 0x40, "protect_name": "EXECUTE_READWRITE",
            "is_executable": True, "is_private": True, "is_private_executable": True,
        }]},
    }


def test_memory_forensics_snapshot_is_deterministic():
    a = build_memory_forensics(_evidence())
    b = build_memory_forensics(_evidence())
    assert a["snapshot_hash"] == b["snapshot_hash"]
    assert a["summary"]["private_executable_regions"] == 1
    assert a["summary"]["writable_executable_regions"] == 1
    assert a["thread_hits"][0]["pid"] == 123


def test_v24_runtime_identity():
    assert RUNTIME_VERSION == "2.4.0"
    assert RUNTIME_MODE == "in-memory-interpreter"


def test_memory_forensics_api_requires_auth_and_returns_snapshot():
    import hashlib
    import os
    os.environ.setdefault("JOCKY_API_TOKEN_HASH", hashlib.sha256(b"t" * 43).hexdigest())
    from fastapi.testclient import TestClient
    from jocky.api.main import app
    auth = {"Authorization": "Bearer " + "t" * 43}
    with TestClient(app) as client:
        assert client.post("/api/memory-forensics/scan").status_code == 401
        response = client.post("/api/memory-forensics/scan", json={}, headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "3.0.0"
    assert len(body["snapshot_hash"]) == 64


def test_memory_forensics_findings_are_emitted_for_non_context_processes():
    report = build_memory_forensics(_evidence())
    findings = build_memory_forensics_findings(report)
    assert findings
    assert findings[0].rule_name == "memory_forensics_correlation"
    assert findings[0].related_evidence["pid"] == 123
    assert findings[0].related_evidence["writable_executable_region_count"] == 1


def test_memory_forensics_api_surfaces_correlation_findings(monkeypatch):
    import hashlib
    import os
    os.environ.setdefault("JOCKY_API_TOKEN_HASH", hashlib.sha256(b"t" * 43).hexdigest())
    import jocky.collectors.registry as collector_registry
    from fastapi.testclient import TestClient
    from jocky.api.main import app

    evidence = _evidence()
    original = collector_registry.get_collector
    monkeypatch.setattr(
        collector_registry, "get_collector",
        lambda name: (lambda: evidence[name]),
    )
    auth = {"Authorization": "Bearer " + "t" * 43}
    with TestClient(app) as client:
        response = client.post("/api/memory-forensics/scan", json={}, headers=auth)
    monkeypatch.setattr(collector_registry, "get_collector", original)
    assert response.status_code == 200
    body = response.json()
    assert body["finding_count"] >= 1
    assert any(f["rule_name"] == "memory_forensics_correlation" for f in body["findings"])


def test_writable_executable_region_alone_is_visible_as_review_finding():
    evidence = _evidence()
    evidence["threads"]["threads"] = []
    report = build_memory_forensics(evidence)
    findings = build_memory_forensics_findings(report)
    assert findings
    assert findings[0].severity == "review_recommended"
    assert findings[0].related_evidence["writable_executable_region_count"] == 1
