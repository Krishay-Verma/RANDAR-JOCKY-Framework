import hashlib
import os
import time


def _auth():
    os.environ.setdefault("JOCKY_API_TOKEN_HASH", hashlib.sha256(b"t" * 43).hexdigest())
    return {"Authorization": "Bearer " + "t" * 43}


def test_forensic_job_completes_and_persists(monkeypatch):
    from fastapi.testclient import TestClient
    from jocky.api import forensic_jobs
    from jocky.api import bytecode_routes

    fake = {
        "investigation_id": 991,
        "persisted": True,
        "finding_count": 1,
        "findings": [{"rule_name": "memory_forensics_correlation"}],
        "snapshot_hash": "abc",
    }
    monkeypatch.setattr(bytecode_routes, "memory_forensics_scan", lambda: fake)
    from jocky.api.main import app
    with TestClient(app) as client:
        response = client.post("/api/forensic-jobs/memory", headers=_auth())
        assert response.status_code == 200
        job_id = response.json()["job_id"]
        for _ in range(40):
            status = client.get(f"/api/forensic-jobs/{job_id}", headers=_auth())
            assert status.status_code == 200
            body = status.json()
            if body["status"] == "complete":
                assert body["investigation_id"] == 991
                assert body["result"]["persisted"] is True
                break
            time.sleep(0.01)
        else:
            raise AssertionError("forensic background job did not complete")


def test_forensic_job_rejects_unknown_type():
    from fastapi.testclient import TestClient
    from jocky.api.main import app
    response = TestClient(app).post("/api/forensic-jobs/not-a-scan", headers=_auth())
    assert response.status_code == 404


def test_forensic_pages_use_server_side_jobs_and_recover_active_job():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "frontend" / "src"
    hook = (root / "hooks" / "useForensicJob.js").read_text(encoding="utf-8")
    client = (root / "api" / "client.js").read_text(encoding="utf-8")
    assert "/api/forensic-jobs/" in client
    assert "sessionStorage" in hook
    assert "Route changes only stop polling" in hook
    for name in ("MemoryForensics.jsx", "DriverForensics.jsx", "PersistenceForensics.jsx"):
        source = (root / "pages" / name).read_text(encoding="utf-8")
        assert "useForensicJob" in source
