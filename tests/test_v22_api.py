import hashlib
import os
import tempfile
os.environ.setdefault("JOCKY_API_TOKEN_HASH", hashlib.sha256(b"t" * 43).hexdigest())
os.environ.setdefault("JOCKY_BYTECODE_KEY", "k" * 40)
os.environ.setdefault("JOCKY_DB_PATH", tempfile.mktemp(suffix=".db"))
from fastapi.testclient import TestClient
from jocky.api.main import app
AUTH = {"Authorization": "Bearer " + "t" * 43}

def test_v22_automated_obfuscation_api():
    with TestClient(app) as client:
        response = client.post("/api/bytecode/compile", json={
            "script": 'investigation "api-v22" { let x = 1; report "r"; }',
            "target": "portable", "deterministic": True,
            "transformation_profile": "automated-obfuscation",
        }, headers=AUTH)
    assert response.status_code == 200
    body=response.json()
    assert body["toolchain_version"] == "2.4.0"
    assert body["transformation_profile"] == "automated-obfuscation"
    assert "serialized_layout_diversification" in body["transformation_changes"]

def test_v22_experiment_api():
    with TestClient(app) as client:
        response=client.post("/api/transformations/experiments", json={
            "script": 'investigation "api-exp" { let x = 1; report "r"; }',
            "profile":"automated-obfuscation", "seed":"api",
        }, headers=AUTH)
    assert response.status_code == 200
    body=response.json()
    assert body["validation"] == "passed"
    assert body["semantic_equivalent"] is True
    with TestClient(app) as client:
        response=client.get("/api/transformations/experiments?limit=5", headers=AUTH)
    assert response.status_code == 200
    assert response.json()
