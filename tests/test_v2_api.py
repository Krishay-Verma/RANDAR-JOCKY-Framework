import hashlib
import os
import tempfile

os.environ.setdefault("JOCKY_API_TOKEN_HASH", hashlib.sha256(b"t" * 43).hexdigest())
os.environ.setdefault("JOCKY_BYTECODE_KEY", "k" * 40)
os.environ.setdefault("JOCKY_DB_PATH", tempfile.mktemp(suffix=".db"))

from fastapi.testclient import TestClient
from jocky.api.main import app

AUTH = {"Authorization": "Bearer " + "t" * 43}


def test_v2_compile_api_exposes_toolchain_metadata():
    source = 'investigation "api-v2" { collect system_info; report "r"; }'
    with TestClient(app) as client:
        response = client.post(
            "/api/bytecode/compile",
            json={"script": source, "target": "ubuntu", "deterministic": True},
            headers=AUTH,
        )
    assert response.status_code == 200
    body = response.json()
    assert body["toolchain_version"] == "2.4.0"
    assert body["ir_version"] == "1.0"
    assert body["target"] == "ubuntu"
    assert body["deterministic"] is True
    assert len(body["source_hash"]) == 64
    assert len(body["ir_hash"]) == 64


def test_v2_compile_api_rejects_invalid_source_as_400():
    with TestClient(app) as client:
        response = client.post(
            "/api/bytecode/compile",
            json={"script": 'investigation "broken" { collect missing_collector; }'},
            headers=AUTH,
        )
    assert response.status_code == 400


def test_v21_compile_api_exposes_transformation_and_build_identity():
    source = 'investigation "api-v21" { let x = 1; report "r"; }'
    with TestClient(app) as client:
        response = client.post(
            "/api/bytecode/compile",
            json={
                "script": source,
                "target": "ubuntu",
                "deterministic": True,
                "transformation_profile": "reproducible-randomized",
                "transformation_seed": "api-seed",
            },
            headers=AUTH,
        )
    assert response.status_code == 200
    body = response.json()
    assert body["transformation_profile"] == "reproducible-randomized"
    assert len(body["transformation_id"]) == 64
    assert len(body["build_id"]) == 64
    assert len(body["artifact_hash"]) == 64
    assert body["transformation_seed"]
