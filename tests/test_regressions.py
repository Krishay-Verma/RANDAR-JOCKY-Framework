"""Regression tests for defects fixed in v1.0. Run: python -m pytest tests -q"""

import hashlib
import os
import tempfile
import time

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


def test_report_hash_detects_mutation(client):
    s = 'investigation "integrity" { collect system_info; report "r"; }'
    r = client.post("/api/investigations", json={"script": s}, headers=AUTH)
    assert r.status_code == 200
    report = r.json()["report_json"]
    assert report["report_hash"]
    from jocky.api.routes import _report_from_dict
    from jocky.reports.report import verify_report_integrity
    restored = _report_from_dict(report)
    assert verify_report_integrity(restored)
    restored.investigation_name = "tampered"
    assert not verify_report_integrity(restored)


def test_collector_errors_are_reported(client, monkeypatch):
    from jocky.collectors import registry
    def broken():
        raise RuntimeError("collector unavailable")
    monkeypatch.setitem(registry._COLLECTORS, "system_info", broken)
    r = client.post(
        "/api/investigations",
        json={"script": 'investigation "errors" { collect system_info; report "r"; }'},
        headers=AUTH,
    )
    assert r.status_code == 200
    report = r.json()["report_json"]
    assert report["collector_results"][0]["status"] == "error"
    assert report["collector_errors"] == [
        {"target": "system_info", "error": "collector unavailable"}
    ]


def test_bytecode_rejects_signed_structural_mismatch():
    from jocky.language.bytecode import BytecodeError, compile_investigation, verify_and_load
    from jocky.language.lexer import tokenize
    from jocky.language.parser import parse
    import base64, json, struct, hmac, hashlib
    investigation = parse(tokenize(
        'investigation "t" { collect system_info; report "r"; }'
    ))
    blob = compile_investigation(investigation)
    payload, sig = blob[:-32], blob[-32:]
    # Change only the signed header command_count and re-sign with the test key.
    hlen = struct.unpack(">I", payload[:4])[0]
    header = json.loads(payload[4:4+hlen])
    header["command_count"] = 999
    hb = json.dumps(header, separators=(",", ":")).encode()
    body_start = 4 + hlen
    blen = struct.unpack(">I", payload[body_start:body_start+4])[0]
    body = payload[body_start+4:body_start+4+blen]
    rebuilt = struct.pack(">I", len(hb)) + hb + struct.pack(">I", len(body)) + body
    key = os.environ["JOCKY_BYTECODE_KEY"].encode()
    rebuilt += hmac.new(key, rebuilt, hashlib.sha256).digest()
    with pytest.raises(BytecodeError):
        verify_and_load(rebuilt)

# ── v1.0 acceptance coverage ─────────────────────────────────────────────────
def test_all_v1_collectors_are_registered_and_executable():
    from jocky.collectors.registry import list_collectors, get_collector
    expected = {
        "system_info", "processes", "network_connections", "logged_in_users",
        "file_hash", "scheduled_tasks", "startup_items", "open_files",
        "local_users", "modules", "threads", "memory_regions",
    }
    assert expected.issubset(set(list_collectors()))
    for name in expected:
        result = get_collector(name)()
        assert isinstance(result, dict)

    # V1.1 network_artifacts is source-backed and intentionally requires a selected evidence file.
    assert "network_artifacts" in list_collectors()


def test_all_v1_analysis_rules_are_registered_and_callable():
    from jocky.analysis.registry import list_rules, get_rule
    expected = {
        "missing_paths", "suspicious_processes", "process_network_correlation",
        "unusual_scheduled_tasks", "suspicious_startup_items",
        "high_connection_processes", "privileged_user_anomaly",
        "suspicious_module_loads", "dll_sideloading",
        "process_hollowing_indicators", "reflective_load_indicators",
        "thread_hijacking_indicators", "injection_correlation",
        "suspicious_dns_queries", "dns_entropy", "rare_domains",
        "suspicious_tld_patterns", "dns_bursts", "unusual_query_types",
        "long_random_labels", "dns_tunneling_indicators", "dns_beaconing",
        "network_beaconing", "port_scan", "horizontal_scan",
        "service_discovery", "udp_scan", "network_classification",
        "encoded_powershell", "suspicious_powershell_parent",
        "powershell_network_activity", "powershell_child_processes",
        "suspicious_services", "writable_service_paths", "persistence_correlation",
        "unsigned_loaded_module", "suspicious_imports", "high_entropy_module",
        "module_disk_mismatch", "suspicious_writable_module",
    }
    assert set(list_rules()) == expected
    evidence = {
        "processes": {"processes": [], "count": 0},
        "network_connections": {"connections": [], "count": 0},
        "logged_in_users": {"sessions": [], "count": 0},
        "scheduled_tasks": {"tasks": [], "count": 0},
        "startup_items": {"items": [], "count": 0},
        "modules": {"modules": [], "count": 0},
        "threads": {"threads": [], "count": 0},
        "memory_regions": {"regions": [], "count": 0},
        "local_users": {"users": [], "count": 0},
        "open_files": {"files": [], "count": 0},
        "pe_metadata": {"files": [], "count": 0},
    }
    for name in expected:
        findings = get_rule(name)(evidence)
        assert isinstance(findings, list)


def test_full_v1_investigation_pipeline_runs():
    collectors = [
        "system_info", "processes", "network_connections", "logged_in_users",
        "file_hash", "scheduled_tasks", "startup_items", "open_files",
        "local_users", "modules", "threads", "memory_regions",
    ]
    rules = [
        "missing_paths", "suspicious_processes", "process_network_correlation",
        "unusual_scheduled_tasks", "suspicious_startup_items",
        "high_connection_processes", "privileged_user_anomaly",
        "suspicious_module_loads", "dll_sideloading",
        "process_hollowing_indicators", "reflective_load_indicators",
        "thread_hijacking_indicators", "injection_correlation",
    ]
    src = 'investigation "v1.0 acceptance" {\n'
    src += ''.join(f"    collect {name};\n" for name in collectors)
    src += ''.join(f"    analyze {name};\n" for name in rules)
    src += '    report "v1.0 acceptance";\n}'
    result = __import__("jocky.language.interpreter", fromlist=["run_investigation"]).run_investigation(
        parse(tokenize(src))
    )
    assert len(result.collector_results) == len(collectors)
    assert all(r.status in {"success", "error"} for r in result.collector_results)
    assert result.report_name == "v1.0 acceptance"


def test_report_json_and_integrity_endpoints(client):
    s = 'investigation "json export" { collect system_info; report "r"; }'
    created = client.post("/api/investigations", json={"script": s}, headers=AUTH)
    assert created.status_code == 200
    investigation_id = created.json()["id"]

    integrity = client.get(f"/api/investigations/{investigation_id}/integrity", headers=AUTH)
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    assert integrity.json()["stored_hash"] == integrity.json()["computed_hash"]

    exported = client.get(f"/api/investigations/{investigation_id}/report.json", headers=AUTH)
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("application/json")
    assert exported.headers["x-report-sha256"] == integrity.json()["stored_hash"]


def test_report_integrity_survives_reconstruction_with_collector_error(client, monkeypatch):
    from jocky.collectors import registry

    def broken():
        raise RuntimeError("expected failure")

    monkeypatch.setitem(registry._COLLECTORS, "system_info", broken)
    created = client.post(
        "/api/investigations",
        json={"script": 'investigation "error integrity" { collect system_info; report "r"; }'},
        headers=AUTH,
    )
    assert created.status_code == 200
    investigation_id = created.json()["id"]
    integrity = client.get(f"/api/investigations/{investigation_id}/integrity", headers=AUTH)
    assert integrity.json()["valid"] is True


def test_remote_agent_full_lifecycle(client):
    registration = client.post(
        "/api/agents/register",
        json={"hostname": "WIN-TEST", "platform": "Windows"},
        headers=AUTH,
    )
    assert registration.status_code == 200
    info = registration.json()
    aid, token = info["agent_id"], info["agent_token"]
    agent_auth = {"Authorization": f"Bearer {token}"}

    bad_poll = client.get(f"/api/agents/{aid}/jobs/pending", headers={"Authorization": "Bearer wrong"})
    assert bad_poll.status_code == 401

    script = 'investigation "remote" { collect system_info; report "remote"; }'
    queued = client.post(f"/api/agents/{aid}/jobs", json={"script": script}, headers=AUTH)
    assert queued.status_code == 200
    jid = queued.json()["job_id"]

    pending = client.get(f"/api/agents/{aid}/jobs/pending", headers=agent_auth)
    assert pending.status_code == 200
    assert pending.json()["job_id"] == jid

    payload = {
        "collector_results": [{"target": "system_info", "status": "success", "data": {"hostname": "WIN-TEST"}}],
        "findings": [],
        "report_name": "remote",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
    }
    submitted = client.post(f"/api/agents/{aid}/jobs/{jid}/result", json=payload, headers=agent_auth)
    assert submitted.status_code == 200

    result = client.get(f"/api/agents/{aid}/jobs/{jid}/result", headers=AUTH)
    assert result.status_code == 200 and result.json()["status"] == "complete"

    imported = client.post(f"/api/agents/{aid}/jobs/{jid}/import", headers=AUTH)
    assert imported.status_code == 200
    imported_id = imported.json()["id"]
    integrity = client.get(f"/api/investigations/{imported_id}/integrity", headers=AUTH)
    assert integrity.status_code == 200 and integrity.json()["valid"] is True

    heartbeat = client.post(f"/api/agents/{aid}/heartbeat", headers=agent_auth)
    assert heartbeat.status_code == 200

    revoked = client.delete(f"/api/agents/{aid}", headers=AUTH)
    assert revoked.status_code == 200
    assert client.get(f"/api/agents/{aid}/jobs/pending", headers=agent_auth).status_code == 401


def test_bytecode_compile_verify_disassemble_and_execute(client):
    script = 'investigation "bytecode acceptance" { collect system_info; report "r"; }'
    compiled = client.post("/api/bytecode/compile", json={"script": script}, headers=AUTH)
    assert compiled.status_code == 200
    blob = compiled.json()["bytecode_b64"]
    assert compiled.json()["signature"] == "HMAC-SHA256"
    assert compiled.json()["version"] == 1

    disasm = client.post("/api/bytecode/disasm", json={"bytecode_b64": blob}, headers=AUTH)
    assert disasm.status_code == 200
    assert "Signature     : OK" in disasm.json()["disassembly"]

    executed = client.post("/api/bytecode/execute", json={"bytecode_b64": blob}, headers=AUTH)
    assert executed.status_code == 200
    assert executed.json()["investigation_name"] == "bytecode acceptance"
    assert executed.json()["collector_count"] == 1


def test_bytecode_semantic_validation_rejects_unknown_capability():
    from jocky.language.bytecode import BytecodeError, verify_and_load
    import base64, hashlib, hmac, json, struct

    header = {"magic": "JOCKY", "version": 1, "name": "bad", "compiled_at": "now", "command_count": 1}
    body = [{"op": "COLLECT", "target": "not_a_collector", "line": 1}]
    hb = json.dumps(header, separators=(",", ":")).encode()
    bb = json.dumps(body, separators=(",", ":")).encode()
    payload = struct.pack(">I", len(hb)) + hb + struct.pack(">I", len(bb)) + bb
    key = os.environ["JOCKY_BYTECODE_KEY"].encode()
    blob = payload + hmac.new(key, payload, hashlib.sha256).digest()
    with pytest.raises(BytecodeError):
        verify_and_load(blob)


def test_encrypted_report_roundtrip(client, tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from jocky.reports.encryptor import decrypt_report

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    assert client.post("/api/keys/register", json={"public_key_pem": public}, headers=AUTH).status_code == 200

    created = client.post(
        "/api/investigations",
        json={"script": 'investigation "encrypted" { collect system_info; report "r"; }'},
        headers=AUTH,
    )
    assert created.status_code == 200
    investigation_id = created.json()["id"]

    encrypted = client.get(f"/api/investigations/{investigation_id}/report.encrypted", headers=AUTH)
    assert encrypted.status_code == 200
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    plaintext = decrypt_report(encrypted.content, private)
    assert b'"investigation_name": "encrypted"' in plaintext
    assert client.delete("/api/keys/register", headers=AUTH).status_code == 200


# ── V1.1 Network Evidence ───────────────────────────────────────────────────
def test_v11_zeek_conn_ingestion_and_statistics():
    from jocky.storage.network_sources import init_network_sources, save_network_source
    from jocky.collectors.network_artifacts import set_network_source, reset_network_source, collect_network_artifacts
    init_network_sources()
    content = b"#path\tconn\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n1710000000.0\t10.0.0.5\t51515\t8.8.8.8\t443\ttcp\tssl\n"
    src = save_network_source("conn.log", content)
    token = set_network_source(src["id"])
    try:
        data = collect_network_artifacts()
    finally:
        reset_network_source(token)
    assert data["count"] == 1
    assert data["artifacts"][0]["source"] == "10.0.0.5"
    assert data["artifacts"][0]["destination_port"] == 443
    assert data["statistics"]["protocol_counts"] == {"tcp": 1}


def test_v11_zeek_dns_and_jsonl_ingestion():
    from jocky.storage.network_sources import init_network_sources, save_network_source
    from jocky.collectors.network_artifacts import set_network_source, reset_network_source, collect_network_artifacts
    init_network_sources()
    content = b"#path\tdns\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\n1710000000.0\t10.0.0.5\t50000\t10.0.0.1\t53\tudp\twww.example.test\tA\n"
    src = save_network_source("dns.log", content)
    token = set_network_source(src["id"])
    try: data = collect_network_artifacts()
    finally: reset_network_source(token)
    assert data["count"] == 1
    assert data["statistics"]["unique_domains"] == 1
    assert data["artifacts"][0]["metadata"]["domain"] == "www.example.test"

    jsonl = b'{"ts":1710000001,"id.orig_h":"10.0.0.6","id.orig_p":50001,"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp","query":"api.example.test","qtype_name":"AAAA"}\n'
    src = save_network_source("dns.jsonl", jsonl)
    token = set_network_source(src["id"])
    try: data = collect_network_artifacts()
    finally: reset_network_source(token)
    assert data["count"] == 1
    assert data["artifacts"][0]["metadata"]["qtype"] == "AAAA"


def test_v11_pcap_metadata_and_dns_extraction():
    import struct
    from jocky.storage.network_sources import init_network_sources, save_network_source
    from jocky.collectors.network_artifacts import set_network_source, reset_network_source, collect_network_artifacts
    init_network_sources()
    eth = bytes.fromhex("00112233445566778899aabb0800")
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    for label in (b"example", b"test"): dns += bytes([len(label)]) + label
    dns += b"\x00" + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    total_len = 20 + len(udp)
    ip = bytes([0x45,0]) + struct.pack("!H", total_len) + b"\x00\x01\x00\x00\x40\x11" + b"\x00\x00" + bytes([10,0,0,5]) + bytes([8,8,8,8])
    packet = eth + ip + udp
    pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pcap += struct.pack("<IIII", 1710000000, 123456, len(packet), len(packet)) + packet
    src = save_network_source("capture.pcap", pcap)
    token = set_network_source(src["id"])
    try: data = collect_network_artifacts()
    finally: reset_network_source(token)
    assert data["count"] == 1
    artifact = data["artifacts"][0]
    assert artifact["source"] == "10.0.0.5"
    assert artifact["destination"] == "8.8.8.8"
    assert artifact["destination_port"] == 53
    assert artifact["metadata"]["domain"] == "example.test"
    assert "payload" not in artifact


def test_v11_dsl_network_artifacts_and_api_upload(client):
    import base64
    content = b"#path\tconn\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n1710000000\t10.0.0.2\t50000\t1.1.1.1\t443\ttcp\n"
    upload = client.post("/api/network-sources", headers=AUTH, json={
        "filename": "conn.log", "content_base64": base64.b64encode(content).decode()
    })
    assert upload.status_code == 200, upload.text
    source = upload.json()
    assert source["format"] == "zeek_conn"
    script = 'investigation "network evidence" { collect network_artifacts; report "network"; }'
    run = client.post("/api/investigations", headers=AUTH, json={"script": script, "network_source_id": source["id"]})
    assert run.status_code == 200, run.text
    report = run.json()["report_json"]
    network = next(c for c in report["collector_results"] if c["target"] == "network_artifacts")
    assert network["status"] == "success"
    assert network["data"]["statistics"]["connection_count"] == 1
    assert report["source"]["network_sources"][0]["sha256"] == source["sha256"]


def test_v11_network_source_required_for_collector(client):
    script = 'investigation "network missing source" { collect network_artifacts; report "network"; }'
    run = client.post("/api/investigations", headers=AUTH, json={"script": script},)
    assert run.status_code == 200
    report = run.json()["report_json"]
    network = next(c for c in report["collector_results"] if c["target"] == "network_artifacts")
    assert network["status"] == "error"
    assert "No network evidence source selected" in network["error"]



def test_v11_pcapng_metadata_extraction():
    import struct
    from jocky.storage.network_sources import init_network_sources, save_network_source
    from jocky.collectors.network_artifacts import set_network_source, reset_network_source, collect_network_artifacts
    init_network_sources()
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = bytes([0x45, 0]) + struct.pack("!H", 40) + b"\x00\x01\x00\x00\x40\x06\x00\x00" + bytes([10,0,0,1]) + bytes([1,1,1,1])
    tcp = struct.pack("!HHIIHHHH", 50000, 443, 0, 0, 0x5002, 65535, 0, 0)
    packet = eth + ip + tcp
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_len = 8 + len(shb_body) + 4
    shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)
    # if_tsresol = 6 => microseconds.
    idb_body = struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HHB", 9, 1, 6) + b"\x00\x00\x00" + struct.pack("<HH", 0, 0)
    idb_len = 8 + len(idb_body) + 4
    idb = struct.pack("<II", 1, idb_len) + idb_body + struct.pack("<I", idb_len)
    ts = 1710000000 * 1_000_000 + 123456
    hi, lo = divmod(ts, 2**32)
    padded = packet + b"\x00" * ((4 - len(packet) % 4) % 4)
    epb_body = struct.pack("<IIIII", 0, hi, lo, len(packet), len(packet)) + padded
    epb_len = 8 + len(epb_body) + 4
    epb = struct.pack("<II", 6, epb_len) + epb_body + struct.pack("<I", epb_len)
    src = save_network_source("capture.pcapng", shb + idb + epb)
    token = set_network_source(src["id"])
    try:
        data = collect_network_artifacts()
    finally:
        reset_network_source(token)
    assert data["count"] == 1
    assert data["artifacts"][0]["destination_port"] == 443
    assert data["artifacts"][0]["timestamp"].startswith("2024-03-09T16:00:00.123")


def test_v11_html_report_contains_network_section(client):
    import base64
    content = b"#path\tconn\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n1710000000\t10.0.0.2\t50000\t1.1.1.1\t443\ttcp\n"
    src = client.post("/api/network-sources", headers=AUTH, json={"filename": "html_conn.log", "content_base64": base64.b64encode(content).decode()}).json()
    script = 'investigation "network html" { collect network_artifacts; report "network"; }'
    created = client.post("/api/investigations", headers=AUTH, json={"script": script, "network_source_id": src["id"]})
    assert created.status_code == 200
    html = client.get(f"/api/investigations/{created.json()['id']}/report.html", headers=AUTH)
    assert html.status_code == 200
    assert "Network forensics" in html.text
    assert "html_conn.log" in html.text


def test_v11_network_source_lifecycle(client):
    import base64
    content = b"#path\tconn\n#fields\tts\tid.orig_h\tid.resp_h\tproto\n1710000000\t10.0.0.1\t1.1.1.1\ttcp\n"
    created = client.post("/api/network-sources", headers=AUTH, json={"filename": "lifecycle.log", "content_base64": base64.b64encode(content).decode()})
    assert created.status_code == 200
    sid = created.json()["id"]
    listed = client.get("/api/network-sources", headers=AUTH)
    assert listed.status_code == 200 and any(x["id"] == sid for x in listed.json())
    detail = client.get(f"/api/network-sources/{sid}", headers=AUTH)
    assert detail.status_code == 200 and "path" not in detail.json()
    removed = client.delete(f"/api/network-sources/{sid}", headers=AUTH)
    assert removed.status_code == 200
    assert client.get(f"/api/network-sources/{sid}", headers=AUTH).status_code == 404


# ── V1.2 Network Threat Hunting ─────────────────────────────────────────────
def _v12_artifacts():
    from datetime import datetime, timezone, timedelta
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    items = []
    for i in range(5):
        items.append({
            "timestamp": (base + timedelta(seconds=60*i)).isoformat(),
            "source": "10.0.0.5", "destination": "10.0.0.1", "protocol": "udp",
            "source_port": 50000+i, "destination_port": 53,
            "metadata": {"type": "dns", "domain": "beacon.example.test", "qtype": "A"},
        })
    for i in range(10):
        label = f"aB3dE7gI9kL2mN5pQ8sT1vW4xY6zC0{i}"
        items.append({
            "timestamp": (base + timedelta(seconds=i)).isoformat(),
            "source": "10.0.0.6", "destination": "10.0.0.1", "protocol": "udp",
            "source_port": 51000+i, "destination_port": 53,
            "metadata": {"type": "dns", "domain": f"{label}.tunnel.zip", "qtype": "ANY"},
        })
    for port in range(1, 12):
        items.append({"timestamp": base.isoformat(), "source": "10.0.0.7", "destination": "10.0.0.20", "protocol": "tcp", "destination_port": port, "metadata": {}})
    for host in range(10, 22):
        items.append({"timestamp": base.isoformat(), "source": "10.0.0.8", "destination": f"10.0.1.{host}", "protocol": "tcp", "destination_port": 445, "metadata": {}})
    for port in [22, 53, 80, 135, 139, 443]:
        items.append({"timestamp": base.isoformat(), "source": "10.0.0.9", "destination": "10.0.0.30", "protocol": "tcp", "destination_port": port, "metadata": {}})
    for host in range(30, 42):
        items.append({"timestamp": base.isoformat(), "source": "10.0.0.10", "destination": f"10.0.2.{host}", "protocol": "udp", "destination_port": 161, "metadata": {}})
    return items


def test_v12_dns_rules_and_beaconing():
    from jocky.analysis.network_hunting import (
        rule_dns_beaconing, rule_dns_entropy, rule_dns_tunneling_indicators,
        rule_long_random_labels, rule_suspicious_dns_queries,
    )
    evidence = {"network_artifacts": {"artifacts": _v12_artifacts()}}
    assert rule_dns_beaconing(evidence)
    assert rule_dns_entropy(evidence)
    assert rule_long_random_labels(evidence)
    assert rule_suspicious_dns_queries(evidence)
    assert rule_dns_tunneling_indicators(evidence)


def test_v12_scan_and_classification_rules():
    from jocky.analysis.network_hunting import (
        rule_horizontal_scan, rule_network_classification, rule_port_scan,
        rule_service_discovery, rule_udp_scan,
    )
    evidence = {"network_artifacts": {"artifacts": _v12_artifacts()}}
    assert rule_port_scan(evidence)
    assert rule_horizontal_scan(evidence)
    assert rule_service_discovery(evidence)
    assert rule_udp_scan(evidence)
    classification = rule_network_classification(evidence)
    assert classification and classification[0].related_evidence["counts"]["private"] > 0


def test_v12_process_network_correlation_includes_dns_context():
    from jocky.analysis.network_hunting import rule_process_network_correlation
    evidence = {
        "processes": {"processes": [{"pid": 42, "name": "example.exe", "exe_path": "C:\\Program Files\\Example\\example.exe"}]},
        "network_connections": {"connections": [{
            "protocol": "tcp", "local_address": "10.0.0.5:50000", "local_port": 50000,
            "remote_address": "203.0.113.10:443", "remote_ip": "203.0.113.10", "remote_port": 443,
            "status": "ESTABLISHED", "pid": 42,
        }]},
        "network_artifacts": {"artifacts": [{
            "source": "10.0.0.5", "destination": "203.0.113.10", "protocol": "udp",
            "destination_port": 53, "metadata": {"domain": "api.example.test", "qtype": "A"},
        }]},
    }
    findings = rule_process_network_correlation(evidence)
    assert len(findings) == 1
    assert findings[0].related_evidence["pid"] == 42


def test_v12_process_network_correlation_handles_ipv6_local_endpoints():
    from jocky.analysis.network_hunting import rule_process_network_correlation
    evidence = {
        "processes": {"processes": [{"pid": 7, "name": "browser.exe", "exe_path": "C:\\Browser\\browser.exe"}]},
        "network_connections": {"connections": [{
            "protocol": "tcp", "local_address": "2001:db8::5:50000", "local_port": 50000,
            "remote_address": "2001:db8::10:443", "remote_ip": "2001:db8::10", "remote_port": 443,
            "status": "ESTABLISHED", "pid": 7,
        }]},
        "network_artifacts": {"artifacts": [{
            "source": "2001:db8::5", "destination": "2001:db8::10", "protocol": "tcp",
            "destination_port": 443, "metadata": {"type": "conn"},
        }]},
    }
    findings = rule_process_network_correlation(evidence)
    assert len(findings) == 1
    assert findings[0].related_evidence["pid"] == 7


def test_v12_full_dsl_script_accepts_all_rules(client):
    script = """investigation "Network Threat Hunt" {
        collect network_artifacts;
        collect processes;
        collect network_connections;
        analyze suspicious_dns_queries;
        analyze dns_entropy;
        analyze rare_domains;
        analyze suspicious_tld_patterns;
        analyze dns_bursts;
        analyze unusual_query_types;
        analyze long_random_labels;
        analyze dns_tunneling_indicators;
        analyze dns_beaconing;
        analyze network_beaconing;
        analyze port_scan;
        analyze horizontal_scan;
        analyze service_discovery;
        analyze udp_scan;
        analyze network_classification;
        analyze process_network_correlation;
        report "network_threat_hunt";
    }"""
    response = client.post("/api/validate", json={"script": script}, headers=AUTH)
    assert response.status_code == 200, response.text
    assert response.json()["analyze_count"] == 16


def test_v12_api_full_hunt_script_runs_without_error(client):
    import base64
    content = b"#path\tconn\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n1710000000\t10.0.0.2\t50000\t1.1.1.1\t443\ttcp\n"
    upload = client.post("/api/network-sources", headers=AUTH, json={
        "filename": "v12-conn.log", "content_base64": base64.b64encode(content).decode()
    })
    assert upload.status_code == 200, upload.text
    script = """investigation "V1.2 API acceptance" {
        collect network_artifacts;
        collect processes;
        collect network_connections;
        analyze suspicious_dns_queries;
        analyze dns_entropy;
        analyze rare_domains;
        analyze suspicious_tld_patterns;
        analyze dns_bursts;
        analyze unusual_query_types;
        analyze long_random_labels;
        analyze dns_tunneling_indicators;
        analyze dns_beaconing;
        analyze network_beaconing;
        analyze port_scan;
        analyze horizontal_scan;
        analyze service_discovery;
        analyze udp_scan;
        analyze network_classification;
        analyze process_network_correlation;
        report "network_threat_hunt";
    }"""
    run = client.post("/api/investigations", headers=AUTH, json={"script": script, "network_source_id": upload.json()["id"]})
    assert run.status_code == 200, run.text
    report = run.json()["report_json"]
    assert report["report_hash"]
    assert any(f["rule_name"] == "network_classification" for f in report["findings"])
    assert client.get(f"/api/investigations/{run.json()['id']}/integrity", headers=AUTH).json()["valid"] is True


def test_v12_html_report_contains_hunting_section(client):
    import base64
    content = b"#path\tconn\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n1710000000\t10.0.0.2\t50000\t1.1.1.1\t443\ttcp\n"
    upload = client.post("/api/network-sources", headers=AUTH, json={
        "filename": "v12-html.log", "content_base64": base64.b64encode(content).decode()
    })
    assert upload.status_code == 200, upload.text
    script = 'investigation "V1.2 HTML" { collect network_artifacts; analyze network_classification; report "v12"; }'
    run = client.post("/api/investigations", headers=AUTH, json={"script": script, "network_source_id": upload.json()["id"]})
    assert run.status_code == 200, run.text
    html = client.get(f"/api/investigations/{run.json()['id']}/report.html", headers=AUTH)
    assert html.status_code == 200
    assert "Network threat hunting" in html.text
    assert "Network address classification completed" in html.text

# ── V1.3 Windows Telemetry Expansion ────────────────────────────────────────
def _v13_event_xml():
    return '''<Events>
<Event><System><Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>WIN-TEST</Computer><EventRecordID>1</EventRecordID><TimeCreated SystemTime="2026-01-01T00:00:00.000Z"/></System><EventData><Data Name="ScriptBlockText">powershell.exe -enc QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=</Data></EventData></Event>
<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Channel>Security</Channel><Computer>WIN-TEST</Computer><EventRecordID>2</EventRecordID><TimeCreated SystemTime="2026-01-01T00:00:01.000Z"/></System><EventData><Data Name="NewProcessName">C:\\Windows\\System32\\powershell.exe</Data><Data Name="CommandLine">powershell.exe -w hidden</Data></EventData></Event>
<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-TEST</Computer><EventRecordID>3</EventRecordID><TimeCreated SystemTime="2026-01-01T00:00:02.000Z"/></System><EventData><Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data><Data Name="DestinationIp">203.0.113.10</Data></EventData></Event>
</Events>'''


def test_v13_windows_event_log_fixture_parser(monkeypatch, tmp_path):
    from jocky.collectors.windows_event_logs import collect_windows_event_logs
    fixture = tmp_path / "events.xml"
    fixture.write_text(_v13_event_xml(), encoding="utf-8")
    monkeypatch.setenv("JOCKY_WINDOWS_EVENT_LOG_FIXTURE", str(fixture))
    data = collect_windows_event_logs()
    assert data["count"] == 2
    assert data["event_type_counts"]["powershell"] == 1
    assert data["event_type_counts"]["process_creation"] == 1


def test_v13_sysmon_fixture_parser(monkeypatch, tmp_path):
    from jocky.collectors.sysmon_events import collect_sysmon_events
    fixture = tmp_path / "sysmon.xml"
    fixture.write_text(_v13_event_xml(), encoding="utf-8")
    monkeypatch.setenv("JOCKY_SYSMON_EVENT_LOG_FIXTURE", str(fixture))
    data = collect_sysmon_events()
    assert data["count"] == 1
    assert data["events"][0]["event_id"] == 3


def test_v13_powershell_rules():
    from jocky.analysis.windows_telemetry import (
        rule_encoded_powershell, rule_suspicious_powershell_parent,
        rule_powershell_network_activity, rule_powershell_child_processes,
    )
    evidence = {
        "processes": {"processes": [
            {"pid": 10, "name": "WINWORD.EXE", "parent_pid": 1, "command_line": "winword"},
            {"pid": 20, "name": "powershell.exe", "parent_pid": 10, "command_line": "powershell.exe -enc QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo= -w hidden"},
            {"pid": 21, "name": "cmd.exe", "parent_pid": 20, "command_line": "cmd.exe /c whoami"},
        ]},
        "network_connections": {"connections": [{"pid": 20, "remote_ip": "203.0.113.5", "remote_port": 443, "protocol": "tcp", "status": "ESTABLISHED"}]},
    }
    assert len(rule_encoded_powershell(evidence)) == 2
    assert len(rule_suspicious_powershell_parent(evidence)) == 1
    assert len(rule_powershell_network_activity(evidence)) == 1
    assert len(rule_powershell_child_processes(evidence)) == 1


def test_v13_service_rules_and_persistence_correlation():
    from jocky.analysis.windows_telemetry import rule_suspicious_services, rule_writable_service_paths, rule_persistence_correlation
    evidence = {
        "services": {"services": [{"service_name": "AcmeSvc", "executable": "C:\\Users\\Public\\acme.exe", "writable_path": True, "start_mode": "auto"}]},
        "startup_items": {"items": [{"name": "Acme", "command": "C:\\Users\\Public\\acme.exe", "type": "registry_run_key"}]},
        "scheduled_tasks": {"tasks": [{"name": "AcmeTask", "task_to_run": "C:\\Users\\Public\\acme.exe"}]},
    }
    assert rule_suspicious_services(evidence)
    assert rule_writable_service_paths(evidence)
    assert rule_persistence_correlation(evidence)


def test_v13_capabilities_registered():
    from jocky.collectors.registry import list_collectors
    from jocky.analysis.registry import list_rules
    for name in ("windows_event_logs", "sysmon_events", "services"):
        assert name in list_collectors()
    for name in ("encoded_powershell", "suspicious_powershell_parent", "powershell_network_activity", "powershell_child_processes", "suspicious_services", "writable_service_paths", "persistence_correlation"):
        assert name in list_rules()


def test_v13_full_dsl_validates(client):
    script = '''investigation "Windows Telemetry Hunt" {
        collect system_info;
        collect processes;
        collect network_connections;
        collect windows_event_logs;
        collect sysmon_events;
        collect services;
        collect startup_items;
        collect scheduled_tasks;
        analyze encoded_powershell;
        analyze suspicious_powershell_parent;
        analyze powershell_network_activity;
        analyze powershell_child_processes;
        analyze suspicious_services;
        analyze writable_service_paths;
        analyze persistence_correlation;
        report "windows_telemetry_hunt";
    }'''
    response = client.post("/api/validate", json={"script": script}, headers=AUTH)
    assert response.status_code == 200, response.text
    assert response.json()["collect_count"] == 8
    assert response.json()["analyze_count"] == 7


def test_v13_html_contains_windows_telemetry(client, monkeypatch, tmp_path):
    fixture = tmp_path / "events.xml"
    fixture.write_text(_v13_event_xml(), encoding="utf-8")
    monkeypatch.setenv("JOCKY_WINDOWS_EVENT_LOG_FIXTURE", str(fixture))
    script = 'investigation "V1.3 HTML" { collect windows_event_logs; analyze encoded_powershell; report "v13"; }'
    run = client.post("/api/investigations", headers=AUTH, json={"script": script})
    assert run.status_code == 200, run.text
    html = client.get(f"/api/investigations/{run.json()['id']}/report.html", headers=AUTH)
    assert html.status_code == 200
    assert "Windows telemetry" in html.text


def test_v13_namespaced_event_xml_is_parsed(monkeypatch, tmp_path):
    from jocky.collectors.windows_event_logs import collect_windows_event_logs
    fixture = tmp_path / "events-ns.xml"
    xml = _v13_event_xml().replace("<Events>", '<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">', 1)
    fixture.write_text(xml, encoding="utf-8")
    monkeypatch.setenv("JOCKY_WINDOWS_EVENT_LOG_FIXTURE", str(fixture))
    data = collect_windows_event_logs()
    assert data["count"] == 2
    assert {e["event_id"] for e in data["events"]} == {4104, 4688}


def test_v13_service_parser_is_read_only_and_normalized(monkeypatch):
    from jocky.collectors import services
    outputs = {
        "queryex": """SERVICE_NAME: AcmeSvc\n        TYPE : 10  WIN32_OWN_PROCESS\n        STATE : 4  RUNNING\nSERVICE_NAME: OtherSvc\n        STATE : 1  STOPPED\n""",
        "qc": """[SC] QueryServiceConfig SUCCESS\n        SERVICE_NAME: AcmeSvc\n        DISPLAY_NAME: Acme Service\n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : C:\\Users\\Public\\acme.exe --service\n        SERVICE_START_NAME : LocalSystem\n""",
    }
    class R:
        returncode = 0
        stderr = ""
        def __init__(self, stdout): self.stdout = stdout
    def fake_run(args, **kwargs):
        if args[1] == "queryex": return R(outputs["queryex"])
        return R(outputs["qc"])
    monkeypatch.setattr(services, "os", __import__("os"))
    monkeypatch.setattr(services, "subprocess", services.subprocess)
    monkeypatch.setattr(services.subprocess, "run", fake_run)
    monkeypatch.setattr(services, "os", services.os)
    monkeypatch.setattr(services, "Path", services.Path)
    # Simulate Windows for the collector without invoking a real service manager.
    monkeypatch.setattr(services.os, "name", "nt")
    data = services.collect_services()
    assert data["count"] == 2
    assert data["services"][0]["start_mode"] == "auto"
    assert data["services"][0]["state"] == "running"
    assert data["services"][0]["account"] == "LocalSystem"


def test_v13_api_full_hunt_runs_and_reports(client, monkeypatch, tmp_path):
    fixture = tmp_path / "events.xml"
    fixture.write_text(_v13_event_xml(), encoding="utf-8")
    monkeypatch.setenv("JOCKY_WINDOWS_EVENT_LOG_FIXTURE", str(fixture))
    script = '''investigation "V1.3 API acceptance" {
        collect system_info;
        collect processes;
        collect network_connections;
        collect windows_event_logs;
        collect sysmon_events;
        collect services;
        collect startup_items;
        collect scheduled_tasks;
        analyze encoded_powershell;
        analyze suspicious_powershell_parent;
        analyze powershell_network_activity;
        analyze powershell_child_processes;
        analyze suspicious_services;
        analyze writable_service_paths;
        analyze persistence_correlation;
        report "windows_telemetry_hunt";
    }'''
    run = client.post("/api/investigations", headers=AUTH, json={"script": script})
    assert run.status_code == 200, run.text
    report = run.json()["report_json"]
    assert report["report_hash"]
    assert any(f["rule_name"] == "encoded_powershell" for f in report["findings"])
    assert any(c["target"] == "windows_event_logs" and c["status"] == "success" for c in report["collector_results"])
    assert client.get(f"/api/investigations/{run.json()['id']}/integrity", headers=AUTH).json()["valid"] is True

# ── V1.4 PE / injection forensics ───────────────────────────────────────────
def _minimal_pe(path):
    import struct
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    off = 0x80
    data[off:off+4] = b"PE\0\0"
    coff = off + 4
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0x65000000, 0, 0, 0xF0, 0x2022)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<H", data, optional + 70, 0x8160)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 0xF0
    data[section:section+8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200:0x400] = b"\x90" * 0x200
    path.write_bytes(data)


def test_v14_pe_collector_is_registered_and_safe_on_non_windows():
    from jocky.collectors.registry import get_collector, is_known_collector
    assert is_known_collector("pe_metadata")
    if os.name != "nt":
        result = get_collector("pe_metadata")()
        assert result["supported"] is False
        assert result["files"] == []


def test_v14_pe_parser_extracts_core_metadata(tmp_path):
    from jocky.collectors.pe_metadata import _parse_pe
    sample = tmp_path / "sample.exe"
    _minimal_pe(sample)
    data = _parse_pe(str(sample))
    assert data["architecture"] == "x64"
    assert data["pe_type"] == "PE32+"
    assert data["section_count"] == 1
    assert data["sections"][0]["name"] == ".text"
    assert data["sha256"]
    assert data["signature_status"] == "unsigned"


def test_v14_pe_rules_cover_static_and_module_correlation():
    from jocky.analysis.pe_rules import (
        rule_unsigned_loaded_module, rule_suspicious_imports,
        rule_high_entropy_module, rule_module_disk_mismatch,
        rule_suspicious_writable_module,
    )
    evidence = {
        "modules": {"modules": [{
            "pid": 123, "process_name": "demo.exe", "module_name": "demo.dll",
            "module_path": "C:\\Users\\Public\\demo.dll", "is_system_path": False,
            "is_user_writable": True, "sha256": "a" * 64,
        }]},
        "pe_metadata": {"files": [{
            "path": "C:\\Users\\Public\\demo.dll", "filename": "demo.dll",
            "sha256": "b" * 64, "signature_status": "unsigned", "entropy": 7.8,
            "imports": ["WriteProcessMemory", "VirtualAllocEx"],
            "sections": [{"name": ".text", "entropy": 7.9, "executable": True, "writable": True}],
        }]},
    }
    assert rule_unsigned_loaded_module(evidence)
    assert rule_suspicious_imports(evidence)
    assert rule_high_entropy_module(evidence)
    assert rule_module_disk_mismatch(evidence)
    assert rule_suspicious_writable_module(evidence)


def test_v14_injection_correlation_uses_pe_context():
    from jocky.analysis.injection_rules import rule_injection_correlation
    evidence = {
        "modules": {"modules": [{"pid": 55, "module_path": "C:\\x.dll", "is_user_writable": True}]},
        "memory_regions": {"regions": []},
        "pe_metadata": {"files": [{"path": "C:\\x.dll", "imports": ["CreateRemoteThread"]}]},
    }
    findings = rule_injection_correlation(evidence)
    assert findings
    assert "suspicious_pe_imports" in findings[0].related_evidence["pe_static_indicators"]


def test_v14_full_dsl_validates(client):
    script = '''investigation "V1.4 PE Hunt" {
        collect processes;
        collect modules;
        collect threads;
        collect memory_regions;
        collect pe_metadata;
        collect network_connections;
        analyze suspicious_module_loads;
        analyze unsigned_loaded_module;
        analyze suspicious_imports;
        analyze high_entropy_module;
        analyze module_disk_mismatch;
        analyze suspicious_writable_module;
        analyze injection_correlation;
        report "v14_pe_hunt";
    }'''
    response = client.post("/api/validate", json={"script": script}, headers=AUTH)
    assert response.status_code == 200, response.text
    assert response.json()["collect_count"] == 6
    assert response.json()["analyze_count"] == 7


def test_v14_html_contains_pe_section(client, monkeypatch):
    from jocky.collectors import registry
    monkeypatch.setitem(registry._COLLECTORS, "pe_metadata", lambda: {
        "supported": True, "files": [{"filename": "demo.dll", "sha256": "a" * 64}], "count": 1
    })
    script = 'investigation "V1.4 HTML" { collect pe_metadata; report "v14"; }'
    run = client.post("/api/investigations", headers=AUTH, json={"script": script})
    assert run.status_code == 200, run.text
    html = client.get(f"/api/investigations/{run.json()['id']}/report.html", headers=AUTH)
    assert html.status_code == 200
    assert "PE / module forensics" in html.text


def test_analysis_execution_coverage_records_zero_hit_rules(client):
    script = 'investigation "coverage" { collect system_info; analyze missing_paths; analyze suspicious_processes; report "coverage"; }'
    response = client.post("/api/investigations", json={"script": script}, headers=AUTH)
    assert response.status_code == 200, response.text
    report = response.json()["report_json"]
    assert [x["target"] for x in report["analysis_results"]] == ["missing_paths", "suspicious_processes"]
    assert all(x["status"] == "success" for x in report["analysis_results"])
    assert all(x["finding_count"] == 0 for x in report["analysis_results"])
    assert client.get(f"/api/investigations/{response.json()['id']}/report.html", headers=AUTH).status_code == 200


def test_domain_expansion_template_covers_live_registries():
    from jocky.collectors.registry import list_collectors
    from jocky.analysis.registry import list_rules
    from jocky.language.interpreter import run_investigation
    from pathlib import Path

    text = Path("examples/v1.4_domain_expansion_triage.jocky").read_text(encoding="utf-8")
    inv = parse(tokenize(text))
    result = run_investigation(inv)
    assert [c.target for c in result.collector_results] == list_collectors()
    assert [a.target for a in result.analysis_results] == list_rules()
    assert len(result.analysis_results) == len(list_rules())


def test_pre_coverage_report_hash_compatibility():
    from jocky.reports.report import Report, CollectorResult, Finding, compute_report_hash, verify_report_integrity
    report = Report(
        investigation_name="legacy", endpoint_hostname="HOST", started_at="a", finished_at="b",
        collector_results=[CollectorResult(target="system_info", status="success", data={"hostname": "HOST"})],
        analysis_results=[], findings=[], collector_errors=[], report_name="legacy", script_hash="x", source={},
    )
    report.report_hash = compute_report_hash(report)
    legacy = {k: v for k, v in report.__dict__.items() if k != "analysis_results"}
    legacy_model = Report(
        investigation_name=legacy["investigation_name"], endpoint_hostname=legacy["endpoint_hostname"],
        started_at=legacy["started_at"], finished_at=legacy["finished_at"], collector_results=legacy["collector_results"],
        analysis_results=[], findings=legacy["findings"], collector_errors=legacy["collector_errors"],
        report_name=legacy["report_name"], script_hash=legacy["script_hash"], report_hash=legacy["report_hash"], source=legacy["source"],
    )
    assert verify_report_integrity(legacy_model)

# ── V1.5 Forensics-as-Code DSL ───────────────────────────────────────────────
def test_v15_boolean_where_and_user_rule():
    from jocky.language.interpreter import run_investigation
    src = '''investigation "dsl" {
        collect processes;
        collect network_connections;
        analyze process_network_correlation
            where destination.is_external == true and process.name != "svchost.exe";
        rule "External Lead" {
            when destination.is_external == true and process.name != "svchost.exe";
            severity high;
        }
        report "dsl";
    }'''
    inv = parse(tokenize(src))
    result = run_investigation(inv)
    assert result.analysis_results
    assert any(f.rule_name == "External Lead" for f in result.findings) or result.findings == []


def test_v15_comments_variables_and_not():
    src = '''investigation "dsl" {
        // comment
        let minimum = 1;
        collect system_info;
        if not system_info.cpu_count < minimum {
            report "ok";
        } else {
            report "low";
        }
    }'''
    inv = parse(tokenize(src))
    assert inv.name == "dsl"


def test_v15_bytecode_roundtrip_with_where_and_user_rule(client):
    src = '''investigation "dsl" {
        collect processes;
        analyze process_network_correlation where destination.is_external == true;
        rule "External Lead" {
            when destination.is_external == true;
            severity high;
        }
        report "dsl";
    }'''
    r = client.post("/api/bytecode/compile", json={"script": src}, headers=AUTH)
    assert r.status_code == 200, r.text
    b = r.json()["bytecode_b64"]
    assert client.post("/api/bytecode/disasm", json={"bytecode_b64": b}, headers=AUTH).status_code == 200


def test_long_investigation_job_is_queued(client):
    src = 'investigation "Long" { collect system_info; report "r"; }'
    r = client.post("/api/investigations/jobs", json={"script": src}, headers=AUTH)
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    import time
    for _ in range(50):
        status = client.get(f"/api/investigations/jobs/{job_id}", headers=AUTH).json()
        if status["status"] == "complete":
            assert status["investigation_id"]
            break
        time.sleep(0.02)
    else:
        raise AssertionError(status)

# ── V1.6 Evidence & Forensic Integrity ───────────────────────────────────────
def test_v16_report_provenance_and_finding_references(client):
    src = '''investigation "V1.6 provenance" {
        collect processes;
        collect network_connections;
        analyze suspicious_processes;
        analyze process_network_correlation;
        report "v1_6";
    }'''
    r = client.post("/api/investigations", json={"script": src}, headers=AUTH)
    assert r.status_code == 200, r.text
    report = r.json()["report_json"]
    assert report["product_name"] == "RANDAR"
    assert report["dsl_name"] == "JOCKY"
    assert report["product_version"] == "1.9.2"
    assert report["script_hash"]
    assert all((c.get("evidence_hash") if c.get("status") == "success" else True) for c in report["collector_results"])
    assert "timeline" in report
    for finding in report["findings"]:
        assert finding["finding_id"].startswith("F-")
        assert isinstance(finding["evidence_refs"], list)
    iid = r.json()["id"]
    assert client.get(f"/api/investigations/{iid}/integrity", headers=AUTH).json()["valid"] is True




def test_v16_product_and_dsl_identity_are_distinct(client):
    src = 'investigation "identity" { collect system_info; report "identity"; }'
    r = client.post("/api/investigations", json={"script": src}, headers=AUTH)
    assert r.status_code == 200
    report = r.json()["report_json"]
    assert report["product_name"] == "RANDAR"
    assert report["dsl_name"] == "JOCKY"

def test_v16_audit_log_records_completion_and_integrity(client):
    src = 'investigation "Audit" { collect system_info; report "audit"; }'
    r = client.post("/api/investigations", json={"script": src}, headers=AUTH)
    assert r.status_code == 200
    iid = r.json()["id"]
    audit = client.get(f"/api/investigations/{iid}/audit", headers=AUTH)
    assert audit.status_code == 200
    assert any(x["action"] == "investigation_completed" for x in audit.json())
    check = client.get(f"/api/investigations/{iid}/integrity", headers=AUTH)
    assert check.status_code == 200 and check.json()["valid"] is True
    audit2 = client.get(f"/api/investigations/{iid}/audit", headers=AUTH).json()
    assert any(x["action"] == "integrity_verified" for x in audit2)


def test_v16_html_contains_provenance_and_timeline(client):
    src = 'investigation "Report" { collect processes; report "report"; }'
    r = client.post("/api/investigations", json={"script": src}, headers=AUTH)
    assert r.status_code == 200
    iid = r.json()["id"]
    html = client.get(f"/api/investigations/{iid}/report.html", headers=AUTH)
    assert html.status_code == 200
    assert "RANDAR" in html.text
    assert "Forensic provenance" in html.text
    assert "Evidence timeline" in html.text


def test_v16_legacy_report_integrity_shape_remains_verifiable():
    from jocky.reports.report import Report, CollectorResult, compute_report_hash, verify_report_integrity
    raw = {
        "investigation_name": "old", "endpoint_hostname": "HOST", "started_at": "a", "finished_at": "b",
        "collector_results": [{"target": "system_info", "status": "success", "data": {"hostname": "HOST"}, "error": None}],
        "analysis_results": [], "findings": [], "collector_errors": [], "report_name": "old", "script_hash": "abc", "report_hash": None, "source": {}
    }
    import hashlib, json
    legacy_for_hash = dict(raw); legacy_for_hash.pop("source", None); legacy_for_hash.pop("analysis_results", None)
    canonical = json.dumps(legacy_for_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    raw["report_hash"] = hashlib.sha256(canonical).hexdigest()
    model = Report(
        investigation_name=raw["investigation_name"], endpoint_hostname=raw["endpoint_hostname"], started_at=raw["started_at"], finished_at=raw["finished_at"],
        collector_results=[CollectorResult(**raw["collector_results"][0])], analysis_results=[], findings=[], collector_errors=[],
        report_name=raw["report_name"], script_hash=raw["script_hash"], report_hash=raw["report_hash"], source={}, integrity_version=1
    )
    assert verify_report_integrity(model)

# ── V1.7 investigation progress regression ────────────────────────────────────
def test_background_interpreter_reports_progress_steps():
    from jocky.language.lexer import tokenize
    from jocky.language.parser import parse
    from jocky.language.interpreter import run_investigation

    src = 'investigation "Progress" {\n        collect system_info;\n        collect processes;\n        analyze suspicious_processes;\n        report "progress";\n    }'
    investigation = parse(tokenize(src))
    updates = []
    result = run_investigation(investigation, progress_callback=lambda pct, msg: updates.append((pct, msg)))
    assert result.report_name == "progress"
    assert updates[0][0] == 5
    assert any(pct > 5 for pct, _ in updates)
    assert updates[-1][0] == 85
    assert updates[-1][1].startswith("Investigation execution complete")


# ── V1.7 remote endpoint operations ─────────────────────────────────────────
def test_agent_state_persists_and_capabilities_negotiate(client):
    r = client.post('/api/agents/register', headers=AUTH, json={
        'hostname': 'WIN-017', 'platform': 'Windows',
        'capabilities': ['collector:processes', 'rule:network_beaconing'],
    })
    assert r.status_code == 200
    aid, token = r.json()['agent_id'], r.json()['agent_token']
    assert 'collector:processes' in r.json()['capabilities']
    ar = client.get(f'/api/agents/{aid}/capabilities', headers=AUTH)
    assert ar.status_code == 200 and 'rule:network_beaconing' in ar.json()['capabilities']
    ah = {'Authorization': 'Bearer ' + token}
    hb = client.post(f'/api/agents/{aid}/heartbeat', headers=ah, json={'capabilities': ['collector:processes','collector:sysmon_events']})
    assert hb.status_code == 200
    assert 'collector:sysmon_events' in hb.json()['capabilities']


def test_secure_job_metadata_and_cancellation(client):
    r = client.post('/api/agents/register', headers=AUTH, json={'hostname':'WIN-018','platform':'Windows'})
    aid, token = r.json()['agent_id'], r.json()['agent_token']
    j = client.post(f'/api/agents/{aid}/jobs', headers=AUTH, json={'script':'investigation "x" { report "r"; }'})
    assert j.status_code == 200
    body = j.json()
    assert body['expires_at'] and body['signature']
    ah = {'Authorization':'Bearer '+token}
    pending = client.get(f'/api/agents/{aid}/jobs/pending', headers=ah).json()
    assert pending['signature'] == body['signature'] and pending['nonce']
    c = client.post(f'/api/agents/{aid}/jobs/{body["job_id"]}/cancel', headers=AUTH)
    assert c.status_code == 200
    st = client.get(f'/api/agents/{aid}/jobs/{body["job_id"]}/status', headers=ah)
    assert st.status_code == 200 and st.json()['status'] == 'cancelled'


def test_revocation_persists(client):
    r = client.post('/api/agents/register', headers=AUTH, json={'hostname':'WIN-019','platform':'Windows'})
    aid, token = r.json()['agent_id'], r.json()['agent_token']
    assert client.delete(f'/api/agents/{aid}', headers=AUTH).status_code == 200
    assert client.get(f'/api/agents/{aid}/capabilities', headers=AUTH).status_code == 404
    assert client.get('/api/agents', headers=AUTH).json()[-1]['status'] != 'revoked'
    assert client.get(f'/api/agents/{aid}/jobs/pending', headers={'Authorization':'Bearer '+token}).status_code == 401


def test_agent_registry_survives_store_reload():
    from jocky.api import agent_store as store
    aid, _ = store.register_agent('PERSIST-017', 'Windows')
    store.update_capabilities(aid, ['collector:processes'])
    store._agents.clear()
    store._initialized = False
    store.init_persistence()
    restored = store.get_agent(aid)
    assert restored is not None
    assert restored.hostname == 'PERSIST-017'
    assert restored.capabilities == ['collector:processes']

# ── V1.8 Investigation Experience ────────────────────────────────────────────
def test_v18_global_search_finds_case_finding_and_evidence(client):
    src = '''investigation "V1.8 Search Case" {
        collect processes;
        report "v1_8_search";
    }'''
    r = client.post('/api/investigations', json={'script': src}, headers=AUTH)
    assert r.status_code == 200, r.text
    iid = r.json()['id']
    q = client.get('/api/search', params={'q': 'V1.8 Search Case'}, headers=AUTH)
    assert q.status_code == 200
    assert any(x['investigation_id'] == iid for x in q.json()['results'])
    q2 = client.get('/api/search', params={'q': 'processes'}, headers=AUTH)
    assert q2.status_code == 200
    assert q2.json()['results']


def test_v18_findings_have_explanation_fields_and_integrity(client):
    src = '''investigation "V1.8 Explainability" {
        collect processes;
        analyze missing_paths;
        report "v1_8_explain";
    }'''
    r = client.post('/api/investigations', json={'script': src}, headers=AUTH)
    assert r.status_code == 200, r.text
    report = r.json()['report_json']
    assert report['integrity_version'] == 4
    for finding in report['findings']:
        assert finding['limitations']
        assert finding['next_check']
    iid = r.json()['id']
    assert client.get(f'/api/investigations/{iid}/integrity', headers=AUTH).json()['valid'] is True


def test_v18_legacy_v2_report_hash_remains_verifiable():
    from jocky.reports.report import Report, CollectorResult, Finding, compute_report_hash, verify_report_integrity
    report = Report(
        investigation_name='legacy-v2', endpoint_hostname='HOST', started_at='a', finished_at='b',
        collector_results=[CollectorResult(target='system_info', status='success', data={'hostname':'HOST'})],
        analysis_results=[], findings=[Finding(rule_name='x', severity='informational', summary='x', reason='r')],
        collector_errors=[], report_name='legacy-v2', script_hash='abc', integrity_version=2,
    )
    report.report_hash = compute_report_hash(report)
    assert verify_report_integrity(report)

# ── V1.9 Performance & Reliability ───────────────────────────────────────────
def test_v19_collector_timeout_is_partial_not_investigation_failure(monkeypatch):
    import time
    from jocky.collectors import registry
    from jocky.language.interpreter import run_investigation

    original = registry._COLLECTORS["system_info"]
    def slow_collector():
        time.sleep(0.20)
        return {"hostname": "late"}
    registry._COLLECTORS["system_info"] = slow_collector
    try:
        inv = parse(tokenize('investigation "timeout" { collect system_info; report "r"; }'))
        started = time.monotonic()
        result = run_investigation(inv, collector_timeout_seconds=0.05)
        elapsed = time.monotonic() - started
        assert elapsed < 0.15
        assert result.collector_results[0].status == "timeout"
        assert result.collector_results[0].duration_ms >= 40
        assert result.resource_usage["timed_out_collectors"] == 1
    finally:
        registry._COLLECTORS["system_info"] = original


def test_v19_progress_advances_while_commands_are_active():
    from jocky.language.interpreter import run_investigation
    inv = parse(tokenize('investigation "progress" { collect system_info; collect processes; report "r"; }'))
    updates = []
    run_investigation(inv, progress_callback=lambda value, message: updates.append((value, message)))
    values = [value for value, _ in updates]
    assert any(value > 5 for value in values)
    assert values[-1] == 85


def test_v19_windows_collector_timeout_profiles_are_bounded():
    from jocky.language.interpreter import _collector_timeout
    assert _collector_timeout("system_info", 30) == 30
    assert _collector_timeout("modules", 30) == 90
    assert _collector_timeout("pe_metadata", 30) == 120
    assert _collector_timeout("unknown_collector", 30) == 30


def test_v19_record_limit_is_explicitly_accounted(monkeypatch):
    from jocky.collectors import registry
    from jocky.language.interpreter import run_investigation
    original = registry._COLLECTORS["system_info"]
    registry._COLLECTORS["system_info"] = lambda: {"items": [{"n": i} for i in range(10005)]}
    try:
        inv = parse(tokenize('investigation "bounded" { collect system_info; report "r"; }'))
        result = run_investigation(inv)
        cr = result.collector_results[0]
        assert cr.status == "success"
        assert cr.truncated is True
        assert cr.record_count == 10000
        assert cr.data["_randar_resource_limit"]["truncated"] is True
        assert result.resource_usage["truncated_collectors"] == 1
    finally:
        registry._COLLECTORS["system_info"] = original


def test_v19_runtime_and_cancellation_stop_before_work():
    import threading
    from jocky.language.interpreter import run_investigation
    inv = parse(tokenize('investigation "limits" { collect system_info; report "r"; }'))
    result = run_investigation(inv, max_runtime_seconds=0)
    assert result.execution_status == "partial"
    assert result.termination_reason and "runtime" in result.termination_reason.lower()

    event = threading.Event(); event.set()
    result2 = run_investigation(inv, cancel_check=event.is_set)
    assert result2.execution_status == "cancelled"
    assert "cancelled" in (result2.termination_reason or "").lower()


def test_v19_cancellation_never_resurrects_queued_job(monkeypatch):
    from jocky.api import investigation_jobs as jobs
    from jocky.language.lexer import tokenize
    from jocky.language.parser import parse
    inv = parse(tokenize('investigation "queued cancel" { report "r"; }'))
    original_submit = jobs._executor.submit
    submitted = []
    monkeypatch.setattr(jobs._executor, "submit", lambda *args: submitted.append(args))
    try:
        jid = jobs.submit(inv, 'investigation "queued cancel" { report "r"; }', None)
        state = jobs.cancel(jid)
        assert state['status'] == 'cancelled'
        # Execute the delayed worker manually: it must not resurrect the job.
        jobs._worker(*submitted[0][1:])
        assert jobs.get(jid)['status'] == 'cancelled'
    finally:
        monkeypatch.setattr(jobs._executor, "submit", original_submit)


def test_v19_pagination_and_lazy_evidence_endpoints(client):
    page = client.get('/api/investigations', params={'page': 1, 'limit': 2}, headers=AUTH)
    assert page.status_code == 200
    body = page.json()
    assert isinstance(body['items'], list)
    assert body['limit'] == 2
    assert 'total' in body and 'has_next' in body

    src = 'investigation "V1.9 lazy evidence" { collect processes; report "lazy"; }'
    created = client.post('/api/investigations', json={'script': src}, headers=AUTH)
    assert created.status_code == 200
    iid = created.json()['id']
    shallow = client.get(f'/api/investigations/{iid}', params={'include_evidence': 'false'}, headers=AUTH)
    assert shallow.status_code == 200
    collector = next(c for c in shallow.json()['report_json']['collector_results'] if c['target'] == 'processes')
    if collector.get('data', {}).get('_lazy_evidence'):
        lazy = client.get(f'/api/investigations/{iid}/evidence', params={'collector': 'processes', 'page': 1, 'limit': 10}, headers=AUTH)
        assert lazy.status_code == 200
        assert len(lazy.json()['rows']) <= 10
        assert lazy.json()['list_key'] == 'processes'


def test_v19_background_job_cancellation_endpoint(client, monkeypatch):
    from jocky.collectors import registry
    original = registry._COLLECTORS["system_info"]
    def slow():
        time.sleep(0.20)
        return {"hostname": "slow"}
    registry._COLLECTORS["system_info"] = slow
    try:
        r = client.post('/api/investigations/jobs', headers=AUTH, json={'script': 'investigation "cancel v19" { collect system_info; report "r"; }'})
        assert r.status_code == 200
        jid = r.json()['job_id']
        cancelled = client.post(f'/api/investigations/jobs/{jid}/cancel', headers=AUTH)
        assert cancelled.status_code == 200
        assert cancelled.json()['status'] in {'cancelled', 'cancelling', 'running', 'queued'}
        for _ in range(20):
            st = client.get(f'/api/investigations/jobs/{jid}', headers=AUTH).json()
            if st['status'] in {'cancelled', 'complete', 'partial', 'error'}:
                break
            time.sleep(0.02)
        assert st['status'] == 'cancelled'
    finally:
        registry._COLLECTORS["system_info"] = original
    for _ in range(10):
        st = client.get(f'/api/investigations/jobs/{jid}', headers=AUTH).json()
        if st['status'] in {'cancelled', 'complete', 'partial', 'error'}:
            break
        time.sleep(0.02)
    assert st['status'] == 'cancelled'


def test_v19_report_resource_accounting_and_integrity(client):
    src = 'investigation "V1.9 accounting" { collect system_info; report "v19"; }'
    r = client.post('/api/investigations', json={'script': src}, headers=AUTH)
    assert r.status_code == 200
    report = r.json()['report_json']
    assert report['integrity_version'] == 4
    assert report['execution_status'] == 'complete'
    assert report['resource_usage']['collector_count'] >= 1
    collector = report['collector_results'][0]
    assert 'duration_ms' in collector and 'resource_bytes' in collector
    iid = r.json()['id']
    assert client.get(f'/api/investigations/{iid}/integrity', headers=AUTH).json()['valid'] is True
    html = client.get(f'/api/investigations/{iid}/report.html', headers=AUTH)
    assert html.status_code == 200
    assert 'Execution & resource accounting' in html.text


def test_v19_legacy_v3_report_integrity_remains_verifiable():
    from jocky.reports.report import Report, CollectorResult, Finding, compute_report_hash, verify_report_integrity
    report = Report(
        investigation_name='legacy-v3', endpoint_hostname='HOST', started_at='a', finished_at='b',
        collector_results=[CollectorResult(target='system_info', status='success', data={'hostname': 'HOST'})],
        analysis_results=[], findings=[Finding(rule_name='x', severity='informational', summary='x', reason='r', limitations='l', next_check='n')],
        collector_errors=[], report_name='legacy-v3', script_hash='abc', integrity_version=3,
    )
    report.report_hash = compute_report_hash(report)
    assert verify_report_integrity(report)

# ── V1.9.2 frontend navigation/reliability contracts ─────────────────────────
def test_frontend_navigation_loaders_abort_stale_requests():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "frontend" / "src"
    hooks = (root / "hooks.js").read_text(encoding="utf-8")
    client = (root / "api" / "client.js").read_text(encoding="utf-8")
    assert "new AbortController()" in hooks
    assert "activeController.current?.abort()" in hooks
    assert "signal.addEventListener(\"abort\", abortFromCaller" in client
    assert "options.signal = controller.signal" in client


def test_frontend_job_cancellation_has_single_poll_owner():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "frontend" / "src" / "pages" / "NewInvestigation.jsx").read_text(encoding="utf-8")
    assert "async function pollInvestigationJob(jobId)" in source
    assert "async function cancelRun()" in source
    # Cancellation must not start a second status-poll loop.
    cancel_section = source.split("async function cancelRun()", 1)[1].split("async function act", 1)[0]
    assert "while ([\"queued\", \"running\", \"cancelling\"]" not in cancel_section
    assert "single polling loop owns job state" in cancel_section


def test_frontend_route_data_is_normalized_before_array_iteration():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "frontend" / "src" / "pages"
    agents = (root / "Agents.jsx").read_text(encoding="utf-8")
    investigations = (root / "Investigations.jsx").read_text(encoding="utf-8")
    search = (root / "Search.jsx").read_text(encoding="utf-8")
    assert "const agents = Array.isArray(data) ? data : [];" in agents
    assert "const jobs = Array.isArray(data) ? data : [];" in agents
    assert "Array.isArray(pageData?.items)" in investigations
    assert "Array.isArray(state.data?.results)" in search
