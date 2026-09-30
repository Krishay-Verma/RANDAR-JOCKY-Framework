from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_driver_forensics_rule_is_live_registered():
    from jocky.analysis.registry import is_known_rule, get_rule
    assert is_known_rule("driver_forensics_exposure")
    assert callable(get_rule("driver_forensics_exposure"))


def test_domain_expansion_template_contains_registered_driver_rule():
    text = (ROOT / "examples" / "v1.4_domain_expansion_triage.jocky").read_text(encoding="utf-8")
    assert "analyze driver_forensics_exposure;" in text


def test_standalone_forensic_pages_persist_results_into_investigations():
    for name in ("MemoryForensics.jsx", "DriverForensics.jsx", "PersistenceForensics.jsx"):
        source = (ROOT / "frontend" / "src" / "pages" / name).read_text(encoding="utf-8")
        assert "result.investigation_id" in source
        assert "Open saved investigation" in source


def test_summary_resource_strip_has_explicit_spacing_and_wrapping():
    css = (ROOT / "frontend" / "src" / "index.css").read_text(encoding="utf-8")
    assert ".v19-resource-strip{display:flex;flex-wrap:wrap" in css
    assert "gap:8px 18px" in css
    assert ".v19-resource-strip span" in css


def test_product_version_is_2_8_1():
    assert 'version = "3.0.0"' in (ROOT / "pyproject.toml").read_text()
    assert '__version__ = "3.0.0"' in (ROOT / "jocky" / "__init__.py").read_text()


def test_memory_scan_api_returns_persisted_investigation_id(monkeypatch):
    import hashlib, os
    os.environ.setdefault("JOCKY_API_TOKEN_HASH", hashlib.sha256(b"t" * 43).hexdigest())
    from fastapi.testclient import TestClient
    import jocky.collectors.registry as collector_registry
    from jocky.api.main import app
    evidence = {
        "processes": {"count": 1, "processes": [{"pid": 7, "name": "sample.exe", "exe_path": r"C:\\sample.exe"}]},
        "modules": {"count": 1, "modules": [{"pid": 7}]},
        "threads": {"count": 0, "threads": []},
        "memory_regions": {"supported": True, "count": 1, "regions": [{"pid": 7, "base_address": 4096, "region_size": 4096, "protect": 0x40, "is_executable": True, "is_private": True, "is_private_executable": True}]},
    }
    monkeypatch.setattr(collector_registry, "get_collector", lambda name: (lambda: evidence[name]))
    auth = {"Authorization": "Bearer " + "t" * 43}
    with TestClient(app) as client:
        response = client.post("/api/memory-forensics/scan", json={}, headers=auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert isinstance(body.get("investigation_id"), int)
        assert body.get("persisted") is True
        stored = client.get(f"/api/investigations/{body['investigation_id']}", headers=auth)
        assert stored.status_code == 200
        stored_body = stored.json()
        assert any(c["target"] == "memory_regions" for c in stored_body["report_json"]["collector_results"])


def test_driver_rule_is_accepted_by_validation():
    from jocky.language.lexer import tokenize
    from jocky.language.parser import parse
    text = '''investigation "driver validation" {\n collect driver_inventory;\n analyze driver_forensics_exposure;\n report "driver";\n}'''
    inv = parse(tokenize(text))
    assert inv.name == "driver validation"
