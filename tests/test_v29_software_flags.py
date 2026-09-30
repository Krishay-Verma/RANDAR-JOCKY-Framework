from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_security_software_catalog_classifies_requested_products():
    from jocky.analysis.software_catalog import classify
    assert classify(name="MsMpEng.exe")[0]["label"] == "Microsoft Defender"
    assert classify(name="avp.exe")[0]["label"] == "Kaspersky"
    assert classify(name="vgc.exe")[0]["label"] == "Riot Vanguard"
    assert classify(name="EasyAntiCheat_EOS.exe")[0]["label"] == "Easy Anti-Cheat"
    assert classify(name="BEService.exe")[0]["label"] == "BattlEye"
    assert classify(path=r"C:\Program Files\Denuvo\DenuvoAntiCheat.exe")[0]["label"] == "Denuvo Anti-Cheat"


def test_kernel_flag_requires_observed_driver_evidence():
    from jocky.analysis.software_catalog import annotate_evidence
    evidence = {
        "processes": {"processes": [{"pid": 1, "name": "vgc.exe", "exe_path": r"C:\Riot Vanguard\vgc.exe"}]},
        "driver_inventory": {"drivers": [{"service_name": "vgk", "image_path": r"C:\Windows\System32\drivers\vgk.sys"}]},
        "modules": {"modules": []},
    }
    annotate_evidence(evidence)
    assert evidence["processes"]["processes"][0]["program_flags"]
    assert evidence["processes"]["processes"][0]["kernel_component_observed"] is True
    assert evidence["driver_inventory"]["drivers"][0]["kernel_component_observed"] is True


def test_report_contains_software_summary_and_new_integrity_version(tmp_path):
    import hashlib, os
    from fastapi.testclient import TestClient
    from jocky.api.main import app
    os.environ["JOCKY_API_TOKEN_HASH"] = hashlib.sha256(b"t" * 43).hexdigest()
    src = 'investigation "software context" { collect processes; collect driver_inventory; report "software"; }'
    with TestClient(app) as client:
        response = client.post('/api/investigations', json={'script': src}, headers={'Authorization': 'Bearer ' + 't' * 43})
    assert response.status_code == 200, response.text
    report = response.json()['report_json']
    assert report['integrity_version'] == 6
    assert 'software_summary' in report


def test_ui_exposes_program_flags_and_async_hunts():
    driver = (ROOT / 'frontend/src/pages/DriverForensics.jsx').read_text()
    memory = (ROOT / 'frontend/src/pages/MemoryForensics.jsx').read_text()
    injection = (ROOT / 'frontend/src/pages/InjectionAnalysis.jsx').read_text()
    windows = (ROOT / 'frontend/src/pages/WindowsTelemetry.jsx').read_text()
    assert 'ProgramFlags' in driver
    assert 'ProgramFlags' in memory
    assert 'useInvestigationJob' in injection
    assert 'useInvestigationJob' in windows


def test_catalog_exposes_software_profiles():
    from jocky.api.catalog import build_catalog
    labels = {x["label"] for x in build_catalog()["software_profiles"]}
    assert "Microsoft Defender" in labels
    assert "Riot Vanguard" in labels
    assert "Denuvo Anti-Cheat" in labels


def test_security_software_template_is_available():
    lib = (ROOT / 'frontend/src/lib.js').read_text()
    assert 'Security software & kernel review' in lib
    assert 'driver_forensics_exposure' in lib
