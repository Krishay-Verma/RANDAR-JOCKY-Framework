from jocky.analysis.driver_forensics import build_driver_forensics, build_driver_forensics_findings
from jocky.collectors.drivers import _loaded_driver_map


def _evidence():
    return {
        "driver_inventory": {
            "supported": True,
            "vulnerability_catalog": "tests/catalog.json",
            "drivers": [
                {
                    "service_name": "LabVuln",
                    "display_name": "Lab Vulnerable Driver",
                    "image_path": r"C:\Windows\System32\drivers\labvuln.sys",
                    "file_exists": True,
                    "sha256": "abc",
                    "loaded": True,
                    "signature_status": "signed",
                    "publisher": "CN=Lab Publisher",
                    "version": "1.2.3",
                    "known_vulnerable": True,
                    "vulnerability_ids": ["LOCAL-001"],
                    "catalog_source": "tests",
                    "is_user_writable_path": False,
                },
                {
                    "service_name": "LabMissing",
                    "display_name": "Missing Driver",
                    "image_path": r"C:\Windows\System32\drivers\missing.sys",
                    "file_exists": False,
                    "loaded": False,
                    "signature_status": "unknown",
                    "known_vulnerable": False,
                    "is_user_writable_path": False,
                },
            ],
        },
        "windows_event_logs": {"supported": True, "count": 4},
        "sysmon_events": {"supported": True, "count": 2},
    }


def test_v25_driver_report_has_inventory_and_kernel_observation():
    report = build_driver_forensics(_evidence())
    assert report["version"] == "3.0.0"
    assert report["summary"]["drivers"] == 2
    assert report["summary"]["loaded_drivers"] == 1
    assert report["summary"]["known_vulnerable_drivers"] == 1
    assert report["kernel_observation"]["kernel_state_modified"] is False
    assert len(report["snapshot_hash"]) == 64


def test_v25_driver_findings_preserve_vulnerability_provenance():
    findings = build_driver_forensics_findings(build_driver_forensics(_evidence()))
    assert any(f.rule_name == "driver_forensics_exposure" for f in findings)
    finding = next(f for f in findings if f.rule_name == "driver_forensics_exposure")
    assert finding.severity == "high"
    assert finding.related_evidence["vulnerability_ids"] == ["LOCAL-001"]
    assert finding.related_evidence["loaded"] is True


def test_loaded_driver_query_parser_handles_empty_output(monkeypatch):
    class Result:
        returncode = 0
        stdout = ""
    monkeypatch.setattr("jocky.collectors.drivers.subprocess.run", lambda *a, **k: Result())
    assert _loaded_driver_map() == {}
