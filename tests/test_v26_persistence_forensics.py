from jocky.analysis.persistence_forensics import (
    build_persistence_forensics,
    build_persistence_forensics_findings,
    rule_persistence_cross_surface_correlation,
    rule_persistence_privilege_correlation,
)
from jocky.analysis.registry import is_known_rule


def evidence():
    shared = r"C:\Program Files\Acme Agent\agent.exe"
    return {
        "startup_items": {"count": 1, "items": [{"name": "Acme", "command": shared, "type": "registry_run_key", "source": "HKLM"}]},
        "scheduled_tasks": {"count": 1, "tasks": [{"name": "\\Acme", "task_to_run": shared}]},
        "services": {"count": 1, "services": [{"service_name": "AcmeSvc", "executable": shared, "account": "LocalSystem", "writable_path": False}]},
        "local_users": {"count": 2, "users": []},
        "logged_in_users": {"count": 1, "sessions": [{"username": "analyst"}]},
        "processes": {"count": 3, "processes": []},
        "windows_event_logs": {"supported": True, "count": 2, "events": [{"event_type": "privilege"}, {"event_type": "service_change"}]},
        "sysmon_events": {"supported": True, "count": 1, "events": []},
    }


def test_v26_report_correlates_persistence_surfaces_and_is_deterministic():
    report = build_persistence_forensics(evidence())
    assert report["version"] == "3.0.0"
    assert report["summary"]["cross_surface_paths"] == 1
    assert len(report["snapshot_hash"]) == 64
    assert report["snapshot_hash"] == build_persistence_forensics(evidence())["snapshot_hash"]


def test_v26_cross_surface_and_privilege_rules_fire_with_context():
    ev = evidence()
    assert any(f.rule_name == "persistence_cross_surface_correlation" for f in rule_persistence_cross_surface_correlation(ev))
    assert any(f.rule_name == "persistence_privilege_correlation" for f in rule_persistence_privilege_correlation(ev))
    findings = build_persistence_forensics_findings(ev, build_persistence_forensics(ev))
    assert {f.rule_name for f in findings} >= {"persistence_cross_surface_correlation", "persistence_privilege_correlation"}


def test_v26_rules_are_registered_for_jocky():
    assert is_known_rule("persistence_cross_surface_correlation")
    assert is_known_rule("persistence_privilege_correlation")


def test_v26_normalizes_quoted_windows_paths_with_spaces():
    ev = evidence()
    ev["startup_items"]["items"][0]["command"] = r'"C:\Program Files\Acme Agent\agent.exe" --service'
    ev["scheduled_tasks"]["tasks"][0]["task_to_run"] = r'"C:\Program Files\Acme Agent\agent.exe" --task'
    report = build_persistence_forensics(ev)
    assert report["summary"]["cross_surface_paths"] == 1
    assert report["cross_surface"][0]["path"] == r"c:\program files\acme agent\agent.exe"
