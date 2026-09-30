import json
from pathlib import Path

from jocky.analysis.rules_extended import check_suspicious_startup_items, check_unusual_scheduled_tasks
from jocky.analysis.windows_telemetry import rule_suspicious_services, rule_writable_service_paths
from jocky.analysis.dedup import deduplicate_findings
from jocky.collectors.win_acl import _parse_icacls, inspect_write_access
from jocky.analysis.advanced_persistence import RULES as ADVANCED_RULES
from jocky.reports.builder import build_report
from jocky.language.interpreter import InvestigationResult, CollectorResult
from datetime import datetime, timezone

FIX = Path(__file__).parent / "fixtures"

def load(name):
    return json.loads((FIX / name).read_text())

def test_dacl_parser_does_not_mark_system32_read_execute_as_writable():
    parsed = _parse_icacls("C:\\Windows\\System32\\svchost.exe\nBUILTIN\\Users:(RX)\nNT AUTHORITY\\Authenticated Users:(RX)\nEveryone:(RX)")
    assert parsed["grants"]
    assert not any(set(x["permissions"]) & {"W","M","F"} for x in parsed["grants"])

def test_non_windows_acl_is_unknown_not_false_positive():
    result = inspect_write_access(r"C:\\Windows\\System32\\svchost.exe")
    assert result["writable"] == "unknown"

def test_env_expansion_and_normalization():
    from jocky.analysis.persistence_enrichment import expand_windows_vars, normalize_windows_path
    assert "\\windows\\system32" in normalize_windows_path(r"%windir%\\System32\\SecurityHealthSystray.exe")
    assert normalize_windows_path(r"C:/Windows/System32/../System32/test.exe").endswith(r"windows\system32\test.exe")

def test_clean_fixture_stays_below_noise_budget():
    ev = load("windows_clean_persistence.json")
    findings = []
    findings += check_suspicious_startup_items(ev)
    findings += check_unusual_scheduled_tasks(ev)
    findings += rule_suspicious_services(ev)
    findings += rule_writable_service_paths(ev)
    assert len(deduplicate_findings(findings)) < 15
    assert not any(f.severity in {"high", "critical"} for f in deduplicate_findings(findings))

def test_planted_fixture_surfaces_distinct_leads():
    ev = load("windows_planted_persistence.json")
    assert check_suspicious_startup_items(ev)
    assert check_unusual_scheduled_tasks(ev)
    assert rule_writable_service_paths(ev)
    wmi = ADVANCED_RULES["wmi_event_subscription"](ev)
    assert wmi and any(f.severity == "high" for f in wmi)

def test_service_alias_rules_merge_to_one_condition():
    ev = load("windows_planted_persistence.json")
    findings = deduplicate_findings(rule_suspicious_services(ev) + rule_writable_service_paths(ev))
    assert len(findings) == 1
    assert "suspicious_services" in findings[0].related_evidence["merged_rules"]
    assert "writable_service_paths" in findings[0].related_evidence["merged_rules"]

def test_report_findings_have_stable_ids_refs_and_mandatory_explanations():
    ev = load("windows_planted_persistence.json")
    findings = deduplicate_findings(check_suspicious_startup_items(ev) + check_unusual_scheduled_tasks(ev) + rule_writable_service_paths(ev))
    result = InvestigationResult(name="fixture")
    for target, data in ev.items():
        result.collector_results.append(CollectorResult(target=target, status="success", data=data, record_count=int(data.get("count",0))))
    result.findings = findings
    report = build_report(result, datetime.now(timezone.utc), datetime.now(timezone.utc), script_hash="a"*64, bytecode_hash="b"*64)
    assert report.findings
    assert all(f.finding_id and len(f.finding_id) > 10 for f in report.findings)
    assert all(f.evidence_refs for f in report.findings)
    assert all(f.limitations and f.next_check for f in report.findings)
    assert report.summary["deduplicated_findings"] == len(report.findings)
    assert report.coverage
    assert report.termination_reason == "completed"

def test_wmi_rule_is_registered_and_reads_direct_collector():
    ev=load("windows_planted_persistence.json")
    assert ADVANCED_RULES["wmi_event_subscription"](ev)

def test_report_and_evidence_hashes_verify_independently():
    from jocky.analysis.report_integrity import verify_evidence_hashes
    ev = load("windows_planted_persistence.json")
    result = InvestigationResult(name="integrity")
    for target, data in ev.items():
        result.collector_results.append(CollectorResult(target=target, status="success", data=data, record_count=int(data.get("count",0))))
    result.findings = deduplicate_findings(check_suspicious_startup_items(ev) + check_unusual_scheduled_tasks(ev))
    report = build_report(result, datetime.now(timezone.utc), datetime.now(timezone.utc), script_hash="a"*64, bytecode_hash="b"*64)
    from jocky.reports.report import verify_report_integrity
    assert verify_report_integrity(report)
    assert all(verify_evidence_hashes(report).values())
