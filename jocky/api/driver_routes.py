"""Protected V2.5 driver/kernel observation endpoints."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from jocky.api.auth import verify_token
from jocky.reports.forensic_scan import persist_forensic_scan
from jocky.analysis.driver_forensics import build_driver_forensics, build_driver_forensics_findings
from jocky.collectors.registry import get_collector
from jocky.analysis.software_catalog import annotate_evidence, summarize as summarize_software


driver_router = APIRouter(dependencies=[Depends(verify_token)], tags=["driver-forensics"])


@driver_router.post("/api/driver-forensics/scan")
def driver_forensics_scan() -> dict:
    """Run a bounded driver scan and persist it as a first-class investigation."""
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    evidence: dict = {}
    errors: list[dict] = []
    for target in ("driver_inventory", "windows_event_logs", "sysmon_events"):
        try:
            evidence[target] = get_collector(target)()
        except Exception as exc:
            evidence[target] = {"error": str(exc), "supported": False}
            errors.append({"collector": target, "error": str(exc)})

    annotate_evidence(evidence)
    report = build_driver_forensics(evidence)
    report["software_summary"] = summarize_software(evidence)
    findings = build_driver_forensics_findings(report)
    analysis_results = [{"target": "driver_forensics_exposure", "status": "success", "finding_count": len(findings)}]

    try:
        from jocky.analysis.research_rules import rule_byoVD_driver_indicators
        compatibility_findings = rule_byoVD_driver_indicators(evidence)
        added = 0
        for finding in compatibility_findings:
            key = (finding.rule_name, (finding.related_evidence or {}).get("service_name"))
            if not any((f.rule_name, (f.related_evidence or {}).get("service_name")) == key for f in findings):
                findings.append(finding)
                added += 1
        analysis_results.append({"target": "byovd_driver_indicators", "status": "success", "finding_count": added})
    except Exception as exc:
        errors.append({"rule": "byovd_driver_indicators", "error": str(exc)})
        analysis_results.append({"target": "byovd_driver_indicators", "status": "error", "finding_count": 0, "error": str(exc)})

    finished_at = datetime.now(timezone.utc)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    finding_dicts = [_finding_to_dict(f) for f in findings]
    investigation_id, stored_report = persist_forensic_scan(
        investigation_name="Driver Forensics Scan",
        scan_type="driver",
        evidence=evidence,
        findings=finding_dicts,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=elapsed_ms,
        collector_errors=errors,
        analysis_results=analysis_results,
        snapshot_hash=report.get("snapshot_hash"),
    )
    report["findings"] = finding_dicts
    report["finding_count"] = len(findings)
    report["collector_errors"] = errors
    report["elapsed_ms"] = elapsed_ms
    report["investigation_id"] = investigation_id
    report["persisted"] = True
    return report


def _finding_to_dict(finding):
    return {
        "rule_name": finding.rule_name, "severity": finding.severity,
        "summary": finding.summary, "reason": finding.reason,
        "related_evidence": finding.related_evidence,
        "limitations": finding.limitations, "next_check": finding.next_check,
        "evidence_refs": finding.evidence_refs,
    }

