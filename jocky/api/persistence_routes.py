"""Protected V2.6 persistence and privilege forensics endpoints."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends

from jocky.api.auth import verify_token
from jocky.reports.forensic_scan import persist_forensic_scan
from jocky.analysis.persistence_forensics import build_persistence_forensics, build_persistence_forensics_findings
from jocky.collectors.registry import get_collector
from jocky.analysis.software_catalog import annotate_evidence, summarize as summarize_software

persistence_router = APIRouter(dependencies=[Depends(verify_token)], tags=["persistence-forensics"])

_TARGETS = (
    "startup_items", "scheduled_tasks", "services", "local_users",
    "logged_in_users", "processes", "windows_event_logs", "sysmon_events",
)

@persistence_router.post("/api/persistence-forensics/scan")
def persistence_forensics_scan() -> dict:
    """Run a bounded persistence scan and persist it as a first-class investigation."""
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    evidence: dict = {}
    errors: list[dict] = []
    for target in _TARGETS:
        try:
            evidence[target] = get_collector(target)()
        except Exception as exc:
            evidence[target] = {"error": str(exc), "supported": False}
            errors.append({"collector": target, "error": str(exc)})

    annotate_evidence(evidence)
    report = build_persistence_forensics(evidence)
    report["software_summary"] = summarize_software(evidence)
    findings = build_persistence_forensics_findings(evidence, report)
    analysis_results = [
        {"target": "persistence_cross_surface_correlation", "status": "success", "finding_count": sum(f.rule_name == "persistence_cross_surface_correlation" for f in findings)},
        {"target": "persistence_privilege_correlation", "status": "success", "finding_count": sum(f.rule_name == "persistence_privilege_correlation" for f in findings)},
    ]
    finished_at = datetime.now(timezone.utc)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    finding_dicts = [_finding_to_dict(f) for f in findings]
    investigation_id, stored_report = persist_forensic_scan(
        investigation_name="Persistence & Privilege Scan",
        scan_type="persistence",
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

