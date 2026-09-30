"""Persistence adapter for standalone forensic scans.

Standalone Memory/Driver/Persistence workspace scans are first-class RANDAR
investigations.  This module converts their bounded collector output into the
same immutable Report shape used by JOCKY investigations, so the evidence is
searchable, auditable, downloadable, and visible in the Investigations UI.
"""
from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from jocky.reports.report import (
    AnalysisResult as ReportAnalysisResult,
    CollectorResult as ReportCollectorResult,
    Finding as ReportFinding,
    Report,
    compute_report_hash,
)
from jocky.storage.audit import audit_event
from jocky.storage.database import save_investigation
from jocky.analysis.software_catalog import annotate_evidence, summarize as summarize_software
from jocky.analysis.dedup import deduplicate_findings, finding_subject
from jocky.analysis.report_integrity import canonical_snapshot_hash, record_refs, validate_report_schema


def persist_forensic_scan(
    *,
    investigation_name: str,
    scan_type: str,
    evidence: dict[str, Any],
    findings: list[dict[str, Any]],
    started_at: datetime,
    finished_at: datetime,
    elapsed_ms: int,
    collector_errors: list[dict[str, Any]] | None = None,
    analysis_results: list[dict[str, Any]] | None = None,
    snapshot_hash: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Persist a standalone forensic scan as a normal immutable investigation."""
    annotate_evidence(evidence)
    collector_results: list[ReportCollectorResult] = []
    total_records = 0
    total_bytes = 0
    errors = list(collector_errors or [])

    for target, data in evidence.items():
        supported = data.get("supported", True) if isinstance(data, dict) else True
        status = "success" if supported and not (isinstance(data, dict) and data.get("error")) else "error"
        error = data.get("error") if isinstance(data, dict) else None
        if error and not any(e.get("collector") == target for e in errors):
            errors.append({"collector": target, "error": str(error)})
        count = _record_count(data)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        evidence_hash = hashlib.sha256(canonical).hexdigest()
        total_records += count
        total_bytes += len(canonical)
        collector_results.append(ReportCollectorResult(
            target=target,
            status=status,
            data=data,
            error=error,
            evidence_hash=evidence_hash,
            duration_ms=0,
            record_count=count,
            truncated=bool(isinstance(data, dict) and data.get("truncated", False)),
            resource_bytes=len(canonical),
        ))

    raw_findings = [f if isinstance(f, ReportFinding) else ReportFinding(**_finding_kwargs(f)) for f in findings]
    report_findings = deduplicate_findings(raw_findings)
    snapshot = snapshot_hash or canonical_snapshot_hash(collector_results)
    for finding in report_findings:
        subject = finding_subject(finding)
        finding.finding_id = "F-" + hashlib.sha256(json.dumps({"rule": finding.rule_name, "subject": subject, "snapshot_hash": snapshot}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16].upper()
        target = next((r for r in collector_results if r.target == scan_type), None)
        finding.evidence_refs = record_refs(scan_type, target.data if target else None, finding.related_evidence or {}, target.evidence_hash if target else None)
        finding.limitations = finding.limitations or "This is a forensic indicator derived from bounded evidence; it is not proof of malicious activity."
        finding.next_check = finding.next_check or "Review the referenced evidence record, signer/hash and surrounding timeline."
    report = Report(
        investigation_name=investigation_name,
        endpoint_hostname=platform.node().upper() or "unknown",
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        collector_results=collector_results,
        analysis_results=[
            ReportAnalysisResult(
                target=item.get("target", scan_type),
                status=item.get("status", "success"),
                finding_count=int(item.get("finding_count", 0)),
                error=item.get("error"),
            )
            for item in (analysis_results or [])
        ],
        findings=report_findings,
        collector_errors=errors,
        report_name=f"{scan_type}_forensics",
        source={
            "type": "standalone_forensic_scan",
            "scan_type": scan_type,
            "snapshot_hash": snapshot_hash,
        },
        product_name="RANDAR",
        product_version="3.0.0",
        dsl_name="JOCKY",
        dsl_version="1.5",
        timeline=[],
        execution_status="complete" if not errors else "partial",
        termination_reason="completed" if not errors else "partial_evidence_preserved",
        elevation={},
        coverage={"collectors": [{"collector": target, "status": "error" if error else "success", "confidence": "none" if error else "high"} for target, data in evidence.items() for error in [data.get("error") if isinstance(data, dict) else None]], "unavailable": [target for target, data in evidence.items() if isinstance(data, dict) and data.get("error")]},
        summary={"findings_by_severity": {}, "deduplicated_findings": len(report_findings), "top_leads": []},
        elapsed_ms=elapsed_ms,
        software_summary=summarize_software(evidence),
        integrity_version=5,
        resource_usage={
            "records_collected": total_records,
            "evidence_bytes": total_bytes,
            "timed_out_collectors": sum(1 for e in errors if "timeout" in str(e.get("error", "")).lower()),
            "truncated_collectors": sum(1 for c in collector_results if c.truncated),
        },
    )
    report.report_hash = compute_report_hash(report)
    report_dict = asdict(report)
    investigation_id = save_investigation(
        investigation_name=report.investigation_name,
        endpoint_hostname=report.endpoint_hostname,
        started_at=report.started_at,
        finished_at=report.finished_at,
        findings_count=len(report.findings),
        report=report_dict,
    )
    audit_event(
        "investigation_completed",
        report=report,
        investigation_id=investigation_id,
        details={"mode": "standalone_forensic_scan", "scan_type": scan_type},
    )
    return investigation_id, report_dict


def _finding_kwargs(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_name": str(finding.get("rule_name", "forensic_scan_observation")),
        "severity": str(finding.get("severity", "review_recommended")),
        "summary": str(finding.get("summary", "Forensic observation")),
        "reason": str(finding.get("reason", "")),
        "related_evidence": finding.get("related_evidence") or {},
        "finding_id": finding.get("finding_id"),
        "evidence_refs": finding.get("evidence_refs") or [],
        "limitations": finding.get("limitations"),
        "next_check": finding.get("next_check"),
    }


def _record_count(data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    if isinstance(data.get("count"), int):
        return data["count"]
    for key in ("processes", "modules", "threads", "regions", "drivers", "events", "tasks", "items", "users", "sessions", "startup_items"):
        value = data.get(key)
        if isinstance(value, list):
            return len(value)
    return 1 if data else 0
