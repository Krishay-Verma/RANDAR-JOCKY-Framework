"""
Builds a Report dataclass from an InvestigationResult.

The builder is the only place that knows about both the interpreter
output shape and the Report shape. It does not perform collection or
analysis — it only assembles the final structure.
"""

import platform
from datetime import datetime
import hashlib
import json
from typing import Optional

from jocky.reports.report import Report, CollectorResult as ReportCollectorResult, AnalysisResult as ReportAnalysisResult, compute_report_hash


def build_report(
    result,
    started_at: datetime,
    finished_at: datetime,
    script_hash: Optional[str] = None,
    bytecode_hash: Optional[str] = None,
) -> Report:
    """
    Convert an InvestigationResult into a Report.

    endpoint_hostname is derived here from the local machine because
    InvestigationResult does not carry it — the interpreter runs
    locally so platform.node() is always correct.
    """
    network_sources = []
    for cr in result.collector_results:
        if cr.target == "network_artifacts" and cr.status == "success" and cr.data and cr.data.get("source"):
            network_sources.append(cr.data["source"])

    findings = []
    for idx, finding in enumerate(result.findings, 1):
        payload = dict(finding.related_evidence or {})
        stable = json.dumps({"rule": finding.rule_name, "summary": finding.summary, "evidence": payload, "index": idx}, sort_keys=True, separators=(",", ":"), default=str)
        finding.finding_id = "F-" + hashlib.sha256(stable.encode()).hexdigest()[:12].upper()
        refs = []
        # Evidence references are explicit, deterministic pointers to the evidence domain.
        collector_map = {
            "suspicious_dns_queries": "network_artifacts", "dns_entropy": "network_artifacts", "rare_domains": "network_artifacts",
            "suspicious_tld_patterns": "network_artifacts", "dns_bursts": "network_artifacts", "unusual_query_types": "network_artifacts",
            "long_random_labels": "network_artifacts", "dns_tunneling_indicators": "network_artifacts", "dns_beaconing": "network_artifacts",
            "network_beaconing": "network_artifacts", "port_scan": "network_artifacts", "horizontal_scan": "network_artifacts",
            "service_discovery": "network_artifacts", "udp_scan": "network_artifacts", "network_classification": "network_artifacts",
            "process_network_correlation": "network_connections", "suspicious_processes": "processes", "missing_paths": "processes",
            "suspicious_module_loads": "modules", "dll_sideloading": "modules", "process_hollowing_indicators": "memory_regions",
            "reflective_load_indicators": "memory_regions", "thread_hijacking_indicators": "threads", "injection_correlation": "modules",
            "unsigned_loaded_module": "pe_metadata", "suspicious_imports": "pe_metadata", "high_entropy_module": "pe_metadata",
            "module_disk_mismatch": "pe_metadata", "suspicious_writable_module": "pe_metadata",
            "encoded_powershell": "windows_event_logs", "suspicious_powershell_parent": "processes", "powershell_network_activity": "network_connections",
            "powershell_child_processes": "processes", "suspicious_services": "services", "writable_service_paths": "services",
            "persistence_correlation": "scheduled_tasks", "unusual_scheduled_tasks": "scheduled_tasks", "suspicious_startup_items": "startup_items",
            "privileged_user_anomaly": "local_users", "high_connection_processes": "network_connections",
        }
        for key, value in payload.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            refs.append({"collector": collector_map.get(finding.rule_name), "key": str(key), "value": str(value), "label": f"{key}={value}"})
        finding.evidence_refs = refs
        finding.limitations, finding.next_check = _finding_explanation(finding.rule_name, finding.severity)
        findings.append(finding)

    timeline = _build_timeline(result)
    for cr in result.collector_results:
        if cr.status == "success" and cr.data is not None:
            canonical = json.dumps(cr.data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
            cr.evidence_hash = hashlib.sha256(canonical).hexdigest()

    report = Report(
        investigation_name=result.name,
        endpoint_hostname=platform.node().upper() or "unknown",
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        collector_results=[
            ReportCollectorResult(
                target=cr.target,
                status=cr.status,
                data=cr.data,
                error=cr.error,
                evidence_hash=getattr(cr, "evidence_hash", None),
                duration_ms=getattr(cr, "duration_ms", 0),
                record_count=getattr(cr, "record_count", 0),
                truncated=getattr(cr, "truncated", False),
                resource_bytes=getattr(cr, "resource_bytes", 0),
            )
            for cr in result.collector_results
        ],
        analysis_results=[
            ReportAnalysisResult(
                target=ar.target,
                status=ar.status,
                finding_count=getattr(ar, "finding_count", 0),
                error=getattr(ar, "error", None),
            )
            for ar in result.analysis_results
        ],
        findings=findings,
        collector_errors=[
            {"target": cr.target, "error": cr.error}
            for cr in result.collector_results
            if cr.status in {"error", "timeout", "cancelled"}
        ],
        report_name=result.report_name,
        script_hash=script_hash,
        bytecode_hash=bytecode_hash,
        source={"type": "local", "network_sources": network_sources} if network_sources else {"type": "local"},
        timeline=timeline,
        execution_status=getattr(result, "execution_status", "complete"),
        termination_reason=getattr(result, "termination_reason", None),
        elapsed_ms=getattr(result, "elapsed_ms", 0),
        resource_usage=getattr(result, "resource_usage", {}),
    )
    report.report_hash = compute_report_hash(report)
    return report


def _finding_explanation(rule_name: str, severity: str) -> tuple[str, str]:
    """Attach analyst-facing limitations and a concrete next check to every finding."""
    limitations = (
        "This is an investigation indicator derived from collected telemetry; it is not, by itself, proof of malicious activity."
    )
    if severity == "informational":
        limitations = "This observation is contextual evidence. It does not indicate suspicious activity by itself."

    next_checks = {
        "missing_executable_path": "Check whether the process is protected or whether collection privileges limited path visibility.",
        "unusual_executable_directory": "Review the executable path, signer/hash and process ancestry for expected software context.",
        "process_network_correlation": "Pivot from the PID to destination, DNS history and process ancestry.",
        "suspicious_dns_queries": "Review the queried domain, resolver context and related endpoint processes.",
        "dns_entropy": "Inspect the domain labels and compare them with expected application or service traffic.",
        "rare_domains": "Check the domain against local prevalence, DNS history and the originating process.",
        "dns_tunneling_indicators": "Inspect query volume, label structure and the originating process before escalating.",
        "dns_beaconing": "Compare query intervals and endpoint process activity over the same time window.",
        "network_beaconing": "Review connection intervals, destination reputation and the owning process.",
        "port_scan": "Inspect the source process and destination set to determine whether the activity is expected administration or discovery.",
        "horizontal_scan": "Review the originating process and destination range for expected inventory or management activity.",
        "service_discovery": "Identify the owning process and determine whether the discovery pattern matches expected administration.",
        "udp_scan": "Review the source process and destination set for expected discovery or monitoring behavior.",
        "encoded_powershell": "Review the event context, parent process and decoded command content using approved offline analysis.",
        "suspicious_powershell_parent": "Inspect the parent process chain and determine whether the relationship is expected for the host role.",
        "powershell_network_activity": "Pivot from the PowerShell process to DNS, destination and command-line telemetry.",
        "powershell_child_processes": "Review child process names, paths, ancestry and execution context.",
        "suspicious_services": "Inspect service configuration, binary path, signer and installation context.",
        "writable_service_paths": "Verify filesystem permissions and whether the service path is expected and trusted.",
        "persistence_correlation": "Review the persistence artifact and associated process/file context together.",
        "suspicious_module_loads": "Inspect the module path, signer/hash and loading process context.",
        "dll_sideloading": "Compare the module path and signer with the expected application installation layout.",
        "process_hollowing_indicators": "Review process image, memory-region metadata and parent/child context; confirm with additional telemetry.",
        "reflective_load_indicators": "Review private executable memory and loaded-module context for a consistent explanation.",
        "thread_hijacking_indicators": "Inspect thread start metadata and owning process context for expected behavior.",
        "injection_correlation": "Correlate module, thread and memory-region observations before drawing conclusions.",
        "unsigned_loaded_module": "Verify the module signature and compare its path/hash with the expected software baseline.",
        "suspicious_imports": "Review imported APIs together with the module path, signer and execution context.",
        "high_entropy_module": "Inspect the module metadata and compare entropy with the file type and expected build characteristics.",
        "module_disk_mismatch": "Compare in-memory module metadata with the corresponding on-disk file and acquisition timing.",
        "suspicious_writable_module": "Review module permissions, path and process context to determine whether write access is expected.",
    }
    return limitations, next_checks.get(rule_name, "Pivot to the supporting evidence and validate the observation against expected host behavior.")


def _build_timeline(result) -> list[dict]:
    """Build a bounded, deterministic event timeline from collected metadata."""
    events = []
    for cr in result.collector_results:
        if cr.status != "success" or not cr.data:
            continue
        data = cr.data
        if cr.target == "processes":
            for item in data.get("processes", [])[:2000]:
                ts = item.get("start_time")
                if ts is not None:
                    events.append({"timestamp": _timeline_ts(ts), "type": "process_started", "collector": cr.target, "summary": f"Process started: {item.get('name') or 'unknown'}", "evidence": {"pid": item.get("pid"), "name": item.get("name"), "exe_path": item.get("exe_path")}})
        elif cr.target == "network_artifacts":
            for item in data.get("artifacts", [])[:5000]:
                meta = item.get("metadata") or {}
                is_dns = meta.get("type") == "dns" or meta.get("domain")
                events.append({"timestamp": _timeline_ts(item.get("timestamp")), "type": "dns_query" if is_dns else "network_connection", "collector": cr.target, "summary": f"{'DNS query' if is_dns else 'Network connection'}: {item.get('source')} → {item.get('destination')}", "evidence": {"source": item.get("source"), "destination": item.get("destination"), "destination_port": item.get("destination_port"), "domain": meta.get("domain")}})
        elif cr.target == "network_connections":
            for item in data.get("connections", [])[:3000]:
                events.append({"timestamp": None, "type": "network_connection", "collector": cr.target, "summary": f"Network connection: {item.get('remote_ip') or '-'}:{item.get('remote_port') or '-'}", "evidence": {"pid": item.get("pid"), "remote_ip": item.get("remote_ip"), "remote_port": item.get("remote_port"), "protocol": item.get("protocol")}})
        elif cr.target == "windows_event_logs" or cr.target == "sysmon_events":
            for item in data.get("events", [])[:4000]:
                events.append({"timestamp": _timeline_ts(item.get("timestamp")), "type": item.get("event_type", "windows_event"), "collector": cr.target, "summary": f"{item.get('event_type', 'Windows event')} (Event {item.get('event_id', '-')})", "evidence": {"event_id": item.get("event_id"), "record_id": item.get("record_id"), "source": item.get("source"), "computer": item.get("computer")}})
    events.sort(key=lambda e: (e.get("timestamp") or "9999", e.get("collector") or "", e.get("summary") or ""))
    return events[:10000]


def _timeline_ts(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=__import__('datetime').timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return str(value)
