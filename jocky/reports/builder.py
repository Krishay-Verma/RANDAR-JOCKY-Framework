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
from jocky.analysis.software_catalog import annotate_evidence, summarize as summarize_software
from jocky.analysis.dedup import deduplicate_findings, finding_subject
from jocky.analysis.report_integrity import canonical_snapshot_hash, record_refs, validate_report_schema


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
    # Add deterministic software classifications to already-collected evidence.
    # This is enrichment only: no extra collection or process access occurs.
    evidence_map = {cr.target: cr.data for cr in result.collector_results if cr.status == "success" and cr.data is not None}
    annotate_evidence(evidence_map)
    for cr in result.collector_results:
        if cr.status == "success" and cr.target in evidence_map:
            cr.data = evidence_map[cr.target]

    network_sources = []
    for cr in result.collector_results:
        if cr.target == "network_artifacts" and cr.status == "success" and cr.data and cr.data.get("source"):
            network_sources.append(cr.data["source"])

    # Evidence hashes are computed before findings so every finding can point to
    # the exact collector snapshot and record index that supports it.
    for cr in result.collector_results:
        if cr.status == "success" and cr.data is not None:
            canonical = json.dumps(cr.data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
            cr.evidence_hash = hashlib.sha256(canonical).hexdigest()
    snapshot_hash = canonical_snapshot_hash(result.collector_results)

    findings = deduplicate_findings(list(result.findings))
    collector_map = {
        "suspicious_dns_queries": "network_artifacts", "dns_entropy": "network_artifacts", "rare_domains": "network_artifacts",
        "suspicious_tld_patterns": "network_artifacts", "dns_bursts": "network_artifacts", "unusual_query_types": "network_artifacts",
        "long_random_labels": "network_artifacts", "dns_tunneling_indicators": "network_artifacts", "dns_beaconing": "network_artifacts",
        "network_beaconing": "network_artifacts", "port_scan": "network_artifacts", "horizontal_scan": "network_artifacts",
        "service_discovery": "network_artifacts", "udp_scan": "network_artifacts", "network_classification": "network_artifacts",
        "process_network_correlation": "network_connections", "suspicious_processes": "processes", "missing_paths": "processes",
        "missing_executable_path": "processes", "suspicious_module_loads": "modules", "dll_sideloading": "modules",
        "process_hollowing_indicators": "memory_regions", "reflective_load_indicators": "memory_regions", "thread_hijacking_indicators": "threads", "injection_correlation": "modules",
        "unsigned_loaded_module": "pe_metadata", "suspicious_imports": "pe_metadata", "high_entropy_module": "pe_metadata", "module_disk_mismatch": "pe_metadata", "suspicious_writable_module": "pe_metadata",
        "encoded_powershell": "windows_event_logs", "suspicious_powershell_parent": "processes", "powershell_network_activity": "network_connections", "powershell_child_processes": "processes",
        "suspicious_services": "services", "writable_service_paths": "services", "persistence_correlation": "scheduled_tasks", "persistence_cross_surface_correlation": "scheduled_tasks", "unusual_scheduled_tasks": "scheduled_tasks", "suspicious_startup_items": "startup_items",
        "privileged_user_anomaly": "local_users", "high_connection_processes": "network_connections",
        "service_configuration_anomalies": "services",
        "wmi_event_subscription": "wmi_event_subscriptions", "ifeo_debugger": "ifeo_persistence",
        "winlogon_persistence": "winlogon_persistence", "appinit_dlls": "appinit_persistence",
        "com_hijack": "com_hijack_persistence", "bits_persistence": "bits_persistence",
        "all_users_startup": "all_users_startup", "browser_extensions": "browser_extensions",
        "office_addins": "office_addins", "lsa_auth_packages": "lsa_auth_packages",
    }
    evidence_by_target = {cr.target: cr for cr in result.collector_results if cr.status == "success"}
    for finding in findings:
        _augment_finding_context(finding, evidence_map)
        subject = finding_subject(finding)
        stable = json.dumps({"rule": finding.rule_name, "subject": subject, "snapshot_hash": snapshot_hash}, sort_keys=True, separators=(",", ":"), default=str)
        finding.finding_id = "F-" + hashlib.sha256(stable.encode()).hexdigest()[:16].upper()
        target = collector_map.get(finding.rule_name)
        cr = evidence_by_target.get(target) if target else None
        refs = record_refs(target, cr.data if cr else None, finding.related_evidence or {}, getattr(cr, "evidence_hash", None) if cr else None)
        if not refs and cr is not None:
            refs = [{"collector": target, "evidence_hash": cr.evidence_hash, "record_index": None}]
        finding.evidence_refs = refs
        finding.limitations, finding.next_check = _finding_explanation(finding.rule_name, finding.severity)
        finding.related_evidence = dict(finding.related_evidence or {})
        finding.related_evidence["snapshot_hash"] = snapshot_hash

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
        product_version="3.0.0",
        script_hash=script_hash,
        bytecode_hash=bytecode_hash,
        source={"type": "local", "network_sources": network_sources} if network_sources else {"type": "local"},
        timeline=timeline,
        elevation=_build_elevation(evidence_map),
        coverage=_build_coverage(result),
        summary=_build_summary(findings, result),
        execution_status=getattr(result, "execution_status", "complete"),
        termination_reason=getattr(result, "termination_reason", None),
        elapsed_ms=getattr(result, "elapsed_ms", 0),
        resource_usage=getattr(result, "resource_usage", {}),
        software_summary=summarize_software(evidence_map),
        integrity_version=6,
    )
    if not report.termination_reason:
        report.termination_reason = "completed" if report.execution_status == "complete" else "partial_evidence_preserved"
    if not report.bytecode_hash and script_hash:
        # Deterministic compilation-plan identity for environments where the
        # signing key is unavailable. It is explicitly labelled in source.
        plan = json.dumps({"script_hash": script_hash, "dsl": report.dsl_version, "rules": [a.target for a in report.analysis_results]}, sort_keys=True, separators=(",", ":"))
        report.bytecode_hash = hashlib.sha256(plan.encode()).hexdigest()
        report.source["bytecode_hash_kind"] = "deterministic_plan_hash"
    report.report_hash = compute_report_hash(report)
    validate_report_schema(report)
    return report


def _augment_finding_context(finding, evidence: dict) -> None:
    """Attach bounded related process/network context to persistence leads."""
    if finding.rule_name not in {"unusual_scheduled_tasks", "suspicious_startup_items", "service_writable", "writable_service_paths", "suspicious_services"}:
        return
    related = dict(finding.related_evidence or {})
    task = related.get("task") if isinstance(related.get("task"), dict) else None
    path = related.get("path") or (task or {}).get("path_normalized") or (task or {}).get("task_to_run")
    if not path:
        return
    path_text = str(path).casefold().replace("/", "\\").strip('"')
    processes = (evidence.get("processes") or {}).get("processes", [])
    matches = []
    pids = set()
    for proc in processes:
        exe = str(proc.get("exe_path") or "").casefold().replace("/", "\\").strip('"')
        if exe and (exe == path_text or exe.startswith(path_text) or path_text in exe):
            matches.append({"pid": proc.get("pid"), "name": proc.get("name"), "username": proc.get("username"), "start_time": proc.get("start_time")})
            if proc.get("pid") is not None:
                pids.add(proc.get("pid"))
    if matches:
        related["related_processes"] = matches[:10]
        conns = []
        for conn in (evidence.get("network_connections") or {}).get("connections", []):
            if conn.get("pid") in pids:
                conns.append({"pid": conn.get("pid"), "remote_address": conn.get("remote_address"), "remote_ip": conn.get("remote_ip"), "remote_port": conn.get("remote_port"), "status": conn.get("status")})
        related["related_network_connections"] = conns[:25]
    finding.related_evidence = related


def _build_elevation(evidence: dict) -> dict:
    info = evidence.get("system_info") or {}
    return {
        "is_admin": info.get("is_admin"),
        "is_elevated": info.get("is_elevated"),
        "integrity_level": info.get("integrity_level"),
        "elevation_required_for": info.get("elevation_required_for") or [
            "Windows Security event log access may require elevation or policy access.",
            "Protected-process fields and some service/driver metadata may require elevation.",
        ],
    }


def _build_coverage(result) -> dict:
    rows = []
    for cr in result.collector_results:
        data = cr.data or {}
        status = cr.status
        confidence = "high"
        if status in {"error", "timeout", "cancelled"}:
            confidence = "none"
        elif isinstance(data, dict) and data.get("status") == "not_installed":
            status = "not_installed"; confidence = "informational"
        elif isinstance(data, dict) and data.get("supported") is False:
            status = "not_supported"; confidence = "none"
        elif cr.truncated or data.get("truncated"):
            confidence = "degraded"
        elif data.get("fields_unavailable"):
            confidence = "degraded"
        rows.append({"collector": cr.target, "status": status, "confidence": confidence, "record_count": cr.record_count, "truncated": bool(cr.truncated or data.get("truncated")), "error": cr.error or data.get("error")})
    return {"collectors": rows, "unavailable": [r["collector"] for r in rows if r["confidence"] == "none"], "degraded": [r["collector"] for r in rows if r["confidence"] == "degraded"]}


def _build_summary(findings, result) -> dict:
    order = {"informational": 0, "review_recommended": 1, "medium": 2, "high": 3, "critical": 4}
    counts = {k: 0 for k in order}
    leads = []
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        base = order.get(f.severity, 0) * 25
        evidence_score = int((f.related_evidence or {}).get("score") or 0)
        leads.append({"finding_id": f.finding_id, "rule": f.rule_name, "subject": finding_subject(f), "severity": f.severity, "risk_score": base + evidence_score, "summary": f.summary})
    leads.sort(key=lambda x: (-x["risk_score"], x["finding_id"] or ""))
    return {"findings_by_severity": counts, "deduplicated_findings": len(findings), "top_leads": leads[:10]}


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
        "unusual_scheduled_tasks": "Review task action, signature, publisher, creation time, arguments and run-as account; path alone is not sufficient for high severity.",
        "suspicious_startup_items": "Resolve the startup target, verify its signature/hash and review the multiple-signal score before escalation.",
        "service_configuration_anomalies": "Verify the exact service ImagePath/ServiceDll, signer/hash, ACL and service installation history.",
        "wmi_event_subscription": "Review the WMI filter, consumer, binding and referenced executable/script plus its signer and creation context.",
        "ifeo_debugger": "Verify the IFEO debugger/verifier value, target image, signer/hash and whether the configuration is intentionally deployed.",
        "winlogon_persistence": "Compare Shell/Userinit and related Winlogon values with the Windows baseline and verify referenced files.",
        "appinit_dlls": "Verify AppInit_DLLs, LoadAppInit_DLLs and referenced DLL signatures; confirm whether the configuration is expected.",
        "com_hijack": "Review the CLSID override, server path, signer/hash and owning user profile.",
        "bits_persistence": "Review BITS owner, source/destination, job state and referenced local executable or script.",
        "all_users_startup": "Review the affected user profile, target path, signer/hash and startup-folder timestamp.",
        "browser_extensions": "Review extension ID, manifest, installation path, publisher/signature and whether it was installed by policy or the user.",
        "office_addins": "Review Office application, add-in load behavior, registry values and referenced binary signature/hash.",
        "lsa_auth_packages": "Compare authentication packages with the OS baseline and verify any non-default package binary/signature.",
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
        elif cr.target == "scheduled_tasks":
            for item in data.get("tasks", [])[:2000]:
                for field, typ in (("creation_time", "scheduled_task_created"), ("last_run", "scheduled_task_last_run")):
                    if item.get(field):
                        events.append({"timestamp": _timeline_ts(item.get(field)), "type": typ, "collector": cr.target, "summary": f"{typ.replace('_',' ').title()}: {item.get('name')}", "evidence": {"name": item.get("name"), "task_to_run": item.get("task_to_run")}})
        elif cr.target == "services":
            proc_times = {p.get("pid"): p.get("start_time") for c in result.collector_results if c.target == "processes" and c.status == "success" for p in (c.data or {}).get("processes", [])}
            for item in data.get("services", [])[:1000]:
                pid = item.get("pid")
                if pid is not None:
                    events.append({"timestamp": _timeline_ts(proc_times.get(pid)), "type": "service_process_started", "collector": cr.target, "summary": f"Service process: {item.get('service_name')}", "evidence": {"service_name": item.get("service_name"), "pid": pid, "executable": item.get("executable")}})
                for field, typ in (("file_created_at", "service_binary_created"), ("file_modified_at", "service_binary_modified")):
                    if item.get(field):
                        events.append({"timestamp": _timeline_ts(item.get(field)), "type": typ, "collector": cr.target, "summary": f"{typ.replace('_',' ').title()}: {item.get('service_name')}", "evidence": {"service_name": item.get("service_name"), "executable": item.get("executable")}})
        elif cr.target == "startup_items":
            for item in data.get("items", [])[:1000]:
                for field, typ in (("file_created_at", "startup_file_created"), ("file_modified_at", "startup_file_modified"), (("verification"), "startup_file_created")):
                    value = item.get(field)
                    if field == "verification" and isinstance(value, dict):
                        value = value.get("created_at")
                    if value:
                        events.append({"timestamp": _timeline_ts(item.get(field)), "type": typ, "collector": cr.target, "summary": f"{typ.replace('_',' ').title()}: {item.get('name')}", "evidence": {"name": item.get("name"), "path": item.get("path_normalized")}})
        elif cr.target == "windows_event_logs" or cr.target == "sysmon_events":
            for item in data.get("events", [])[:4000]:
                events.append({"timestamp": _timeline_ts(item.get("timestamp")), "type": item.get("event_type", "windows_event"), "collector": cr.target, "summary": f"{item.get('event_type', 'Windows event')} (Event {item.get('event_id', '-')})", "evidence": {"event_id": item.get("event_id"), "record_id": item.get("record_id"), "source": item.get("source"), "computer": item.get("computer")}})
    events.sort(key=lambda e: (e.get("timestamp") or "9999", e.get("collector") or "", e.get("summary") or ""))
    return events[:10000]


def _timeline_ts(value):
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=__import__('datetime').timezone.utc).isoformat()
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=__import__('datetime').timezone.utc)
        return parsed.astimezone(__import__('datetime').timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return str(value)
