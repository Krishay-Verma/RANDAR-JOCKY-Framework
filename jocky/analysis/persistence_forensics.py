"""Read-only persistence and privilege correlation for RANDAR V2.6.

Consumes existing startup, scheduled-task, service, account, process and
Windows telemetry collectors. It never creates, edits, enables, disables,
or executes persistence mechanisms.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from jocky.analysis.finding import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_REVIEW
from jocky.analysis.rules_extended import (
    check_privileged_user_anomaly,
    check_suspicious_startup_items,
    check_unusual_scheduled_tasks,
)
from jocky.analysis.windows_telemetry import (
    rule_persistence_correlation,
    rule_suspicious_services,
    rule_writable_service_paths,
)

_QUOTED_PATH_RE = re.compile(r'(?i)"([a-z]:\\[^"\r\n]+\.(?:exe|dll|sys))"')
_PATH_RE = re.compile(r"(?i)([a-z]:\\[^\r\n]+?\.(?:exe|dll|sys)(?=\s|$)|/[^\s]+)")


def _path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    quoted = _QUOTED_PATH_RE.search(text)
    if quoted:
        return quoted.group(1).lower().rstrip("\\/")
    match = _PATH_RE.search(text)
    if match:
        return match.group(1).strip('"').lower().rstrip("\\/")
    return text.strip('"').split()[0].lower().rstrip("\\/")


def _persistence_objects(evidence: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    startup = evidence.get("startup_items", {}).get("items", []) or []
    tasks = evidence.get("scheduled_tasks", {}).get("tasks", []) or []
    services = evidence.get("services", {}).get("services", []) or []
    return {
        "startup_items": startup,
        "scheduled_tasks": tasks,
        "services": services,
    }


def build_persistence_forensics(evidence: dict[str, Any]) -> dict[str, Any]:
    objects = _persistence_objects(evidence)
    surfaces: dict[str, list[dict[str, Any]]] = {k: [] for k in objects}
    path_index: dict[str, set[str]] = {}

    for surface, rows in objects.items():
        for row in rows:
            candidate = row.get("command") or row.get("task_to_run") or row.get("executable") or row.get("entry") or row.get("name")
            normalized = _path(candidate)
            if not normalized:
                continue
            path_index.setdefault(normalized, set()).add(surface)
            surfaces[surface].append({"name": row.get("name") or row.get("service_name"), "path": normalized, "source": row.get("source")})

    cross_surface = [
        {"path": path, "surfaces": sorted(surfaces_set)}
        for path, surfaces_set in sorted(path_index.items())
        if len(surfaces_set) >= 2
    ]

    users = evidence.get("local_users", {}) or {}
    sessions = evidence.get("logged_in_users", {}) or {}
    processes = evidence.get("processes", {}) or {}
    events = evidence.get("windows_event_logs", {}) or {}
    privileged_events = [e for e in events.get("events", []) or [] if e.get("event_type") == "privilege"]
    service_events = [e for e in events.get("events", []) or [] if e.get("event_type") == "service_change"]

    normalized = {
        "surfaces": surfaces,
        "cross_surface": cross_surface,
        "users_count": int(users.get("count") or 0),
        "sessions_count": int(sessions.get("count") or 0),
        "processes_count": int(processes.get("count") or 0),
        "privileged_events": len(privileged_events),
        "service_change_events": len(service_events),
    }
    snapshot_hash = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

    return {
        "version": "3.0.0",
        "mode": "read-only-persistence-privilege-correlation",
        "supported": bool(objects["startup_items"] or objects["scheduled_tasks"] or objects["services"] or users.get("count") is not None),
        "snapshot_hash": snapshot_hash,
        "summary": {
            "startup_items": len(objects["startup_items"]),
            "scheduled_tasks": len(objects["scheduled_tasks"]),
            "services": len(objects["services"]),
            "local_users": int(users.get("count") or 0),
            "logged_in_sessions": int(sessions.get("count") or 0),
            "processes": int(processes.get("count") or 0),
            "privilege_events": len(privileged_events),
            "service_change_events": len(service_events),
            "cross_surface_paths": len(cross_surface),
        },
        "cross_surface": cross_surface,
        "telemetry": {
            "windows_event_logs": {"supported": bool(events.get("supported")), "count": int(events.get("count") or 0), "error": events.get("error")},
            "sysmon_events": {"supported": bool((e := evidence.get("sysmon_events", {}) or {}).get("supported")), "count": int(e.get("count") or 0), "error": e.get("error")},
        },
        "limitations": [
            "Persistence correlation is based on metadata returned by the configured collectors.",
            "A shared executable path across persistence surfaces is an investigation lead, not proof of malicious persistence.",
            "Privilege-event visibility depends on Windows Event Log access and retention.",
            "No persistence mechanism is created, modified, enabled, disabled, or executed.",
        ],
    }


def build_persistence_forensics_findings(evidence: dict[str, Any], report: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add_many(items: list[Finding]) -> None:
        for f in items:
            key = (f.rule_name, json.dumps(f.related_evidence or {}, sort_keys=True, default=str))
            if key not in seen:
                seen.add(key)
                findings.append(f)

    for fn in (
        check_unusual_scheduled_tasks,
        check_suspicious_startup_items,
        check_privileged_user_anomaly,
        rule_suspicious_services,
        rule_writable_service_paths,
        rule_persistence_correlation,
    ):
        try:
            add_many(fn(evidence))
        except Exception:
            # The API records collector/rule errors separately; one optional
            # platform-specific rule must never hide the other evidence.
            continue

    for f in rule_persistence_cross_surface_correlation(evidence):
        add_many([f])
    for f in rule_persistence_privilege_correlation(evidence):
        add_many([f])

    # Deterministic order makes the scan reproducible and easier to compare.
    return sorted(findings, key=lambda f: (f.severity, f.rule_name, f.summary))


def rule_persistence_cross_surface_correlation(evidence: dict[str, Any]) -> list[Finding]:
    report = build_persistence_forensics(evidence)
    findings: list[Finding] = []
    for item in report.get("cross_surface", []) or []:
        surfaces = item.get("surfaces", [])
        if len(surfaces) >= 2:
            findings.append(Finding(
                rule_name="persistence_cross_surface_correlation",
                severity=SEVERITY_REVIEW,
                summary="One executable path appears across multiple persistence surfaces",
                reason=(f"The normalized path '{item.get('path')}' appears in {', '.join(surfaces)}. "
                        "This increases investigative relevance but does not establish persistence abuse."),
                related_evidence={"path": item.get("path"), "surfaces": surfaces, "snapshot_hash": report.get("snapshot_hash")},
                limitations="The same legitimate service or updater can intentionally appear in multiple startup surfaces.",
                next_check="Verify the executable publisher, signature, expected installation path, owner, and service/task configuration.",
            ))
    return findings


def rule_persistence_privilege_correlation(evidence: dict[str, Any]) -> list[Finding]:
    report = build_persistence_forensics(evidence)
    if not (report.get("summary", {}).get("privilege_events") and report.get("summary", {}).get("cross_surface_paths")):
        return []
    return [Finding(
        rule_name="persistence_privilege_correlation",
        severity=SEVERITY_MEDIUM,
        summary="Persistence evidence overlaps with privileged-event telemetry",
        reason="The evidence contains both persistence-surface correlation and Windows privilege events; timestamp and account correlation is required.",
        related_evidence={"privilege_events": report["summary"]["privilege_events"], "cross_surface_paths": report["summary"]["cross_surface_paths"], "snapshot_hash": report.get("snapshot_hash")},
        limitations="The current collector records event metadata and does not infer causality between an event and a persistence item.",
        next_check="Correlate event timestamps, account names, service/task names and executable hashes in the case timeline.",
    )]
