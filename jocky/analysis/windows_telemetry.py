"""Pure V1.3 Windows telemetry analysis rules.

Rules consume only collected process, network, Windows Event Log, Sysmon and
service evidence. They do not execute PowerShell or touch the endpoint.
Findings are investigation indicators, not malware verdicts.
"""

from __future__ import annotations

import re
from typing import Any

from jocky.analysis.finding import Finding, SEVERITY_REVIEW, SEVERITY_MEDIUM

_PS_NAMES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}
_SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "msaccess.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "wmiprvse.exe", "mmc.exe",
}
_ENCODED_RE = re.compile(r"(?i)(?:^|\s)-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{12,}")
_HIDDEN_RE = re.compile(r"(?i)(?:-w(?:indowstyle)?\s+hidden|-hidden|\-nop(?:rofile)?|\-noni(?:nteractive)?|\-executionpolicy\s+(?:bypass|unrestricted))")


def _processes(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return evidence.get("processes", {}).get("processes", [])


def _powershell_processes(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [p for p in _processes(evidence) if str(p.get("name") or "").lower() in _PS_NAMES]


def _cmdline(p: dict[str, Any]) -> str:
    return str(p.get("command_line") or "")


def rule_encoded_powershell(evidence: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for proc in _powershell_processes(evidence):
        cmd = _cmdline(proc)
        if _ENCODED_RE.search(cmd):
            findings.append(Finding(
                "encoded_powershell", SEVERITY_MEDIUM,
                f"PowerShell PID {proc.get('pid')} uses an encoded command indicator",
                "The PowerShell command line contains an encoded-command switch and a base64-like argument. This can be legitimate automation but warrants review.",
                {"pid": proc.get("pid"), "name": proc.get("name"), "command_line": cmd},
            ))
        if _HIDDEN_RE.search(cmd):
            findings.append(Finding(
                "encoded_powershell", SEVERITY_REVIEW,
                f"PowerShell PID {proc.get('pid')} uses a hidden/non-interactive execution indicator",
                "The PowerShell command line contains a hidden, non-interactive, or execution-policy indicator. Review the parent, script source and surrounding activity.",
                {"pid": proc.get("pid"), "name": proc.get("name"), "command_line": cmd},
            ))
    # Also inspect controlled PowerShell event evidence where available.
    for event in evidence.get("windows_event_logs", {}).get("events", []):
        if event.get("event_type") != "powershell":
            continue
        data = event.get("data") or {}
        text = " ".join(str(v) for v in data.values())
        if _ENCODED_RE.search(text):
            findings.append(Finding(
                "encoded_powershell", SEVERITY_MEDIUM,
                f"PowerShell event {event.get('event_id')} contains an encoded-command indicator",
                "A controlled Windows PowerShell event contains an encoded-command pattern. Event evidence alone does not establish malicious intent.",
                {"event_id": event.get("event_id"), "timestamp": event.get("timestamp"), "data": data},
            ))
    return findings


def rule_suspicious_powershell_parent(evidence: dict[str, Any]) -> list[Finding]:
    processes = {p.get("pid"): p for p in _processes(evidence) if p.get("pid") is not None}
    findings: list[Finding] = []
    for proc in _powershell_processes(evidence):
        parent = processes.get(proc.get("parent_pid"))
        parent_name = str(parent.get("name") or "").lower() if parent else ""
        if parent_name in _SUSPICIOUS_PARENTS:
            findings.append(Finding(
                "suspicious_powershell_parent", SEVERITY_REVIEW,
                f"PowerShell PID {proc.get('pid')} was started by {parent.get('name')}",
                "The PowerShell process has a parent commonly associated with document viewers, script hosts or management utilities. Validate the user action and command line.",
                {"pid": proc.get("pid"), "parent_pid": proc.get("parent_pid"), "parent_name": parent.get("name"), "command_line": _cmdline(proc)},
            ))
    return findings


def rule_powershell_network_activity(evidence: dict[str, Any]) -> list[Finding]:
    ps_pids = {p.get("pid"): p for p in _powershell_processes(evidence) if p.get("pid") is not None}
    findings: list[Finding] = []
    for conn in evidence.get("network_connections", {}).get("connections", []):
        pid = conn.get("pid")
        proc = ps_pids.get(pid)
        if not proc or not conn.get("remote_ip"):
            continue
        findings.append(Finding(
            "powershell_network_activity", SEVERITY_REVIEW,
            f"PowerShell PID {pid} has an active remote network connection",
            "A PowerShell process is associated with a remote network connection. Review the destination, command line and initiating user context.",
            {"pid": pid, "process_name": proc.get("name"), "remote_ip": conn.get("remote_ip"), "remote_port": conn.get("remote_port"), "protocol": conn.get("protocol"), "status": conn.get("status")},
        ))
    return findings


def rule_powershell_child_processes(evidence: dict[str, Any]) -> list[Finding]:
    processes = _processes(evidence)
    ps_pids = {p.get("pid") for p in _powershell_processes(evidence) if p.get("pid") is not None}
    findings: list[Finding] = []
    for child in processes:
        if child.get("parent_pid") not in ps_pids:
            continue
        name = str(child.get("name") or "unknown")
        findings.append(Finding(
            "powershell_child_processes", SEVERITY_REVIEW,
            f"PowerShell spawned child process '{name}'",
            "The process tree shows a child process whose parent is PowerShell. Review the child executable, command line and expected administrative workflow.",
            {"pid": child.get("pid"), "name": name, "parent_pid": child.get("parent_pid"), "command_line": child.get("command_line")},
        ))
    return findings


def rule_suspicious_services(evidence: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for service in evidence.get("services", {}).get("services", []):
        if service.get("writable_path") is not True:
            continue
        findings.append(Finding(
            "suspicious_services", SEVERITY_REVIEW,
            f"Service '{service.get('service_name')}' points to a writable path",
            "The collected service executable path is marked writable or located in a commonly user-writable directory. Validate ownership and installation context.",
            {"service": service},
        ))
    return findings


def rule_writable_service_paths(evidence: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for service in evidence.get("services", {}).get("services", []):
        if service.get("writable_path") is True:
            findings.append(Finding(
                "writable_service_paths", SEVERITY_MEDIUM,
                f"Writable service executable path: {service.get('service_name')}",
                "The service inventory indicates that the executable or its parent directory is writable by the collecting account. This is a persistence review lead, not proof of abuse.",
                {"service_name": service.get("service_name"), "executable": service.get("executable"), "writable_path": True, "start_mode": service.get("start_mode")},
            ))
    return findings


def rule_persistence_correlation(evidence: dict[str, Any]) -> list[Finding]:
    """Correlate the V1.3 persistence surfaces; registry Run keys are represented by startup_items."""
    surfaces: list[tuple[str, list[dict[str, Any]]]] = []
    startup = evidence.get("startup_items", {}).get("items", [])
    tasks = evidence.get("scheduled_tasks", {}).get("tasks", [])
    services = evidence.get("services", {}).get("services", [])
    if startup: surfaces.append(("startup_items", startup))
    if tasks: surfaces.append(("scheduled_tasks", tasks))
    if services: surfaces.append(("services", services))
    if not surfaces:
        return []

    findings: list[Finding] = []
    normalized: dict[str, list[str]] = {}
    for surface, items in surfaces:
        for item in items:
            text = " ".join(str(v) for v in item.values()).lower()
            paths = re.findall(r'(?i)[a-z]:\\(?:[^<>:"/|?*\\\r\n]+\\)*[^<>:"/|?*\\\r\n]+\.(?:exe|cmd|bat|ps1|vbs)|/[^\s]+\.(?:sh|py|bin)', text)
            for path in paths:
                normalized.setdefault(path.rstrip(".,);"), []).append(surface)
    for path, source_surfaces in normalized.items():
        unique = sorted(set(source_surfaces))
        if len(unique) < 2:
            continue
        findings.append(Finding(
            "persistence_correlation", SEVERITY_REVIEW,
            "The same executable appears across multiple persistence surfaces",
            "A common executable path was observed in more than one of the collected startup, scheduled-task and service datasets. Registry Run keys are represented within startup_items.",
            {"path": path, "surfaces": unique},
        ))
    return findings


def rule_service_configuration_anomalies(evidence: dict[str, Any]) -> list[Finding]:
    findings = []
    for service in evidence.get("services", {}).get("services", []):
        if service.get("unquoted_path"):
            findings.append(Finding(
                "service_configuration_anomalies", SEVERITY_MEDIUM,
                f"Service '{service.get('service_name')}' has an unquoted executable path",
                "The service ImagePath contains spaces but is not quoted, creating ambiguous executable resolution. Validate the exact path and ACLs.",
                {"service_name": service.get("service_name"), "executable": service.get("executable"), "command_line": service.get("command_line"), "unquoted_path": True},
            ))
        if service.get("service_dll"):
            verification = service.get("service_dll_verification") or {}
            if verification.get("signature_status") in {"invalid", "nottrusted", "notsigned", "unsigned"}:
                findings.append(Finding(
                    "service_configuration_anomalies", SEVERITY_HIGH,
                    f"Service '{service.get('service_name')}' loads an untrusted ServiceDll",
                    "The service Parameters\\ServiceDll value resolves to a file whose signature is not trusted or is absent.",
                    {"service_name": service.get("service_name"), "service_dll": service.get("service_dll"), "verification": verification},
                ))
    return findings
