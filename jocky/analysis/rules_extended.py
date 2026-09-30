"""
Extended analysis rules for JOCKY.

Rules operate on already-collected evidence — no host access occurs here.
Each rule is a pure function: evidence dict in, list[Finding] out.

Rules added:
  - unusual_scheduled_tasks    tasks running from suspicious locations
  - suspicious_startup_items   persistence via non-standard startup paths
  - high_connection_processes  processes with excessive outbound connections
  - privileged_user_anomaly    unexpected root/SYSTEM process origins
"""

import re
from typing import Any

from jocky.analysis.finding import Finding
from jocky.analysis.persistence_enrichment import is_executable_path

# ── Pattern libraries ──────────────────────────────────────────────────────────

# Directories commonly abused for malware staging.
_SUSPICIOUS_PATH_FRAGMENTS: list[str] = [
    "\\temp\\", "\\tmp\\", "%temp%", "%tmp%",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\recycle.bin\\",
    "\\public\\downloads\\",
    "/tmp/", "/dev/shm/", "/var/tmp/",
    "/.cache/",
]

# Double-extension masquerading (e.g. invoice.pdf.exe).
_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|jpg|png|txt|zip)\.(exe|bat|ps1|vbs|cmd|sh|py)$",
    re.IGNORECASE,
)

# Base64-encoded PowerShell commands — strong obfuscation indicator.
_PS_ENCODED_RE = re.compile(
    r"(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}"
)

# Ports associated with remote access tools and C2 traffic.
_SUSPICIOUS_PORTS = {4444, 4445, 5555, 1337, 31337, 6666, 8888, 9001, 9002}

# Threshold for flagging a process with an unusually high connection count.
_HIGH_CONNECTION_THRESHOLD = 15


# ── Rule: unusual_scheduled_tasks ─────────────────────────────────────────────

def _verification(row: dict[str, Any]) -> dict[str, Any]:
    return row.get("verification") or {}


def _score_persistence(row: dict[str, Any], *, kind: str) -> tuple[int, list[str]]:
    score = 0
    signals: list[str] = []
    command = str(row.get("task_to_run") or row.get("resolved_target") or row.get("command") or row.get("executable") or "")
    p = row.get("path_normalized") or command.casefold()
    risk = int(row.get("path_risk_score") or 0)
    if risk:
        score += risk; signals.append("user-writable-style path")
    v = _verification(row)
    status = str(v.get("signature_status") or "unknown").casefold()
    trusted = bool(v.get("trusted_publisher"))
    if status in {"invalid", "hashmismatch", "unknownerror"}:
        score += 4; signals.append("invalid signature")
    elif status in {"nottrusted", "notsigned", "unsigned"}:
        score += 3; signals.append("unsigned or untrusted signature")
    elif status in {"valid", "validcatalogsigned"} and trusted:
        score -= 3; signals.append("valid trusted publisher")
    elif trusted:
        score -= 1
    if row.get("unquoted_path"):
        score += 2; signals.append("unquoted service path")
    if _DOUBLE_EXT_RE.search(command):
        score += 3; signals.append("double extension")
    if _PS_ENCODED_RE.search(command):
        score += 4; signals.append("encoded PowerShell")
    if re.search(r"(?i)\b(?:-enc|-encodedcommand|frombase64string|mshta|rundll32|regsvr32)\b", command):
        score += 2; signals.append("script/LOLBin style arguments")
    if row.get("recent_creation"):
        score += 2; signals.append("recently created")
    if str(row.get("run_as") or row.get("account") or "").casefold() in {"system", "localsystem", "nt authority\\system"}:
        score += 1; signals.append("runs as SYSTEM")
    if row.get("verification", {}).get("exists") is False:
        score += 2; signals.append("target missing")
    if kind == "startup" and not is_executable_path(str(row.get("resolved_target") or row.get("command") or "")):
        return 0, ["non-executable startup item"]
    return max(score, 0), signals


def _severity_for_score(score: int) -> str:
    if score >= 8:
        return "high"
    if score >= 5:
        return "medium"
    if score >= 3:
        return "review_recommended"
    return "informational"


def check_unusual_scheduled_tasks(evidence: dict[str, Any]) -> list[Finding]:
    """Score scheduled tasks using multiple weak signals; path alone is never high."""
    findings: list[Finding] = []
    tasks = evidence.get("scheduled_tasks", {}).get("tasks", [])
    task_creation = {}
    for event in evidence.get("windows_event_logs", {}).get("events", []) or []:
        if event.get("event_type") != "scheduled_task_created":
            continue
        data = event.get("data") or {}
        name = data.get("TaskName") or data.get("Task Name") or data.get("TaskNameXml")
        if name:
            task_creation[str(name).casefold()] = event.get("timestamp")
    for task in tasks:
        command = str(task.get("task_to_run") or task.get("entry") or "").strip()
        if not command:
            continue
        if task.get("name") and str(task.get("name")).casefold() in task_creation:
            task = dict(task)
            task["creation_time"] = task_creation[str(task.get("name")).casefold()]
            task["recent_creation"] = True
        score, signals = _score_persistence(task, kind="task")
        if score < 3:
            continue
        sev = _severity_for_score(score)
        name = task.get("name") or "unknown"
        findings.append(Finding(
            "unusual_scheduled_tasks", sev,
            f"Scheduled task '{name}' has {len(signals)} persistence risk signal(s)",
            f"Risk score {score}: {', '.join(signals)}. A temporary/AppData path by itself is not sufficient for a high-severity finding.",
            {"task_name": name, "path": task.get("path_normalized") or command, "score": score, "signals": signals, "task": task, "parent_folder_context": task.get("parent_folder_context")},
        ))
    return findings


def check_suspicious_startup_items(evidence: dict[str, Any]) -> list[Finding]:
    """Filter non-executables and score startup entries from several weak signals."""
    findings: list[Finding] = []
    for item in evidence.get("startup_items", {}).get("items", []):
        target = item.get("resolved_target") or item.get("command") or ""
        if not is_executable_path(str(target)):
            continue
        score, signals = _score_persistence(item, kind="startup")
        if score < 3:
            continue
        sev = _severity_for_score(score)
        name = item.get("name") or "unknown"
        findings.append(Finding(
            "suspicious_startup_items", sev,
            f"Startup item '{name}' has {len(signals)} persistence risk signal(s)",
            f"Risk score {score}: {', '.join(signals)}. Being outside a Windows system directory is not suspicious by itself.",
            {"name": name, "path": item.get("path_normalized") or target, "score": score, "signals": signals, "item": item},
        ))
    return findings


# ── Rule: high_connection_processes ───────────────────────────────────────────

def check_high_connection_processes(evidence: dict[str, Any]) -> list[Finding]:
    """
    Flag processes with an unusually high number of active network
    connections, or any process connected to known suspicious ports.
    """
    findings: list[Finding] = []
    connections = evidence.get("network_connections", {}).get("connections", [])

    if not connections:
        return findings

    # Group connections by PID.
    by_pid: dict[int, list[dict]] = {}
    for conn in connections:
        pid = conn.get("pid")
        if pid is not None:
            by_pid.setdefault(pid, []).append(conn)

    # Cross-reference with process list for names.
    processes = evidence.get("processes", {}).get("processes", [])
    pid_to_name: dict[int, str] = {
        p.get("pid", -1): p.get("name", "unknown") for p in processes
    }

    for pid, conns in by_pid.items():
        proc_name = pid_to_name.get(pid, "unknown")

        if len(conns) >= _HIGH_CONNECTION_THRESHOLD:
            findings.append(Finding(
                rule_name="high_connection_processes",
                severity="medium",
                summary=f"Process '{proc_name}' has unusually high connection count",
                reason=(
                    f"PID {pid} ({proc_name}) has {len(conns)} active network "
                    f"connections (threshold: {_HIGH_CONNECTION_THRESHOLD}). "
                    "May indicate beaconing, port scanning, or data exfiltration."
                ),
                related_evidence={"pid": pid, "process_name": proc_name,
                                  "connection_count": len(conns)},
            ))

        # Check for suspicious ports.
        for conn in conns:
            try:
                rport = int(conn.get("remote_port"))
            except (TypeError, ValueError):
                continue
            if rport in _SUSPICIOUS_PORTS:
                findings.append(Finding(
                    rule_name="high_connection_processes",
                    severity="high",
                    summary=(
                        f"Process '{proc_name}' connected to suspicious port {rport}"
                    ),
                    reason=(
                        f"PID {pid} ({proc_name}) has an active connection on "
                        f"port {rport}, associated with remote access tools and C2."
                    ),
                    related_evidence={"pid": pid, "connection": conn},
                ))

    return findings


# ── Rule: privileged_user_anomaly ─────────────────────────────────────────────

def check_privileged_user_anomaly(evidence: dict[str, Any]) -> list[Finding]:
    """
    Cross-correlate local_users and processes.

    Flags:
      - Interactive local accounts with UIDs < 1000 that aren't root
        (Linux: unexpected system accounts with login shells)
      - Processes running as a user not found in the local user list
        (potential lateral movement or service account abuse)
    """
    findings: list[Finding] = []
    users_data = evidence.get("local_users", {})
    users = users_data.get("users", [])
    platform_name = users_data.get("platform", "unknown")

    # Linux: flag system accounts that have interactive shells.
    if platform_name == "Linux":
        for user in users:
            if (
                user.get("is_system_account")
                and user.get("interactive")
                and not user.get("is_root")
            ):
                findings.append(Finding(
                    rule_name="privileged_user_anomaly",
                    severity="high",
                    summary=(
                        f"System account '{user.get('username')}' has an "
                        "interactive shell"
                    ),
                    reason=(
                        f"UID {user.get('uid')} ({user.get('username')}) is a "
                        "system account (UID < 1000) but has been assigned "
                        f"an interactive shell ({user.get('shell')}). "
                        "This may indicate account manipulation."
                    ),
                    related_evidence={"user": user},
                ))

    # Cross-reference: processes running as users not in local account list.
    if users and platform_name == "Windows":
        local_names = {u["username"].lower() for u in users}
        processes = evidence.get("processes", {}).get("processes", [])
        flagged: set[str] = set()

        for proc in processes:
            username = proc.get("username") or ""
            # Strip domain prefix if present (e.g. DOMAIN\user).
            short_name = username.split("\\")[-1].lower()
            if (
                short_name
                and short_name not in local_names
                and short_name not in ("system", "network service",
                                       "local service", "")
                and short_name not in flagged
            ):
                flagged.add(short_name)
                findings.append(Finding(
                    rule_name="privileged_user_anomaly",
                    severity="medium",
                    summary=(
                        f"Process running as unrecognised account '{username}'"
                    ),
                    reason=(
                        f"A process is running under '{username}' which is not "
                        "in the local user account list. This may indicate a "
                        "service account, a compromised credential, or lateral "
                        "movement from another host."
                    ),
                    related_evidence={"username": username},
                ))

    return findings