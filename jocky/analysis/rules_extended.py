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

def check_unusual_scheduled_tasks(evidence: dict[str, Any]) -> list[Finding]:
    """
    Flag scheduled tasks that exhibit common persistence/evasion patterns:
      - Command running from a temp or user-writable directory
      - Double file extension in the command
      - Base64-encoded PowerShell command
    """
    findings: list[Finding] = []
    tasks = evidence.get("scheduled_tasks", {}).get("tasks", [])

    for task in tasks:
        # Normalise the command field across Windows/Linux schemas.
        command = (task.get("task_to_run") or task.get("entry") or "").lower()
        name = task.get("name") or task.get("entry") or "unknown"

        if not command:
            continue

        for fragment in _SUSPICIOUS_PATH_FRAGMENTS:
            if fragment in command:
                findings.append(Finding(
                    rule_name="unusual_scheduled_tasks",
                    severity="high",
                    summary=f"Scheduled task runs from suspicious directory",
                    reason=(
                        f"Task '{name}' executes from '{fragment}' — a writable "
                        "location commonly used for malware staging or persistence."
                    ),
                    related_evidence={"task": task},
                ))
                break

        if _DOUBLE_EXT_RE.search(command):
            findings.append(Finding(
                rule_name="unusual_scheduled_tasks",
                severity="high",
                summary="Scheduled task uses double file extension",
                reason=(
                    f"Task '{name}' command path has a double extension "
                    "(e.g. .pdf.exe) — a common technique to disguise executables."
                ),
                related_evidence={"task": task},
            ))

        if _PS_ENCODED_RE.search(command):
            findings.append(Finding(
                rule_name="unusual_scheduled_tasks",
                severity="critical",
                summary="Scheduled task uses encoded PowerShell",
                reason=(
                    f"Task '{name}' uses a base64-encoded PowerShell command — "
                    "a strong obfuscation indicator."
                ),
                related_evidence={"task": task},
            ))

    return findings


# ── Rule: suspicious_startup_items ────────────────────────────────────────────

def check_suspicious_startup_items(evidence: dict[str, Any]) -> list[Finding]:
    """
    Flag startup items whose command path points outside standard
    system directories, or whose filename uses double extensions.
    """
    findings: list[Finding] = []
    items = evidence.get("startup_items", {}).get("items", [])

    _TRUSTED_PREFIXES_WIN = (
        "c:\\windows\\", "c:\\program files\\",
        "c:\\program files (x86)\\",
    )
    _TRUSTED_PREFIXES_LIN = ("/usr/", "/bin/", "/sbin/", "/opt/")

    for item in items:
        command = (item.get("command") or "").strip()
        name = item.get("name", "unknown")
        item_type = item.get("type", "")
        command_lower = command.lower().lstrip('"\' ')

        if not command:
            continue

        # Check path origin for registry run keys and startup folder items.
        if item_type in ("registry_run_key", "startup_folder"):
            in_trusted = (
                any(command_lower.startswith(p) for p in _TRUSTED_PREFIXES_WIN)
                or any(command_lower.startswith(p) for p in _TRUSTED_PREFIXES_LIN)
            )
            if not in_trusted and command:
                findings.append(Finding(
                    rule_name="suspicious_startup_items",
                    severity="medium",
                    summary=f"Startup item runs from non-standard location",
                    reason=(
                        f"'{name}' ({item_type}) points to '{command}' — "
                        "outside standard system directories. "
                        "Verify this is a legitimate application."
                    ),
                    related_evidence={"item": item},
                ))

        if _DOUBLE_EXT_RE.search(command):
            findings.append(Finding(
                rule_name="suspicious_startup_items",
                severity="high",
                summary="Startup item has double file extension",
                reason=(
                    f"Startup item '{name}' uses a double file extension — "
                    "a common masquerading technique."
                ),
                related_evidence={"item": item},
            ))

        if _PS_ENCODED_RE.search(command_lower):
            findings.append(Finding(
                rule_name="suspicious_startup_items",
                severity="critical",
                summary="Startup item uses encoded PowerShell",
                reason=(
                    f"Startup item '{name}' uses base64-encoded PowerShell — "
                    "a strong obfuscation and evasion indicator."
                ),
                related_evidence={"item": item},
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