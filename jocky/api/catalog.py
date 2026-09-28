"""Describes what the engine can do, so clients (the UI editor) never
hard-code capabilities. Names come from the live registries; descriptions
are metadata only and never affect execution."""

from jocky.analysis.registry import list_rules
from jocky.collectors.registry import list_collectors
from jocky.language.interpreter import list_evidence_properties

_COLLECTORS = {
    "system_info": "Host name, OS, architecture, CPU and memory.",
    "processes": "Running processes with path, owner and start time.",
    "network_connections": "Active inet connections with owning PID.",
    "logged_in_users": "Interactive sessions currently logged in.",
    "file_hash": "SHA-256 of files in the operator-approved evidence directory.",
    "scheduled_tasks": "Windows Task Scheduler entries or Linux cron entries.",
    "startup_items": "Run keys / startup folders (Windows), systemd and init.d (Linux).",
    "open_files": "Open file handles per process (bounded).",
    "local_users": "Local accounts from net user (Windows) or /etc/passwd (Linux).",
}
_RULES = {
    "missing_paths": ("informational", "Processes whose executable path is unreadable."),
    "suspicious_processes": ("review_recommended", "Executables running from temp/download paths."),
    "process_network_correlation": ("informational", "Links processes to remote connections."),
    "unusual_scheduled_tasks": ("high-critical", "Tasks from writable paths, double extensions, encoded PowerShell."),
    "suspicious_startup_items": ("medium-critical", "Persistence outside system directories."),
    "high_connection_processes": ("medium-high", "Connection-count outliers and known C2 ports."),
    "privileged_user_anomaly": ("medium-high", "System accounts with shells; unknown process owners."),
}


def build_catalog() -> dict:
    return {
        "collectors": [{"name": n, "description": _COLLECTORS.get(n, "")} for n in list_collectors()],
        "rules": [
            {"name": n, "severity": _RULES.get(n, ("", ""))[0],
             "description": _RULES.get(n, ("", ""))[1]}
            for n in list_rules()
        ],
        "properties": list_evidence_properties(),
        "severities": ["informational", "review_recommended", "medium", "high", "critical"],
    }
