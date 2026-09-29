"""Describes what the engine can do, so clients (the UI editor) never
hard-code capabilities. Names come from the live registries; descriptions
are metadata only and never affect execution."""

from jocky.analysis.registry import list_rules
from jocky.collectors.registry import list_collectors
from jocky.language.interpreter import list_evidence_properties

_COLLECTORS = {
    "system_info": "Host name, OS, architecture, CPU and memory.",
    "processes": "Running processes with path, owner and start time.",
    "network_artifacts": "First-class V1.1 normalized Zeek/PCAP/PCAPNG metadata evidence; packet payloads are not retained.",
    "network_connections": "Active inet connections with owning PID.",
    "logged_in_users": "Interactive sessions currently logged in.",
    "file_hash": "SHA-256 of files in the operator-approved evidence directory.",
    "scheduled_tasks": "Windows Task Scheduler entries or Linux cron entries.",
    "startup_items": "Run keys / startup folders (Windows), systemd and init.d (Linux).",
    "open_files": "Open file handles per process (bounded).",
    "local_users": "Local accounts from net user (Windows) or /etc/passwd (Linux).",
    "modules": "Windows loaded DLL/EXE/SYS module inventory with bounded hashing of user-writable paths.",
    "threads": "Windows process-thread inventory using read-only thread metadata.",
    "memory_regions": "Windows virtual-memory metadata; no process memory is read or written.",
    "windows_event_logs": "Controlled Windows Event Log metadata: process creation, logon, privilege, service-change and PowerShell events.",
    "sysmon_events": "Bounded Sysmon Operational events: 1, 3, 7, 8, 10, 11, 12/13/14 and 22.",
    "services": "Windows service inventory with executable, account, state and start-mode metadata.",
    "pe_metadata": "Bounded read-only PE metadata for process/module files: architecture, sections, imports, exports, entropy, signature metadata and SHA-256.",
}
_RULES = {
    "missing_paths": ("informational", "Processes whose executable path is unreadable."),
    "suspicious_processes": ("review_recommended", "Executables running from temp/download paths."),
    "process_network_correlation": ("informational", "Links processes to remote connections."),
    "unusual_scheduled_tasks": ("high-critical", "Tasks from writable paths, double extensions, encoded PowerShell."),
    "suspicious_startup_items": ("medium-critical", "Persistence outside system directories."),
    "high_connection_processes": ("medium-high", "Connection-count outliers and known C2 ports."),
    "privileged_user_anomaly": ("medium-high", "System accounts with shells; unknown process owners."),
    "suspicious_module_loads": ("review", "Modules loaded from commonly user-writable Windows paths."),
    "dll_sideloading": ("review", "DLLs loaded outside the owning process directory."),
    "process_hollowing_indicators": ("high", "Private executable memory correlated with process evidence."),
    "reflective_load_indicators": ("review", "Executable private memory retained as a reflective-loading lead."),
    "thread_hijacking_indicators": ("review", "Thread-density leads requiring additional thread-level review."),
    "injection_correlation": ("high", "Correlates module and executable-memory indicators on one process."),
    "suspicious_dns_queries": ("review", "DNS queries matching configured review patterns."),
    "dns_entropy": ("review", "High-entropy DNS labels requiring contextual review."),
    "rare_domains": ("informational", "Domains that occur only once in a sufficiently diverse DNS evidence set."),
    "suspicious_tld_patterns": ("review", "DNS domains using configured review TLD patterns."),
    "dns_bursts": ("review", "High-volume repeated queries for one domain in a short window."),
    "unusual_query_types": ("review", "Uncommon DNS query types such as ANY or zone-transfer requests."),
    "long_random_labels": ("review", "Long or random-looking DNS labels."),
    "dns_tunneling_indicators": ("review", "Combined DNS characteristics that can indicate tunneling; not proof."),
    "dns_beaconing": ("review", "Repeated DNS queries with low interval jitter."),
    "network_beaconing": ("review", "Repeated network connections with low interval jitter."),
    "port_scan": ("review", "One source touching many ports on one target."),
    "horizontal_scan": ("review", "One source touching one service across many hosts."),
    "service_discovery": ("review", "Systematic contact with common infrastructure ports."),
    "udp_scan": ("review", "Repeated UDP probes inferred from supplied metadata."),
    "network_classification": ("informational", "Descriptive classification of network addresses."),
    "encoded_powershell": ("medium", "PowerShell encoded-command or hidden/non-interactive execution indicators."),
    "suspicious_powershell_parent": ("review", "PowerShell launched by a document, script-host or management process requiring context."),
    "powershell_network_activity": ("review", "PowerShell process associated with an active remote network connection."),
    "powershell_child_processes": ("review", "Child processes spawned by PowerShell."),
    "suspicious_services": ("review", "Services whose executable path is writable or commonly user-writable."),
    "writable_service_paths": ("medium", "Service executable or parent directory is writable by the collecting account."),
    "persistence_correlation": ("review", "Common executable observed across multiple persistence surfaces."),
    "unsigned_loaded_module": ("review", "Loaded PE module has no embedded Authenticode signature metadata."),
    "suspicious_imports": ("review", "PE imports associated with process injection or memory manipulation require contextual review."),
    "high_entropy_module": ("review", "PE or section entropy is unusually high and warrants file-level review."),
    "module_disk_mismatch": ("high", "Loaded module metadata and disk PE evidence disagree or the backing file is unavailable."),
    "suspicious_writable_module": ("review", "Loaded PE module resides in a commonly writable location or contains writable executable content."),
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
