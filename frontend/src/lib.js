// Shared constants and pure helpers (kept out of component files).

export const SEVERITIES = ["critical", "high", "medium", "review_recommended", "informational"];
export const SEV_LABEL = {
  critical: "Critical", high: "High", medium: "Medium",
  review_recommended: "Review", informational: "Info",
};
export const SEV_COLOR = {
  critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)",
  review_recommended: "var(--review)", informational: "var(--info)",
};
export const STATUS_LABEL = { open: "Open", in_review: "In review", closed: "Closed" };

export const asArray = (value) => Array.isArray(value) ? value : [];

export const RULE_LABEL = {
  suspicious_module_loads: "Suspicious module load",
  dll_sideloading: "Possible DLL sideloading",
  process_hollowing_indicators: "Process hollowing indicator",
  reflective_load_indicators: "Reflective loading indicator",
  thread_hijacking_indicators: "Thread start anomaly",
  injection_correlation: "Injection evidence correlation",
  suspicious_dns_queries: "Suspicious DNS query pattern",
  dns_entropy: "DNS entropy indicator",
  rare_domains: "Rare DNS domain",
  suspicious_tld_patterns: "Suspicious TLD pattern",
  dns_bursts: "DNS burst",
  unusual_query_types: "Unusual DNS query type",
  long_random_labels: "Long / random DNS label",
  dns_tunneling_indicators: "Possible DNS tunneling indicator",
  dns_beaconing: "Possible DNS beaconing",
  network_beaconing: "Possible network beaconing",
  port_scan: "Possible port scan",
  horizontal_scan: "Possible horizontal scan",
  service_discovery: "Possible service discovery",
  udp_scan: "Possible UDP scan",
  network_classification: "Network address classification",
  encoded_powershell: "PowerShell encoded / hidden execution indicator",
  suspicious_powershell_parent: "Suspicious PowerShell parent",
  powershell_network_activity: "PowerShell network activity",
  powershell_child_processes: "PowerShell child process",
  suspicious_services: "Suspicious service",
  writable_service_paths: "Writable service path",
  persistence_correlation: "Persistence surface correlation",
  unsigned_loaded_module: "Unsigned loaded module",
  suspicious_imports: "Suspicious PE imports",
  high_entropy_module: "High-entropy PE module",
  module_disk_mismatch: "Module / disk mismatch",
  suspicious_writable_module: "Suspicious writable module",
  memory_forensics_correlation: "Memory forensics correlation",
  driver_forensics_exposure: "Driver forensics exposure",
  byovd_driver_indicators: "Vulnerable-driver exposure",
  persistence_cross_surface_correlation: "Persistence cross-surface correlation",
  persistence_privilege_correlation: "Persistence / privilege correlation",
};

export function humanizeRule(name) {
  if (RULE_LABEL[name]) return RULE_LABEL[name];
  return String(name || "Unknown rule")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export const COLLECTOR_LABEL = {
  system_info: "System information",
  processes: "Processes",
  network_connections: "Network connections",
  network_artifacts: "Network evidence artifacts",
  logged_in_users: "Logged-in users",
  file_hash: "File hashes",
  scheduled_tasks: "Scheduled tasks",
  startup_items: "Startup items",
  open_files: "Open files",
  local_users: "Local users",
  modules: "Loaded DLLs / modules",
  threads: "Process threads",
  memory_regions: "Virtual memory regions",
  windows_event_logs: "Windows Event Logs",
  sysmon_events: "Sysmon events",
  services: "Windows services",
  driver_inventory: "Driver inventory",
};

export function humanizeCollector(name) {
  return COLLECTOR_LABEL[name] || humanizeRule(name);
}

export const fmtTime = (iso) => {
  if (!iso) return "-";
  const d = new Date(iso);
  return isNaN(d) ? String(iso) : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};

export const fmtDuration = (a, b) => {
  const ms = new Date(b) - new Date(a);
  if (!isFinite(ms) || ms < 0) return "-";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
};

export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

export function lineFromError(message) {
  const m = /line\s+(\d+)/i.exec(message || "");
  return m ? Number(m[1]) : null;
}

export const TEMPLATES = {
  "Quick endpoint triage": `investigation "Quick Endpoint Triage" {
    collect system_info;
    collect processes;
    collect network_connections;
    analyze suspicious_processes;
    analyze missing_paths;
    analyze process_network_correlation;
    report "quick_triage";
}
`,
  "Persistence hunt": `investigation "Persistence Hunt" {
    collect system_info;
    collect scheduled_tasks;
    collect startup_items;
    collect local_users;
    analyze unusual_scheduled_tasks;
    analyze suspicious_startup_items;
    analyze privileged_user_anomaly;
    report "persistence_hunt";
}
`,
  "Adaptive full triage": `investigation "Adaptive Full Triage" {
    let conn_threshold = 10;

    collect system_info;
    collect processes;
    collect network_connections;
    collect local_users;
    collect scheduled_tasks;
    collect startup_items;

    // Only run network analysis when the host is unusually chatty.
    if network_connections.count > conn_threshold {
        analyze high_connection_processes;
    }
    analyze suspicious_processes;
    analyze unusual_scheduled_tasks;
    analyze suspicious_startup_items;
    analyze privileged_user_anomaly;
    report "adaptive_triage";
}
`,
  "Windows injection hunt": `investigation "Windows Injection Forensics" {
    collect system_info;
    collect processes;
    collect modules;
    collect threads;
    collect memory_regions;
    collect network_connections;
    analyze suspicious_module_loads;
    analyze dll_sideloading;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;
    report "windows_injection_forensics";
}
`,
  "Memory forensics": `investigation "Memory Forensics" {
    collect system_info;
    collect processes;
    collect modules;
    collect threads;
    collect memory_regions;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;
    analyze in_memory_execution_indicators;
    analyze memory_forensics_correlation;
    report "memory_forensics";
}
`,
  "Driver forensics": `investigation "Driver Forensics" {
    collect system_info;
    collect driver_inventory;
    collect windows_event_logs;
    collect sysmon_events;
    analyze byovd_driver_indicators;
    analyze driver_forensics_exposure;
    report "driver_forensics";
}
`,
  "Security software & kernel review": `investigation "Security Software & Kernel Review" {
    collect system_info;
    collect processes;
    collect modules;
    collect driver_inventory;
    collect services;
    analyze suspicious_services;
    analyze unsigned_loaded_module;
    analyze driver_forensics_exposure;
    report "security_software_kernel_review";
}
`,
  "Deep Windows persistence": `investigation "Deep Windows Persistence" {
    collect system_info;
    collect processes;
    collect services;
    collect scheduled_tasks;
    collect startup_items;
    collect windows_event_logs;
    collect wmi_event_subscriptions;
    collect ifeo_persistence;
    collect winlogon_persistence;
    collect appinit_persistence;
    collect com_hijack_persistence;
    collect bits_persistence;
    collect all_users_startup;
    collect browser_extensions;
    collect office_addins;
    collect lsa_auth_packages;

    analyze unusual_scheduled_tasks;
    analyze suspicious_startup_items;
    analyze suspicious_services;
    analyze writable_service_paths;
    analyze service_configuration_anomalies;
    analyze persistence_correlation;
    analyze persistence_cross_surface_correlation;
    analyze wmi_event_subscription;
    analyze ifeo_debugger;
    analyze winlogon_persistence;
    analyze appinit_dlls;
    analyze com_hijack;
    analyze bits_persistence;
    analyze all_users_startup;
    analyze browser_extensions;
    analyze office_addins;
    analyze lsa_auth_packages;
    report "deep_windows_persistence";
}
`,
  "Windows telemetry hunt": `investigation "Windows Telemetry Hunt" {
    collect system_info;
    collect processes;
    collect network_connections;
    collect windows_event_logs;
    collect sysmon_events;
    collect services;
    collect startup_items;
    collect scheduled_tasks;

    analyze encoded_powershell;
    analyze suspicious_powershell_parent;
    analyze powershell_network_activity;
    analyze powershell_child_processes;
    analyze suspicious_services;
    analyze writable_service_paths;
    analyze persistence_correlation;
    analyze persistence_cross_surface_correlation;
    analyze persistence_privilege_correlation;

    report "windows_telemetry_hunt";
}
`,
  "Evidence file hashing": `investigation "Evidence Hashing" {
    collect system_info;
    collect file_hash;
    report "evidence_hashes";
}
`,
  "Network threat hunt": `investigation "Network Threat Hunt" {
    collect network_artifacts;
    collect processes;
    collect network_connections;

    analyze suspicious_dns_queries;
    analyze dns_entropy;
    analyze rare_domains;
    analyze suspicious_tld_patterns;
    analyze dns_bursts;
    analyze unusual_query_types;
    analyze long_random_labels;
    analyze dns_tunneling_indicators;
    analyze dns_beaconing;
    analyze network_beaconing;

    analyze port_scan;
    analyze horizontal_scan;
    analyze service_discovery;
    analyze udp_scan;
    analyze network_classification;
    analyze process_network_correlation;

    report "network_threat_hunt";
}
`,  "Domain Expansion Triage": `investigation "Domain Expansion Triage" {
    collect system_info;
    collect processes;
    collect network_connections;
    collect network_artifacts;
    collect windows_event_logs;
    collect sysmon_events;
    collect services;
    collect pe_metadata;
    collect logged_in_users;
    collect file_hash;
    collect scheduled_tasks;
    collect startup_items;
    collect open_files;
    collect local_users;
    collect modules;
    collect threads;
    collect memory_regions;
    collect driver_inventory;
    collect wmi_event_subscriptions;
    collect ifeo_persistence;
    collect winlogon_persistence;
    collect appinit_persistence;
    collect com_hijack_persistence;
    collect bits_persistence;
    collect all_users_startup;
    collect browser_extensions;
    collect office_addins;
    collect lsa_auth_packages;
    collect advanced_persistence;
    collect clipboard_metadata;
    collect browser_history_metadata;
    collect browser_cookie_metadata;

    analyze missing_paths;
    analyze suspicious_processes;
    analyze process_network_correlation;
    analyze unusual_scheduled_tasks;
    analyze suspicious_startup_items;
    analyze high_connection_processes;
    analyze privileged_user_anomaly;
    analyze suspicious_module_loads;
    analyze dll_sideloading;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;
    analyze suspicious_dns_queries;
    analyze dns_entropy;
    analyze rare_domains;
    analyze suspicious_tld_patterns;
    analyze dns_bursts;
    analyze unusual_query_types;
    analyze long_random_labels;
    analyze dns_tunneling_indicators;
    analyze dns_beaconing;
    analyze network_beaconing;
    analyze port_scan;
    analyze horizontal_scan;
    analyze service_discovery;
    analyze udp_scan;
    analyze network_classification;
    analyze encoded_powershell;
    analyze suspicious_powershell_parent;
    analyze powershell_network_activity;
    analyze powershell_child_processes;
    analyze suspicious_services;
    analyze writable_service_paths;
    analyze persistence_correlation;
    analyze persistence_cross_surface_correlation;
    analyze persistence_privilege_correlation;
    analyze unsigned_loaded_module;
    analyze suspicious_imports;
    analyze high_entropy_module;
    analyze module_disk_mismatch;
    analyze suspicious_writable_module;
    analyze in_memory_execution_indicators;
    analyze byovd_driver_indicators;
    analyze memory_forensics_correlation;
    analyze driver_forensics_exposure;

    report "domain_expansion_triage";
}
`,
  "V1.5 DSL Showcase": `investigation "V1.5 DSL Showcase" {
    // Variables make repeated thresholds explicit and auditable.
    let minimum_connections = 1;
    collect processes;
    collect network_connections;

    // Boolean evidence filtering is bounded to approved properties.
    analyze process_network_correlation
    where destination.is_external == true and process.name != "svchost.exe";

    // Analyst-authored rules run only against findings already produced by JOCKY.
    rule "External Process Network Lead" {
        when destination.is_external == true and process.name != "svchost.exe";
        severity high;
    }

    report "v1_5_dsl_showcase";
}
`,
};
