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

export const RULE_LABEL = {
  suspicious_module_loads: "Suspicious module load",
  dll_sideloading: "Possible DLL sideloading",
  process_hollowing_indicators: "Process hollowing indicator",
  reflective_load_indicators: "Reflective loading indicator",
  thread_hijacking_indicators: "Thread start anomaly",
  injection_correlation: "Injection evidence correlation",
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
  logged_in_users: "Logged-in users",
  file_hash: "File hashes",
  scheduled_tasks: "Scheduled tasks",
  startup_items: "Startup items",
  open_files: "Open files",
  local_users: "Local users",
  modules: "Loaded DLLs / modules",
  threads: "Process threads",
  memory_regions: "Virtual memory regions",
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
  "Evidence file hashing": `investigation "Evidence Hashing" {
    collect system_info;
    collect file_hash;
    report "evidence_hashes";
}
`,
};
