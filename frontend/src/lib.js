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
  "Evidence file hashing": `investigation "Evidence Hashing" {
    collect system_info;
    collect file_hash;
    report "evidence_hashes";
}
`,
};
