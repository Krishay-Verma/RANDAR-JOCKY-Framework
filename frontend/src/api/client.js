import { getToken, clearToken } from "./token";

// Same-origin when served by the API (production build); local API in dev.
// Override with VITE_API_BASE_URL. No trailing slash.
export const BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ??
  (import.meta.env.PROD ? "" : "http://localhost:8000")
).replace(/\/+$/, "");

export class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthError";
  }
}

export const AUTH_FAILED_EVENT = "jocky:auth-failed";
const TIMEOUT_MS = 60_000;
const RUNTIME_TIMEOUT_MS = 660_000; // V1.9 permits bounded investigations up to 600s. Runtime UI waits slightly longer for the final response.

async function send(method, path, body = null, raw = false, signal = null, timeoutMs = TIMEOUT_MS) {
  const token = getToken();
  if (!token) throw new AuthError("Not signed in.");

  const options = {
    method,
    headers: { Authorization: `Bearer ${token}` },
  };
  if (body !== null) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const controller = new AbortController();
  const abortFromCaller = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", abortFromCaller, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  options.signal = controller.signal;

  let res;
  try {
    res = await fetch(`${BASE_URL}${path}`, options);
  } catch (err) {
    // Navigation/unmount cancellation is expected and must not become a page error.
    if (err?.name === "AbortError" && signal?.aborted) throw err;
    throw new Error(
      err.name === "AbortError"
        ? "Request timed out."
        : "Cannot reach the RANDAR API. Is the server running?",
      { cause: err },
    );
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", abortFromCaller);
  }

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event(AUTH_FAILED_EVENT));
    throw new AuthError("Session expired. Please sign in again.");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    let detail = typeof err.detail === "string" ? err.detail : null;
    if (!detail && Array.isArray(err.detail)) {
      detail = err.detail.map((d) => d.msg).join("; ");
    }
    throw new Error(detail || `Request failed (HTTP ${res.status}).`);
  }
  return raw ? res.blob() : res.json();
}

const id = encodeURIComponent;
export const api = {
  stats: (signal) => send("GET", "/api/stats", null, false, signal),
  search: (query, limit = 50, signal) => send("GET", `/api/search?q=${encodeURIComponent(query)}&limit=${encodeURIComponent(limit)}`, null, false, signal),
  catalog: (signal) => send("GET", "/api/catalog", null, false, signal),
  investigations: (signal) => send("GET", "/api/investigations", null, false, signal),
  investigationsPage: (page = 1, limit = 25, q = "", status = "all", sort = "newest", signal) => send("GET", `/api/investigations?page=${page}&limit=${limit}&q=${encodeURIComponent(q)}&status=${encodeURIComponent(status)}&sort=${encodeURIComponent(sort)}`, null, false, signal),
  investigation: (i, includeEvidence = true, signal) => send("GET", `/api/investigations/${id(i)}${includeEvidence ? "" : "?include_evidence=false"}`, null, false, signal),
  evidencePage: (i, collector, page = 1, limit = 100, q = "") => send("GET", `/api/investigations/${id(i)}/evidence?collector=${encodeURIComponent(collector)}&page=${page}&limit=${limit}&q=${encodeURIComponent(q)}`),
  run: (script, networkSourceId = null) => send("POST", "/api/investigations", { script, network_source_id: networkSourceId }),
  runAsync: (script, networkSourceId = null) => send("POST", "/api/investigations/jobs", { script, network_source_id: networkSourceId }),
  investigationJob: (jobId) => send("GET", `/api/investigations/jobs/${encodeURIComponent(jobId)}`),
  cancelInvestigationJob: (jobId) => send("POST", `/api/investigations/jobs/${encodeURIComponent(jobId)}/cancel`),
  update: (i, patch) => send("PATCH", `/api/investigations/${id(i)}`, patch),
  remove: (i) => send("DELETE", `/api/investigations/${id(i)}`),
  validate: (script) => send("POST", "/api/validate", { script }),
  compile: (script) => send("POST", "/api/compile", { script }),
  htmlReport: (i) => send("GET", `/api/investigations/${id(i)}/report.html`, null, true),
  jsonReport: (i) => send("GET", `/api/investigations/${id(i)}/report.json`, null, true),
  integrity: (i, signal) => send("GET", `/api/investigations/${id(i)}/integrity`, null, false, signal),
  audit: (i, signal) => send("GET", `/api/investigations/${id(i)}/audit`, null, false, signal),
  auditAll: () => send("GET", "/api/audit"),
  networkSources: (signal) => send("GET", "/api/network-sources", null, false, signal),
  uploadNetworkSource: (filename, contentBase64) => send("POST", "/api/network-sources", { filename, content_base64: contentBase64 }),
  removeNetworkSource: (sourceId) => send("DELETE", `/api/network-sources/${id(sourceId)}`),
  encryptedReport: (i) => send("GET", `/api/investigations/${id(i)}/report.encrypted`, null, true),
  keyStatus: (signal) => send("GET", "/api/keys/status", null, false, signal),
  registerKey: (pem) => send("POST", "/api/keys/register", { public_key_pem: pem }),
  clearKey: () => send("DELETE", "/api/keys/register"),
  bcCompile: (script) => send("POST", "/api/bytecode/compile", { script }),
  bcDisasm: (b64) => send("POST", "/api/bytecode/disasm", { bytecode_b64: b64 }),
  bcExecute: (b64) => send("POST", "/api/bytecode/execute", { bytecode_b64: b64 }),
  runtimeExecute: (script, target = "portable", adapter = "jocky-interpreter", transformationProfile = "none", transformationSeed = null) => send("POST", "/api/runtime/execute", { script, target, adapter, transformation_profile: transformationProfile, transformation_seed: transformationSeed }, false, null, RUNTIME_TIMEOUT_MS),
  // Standalone forensic scans run as server-side jobs so route changes cannot interrupt them.
  forensicJobCreate: (scanType) => send("POST", `/api/forensic-jobs/${encodeURIComponent(scanType)}`, {}),
  forensicJob: (jobId) => send("GET", `/api/forensic-jobs/${encodeURIComponent(jobId)}`),
  // Synchronous endpoints remain available for API/automation compatibility.
  memoryForensicsScan: () => send("POST", "/api/memory-forensics/scan", {}, false, null, RUNTIME_TIMEOUT_MS),
  driverForensicsScan: () => send("POST", "/api/driver-forensics/scan", {}, false, null, RUNTIME_TIMEOUT_MS),
  persistenceForensicsScan: () => send("POST", "/api/persistence-forensics/scan", {}, false, null, RUNTIME_TIMEOUT_MS),
  agents: (signal) => send("GET", "/api/agents", null, false, signal),
  registerAgent: (hostname, platform) => send("POST", "/api/agents/register", { hostname, platform }),
  revokeAgent: (a) => send("DELETE", `/api/agents/${id(a)}`),
  dispatch: (a, script) => send("POST", `/api/agents/${id(a)}/jobs`, { script }),
  jobs: (a, signal) => send("GET", `/api/agents/${id(a)}/jobs`, null, false, signal),
  jobResult: (a, j) => send("GET", `/api/agents/${id(a)}/jobs/${id(j)}/result`),
  deleteJob: (a, j) => send("DELETE", `/api/agents/${id(a)}/jobs/${id(j)}`),
  importJob: (a, j) => send("POST", `/api/agents/${id(a)}/jobs/${id(j)}/import`),
  cancelJob: (a, j) => send("POST", `/api/agents/${id(a)}/jobs/${id(j)}/cancel`),
  agentCapabilities: (a) => send("GET", `/api/agents/${id(a)}/capabilities`),
};

/** Verify a candidate token against a protected route without storing it. */
export async function verifyTokenWithServer(candidate) {
  let res;
  try {
    res = await fetch(`${BASE_URL}/api/stats`, {
      headers: { Authorization: `Bearer ${candidate}` },
    });
  } catch (err) {
    throw new Error("Cannot reach the RANDAR API. Is the server running?", { cause: err });
  }
  if (res.status === 401) return false;
  if (!res.ok) throw new Error(`Server returned HTTP ${res.status}.`);
  return true;
}

export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
