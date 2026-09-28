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

async function send(method, path, body = null, raw = false) {
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
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  options.signal = controller.signal;

  let res;
  try {
    res = await fetch(`${BASE_URL}${path}`, options);
  } catch (err) {
    throw new Error(
      err.name === "AbortError"
        ? "Request timed out."
        : "Cannot reach the JOCKY API. Is the server running?",
      { cause: err },
    );
  } finally {
    clearTimeout(timer);
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
  stats: () => send("GET", "/api/stats"),
  catalog: () => send("GET", "/api/catalog"),
  investigations: () => send("GET", "/api/investigations"),
  investigation: (i) => send("GET", `/api/investigations/${id(i)}`),
  run: (script) => send("POST", "/api/investigations", { script }),
  update: (i, patch) => send("PATCH", `/api/investigations/${id(i)}`, patch),
  remove: (i) => send("DELETE", `/api/investigations/${id(i)}`),
  validate: (script) => send("POST", "/api/validate", { script }),
  compile: (script) => send("POST", "/api/compile", { script }),
  htmlReport: (i) => send("GET", `/api/investigations/${id(i)}/report.html`, null, true),
  encryptedReport: (i) => send("GET", `/api/investigations/${id(i)}/report.encrypted`, null, true),
  keyStatus: () => send("GET", "/api/keys/status"),
  registerKey: (pem) => send("POST", "/api/keys/register", { public_key_pem: pem }),
  clearKey: () => send("DELETE", "/api/keys/register"),
  bcCompile: (script) => send("POST", "/api/bytecode/compile", { script }),
  bcDisasm: (b64) => send("POST", "/api/bytecode/disasm", { bytecode_b64: b64 }),
  bcExecute: (b64) => send("POST", "/api/bytecode/execute", { bytecode_b64: b64 }),
  agents: () => send("GET", "/api/agents"),
  registerAgent: (hostname, platform) => send("POST", "/api/agents/register", { hostname, platform }),
  revokeAgent: (a) => send("DELETE", `/api/agents/${id(a)}`),
  dispatch: (a, script) => send("POST", `/api/agents/${id(a)}/jobs`, { script }),
  jobs: (a) => send("GET", `/api/agents/${id(a)}/jobs`),
  jobResult: (a, j) => send("GET", `/api/agents/${id(a)}/jobs/${id(j)}/result`),
  deleteJob: (a, j) => send("DELETE", `/api/agents/${id(a)}/jobs/${id(j)}`),
  importJob: (a, j) => send("POST", `/api/agents/${id(a)}/jobs/${id(j)}/import`),
};

/** Verify a candidate token against a protected route without storing it. */
export async function verifyTokenWithServer(candidate) {
  let res;
  try {
    res = await fetch(`${BASE_URL}/api/stats`, {
      headers: { Authorization: `Bearer ${candidate}` },
    });
  } catch (err) {
    throw new Error("Cannot reach the JOCKY API. Is the server running?", { cause: err });
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
