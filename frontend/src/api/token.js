/**
 * Bearer-token storage for the RANDAR dashboard.
 *
 * Uses sessionStorage: the token is cleared when the tab closes, and is
 * never written to disk-persistent storage. Every access is wrapped in
 * try/catch because browsers can throw (private mode, storage disabled,
 * quota errors) — a storage failure must degrade to "no token", never
 * crash the app.
 */

const KEY = "jocky.token";

// Bearer tokens from token_gen.py are URL-safe base64 (A-Z a-z 0-9 - _),
// ~43 chars. Rejecting anything else stops header-injection attempts
// (e.g. embedded CR/LF) and accidental paste garbage before it reaches
// a request header.
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

export function isValidTokenFormat(value) {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

export function getToken() {
  try {
    const value = sessionStorage.getItem(KEY);
    return isValidTokenFormat(value) ? value : null;
  } catch {
    return null;
  }
}

export function setToken(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (!isValidTokenFormat(trimmed)) {
    throw new Error("Token format is invalid.");
  }
  try {
    sessionStorage.setItem(KEY, trimmed);
  } catch {
    throw new Error("Could not store the token in this browser session.");
  }
}

export function clearToken() {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* nothing to clear if storage is unavailable */
  }
}