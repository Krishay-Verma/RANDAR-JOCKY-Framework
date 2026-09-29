# RANDAR Framework v1.9.2

V1.9.2 is a comprehensive reliability patch over V1.9.1. It addresses intermittent client-side route errors, stale request races, background-run cancellation races, unexpected API response shapes, and routine Windows telemetry timeouts.

## Reliability fixes

- Route-bound data requests now use AbortController cancellation.
- Navigation/unmount cancels obsolete requests instead of allowing stale responses to race the new page.
- Repeated polling aborts the previous request before starting the next one.
- Investigation cancellation has one status-poll owner; the Cancel action no longer starts a competing poll loop.
- Queued/running/cancelling/terminal states are handled as one deterministic lifecycle.
- API list responses are normalized before `.map()`/`.filter()`/`.find()` operations.
- Modal/evidence callbacks are type-checked before invocation.

## Windows execution reliability

- Generic collector bound: 45 seconds.
- Modules / threads / memory regions: 90 seconds.
- Windows Event Logs / Sysmon: 90 seconds.
- PE metadata: 120 seconds.
- Maximum investigation runtime: 600 seconds.

These remain hard bounds. A timeout is recorded as a collector-level timeout and does not discard unrelated evidence.

## Verification

- Full backend regression suite: **91 passing**
- API route duplicate scan: passed
- Python compileall: passed
- Frontend production build: source was updated and the project owner can verify it with `npm ci && npm run build`; this container cannot independently reproduce npm installation because registry package transport is unavailable.

## Product boundary

RANDAR remains a defensive forensic triage platform. JOCKY remains the controlled Forensics-as-Code DSL. No offensive capabilities were added.
