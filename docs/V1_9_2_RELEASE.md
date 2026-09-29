# RANDAR v1.9.2 — Reliability & Documentation Baseline

## Release scope

v1.9.2 is the current repository baseline for RANDAR.

The release combines the reliability work recorded below with the complete implementation-aligned documentation set. Historical release notes remain available separately; the root README and current documentation describe the actual v1.9.2 source tree.

## Root causes addressed

The intermittent console recovery behavior was traced to frontend lifecycle races: requests from an outgoing route could remain active after navigation, periodic loaders could overlap, and the background investigation UI could have competing status pollers.

## Frontend request lifecycle

`useLoad` owns an `AbortController` per active request, aborts the previous request before starting a replacement, and aborts the active request on unmount. The API client composes the caller abort signal with the normal HTTP timeout so either condition terminates the same request.

## Investigation cancellation

The investigation workflow has one polling owner. Cancellation requests the backend cancellation state without creating a second competing polling loop.

## Response-shape hardening

Frontend pages normalize API responses before iteration. This reduces UI failures caused by malformed or transitional response shapes across:

- searches;
- agent lists/jobs;
- investigation pages;
- Windows telemetry;
- injection analysis;
- network sources;
- evidence tables.

## Windows timeout policy

Heavy Windows collectors use bounded collector-specific timeouts. The investigation-wide maximum remains bounded at **600 seconds**.

## Current implementation inventory

The v1.9.2 documentation baseline was reconciled against the live registries:

- **17 registered collectors**
- **40 registered analysis rules**
- JOCKY IR and interpreter
- HMAC-SHA256 signed bytecode
- SQLite investigation persistence
- audit events
- evidence/report hashing
- HTML/JSON/encrypted reporting
- remote-agent registration and job workflow
- network evidence analysis
- Windows Event Log and Sysmon telemetry
- PE metadata analysis
- Windows module/thread/memory-region telemetry

## Verification

The repository regression suite was executed after the documentation update:

```text
91 passed
```

The tests cover the current automated regression surface. Windows-specific behavior should still be validated on controlled Windows hosts before operational deployment.

## Documentation files updated

The current documentation set includes:

- `README.md`
- `docs/README.md`
- `docs/SIH_2026_TECHNICAL_BRIEF.md`
- `docs/PRODUCT_GUIDE.md`
- `docs/ARCHITECTURE.md`
- `docs/DFIR_CAPABILITIES.md`
- `docs/DSL_REFERENCE.md`
- `docs/SECURITY_MODEL.md`
- `docs/DEPLOYMENT.md`
- `docs/PROJECT_STRUCTURE.md`
- `docs/DEMO_PLAYBOOK.md`
- `frontend/README.md`

The historical `docs/V1_*_RELEASE.md` files are retained as release history and should not be interpreted as the authoritative description of the current capability set.
