# RANDAR v3.0.0 Final

**Forensics-as-Code platform for controlled computer and network forensic triage**

> Smart India Hackathon 2026 · Problem Statement **SIH26148**

RANDAR is a digital-forensics and incident-triage platform built around **JOCKY**, a constrained investigation DSL. Investigations declare evidence to collect, analysis rules to run, correlations to perform, and the report to produce. The runtime executes those declarations through explicit registries, bounded execution, provenance tracking, and integrity checks.

> **JOCKY is the language; RANDAR is the platform.** The internal Python package is named `jocky/` for implementation continuity.

## Table of contents

- [Final product scope](#final-product-scope)
- [SIH26148 alignment](#sih26148-alignment)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [The JOCKY language](#the-jocky-language)
- [Command-line interface](#command-line-interface)
- [Collectors](#collectors)
- [Analysis rules](#analysis-rules)
- [Persistence forensics](#persistence-forensics)
- [User-context metadata](#user-context-metadata)
- [Evidence and integrity](#evidence-and-integrity)
- [Web console](#web-console)
- [REST API](#rest-api)
- [Remote agents](#remote-agents)
- [Report encryption](#report-encryption)
- [Runtime limits](#runtime-limits)
- [Repository layout](#repository-layout)
- [Verification](#verification)
- [Documentation](#documentation)
- [Build and run](#build-and-run)
- [Security model](#security-model)

## Final product scope

- **32 live collectors**
- **57 live analysis rules**
- Windows and Linux-aware collection architecture
- JOCKY lexer, parser, IR, compiler, signed bytecode, and bounded runtime
- Transformation/reproducibility research with build identity
- Windows memory and driver forensic detection
- Expanded Windows persistence forensics
- Network/DNS evidence and correlation
- Multi-endpoint authenticated investigation infrastructure
- Stable finding IDs and collector evidence references
- Report/evidence hashing, coverage and elevation reporting
- Software/security-product context and kernel-component evidence
- Privacy-bounded clipboard/browser metadata collection
- React/Vite investigation console
- Hybrid-encrypted report export (AES-256-GCM + RSA-OAEP)
- Append-only audit log and SQLite-backed case storage
- Single-command launcher (`start.py`) that provisions the whole stack

## SIH26148 alignment

The problem statement combines a forensic-language objective with research topics involving polymorphism, in-memory execution, BYOVD/kernel manipulation, and alternate network routing. RANDAR implements the **forensic, measurement, detection, and controlled-research portions** of those themes.

The production platform does **not** implement security-control bypass, vulnerable-driver exploitation, kernel subversion, stealth process injection, process hollowing, reflective injection, API unhooking, or covert transport/domain-fronting behavior. Corresponding behaviors can instead be represented through controlled research metadata and detected through forensic telemetry.

## Architecture

```text
JOCKY source
    ↓
Lexer / Parser / IR
    ↓
Compiler + signed bytecode
    ↓
Bounded interpreter
    ↓
Read-only collectors
    ↓
Evidence normalization + hashes
    ↓
Analysis + cross-surface correlation
    ↓
Deduplication + provenance
    ↓
Timeline + coverage/elevation
    ↓
Integrity-protected report
```

Deployment view:

```text
React/Vite console ──HTTP/JSON + Bearer auth──▶ FastAPI service ──▶ JOCKY engine
                                                     │                 │
                                                     │        collectors + analysis rules
                                                     ▼
                                          SQLite (cases, audit, agents)
                                                     ▲
                        Remote agents (per-agent token) poll for jobs
```

When `frontend/dist` exists, the API serves the built console from the same origin, so the whole product runs on a single port.

## Quick start

Requirements: **Python 3.10+**. **Node.js 20.19+ or 22.12+** is needed for the console (the API runs without it).

```bash
python start.py
```

On the first run the launcher creates a virtual environment, installs the Python dependencies, generates an API token and a bytecode-signing key in `.env`, builds the frontend, starts the API, and opens the console. The API token is **shown once**; store it in a password manager. It is required to sign in.

Platform wrappers:

```powershell
.\start.ps1          # Windows
```

```bash
./start.sh           # Linux / macOS
```

Launcher options:

| Option | Effect |
|---|---|
| `--dev` | Vite dev server (hot reload) plus API auto-reload |
| `--new-token` | Issue a new API token and exit (invalidates the old one) |
| `--rebuild` | Force a frontend rebuild |
| `--no-browser` | Do not open a browser window |
| `--host HOST` / `--port PORT` | Bind address (default `127.0.0.1:8000`) |

The console is served at `http://127.0.0.1:8000` and interactive API documentation at `/docs`. Binding to a non-loopback address exposes the API to the network; place it behind TLS.

## Configuration

Configuration is read from `.env` (never commit it). `python start.py` creates it for you; see `.env.example`. `RANDAR_*` names take precedence and the legacy `JOCKY_*` names remain accepted for backward compatibility.

| Variable | Purpose |
|---|---|
| `RANDAR_API_TOKEN_HASH` | SHA-256 hex digest of the API bearer token. The server refuses to start without it. |
| `RANDAR_BYTECODE_KEY` | HMAC key (32+ characters) used to sign compiled bytecode. |
| `RANDAR_CORS_ORIGINS` | Comma-separated origins allowed to call the API cross-origin (defaults to the Vite dev origins). |
| `JOCKY_EVIDENCE_DIR` | The only directory the `file_hash` collector may read (default `./sample_evidence`). Fixed by the operator, never by a script. |
| `JOCKY_DB_PATH` | SQLite database location (default `./jocky.db`). |
| `RANDAR_DOCS` | Set to `false` to disable the `/docs` page. |
| `RANDAR_OPERATOR_NAME` | Operator name recorded in the audit log (default `admin`). |
| `RANDAR_VT_API_KEY` | Optional. Enables opt-in VirusTotal hash lookups during persistence enrichment. |
| `RANDAR_VULNERABLE_DRIVER_DB` | Optional operator-supplied vulnerable-driver catalog used by the driver rules. |
| `JOCKY_NETWORK_EVIDENCE_DIR` | Location for uploaded network evidence sources. |
| `RANDAR_API_URL`, `RANDAR_AGENT_ID`, `RANDAR_AGENT_TOKEN`, `RANDAR_POLL_INTERVAL`, `RANDAR_TLS_VERIFY` | Remote-agent settings (see [Remote agents](#remote-agents)). |
| `VITE_API_BASE_URL` | Optional, in `frontend/.env`. Only `VITE_`-prefixed values reach the browser bundle; never put secrets there. |

Tokens can also be generated manually with `python -m jocky.api.token_gen`.

## The JOCKY language

JOCKY is deliberately **not** a general-purpose language and **not** a shell. A script can reference only registered collectors and rules plus a small set of bounded language constructs; it cannot invoke Python, shell commands, PowerShell, arbitrary Windows APIs, or arbitrary executables.

```text
investigation "Endpoint Triage" {
    collect system_info;
    collect processes;
    collect network_connections;

    analyze missing_paths;
    analyze suspicious_processes;
    analyze high_connection_processes where network_connections.count > 10;
    analyze process_network_correlation;

    report "endpoint_triage";
}
```

Statements: `collect`, `analyze` (with an optional `where` condition), `report`, `let`, `if` / `else`, and custom `rule ... { when ...; severity ...; }` blocks. Conditions support `and`, `or`, `not` and the comparison operators `> < >= <= == !=`. Severities are `informational`, `review_recommended`, `medium`, `high` and `critical`.

Compilation targets are `portable`, `windows` and `ubuntu`. The runtime refuses to run an artifact built for a different host target rather than silently executing it against the wrong system.

Language limits: source size 20,000 bytes, parse depth 10, and 2,000 bytecode opcodes. Print the machine-readable specification and EBNF grammar with `jocky spec` (add `--json` for JSON). Ready-made scripts are in `examples/`, covering endpoint triage, network evidence and threat hunting, Windows telemetry, domain-expansion triage, injection/PE forensics, and the authorized lab and security-research scenarios. Full reference: `docs/DSL_REFERENCE.md`.

## Command-line interface

Installing the package (`pip install -e .`) provides the `jocky` command; `python -m jocky` is equivalent.

| Command | Purpose |
|---|---|
| `jocky validate <source> [--target T]` | Validate JOCKY source |
| `jocky compile <source> -o <out> [--target T] [--deterministic]` | Compile to signed bytecode |
| `jocky sign <source> -o <out>` | Compile and sign |
| `jocky verify <bytecode>` | Verify a signed artifact |
| `jocky inspect <bytecode>` | Verify and disassemble |
| `jocky run <source> [--target T]` | Compile and execute an investigation locally |
| `jocky experiment <source> [--profile P] [--seed S] [--output F]` | Run a controlled transformation experiment |
| `jocky memory-scan` | Read-only memory-forensics metadata correlation |
| `jocky driver-scan` | Read-only Windows driver/kernel observation |
| `jocky persistence-scan` | Read-only persistence and privilege correlation |
| `jocky spec [--json]` | Print the language specification |

`compile`, `sign` and `experiment` accept transformation profiles (`deterministic`, `randomized`, `reproducible-randomized`, `compatibility-preserving`, `automated-obfuscation`) and an optional `--transformation-seed`. Transformations operate only on the JOCKY IR/bytecode representation, never on native binaries, and preserve investigation semantics.

## Collectors

All 32 collectors are read-only, allowlisted in `jocky/collectors/registry.py`, and bounded by record, size and time limits.

| Area | Collectors |
|---|---|
| Host and identity | `system_info`, `logged_in_users`, `local_users` |
| Processes and memory | `processes`, `modules`, `threads`, `memory_regions`, `open_files` |
| Kernel and drivers | `driver_inventory` |
| Network | `network_connections`, `network_artifacts` |
| Windows telemetry | `windows_event_logs`, `sysmon_events`, `services`, `pe_metadata` |
| Persistence | `scheduled_tasks`, `startup_items`, `wmi_event_subscriptions`, `ifeo_persistence`, `winlogon_persistence`, `appinit_persistence`, `com_hijack_persistence`, `bits_persistence`, `all_users_startup`, `browser_extensions`, `office_addins`, `lsa_auth_packages`, `advanced_persistence` |
| Evidence files | `file_hash` (restricted to the evidence directory) |
| Privacy-bounded user context | `clipboard_metadata`, `browser_history_metadata`, `browser_cookie_metadata` |

Modules, threads, memory regions, Windows Event Logs, Sysmon, services and PE metadata are Windows-specific. On other platforms those collectors return an explicit unsupported status instead of failing silently.

## Analysis rules

All 57 rules are pure functions (evidence in, findings out) registered in `jocky/analysis/registry.py`.

| Category | Rules |
|---|---|
| Process and host | `missing_paths`, `suspicious_processes`, `process_network_correlation`, `high_connection_processes`, `privileged_user_anomaly`, `unusual_scheduled_tasks`, `suspicious_startup_items` |
| Injection and in-memory | `suspicious_module_loads`, `dll_sideloading`, `process_hollowing_indicators`, `reflective_load_indicators`, `thread_hijacking_indicators`, `injection_correlation`, `in_memory_execution_indicators`, `memory_forensics_correlation` |
| Drivers | `byovd_driver_indicators`, `driver_forensics_exposure` |
| DNS and network hunting | `suspicious_dns_queries`, `dns_entropy`, `rare_domains`, `suspicious_tld_patterns`, `dns_bursts`, `unusual_query_types`, `long_random_labels`, `dns_tunneling_indicators`, `dns_beaconing`, `network_beaconing`, `port_scan`, `horizontal_scan`, `service_discovery`, `udp_scan`, `network_classification` |
| Windows telemetry | `encoded_powershell`, `suspicious_powershell_parent`, `powershell_network_activity`, `powershell_child_processes`, `suspicious_services`, `writable_service_paths`, `service_configuration_anomalies` |
| PE and modules | `unsigned_loaded_module`, `suspicious_imports`, `high_entropy_module`, `module_disk_mismatch`, `suspicious_writable_module` |
| Persistence | `persistence_correlation`, `persistence_cross_surface_correlation`, `persistence_privilege_correlation`, `wmi_event_subscription`, `ifeo_debugger`, `winlogon_persistence`, `appinit_dlls`, `com_hijack`, `bits_persistence`, `all_users_startup`, `browser_extensions`, `office_addins`, `lsa_auth_packages` |

Findings are investigation indicators, not verdicts, and must be interpreted in context. A centralized software catalog adds context flags for common endpoint-security/EDR products, anti-cheat, VPN and virtualization software. `KERNEL DRIVER` and `KERNEL COMPONENT` flags are applied only when matching driver evidence is actually observed; a product name alone is never treated as proof of kernel activity.

## Persistence forensics

The final Windows persistence pipeline covers:

- Run / RunOnce
- Startup folders, including local profiles
- Scheduled Tasks
- Services, ServiceDll and unquoted ImagePath
- WMI permanent event subscriptions
- IFEO debugger/verifier configuration
- Winlogon Shell/Userinit and related configuration
- AppInit_DLLs
- HKCU COM CLSID overrides
- BITS jobs
- Browser extensions
- Office add-ins
- LSA Authentication Packages

Persistence findings use multiple weak signals rather than path-only suspicion. Service write checks use ACL evidence where available and return `unknown` when they cannot be verified. Enrichment adds SHA-256, Authenticode, publisher, version and timestamp data, and an opt-in VirusTotal hash lookup when `RANDAR_VT_API_KEY` is set.

## User-context metadata

The final release includes three bounded collectors:

- `clipboard_metadata` — availability/format/length metadata; **clipboard contents are never returned or hashed**.
- `browser_history_metadata` — profile/timestamp metadata and redacted domain hashes; **URLs and titles are not returned**.
- `browser_cookie_metadata` — redacted host hashes plus expiry/Secure/HttpOnly metadata; **cookie values are never returned and cookies are not decrypted**.

## Evidence and integrity

Each collector can contribute an `evidence_hash`. Findings contain stable IDs and references to the collector and record that support them. Reports bind the investigation to `script_hash`, and bytecode-backed runs can also expose `bytecode_hash`. `report_hash` provides an independent integrity check over the canonical report representation.

Reports also explain incomplete coverage: elevation state, collector availability, confidence, access failures, missing Sysmon installation, event-query results, truncation, and termination reason are explicit rather than silently inferred.

Every significant action is written to an append-only **audit log** (timestamp, operator, action, investigation, script hash and report hash). It is exposed at `/api/audit` and per investigation at `/api/investigations/{id}/audit`.

## Web console

The React 19 / Vite console (`frontend/`) requires the API token to sign in and provides:

| Section | Pages |
|---|---|
| Monitor | Dashboard, Investigations (list and detail with evidence drawer and timeline) |
| Operate | New investigation (script editor with validation), Endpoint agents, Runtime, Memory Forensics, Driver Forensics, Persistence & Privilege, Network Forensics, Windows Telemetry |
| Administration | Bytecode (compile, disassemble, execute), DLL / injection analysis, Report encryption (key registration) |

A global search box finds PIDs, IPs, domains, hashes, files, users and findings across stored investigations. Long-running hunts run as server-side background jobs, so they are not tied to the page lifetime or the request timeout.

For development, `python start.py --dev` runs the Vite dev server with hot reload; the frontend lint command is `npm run lint` inside `frontend/`.

## REST API

All routes except `/api/health` require `Authorization: Bearer <token>`. Full interactive documentation is available at `/docs`.

| Area | Endpoints (prefix `/api`) |
|---|---|
| Health and catalog | `GET /health`, `GET /catalog`, `GET /stats` |
| Language | `POST /validate`, `POST /compile` |
| Investigations | `POST /investigations/jobs` (async run), `GET /investigations/jobs/{id}`, `POST /investigations/jobs/{id}/cancel`, `GET /investigations`, `PATCH`/`DELETE /investigations/{id}`, `GET /investigations/{id}/evidence`, `GET /search` |
| Audit | `GET /audit`, `GET /investigations/{id}/audit` |
| Bytecode and runtime | `POST /bytecode/compile`, `/bytecode/disasm`, `/bytecode/execute`, `/runtime/execute` |
| Research | `POST`/`GET /transformations/experiments`, `GET /transformations/experiments/summary` |
| Forensic scans | `POST /memory-forensics/scan`, `/driver-forensics/scan`, `/persistence-forensics/scan`, `POST /forensic-jobs/{scan_type}`, `GET /forensic-jobs/{job_id}` |
| Network evidence | `POST`/`GET /network-sources`, `GET`/`DELETE /network-sources/{id}` |
| Report encryption keys | `POST`/`DELETE /keys/register`, `GET /keys/status` |
| Agents | `POST /agents/register`, `GET /agents`, `DELETE /agents/{id}`, plus job dispatch, result, cancel and import routes |

The service adds baseline security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store` for API routes), rejects oversized request bodies, and restricts CORS methods and headers.

## Remote agents

An agent runs on a target endpoint, polls the central API for pending JOCKY jobs, executes them locally through the same lexer/parser/interpreter safety pipeline, and submits results back.

1. Register the endpoint from the console (or `POST /api/agents/register`) to receive an agent ID and a per-agent token.
2. Start the agent on the endpoint:

```bash
python -m jocky.agent \
    --api-url http://127.0.0.1:8000 \
    --agent-id YOUR_AGENT_ID \
    --agent-token YOUR_AGENT_TOKEN
```

The same values can be supplied as `RANDAR_API_URL`, `RANDAR_AGENT_ID`, `RANDAR_AGENT_TOKEN` and `RANDAR_POLL_INTERVAL` (default 10 s).

Agent tokens are scoped: an agent can reach only its own job, result, error and heartbeat routes and cannot read investigator data or other agents. Scripts are lexed and parsed before dispatch, job claiming is atomic so a job is never double-dispatched, connection errors use exponential backoff (capped at 120 s), and TLS verification is on by default (`RANDAR_TLS_VERIFY=false` is for controlled development only). Completed job results can be imported into the case database as investigations.

## Report encryption

Reports can be exported encrypted to an investigator's public key using hybrid encryption:

1. A fresh 256-bit AES key and 96-bit nonce are generated per report.
2. The report is encrypted with **AES-256-GCM** (authenticated; tampering is detected).
3. The AES key is wrapped with the investigator's **RSA-2048** public key using **OAEP with SHA-256**.

Only the holder of the private key can decrypt; the server never sees it.

```bash
python -m jocky.api.key_gen                 # writes jocky_investigator.key / .pub
# register the .pub in the console (Report encryption) or via /api/keys/register
python -m jocky.api.decrypt_report \
    --key jocky_investigator.key \
    --input jocky_report_1.enc \
    --output jocky_report_1.json
```

Keep the `.key` file secret and never upload it. `*.key` and `*.enc` are git-ignored.

## Runtime limits

Execution is bounded so that a script cannot exhaust the host:

| Limit | Value |
|---|---|
| Per-collector runtime | 45 s (bounded per-surface overrides for slower Windows collectors) |
| Whole-investigation runtime | 600 s |
| Records per collector | 10,000 |
| Evidence size | 8 MiB |
| Variables per script / `if` nesting depth | 50 / 10 |
| Evidence and network-source uploads | 20 MiB each |
| Request body | 28 MiB |
| Tracked background jobs | 64 investigation jobs, 32 forensic jobs |
| Registered agents / stored agent jobs | 100 / 1,000 |

Individual collectors also carry their own caps (for example processes, modules, threads, memory regions, files and events). Truncation and time-outs are reported explicitly in the coverage section of the report.

## Repository layout

```text
jocky/
  language/     lexer, parser, IR, compiler, signed bytecode, interpreter, transforms
  collectors/   read-only evidence collectors and the collector registry
  analysis/     rule modules, software catalog, and the rule registry
  reports/      report builder, JSON/HTML writers, integrity, encryptor
  api/          FastAPI app, auth, routes, jobs, agents, key tooling
  storage/      SQLite case store, audit log, network-source store
  agent/        remote endpoint agent (python -m jocky.agent)
  research/     authorized-lab synthetic scenario generator
  cli.py        `jocky` command
frontend/       React/Vite investigation console
examples/       ready-to-run .jocky investigation scripts
sample_evidence/ default evidence directory for file_hash
tests/          regression suite and Windows persistence fixtures
docs/           product, architecture, security and release documentation
start.py        cross-platform launcher (start.sh / start.ps1 wrappers)
```

New collectors and rules must be added explicitly to their registry; the registry is the only route from a JOCKY identifier to an implementation.

## Verification

The final regression suite currently reports:

**165 passed, 0 failed**

Run it with `python -m pytest -q`. The suite covers the language toolchain, execution engine, API, memory/driver/persistence forensics, transformations, software classification, UI regressions, and clean-versus-planted Windows persistence fixtures.

It includes a regression for the exact Startup Items failure:

```text
bad escape \\W at position 2
```

That failure was caused by using a Windows path containing backslashes as a regular-expression replacement string. Environment-variable substitution now uses a literal replacement callback, and Windows fallback paths are normalized correctly.

## Documentation

The final product documentation is grouped under:

`docs/V3_0_FINAL/`

Start with:

- `docs/V3_0_FINAL/README.md`
- `docs/V3_0_FINAL/FINAL_PRODUCT.md`
- `docs/V3_0_FINAL/SIH26148_ALIGNMENT.md`
- `docs/V3_0_FINAL/PERSISTENCE_FINAL.md`
- `docs/V3_0_FINAL/PRIVACY_METADATA.md`
- `docs/V3_0_FINAL/VERIFICATION.md`
- `docs/V3_0_FINAL/RELEASE_NOTES.md`

Supporting references in `docs/`: `ARCHITECTURE.md`, `DSL_REFERENCE.md`, `SECURITY_MODEL.md`, `DEPLOYMENT.md`, `DFIR_CAPABILITIES.md`, `PRODUCT_GUIDE.md`, `PROJECT_STRUCTURE.md`, `DEMO_PLAYBOOK.md`, and `SIH_2026_TECHNICAL_BRIEF.md`. `CHANGELOG.md` records version history.

Historical V1/V2 release notes remain in the repository as release history; the V3.0 directory is the authoritative final-product documentation. Some older documents under `docs/` still quote earlier capability counts; the live registries and this README are authoritative.

## Build and run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -q
python start.py
```

On Linux/macOS, activate with `source .venv/bin/activate`. Python dependencies: FastAPI, Uvicorn, Pydantic, psutil, cryptography, python-dotenv and requests.

The frontend is under `frontend/`. A production Vite build should be performed in an environment where the declared npm dependencies can be installed:

```bash
cd frontend
npm ci
npm run build
```

RANDAR is intended for local forensic triage, controlled Windows laboratory systems, demonstration environments, and authorized remote-agent experiments. It is not designed to be exposed directly to the public Internet.

## Security model

RANDAR is designed as a controlled forensic platform. Collectors are read-only, capability names are allowlisted, execution is bounded, and evidence/report provenance is explicit. Advanced SIH26148 concepts are treated as controlled research/detection subjects rather than as production evasion mechanisms.

Key controls:

- **Single-operator bearer token.** Only its SHA-256 digest is stored; comparison is constant-time, and the server aborts at startup if authentication is not configured.
- **Scoped agent tokens.** Agents cannot reach investigator routes.
- **DSL isolation.** No path from a script to Python, a shell, or arbitrary executables.
- **Tamper-evident bytecode.** Artifacts are HMAC-signed and verified before execution.
- **Evidence-directory restriction.** `file_hash` can read only the operator-configured directory.
- **Privacy-bounded collectors.** No clipboard contents, URLs, titles, or cookie values.
- **Protected report transfer.** AES-256-GCM with RSA-OAEP key wrapping.
- **Audit trail.** Append-only log of investigation actions.

See `docs/SECURITY_MODEL.md` for the full trust-boundary description.
