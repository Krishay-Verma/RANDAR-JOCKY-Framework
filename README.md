# JOCKY

**Forensics-as-Code platform for computer and network forensic triage**

> **Smart India Hackathon 2026 · Problem Statement SIH26148**  
> **Creation of scripts/functions with a new programming language to commence Computer & Network forensic analysis without triggering security solutions**

**Team:** AVINYA  
**Category:** Software  
**Theme:** Cryptocurrency & Cybersecurity

JOCKY is a modular digital-forensics and incident-triage platform built around a purpose-made investigation language. An analyst writes a compact JOCKY script describing what evidence to collect and what analysis to perform. The script is lexed, parsed, converted into an intermediate representation (IR), optionally compiled into signed bytecode, executed through a fixed allowlist of collectors and deterministic analysis rules, persisted as a case, and rendered through a forensic console or exported as a report.

The platform is designed around a **read-only, low-impact acquisition model**. It does not disable EDR/AV, tamper with security controls, perform DLL injection, write to another process's memory, or provide arbitrary command execution through the DSL. The SIH problem statement's objective is addressed through controlled forensic acquisition and analysis rather than security-control evasion.

---

## Why JOCKY exists

Traditional forensic workflows often combine many independent tools, command-line utilities, scripts, query languages, and report formats. That creates three recurring problems:

1. **Investigation logic becomes difficult to reproduce.**
2. **Collection and analysis are tightly coupled to individual tools.**
3. **A small change in an investigation can require new glue code or a new tool.**

JOCKY introduces a single investigation language and execution pipeline:

```text
Analyst Script
     │
     ▼
 Lexer → Parser → IR
     │
     ├──────────────► Validate / Inspect IR
     │
     ▼
 Interpreter / Signed Bytecode
     │
     ▼
 Allowlisted Collectors
     │
     ▼
 Evidence Store
     │
     ▼
 Deterministic Analysis Rules
     │
     ▼
 Findings + Provenance
     │
     ├──────────────► Web Console
     └──────────────► HTML / Encrypted Report
```

This makes the investigation itself a portable, reviewable artifact rather than a sequence of undocumented manual commands.

---

## What JOCKY can do today

### Investigation language

- Purpose-built JOCKY DSL for forensic investigations.
- Lexer and recursive-descent parser.
- Intermediate representation built from plain dataclasses.
- `collect`, `analyze`, `report`, `let`, `if`, and `else` statements.
- Bounded variables and conditional execution.
- Allowlisted collectors, rules, and evidence properties.
- Script validation without executing collection.
- IR inspection from the console/API.

### Endpoint evidence collection

JOCKY currently exposes **12 collectors**:

| Collector | Platform | Purpose |
|---|---|---|
| `system_info` | Windows/Linux | Host identity, OS, architecture, CPU, memory and current user. |
| `processes` | Windows/Linux | Running processes, paths, owners and start times. |
| `network_connections` | Windows/Linux | Local/remote sockets, ports, state and owning PID. |
| `logged_in_users` | Windows/Linux | Interactive login/session information. |
| `file_hash` | Windows/Linux | SHA-256 hashing of files in the operator-approved evidence directory. |
| `scheduled_tasks` | Windows/Linux | Windows Task Scheduler or Linux cron-related persistence. |
| `startup_items` | Windows/Linux | Windows Run/RunOnce/startup locations or Linux startup units. |
| `open_files` | Windows/Linux | Bounded open-file/handle inventory per process. |
| `local_users` | Windows/Linux | Local account inventory. `/etc/shadow` is never read. |
| `modules` | **Windows** | Loaded DLL/EXE/SYS module inventory with bounded hashing of user-writable modules. |
| `threads` | **Windows** | Read-only process/thread metadata and Windows thread start-address telemetry. |
| `memory_regions` | **Windows** | Virtual-memory region metadata without reading or writing process memory. |

### Deterministic analysis

JOCKY currently exposes **13 analysis rules** covering:

- Missing executable paths
- Suspicious executable directories
- Process/network correlation
- Unusual scheduled tasks
- Suspicious startup items
- High connection processes
- Privileged-user anomalies
- Suspicious Windows module loads
- DLL sideloading indicators
- Process-hollowing indicators
- Reflective-loading indicators
- Thread-hijacking indicators
- Multi-signal injection correlation

Findings are deliberately phrased as **investigation indicators**, not malware verdicts. Each finding contains a rule name, severity, human-readable summary, reason, and related evidence.

### Windows DLL / injection forensics

The Windows-specific forensic layer provides read-only telemetry for investigating:

- Unusual DLL/module locations
- User-writable module loads
- Potential DLL sideloading
- Private executable memory regions
- Potential process-hollowing patterns
- Reflective-loading leads
- Thread start addresses associated with private executable regions
- Correlated module + executable-memory indicators

**Important:** JOCKY detects and correlates evidence associated with these techniques; it does **not** inject DLLs, create remote threads for offensive purposes, suspend victim threads, or write another process's memory.

### Case management and reporting

- SQLite investigation persistence.
- Immutable stored report/evidence JSON; case metadata remains editable separately.
- Investigation status: `open`, `in_review`, `closed`.
- Analyst notes.
- Severity aggregation and dashboard statistics.
- Self-contained HTML reports.
- AES-256-GCM encrypted report export with RSA-OAEP key wrapping.
- SHA-256 source-script fingerprinting.

### Remote endpoint operations

JOCKY includes a polling remote-agent architecture with:

- Per-agent registration.
- Per-agent bearer tokens stored as SHA-256 digests.
- Job dispatch and atomic job claiming.
- Script execution through the same JOCKY pipeline.
- Result submission.
- Heartbeats.
- Agent revocation.
- Exponential backoff for disconnected agents.
- TLS certificate verification enabled by default.

### Signed bytecode

Scripts can be compiled to a compact JOCKY bytecode representation and protected with HMAC-SHA256 signing. Bytecode is verified before disassembly or execution and is reconstructed into the same IR/interpreter path used for source scripts.

This means bytecode does **not** create a second, less-controlled execution path.

---

# Quick start

## Requirements

- Python **3.10+**
- Node.js **20.19+** or **22.12+** for the current Vite build
- Windows is the primary target for the advanced Windows forensic collectors.
- Linux is supported by the cross-platform collectors; Windows-only collectors report an explicit unsupported status instead of silently failing.

## One-command setup

```bash
python start.py
```

Windows PowerShell:

```powershell
.\start.ps1
```

Linux/macOS:

```bash
./start.sh
```

The launcher can:

1. create the Python virtual environment;
2. install Python dependencies;
3. create the local `.env` configuration;
4. generate a bytecode signing key when required;
5. generate/display the API token on first setup;
6. verify/install the frontend dependencies;
7. build the React/Vite console;
8. start Uvicorn;
9. optionally open the browser.

Default console/API:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

## Launcher commands

| Command | Purpose |
|---|---|
| `python start.py` | Set up missing dependencies and run JOCKY. |
| `python start.py --new-token` | Generate a replacement API token. |
| `python start.py --dev` | Run the API and Vite development workflow. |
| `python start.py --rebuild` | Force a frontend production rebuild. |
| `python start.py --no-browser` | Start without opening a browser window. |
| `python start.py --host 127.0.0.1 --port 9000` | Use a custom bind address/port. |

### First-run authentication

The API is authenticated by a bearer token. The launcher prints the token when it is first generated. Store it securely. The browser keeps the token in `sessionStorage` and discards it when the tab/session ends.

---

# JOCKY language at a glance

A complete investigation can be written as a small, readable script:

```text
investigation "Windows Injection Forensics" {
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
```

Conditional investigations are also supported:

```text
investigation "Adaptive Triage" {
    let connection_limit = 10;

    collect system_info;
    collect processes;
    collect network_connections;

    if network_connections.count > connection_limit {
        analyze high_connection_processes;
    } else {
        analyze process_network_correlation;
    }

    report "adaptive_triage";
}
```

The full language reference is in [`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md).

---

# Architecture

```text
┌───────────────────────────────────────────────────────────────┐
│                         JOCKY Console                         │
│ React + Vite · Investigations · Evidence · Agents · Reports  │
└───────────────────────────────┬───────────────────────────────┘
                                │ HTTP / JSON
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                         FastAPI API                           │
│ Authentication · Validation · Case APIs · Bytecode · Reports │
└───────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                    JOCKY Language Engine                     │
│ Lexer → Parser → IR → Interpreter                            │
│                ↘ Bytecode compiler / verifier                │
└───────────────┬──────────────────────┬────────────────────────┘
                │                      │
                ▼                      ▼
       ┌────────────────┐      ┌────────────────────┐
       │   Collectors   │      │  Analysis Rules    │
       │ Read-only      │      │ Pure evidence-in → │
       │ endpoint data  │      │ finding-out        │
       └───────┬────────┘      └─────────┬──────────┘
               │                         │
               └──────────┬──────────────┘
                          ▼
                 ┌─────────────────┐
                 │ Evidence / Case │
                 │ SQLite + JSON   │
                 └────────┬────────┘
                          ▼
              ┌──────────────────────┐
              │ HTML / Encrypted     │
              │ forensic reporting   │
              └──────────────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a component-by-component explanation.

---

# Security philosophy

JOCKY is deliberately constrained.

### The DSL is not a shell

A JOCKY script can invoke only collectors and analysis rules explicitly registered by the engine. Unknown names fail validation. Scripts cannot call arbitrary Python, Windows APIs, PowerShell, `cmd.exe`, or system utilities.

### Collection and analysis are separated

Collectors gather evidence. Rules consume evidence and produce findings. This makes the analytical layer easier to test, reason about, and extend without giving rules direct endpoint access.

### Windows injection analysis is read-only

The Windows injection collectors inspect module metadata, thread metadata, and virtual-memory metadata. They do not read arbitrary process memory and do not modify target processes.

### Reports can be protected for transfer

The report body is encrypted using AES-256-GCM. The AES key is wrapped using the investigator's RSA public key. The server never needs the investigator's private key.

### Security controls are not disabled

JOCKY is not an EDR-bypass framework. It does not disable AV/EDR, tamper with security products, remove telemetry, or attempt to conceal collection. The low-impact design exists to reduce endpoint modification during legitimate forensic acquisition.

See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

---

# Repository layout

```text
JOCKY/
├── jocky/
│   ├── agent/          # Remote endpoint agent
│   ├── analysis/       # Evidence-driven analysis rules
│   ├── api/            # FastAPI routes, auth, catalog, key handling
│   ├── collectors/     # Read-only endpoint collectors
│   ├── language/       # Lexer, parser, IR, interpreter, bytecode
│   ├── reports/        # Report model, builders, HTML and encryption
│   └── storage/        # SQLite case persistence
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── api/
│   └── public/         # JOCKY icon/favicon assets
├── docs/               # Full product and engineering documentation
├── tests/              # Regression and security-boundary tests
├── sample_evidence/    # Small controlled evidence fixture
├── start.py            # Cross-platform launcher
├── start.ps1           # Windows launcher wrapper
├── start.sh            # Unix launcher wrapper
├── requirements.txt
└── README.md
```

---

# Documentation

| Document | Audience | Purpose |
|---|---|---|
| [`docs/PRODUCT_GUIDE.md`](docs/PRODUCT_GUIDE.md) | Investigators, students, judges | What JOCKY does, why it exists, and how the pieces work together. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Developers, architects | Deep component and data-flow explanation. |
| [`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md) | Investigators, developers | JOCKY language syntax, semantics, limits and examples. |
| [`docs/DFIR_CAPABILITIES.md`](docs/DFIR_CAPABILITIES.md) | DFIR analysts | Detailed collector/rule capabilities and interpretation. |
| [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) | Security reviewers | Trust boundaries, authentication, signing, encryption and safety limits. |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Operators | Windows/Linux setup, configuration, agents and operational guidance. |
| [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | Contributors | File-by-file development map and extension points. |
| [`docs/DEMO_PLAYBOOK.md`](docs/DEMO_PLAYBOOK.md) | SIH presenters | A repeatable end-to-end demonstration workflow. |

---

# API

The FastAPI application exposes interactive documentation at `/docs`.

Core authenticated operations include:

- health/liveness
- investigation execution and persistence
- script validation
- IR compilation/inspection
- investigation listing and retrieval
- case metadata updates
- HTML report export
- encrypted report export
- collector/rule catalog discovery
- dashboard statistics
- investigator public-key registration
- signed bytecode compilation/verification/execution
- remote-agent registration and job operations

The authoritative route definitions are under `jocky/api/` and the live capability catalog is served by `GET /api/catalog`.

---

# Testing

Run the regression suite:

```bash
pytest -q
```

The current project baseline contains regression coverage for:

- DSL parsing/interpreter behavior
- bytecode integrity
- collector/rule registration
- Windows-only injection collector safety on non-Windows systems
- injection rule registration and correlation
- authentication/security boundaries

A passing suite is necessary but not sufficient for production forensic validation; endpoint-specific testing should still be performed on controlled Windows systems.

---

# Current limitations

JOCKY is a forensic triage platform, not a complete enterprise EDR or malware-analysis suite.

Current boundaries include:

- Windows injection telemetry is metadata-oriented; JOCKY does not read arbitrary process memory.
- PE static analysis, ETW/Sysmon ingestion, full Windows event-log analytics, and dedicated PowerShell event collection are not yet first-class collectors.
- Remote agent state is held in server memory and is cleared when the API restarts; saved investigations remain in SQLite.
- The current DSL intentionally has a small grammar. It is designed for safe orchestration, not general-purpose programming.
- Some endpoint data requires elevated privileges to observe completely.
- Findings are indicators for human review, not definitive malware determinations.

These boundaries are documented deliberately so users can distinguish implemented functionality from planned extensions.

---

# Responsible use

JOCKY is intended for authorized digital-forensics, incident-response, defensive security research, education, and controlled laboratory environments.

Only investigate systems and data for which you have appropriate authorization. Do not use the platform to evade security controls, obtain unauthorized access, or interfere with other users or systems.

---

# Project status

JOCKY is an actively developed SIH 2026 prototype with a working end-to-end investigation pipeline, Windows-specific advanced telemetry, remote-agent architecture, signed bytecode, case persistence, and protected reporting.

The next engineering priorities are deeper Windows telemetry, stronger evidence correlation, expansion of the JOCKY language, production hardening, endpoint packaging, and broader automated testing.

---

## License

No open-source license is declared in this repository at present. Unless and until a license file is added, treat the project as **all rights reserved** and obtain permission before redistributing or incorporating the source into another product.
