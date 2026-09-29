# RANDAR

**Forensics-as-Code platform for controlled computer and network forensic triage**

> **Smart India Hackathon 2026 · Problem Statement SIH26148**  
> **Creation of scripts/functions with a new programming language to commence Computer & Network forensic analysis without triggering security solutions**

**Team:** AVINYA  
**Category:** Software  
**Theme:** Cryptocurrency & Cybersecurity  
**Current repository release:** **v1.9.2**

RANDAR is a modular digital-forensics and incident-triage platform built around **JOCKY**, a purpose-built investigation language. An analyst describes an investigation as a small, reviewable script: what evidence should be collected, which bounded analysis rules should be evaluated, and how the result should be reported.

The platform converts that script into a controlled execution plan, validates it against explicit capability registries, collects read-only endpoint/network evidence, applies deterministic analysis rules, records provenance and integrity metadata, persists the case, and presents the investigation through a forensic web console or protected report export.

RANDAR is intentionally **not an EDR-bypass or security-control-evasion framework**. Its design addresses the SIH problem through controlled, low-impact forensic acquisition and analysis rather than by disabling or defeating security controls.

---

## 1. Executive summary

Traditional forensic triage often depends on a collection of unrelated commands, scripts, utilities, and analyst notes. That makes an investigation harder to reproduce, review, automate, and preserve as an auditable artifact.

RANDAR introduces a different execution model:

```text
                    INVESTIGATION DEFINITION
                              │
                              ▼
                    JOCKY SOURCE SCRIPT
                              │
                     Lexer → Parser
                              │
                              ▼
                   Intermediate Representation
                         /            \
                        /              \
              Validation / Inspect     Compile
                      │                  │
                      │          HMAC-SHA256 signed
                      │             bytecode
                      └───────┬──────────┘
                              ▼
                    Controlled Interpreter
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
         Endpoint          Network          Windows
         Collectors        Evidence         Telemetry
              │               │                │
              └───────────────┴────────────────┘
                              ▼
                    Evidence Normalization
                              │
                              ▼
                  Deterministic Analysis Rules
                              │
                              ▼
                   Findings + Evidence Refs
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
               Case Store          Report Builder
                    │                   │
                    ▼             HTML / JSON /
               Web Console        Encrypted Export
```

The investigation script therefore becomes a **portable, reviewable unit of forensic logic** rather than a sequence of undocumented manual operations.

---

## 2. What is implemented in v1.9.2

The live registries in the source code currently expose:

| Capability surface | Implemented |
|---|---:|
| JOCKY collectors | **17** |
| Analysis rules | **40** |
| Conditional execution | Yes |
| Analyst variables | Yes |
| Analyst-authored bounded rules | Yes |
| Evidence-property conditions | Yes |
| Source validation without execution | Yes |
| JOCKY IR inspection | Yes |
| Signed bytecode | Yes |
| Local investigations | Yes |
| Remote-agent execution | Yes |
| SQLite case persistence | Yes |
| Append-only audit events | Yes |
| Evidence/report hashing | Yes |
| HTML reporting | Yes |
| JSON reporting | Yes |
| AES-256-GCM report encryption | Yes |
| RSA-OAEP key wrapping | Yes |
| Network evidence ingestion | Yes |
| Windows Event Log metadata | Yes |
| Sysmon event collection | Yes |
| PE metadata analysis | Yes |
| Windows module/thread/memory telemetry | Yes |
| React/Vite investigation console | Yes |

The figures above are derived from the current collector and analysis registries rather than from historical release notes.

---

## 3. Core capabilities

### 3.1 JOCKY — Forensics-as-Code

JOCKY is intentionally small and constrained. It supports:

- `investigation` blocks
- `collect`
- `analyze`
- `report`
- `let`
- `if` / `else`
- `where` conditions on analysis
- boolean `and`, `or`, `not`
- comparison operators `>`, `<`, `>=`, `<=`, `==`, `!=`
- evidence-property references such as `processes.count`
- bounded analyst-authored `rule` definitions
- deterministic IR generation
- signed bytecode compilation

Example:

```text
investigation "Windows Injection Review" {
    collect system_info;
    collect processes;
    collect modules;
    collect threads;
    collect memory_regions;
    collect pe_metadata;

    analyze suspicious_module_loads;
    analyze dll_sideloading;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;

    report "windows_injection_review";
}
```

### 3.2 Endpoint evidence

The 17 registered collectors currently cover:

| Collector | Scope | Evidence |
|---|---|---|
| `system_info` | Cross-platform | Host identity, OS, architecture, CPU, memory |
| `processes` | Cross-platform | Running processes, paths, owners, start times |
| `network_connections` | Cross-platform | Active sockets, ports, state, owning PID |
| `network_artifacts` | Evidence-driven | Normalized DNS/connection metadata from supported network evidence |
| `windows_event_logs` | Windows | Bounded security/process/logon/service/PowerShell event metadata |
| `sysmon_events` | Windows | Bounded Sysmon Operational event set |
| `services` | Windows | Service state, account, start mode and executable metadata |
| `pe_metadata` | Windows | PE structure, imports/exports, entropy, hash and signature metadata |
| `logged_in_users` | Cross-platform | Active interactive sessions |
| `file_hash` | Controlled | SHA-256 for the operator-approved evidence directory |
| `scheduled_tasks` | Cross-platform | Windows scheduled tasks / Linux cron surfaces |
| `startup_items` | Cross-platform | Windows startup/Run surfaces / Linux startup units |
| `open_files` | Cross-platform | Bounded open-file/handle inventory |
| `local_users` | Cross-platform | Local account inventory without reading `/etc/shadow` |
| `modules` | Windows | Loaded DLL/EXE/SYS metadata and bounded hashing |
| `threads` | Windows | Read-only process/thread metadata and thread start addresses |
| `memory_regions` | Windows | Virtual-memory region metadata; no memory contents read |

### 3.3 Analysis

The 40 registered rules span:

**Endpoint/process**
- missing paths
- suspicious executable directories
- process/network correlation
- high connection processes
- privileged-user anomalies

**Persistence and Windows telemetry**
- unusual scheduled tasks
- suspicious startup items
- encoded PowerShell indicators
- suspicious PowerShell parent processes
- PowerShell/network correlation
- PowerShell child processes
- suspicious services
- writable service paths
- persistence correlation

**Network threat hunting**
- suspicious DNS queries
- DNS entropy
- rare domains
- suspicious TLD patterns
- DNS bursts
- unusual DNS query types
- long/random labels
- DNS tunnelling indicators
- DNS beaconing
- network beaconing
- port scans
- horizontal scans
- service discovery
- UDP scan indicators
- network address classification

**Windows module / injection forensics**
- suspicious module loads
- DLL sideloading
- process-hollowing indicators
- reflective-loading indicators
- thread-hijacking indicators
- injection correlation

**PE/module analysis**
- unsigned loaded modules
- suspicious imports
- high-entropy modules
- module/disk mismatch
- suspicious writable modules

Rules are evidence-driven and produce findings with severity, explanation, related evidence and recommended next checks. They are **indicators for analyst review**, not automatic malware verdicts.

---

## 4. Security and execution model

RANDAR deliberately constrains the execution surface.

### JOCKY is not a shell

A script can only reference capabilities registered by the engine. Unknown collectors and analysis rules are rejected. The DSL cannot directly invoke:

- arbitrary Python
- PowerShell
- `cmd.exe`
- arbitrary Windows APIs
- arbitrary system utilities
- unrestricted filesystem paths
- arbitrary process-control operations

### Collection is separated from analysis

Collectors gather evidence. Analysis functions consume evidence and return findings. Analysis rules do not receive unrestricted endpoint access.

### Windows advanced telemetry is read-only

The Windows injection-forensics layer observes:

- loaded module metadata
- thread metadata
- virtual-memory region metadata
- PE metadata
- correlations between those evidence sources

It does **not**:

- inject DLLs
- create remote threads
- write another process's memory
- suspend or resume target threads
- execute collected binaries
- alter security controls

### Bounded execution

The runtime contains explicit bounds for:

- investigation runtime
- collector runtime
- parser nesting
- bytecode operations
- evidence/record volumes
- selected Windows collection surfaces

This reduces the chance that a malformed or unexpectedly expensive investigation can consume unbounded resources.

---

## 5. Evidence provenance and integrity

RANDAR carries forensic context through the execution pipeline.

Reports can contain:

- investigation identity
- endpoint hostname
- execution timing
- collector status
- record counts
- truncation indicators
- resource accounting
- collector evidence hashes
- deterministic finding IDs
- evidence references
- source-script SHA-256
- bytecode hash when applicable
- execution status and termination reason
- bounded investigation timeline
- audit events

Stored report integrity can be verified through a SHA-256 report digest.

This does not make the platform a certified forensic acquisition product; it provides a structured provenance and integrity layer appropriate to the current prototype.

---

## 6. Protected reporting

RANDAR supports:

### JSON

Machine-readable investigation output suitable for integration and archival workflows.

### HTML

Self-contained analyst-facing reports with findings, evidence and investigation context.

### Encrypted report

The implementation uses:

```text
Report
  │
  ▼
AES-256-GCM
  │
  ├── ciphertext
  └── authentication tag
          +
      RSA-2048+ public-key
      OAEP / SHA-256 wrapping
          │
          ▼
      encrypted report
```

The investigator's private key is not stored by the server. The current prototype keeps the active public key in process memory.

---

## 7. Remote endpoint model

RANDAR includes a polling agent architecture for authorized remote investigations.

```text
             RANDAR API
                 │
       ┌─────────┴─────────┐
       │                   │
   Job creation        Agent registry
       │                   │
       ▼                   ▼
   Pending job        Agent metadata
       │
       ▼
   Agent polling
       │
       ▼
   Local JOCKY execution
       │
       ▼
   Signed job/result context
       │
       ▼
   Result import → investigation/case
```

Implemented controls include:

- per-agent registration
- per-agent bearer tokens stored as hashes
- agent revocation
- capability reporting
- heartbeats
- pending/running/completed/failed/cancelled job states
- job expiry
- bounded job storage
- cancellation
- job signatures/nonces
- result import

The agent architecture is intended for controlled enterprise/laboratory deployment; it is not positioned as a complete enterprise endpoint-management system.

---

## 8. Web console

The React/Vite console currently exposes dedicated views for:

- dashboard
- investigations
- new investigation
- investigation detail
- global search
- remote agents
- network evidence
- Windows telemetry
- injection analysis
- JOCKY bytecode
- investigator keys
- sign-in/authentication

The UI is driven from the live backend capability catalog so the editor does not need to hard-code the current collector/rule list.

---

## 9. Quick start

### Requirements

- Python **3.10+**
- Node.js **20.19+** or **22.12+** for the current Vite toolchain
- Windows is required for the Windows-only collectors.
- Linux is supported for the cross-platform collectors.

### Start

```bash
python start.py
```

Windows:

```powershell
.\start.ps1
```

Linux/macOS:

```bash
./start.sh
```

The launcher can create the Python environment, install dependencies, create/update `.env`, generate authentication/signing material, install/build the frontend and start Uvicorn.

Default endpoints:

```text
Console:  http://127.0.0.1:8000
API docs: http://127.0.0.1:8000/docs
```

### Useful launcher commands

```bash
python start.py --new-token
python start.py --dev
python start.py --rebuild
python start.py --no-browser
python start.py --host 127.0.0.1 --port 9000
```

For configuration and remote deployment, see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## 10. Testing

The current repository regression suite was executed during this documentation update:

```text
91 passed
```

Run it locally with:

```bash
pytest -q
```

The suite covers language behavior, bytecode integrity, capability registration, security boundaries and Windows-only collector behavior on unsupported platforms.

A passing test suite does not replace endpoint-specific validation on controlled Windows systems.

---

## 11. Repository structure

```text
RANDAR/
├── jocky/
│   ├── agent/          # Remote endpoint agent
│   ├── analysis/       # Evidence-driven analysis rules and registries
│   ├── api/            # FastAPI API, auth, jobs, catalog and bytecode routes
│   ├── collectors/     # Controlled endpoint/network evidence collectors
│   ├── language/       # JOCKY lexer, parser, IR, interpreter and bytecode
│   ├── reports/        # Report model, builders, HTML/JSON/encryption
│   └── storage/        # SQLite case and audit persistence
├── frontend/
│   └── src/
│       ├── components/
│       ├── pages/
│       └── api/
├── docs/
├── examples/
├── tests/
├── sample_evidence/
├── network_evidence/
├── start.py
├── start.ps1
├── start.sh
└── requirements.txt
```

The Python package retains the `jocky/` directory name because JOCKY is the language/runtime component of the RANDAR product.

---

## 12. Documentation map

| Document | Purpose |
|---|---|
| [`docs/SIH_2026_TECHNICAL_BRIEF.md`](docs/SIH_2026_TECHNICAL_BRIEF.md) | Judge-facing technical summary and SIH problem alignment |
| [`docs/PRODUCT_GUIDE.md`](docs/PRODUCT_GUIDE.md) | Product behavior and investigator workflow |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component architecture and data flow |
| [`docs/DFIR_CAPABILITIES.md`](docs/DFIR_CAPABILITIES.md) | Complete collector/rule capability reference |
| [`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md) | JOCKY syntax, semantics and execution boundaries |
| [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) | Security controls, trust boundaries and protected reporting |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Setup, configuration and operational deployment |
| [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | Developer map and extension workflow |
| [`docs/DEMO_PLAYBOOK.md`](docs/DEMO_PLAYBOOK.md) | Repeatable SIH demonstration flow |
| `CHANGELOG.md` | Release history |
| `docs/V1_*_RELEASE.md` | Historical release notes |

---

## 13. Current boundaries

RANDAR is a **forensic triage and investigation platform**, not a complete enterprise EDR, SIEM, memory-forensics suite, malware sandbox, or courtroom-certified acquisition system.

Important current boundaries:

- Windows memory analysis is metadata-oriented; arbitrary process-memory contents are not collected.
- Network evidence analysis depends on the supplied/ingested normalized evidence surfaces; it is not a full packet-analysis engine.
- PE analysis is bounded static metadata extraction, not full reverse engineering.
- Signature metadata is evidence, not a trust verdict.
- Some endpoint evidence requires elevated privileges.
- Remote-agent state includes bounded in-memory job state; agent registration is persisted, while transient jobs are not intended as a durable queue.
- The DSL is intentionally constrained rather than being a general-purpose programming language.
- Findings are investigative indicators and require contextual validation.
- The prototype is not a replacement for enterprise-grade chain-of-custody acquisition, centralized key management, or large-scale distributed case storage.

These limitations are explicit by design so the implemented system can be distinguished from future extensions.

---

## 14. Responsible use

RANDAR is intended for authorized digital forensics, incident response, defensive security research, education and controlled laboratory environments.

Only investigate systems and data for which appropriate authorization exists. The platform should not be used to bypass security controls, obtain unauthorized access, or interfere with other systems.

---

## 15. Project status

**RANDAR v1.9.2** represents a working end-to-end SIH 2026 prototype with:

- a purpose-built Forensics-as-Code language;
- controlled evidence collection;
- deterministic analysis;
- network threat-hunting capabilities;
- Windows telemetry;
- PE/module/injection-oriented forensics;
- signed bytecode;
- local and remote execution paths;
- case persistence;
- audit and integrity metadata;
- protected reporting;
- and a dedicated web investigation console.

The architecture is intentionally modular: new collectors, rules, report outputs and UI capabilities can be added through explicit extension points without converting the DSL into unrestricted system execution.

---

## License

No open-source license is declared in this repository. Unless a license file is added, treat the source as **all rights reserved** and obtain permission before redistribution or incorporation into another product.
