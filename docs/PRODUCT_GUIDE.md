# JOCKY Product Guide

## 1. Executive overview

JOCKY is a **Forensics-as-Code** platform. Its central idea is simple: an investigation should be expressible as a small, readable program whose execution can be validated, reproduced, inspected, secured, stored, and reported.

Instead of asking an analyst to remember a collection of commands for processes, network sockets, persistence, users, files, DLLs, threads, and memory metadata, JOCKY provides a single investigation language and a controlled execution engine.

A JOCKY investigation has five conceptual stages:

```text
DESCRIBE → COLLECT → CORRELATE → EXPLAIN → REPORT
```

The source script is the investigation plan. Collectors produce endpoint evidence. Analysis rules correlate evidence into observations. The case layer preserves the result. Reporting turns the case into an analyst-readable artifact.

---

## 2. The problem JOCKY addresses

The SIH 2026 problem statement supplied for this project is:

> **Creation of scripts/functions with new programming language to commence Computer & Network forensic analysis without triggering security solutions**

The engineering interpretation adopted by JOCKY is **controlled, low-impact forensic acquisition and analysis**.

JOCKY does not interpret this requirement as permission to bypass or disable security products. Instead, it minimizes endpoint modification by using read-only collectors, bounded operations, explicit capability allowlists, and a DSL that cannot execute arbitrary operating-system commands.

This distinction matters because a forensic platform should preserve evidence and maintain a predictable execution boundary.

---

## 3. What makes JOCKY different

### 3.1 The investigation is executable documentation

A JOCKY script describes exactly what the analyst intended to collect and analyze.

That gives a case a natural provenance chain:

```text
Investigation name
      ↓
Source script
      ↓
SHA-256 script hash
      ↓
Parsed IR
      ↓
Collectors + rules
      ↓
Evidence
      ↓
Findings
      ↓
Report
```

### 3.2 Capabilities are allowlisted

The interpreter does not dynamically discover Python functions from a script. Collector and rule names are resolved against explicit registries.

Adding capability therefore requires an intentional code change and registry entry.

### 3.3 Collection is separate from analysis

A collector should answer:

> “What did the endpoint report?”

A rule should answer:

> “What pattern in that evidence deserves attention?”

Keeping those responsibilities separate makes the system easier to test and reduces accidental coupling.

### 3.4 The platform supports local and remote execution

The same investigation language can be executed locally or through a JOCKY endpoint agent. The agent does not introduce a separate execution language; it uses the same lexer/parser/interpreter pipeline.

---

## 4. What happens when an investigation runs

### Step 1 — Script submission

The console sends the script to the API.

### Step 2 — Lexing

The lexer converts the source text into tokens. Invalid characters or malformed lexical constructs stop execution before collection begins.

### Step 3 — Parsing

The recursive-descent parser verifies the grammar and creates an IR representation.

### Step 4 — Interpreter execution

The interpreter walks the IR. `collect` commands resolve through the collector registry. `analyze` commands resolve through the rule registry.

### Step 5 — Evidence collection

Each collector returns a bounded structured result. Collector failures are represented explicitly so one failed data source does not automatically discard the rest of the investigation.

### Step 6 — Analysis

Rules consume the accumulated evidence and produce `Finding` objects.

A finding contains:

- rule name
- severity
- summary
- reason
- related evidence

### Step 7 — Report construction

The result is assembled into a structured report. The source script is fingerprinted with SHA-256.

### Step 8 — Persistence

The complete report is stored in SQLite. Analyst-editable metadata such as case name, status, and notes is stored separately.

### Step 9 — Presentation/export

The case becomes available in the console and can be exported as HTML or encrypted report data.

---

## 5. What the Windows injection feature actually means

The Windows injection module is a **forensic detection/correlation capability**, not an injection framework.

It combines three read-only evidence sources:

### Modules

Provides loaded module metadata for processes, including path and bounded SHA-256 hashing of modules in user-writable locations.

### Threads

Provides process-thread metadata and, on Windows, attempts to obtain thread start-address information using read-only operating-system APIs.

### Memory regions

Enumerates virtual-memory region metadata through `VirtualQueryEx`. It does not read arbitrary process-memory contents.

The analysis layer then looks for combinations such as:

```text
User-writable DLL
      +
Unexpected module location
      +
Private executable memory
      +
Thread start inside private executable memory
      ↓
Investigation indicator
```

These patterns can have legitimate causes. Browsers, JIT runtimes, security software, debuggers, and other complex applications can create executable private memory. Therefore JOCKY reports them as leads for investigation rather than declaring a process malicious.

---

## 6. Why bounded collection matters

Forensic tools can accidentally become denial-of-service tools if they enumerate unlimited processes, threads, memory regions, or files.

JOCKY therefore applies explicit limits in sensitive collectors. For example, the Windows telemetry layer bounds the number of processes, threads, modules, and memory regions considered.

The objective is predictable resource usage and graceful degradation, not maximum possible enumeration at any cost.

---

## 7. What JOCKY is capable of today

JOCKY can currently perform:

- Host/system triage
- Process inventory
- Process/network correlation
- Network socket inventory
- Logged-in user/session inventory
- Local account inventory
- Scheduled-task/cron inspection
- Startup/persistence inspection
- Bounded open-file inspection
- Controlled file hashing
- Windows loaded-module inspection
- Windows thread metadata inspection
- Windows virtual-memory metadata inspection
- Injection-related correlation
- Script validation
- IR inspection
- Signed bytecode compilation and verification
- Local investigation persistence
- Remote-agent job dispatch
- HTML reporting
- Encrypted report export

---

## 8. What JOCKY deliberately does not do

JOCKY does not currently provide:

- arbitrary shell execution from the DSL
- arbitrary PowerShell execution from the DSL
- process-memory writing
- DLL injection
- remote-thread creation for injection
- thread suspension/hijacking as an action
- EDR/AV disabling
- security-control bypassing
- full memory-dump acquisition
- a claim of automatic malware attribution

These boundaries are part of the security architecture, not missing documentation.

---

## 9. Who the platform is for

### DFIR analysts

Write repeatable triage investigations and review evidence in one console.

### Security engineers

Add new collectors and analysis rules through explicit modules and registries.

### Researchers/students

Study how a small language can orchestrate forensic acquisition safely.

### SOC/IR teams

Use a shared investigation definition instead of manually reproducing a long list of endpoint commands.

### Evaluators/judges

Observe the complete path from source language to endpoint evidence to analysis to protected report.

---

## 10. Mental model for a new developer

If you are new to the project, remember four rules:

1. **Collectors gather facts.**
2. **Rules interpret facts.**
3. **The DSL chooses which registered capabilities run.**
4. **The report preserves what happened.**

That mental model explains most of the repository.
