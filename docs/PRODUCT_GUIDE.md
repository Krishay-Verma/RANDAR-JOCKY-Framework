# RANDAR Product Guide

## 1. Executive overview

RANDAR is a **Forensics-as-Code platform** for computer and network forensic triage.

The product combines:

1. JOCKY, a constrained investigation language;
2. a validation and execution engine;
3. 17 registered evidence collectors;
4. 40 registered analysis rules;
5. a SQLite-backed case layer;
6. evidence/report integrity metadata;
7. protected report export;
8. a remote-agent architecture;
9. a React/Vite forensic console.

The central design idea is simple:

> **The investigation itself becomes a reusable technical artifact.**

---

## 2. The investigation lifecycle

```text
Define
  ↓
Validate
  ↓
Inspect
  ↓
Execute
  ↓
Collect
  ↓
Analyze
  ↓
Correlate
  ↓
Persist
  ↓
Report
```

An analyst can therefore move from an investigation idea to a repeatable workflow without writing unrestricted operating-system commands.

---

## 3. What makes RANDAR different

### 3.1 The investigation is executable documentation

A JOCKY script communicates intent:

```text
collect processes;
collect network_connections;
analyze process_network_correlation;
report "endpoint_network_review";
```

The script can be reviewed before execution and stored with the resulting case.

### 3.2 Capabilities are allowlisted

The engine resolves collectors and analysis rules from explicit registries.

This gives the platform a strong capability boundary:

```text
JOCKY identifier
      │
      ▼
registry lookup
      │
   ┌──┴──┐
 known  unknown
   │       │
 execute  reject
```

### 3.3 Collection and analysis are separated

Collectors produce evidence.

Analysis rules consume evidence.

This separation makes rules easier to test and prevents the analysis layer from becoming an unrestricted endpoint-access layer.

### 3.4 Local and remote execution share the same model

Remote jobs dispatch a JOCKY investigation to an authorized agent. The agent uses the same collector/analysis architecture rather than exposing a separate shell.

---

## 4. What happens when an investigation runs

### Step 1 — Script submission

The API receives a JOCKY script.

### Step 2 — Lexing

The lexer converts source text into bounded tokens and rejects unsupported syntax.

### Step 3 — Parsing

The recursive-descent parser converts tokens into a typed intermediate representation.

### Step 4 — Validation

Collector names, rule names, evidence properties, variables, conditions and language limits are checked.

### Step 5 — Interpreter execution

Commands execute sequentially with runtime, collector and cancellation controls.

### Step 6 — Evidence collection

Registered collectors query their defined evidence surface.

### Step 7 — Analysis

Registered rules consume collected evidence and emit findings.

### Step 8 — Report construction

The report builder assigns deterministic finding IDs, evidence references, collector hashes, timeline entries and execution metadata.

### Step 9 — Persistence

The case and report are stored in SQLite.

### Step 10 — Presentation/export

The console displays the investigation, while JSON/HTML/encrypted exports provide external artifacts.

---

## 5. Windows advanced forensics

The Windows-specific layer combines:

```text
Modules ─────┐
Threads ─────┼──► Injection correlation
Memory ──────┤
PE metadata ─┘
```

The implementation is metadata-oriented.

It can identify review leads involving:

- user-writable module locations;
- DLL path anomalies;
- private executable memory;
- thread start addresses;
- PE imports;
- high entropy;
- signature metadata;
- module/disk hash mismatch;
- writable/executable PE characteristics.

It does not modify the target process.

---

## 6. Network investigation

RANDAR can analyze normalized network evidence for:

- DNS anomalies;
- entropy;
- rare domains;
- suspicious TLD patterns;
- DNS bursts;
- unusual query types;
- long/random labels;
- DNS tunnelling indicators;
- DNS beaconing;
- network beaconing;
- port scans;
- horizontal scans;
- service discovery;
- UDP scan indicators;
- address classification;
- process/network correlation.

Network evidence is bounded and normalized. RANDAR should not be represented as a full replacement for dedicated packet-analysis platforms.

---

## 7. Reporting model

A report has four major layers:

```text
Case metadata
     +
Execution metadata
     +
Evidence
     +
Findings
```

Findings additionally carry:

- severity;
- summary;
- reason;
- related evidence;
- evidence references;
- limitations;
- next-check guidance.

---

## 8. Analyst workflow

A recommended workflow is:

1. define the investigation;
2. validate it;
3. inspect the IR;
4. execute against an authorized endpoint/evidence set;
5. review collector coverage and truncation;
6. review findings;
7. pivot into supporting evidence;
8. verify report integrity;
9. export/share the appropriate report artifact.

---

## 9. Who the platform is for

### DFIR analysts

For repeatable triage and evidence-driven investigation workflows.

### Security engineers

For controlled endpoint telemetry and analysis prototyping.

### Researchers and students

For understanding the relationship between a domain-specific language, execution engine and forensic evidence.

### SIH evaluators

For assessing whether the project demonstrates a coherent implementation rather than only a presentation concept.

---

## 10. Product boundaries

RANDAR intentionally does not promise:

- definitive malware classification;
- arbitrary memory acquisition;
- unrestricted command execution;
- complete enterprise-scale case management;
- certified chain-of-custody acquisition.

The platform's strength is the controlled investigation workflow and the architecture around it.
