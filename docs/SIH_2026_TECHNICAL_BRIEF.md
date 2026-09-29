# RANDAR — SIH 2026 Technical Brief

**Team:** AVINYA  
**Problem Statement:** SIH26148  
**Category:** Software  
**Theme:** Cryptocurrency & Cybersecurity  
**Implementation baseline:** RANDAR v1.9.2

---

## 1. Problem interpretation

The SIH problem asks for scripts/functions using a new programming language to commence computer and network forensic analysis without triggering security solutions.

RANDAR interprets this as a need for a **controlled forensic execution layer** rather than an unrestricted mechanism for evading security products.

The implementation therefore focuses on:

- read-only acquisition;
- allowlisted forensic capabilities;
- deterministic analysis;
- low-impact endpoint interaction;
- bounded execution;
- script validation before execution;
- provenance and integrity;
- reusable investigation definitions.

RANDAR does not disable AV/EDR, tamper with security controls, or provide arbitrary process manipulation.

---

## 2. Technical proposition

RANDAR turns a forensic investigation into an executable artifact.

```text
JOCKY Script
     │
     ▼
Lex / Parse
     │
     ▼
Typed IR
     │
     ├──────────────► Validation / IR inspection
     │
     ▼
Interpreter or signed bytecode
     │
     ▼
Allowlisted collectors
     │
     ▼
Normalized evidence
     │
     ▼
Deterministic rules
     │
     ▼
Findings + evidence references
     │
     ├────────────► Web console
     └────────────► Protected reports
```

This separates **what the investigator wants to examine** from **how the operating system is queried**, while retaining a controlled implementation boundary.

---

## 3. Implemented engineering surface

### Language

JOCKY currently supports:

- investigation blocks;
- collection commands;
- analysis commands;
- report declarations;
- variables;
- conditional branches;
- boolean conditions;
- evidence-property references;
- bounded analyst-authored rules;
- IR inspection;
- signed bytecode.

### Evidence

The live registry exposes **17 collectors** covering:

- host/process state;
- active network connections;
- normalized network evidence;
- users and accounts;
- persistence surfaces;
- open files;
- Windows modules;
- Windows threads;
- Windows virtual-memory metadata;
- Windows Event Logs;
- Sysmon events;
- Windows services;
- PE metadata;
- controlled file hashing.

### Analysis

The live registry exposes **40 rules** spanning:

- endpoint triage;
- persistence;
- PowerShell telemetry;
- network threat hunting;
- DNS analysis;
- beaconing;
- scan patterns;
- service discovery;
- module loading;
- DLL sideloading;
- process-hollowing indicators;
- reflective-loading indicators;
- thread-hijacking indicators;
- PE imports/entropy/signature metadata;
- module/disk correlation.

---

## 4. Why the architecture matters

### Reproducibility

The investigation logic exists as source code or signed bytecode instead of being lost in a sequence of interactive commands.

### Reviewability

A reviewer can validate the script, inspect its IR, and see exactly which registered capabilities it references.

### Controlled execution

The interpreter resolves names through explicit registries. The language cannot directly call arbitrary operating-system functionality.

### Extensibility

Collectors and analysis rules are separate modules. A new evidence source does not require redesigning the language runtime.

### Evidence context

Findings retain links back to the evidence domain that produced them, while reports carry execution and integrity metadata.

---

## 5. Security boundary

The project deliberately avoids an offensive execution model.

**Implemented:**
- read-only collection;
- bounded Windows metadata queries;
- allowlisted capabilities;
- authenticated API;
- hashed bearer-token storage;
- signed bytecode;
- bounded job execution;
- encrypted report export;
- report integrity verification.

**Not implemented as an execution capability:**
- arbitrary shell execution;
- PowerShell execution from JOCKY;
- process-memory writes;
- remote-thread creation;
- DLL injection;
- security-product disabling;
- stealth/persistence mechanisms.

The distinction is important for both safety and architectural clarity.

---

## 6. Forensic interpretation

RANDAR uses language such as:

> **indicator**, **review lead**, **correlation**, **requires contextual validation**

rather than automatically declaring that an endpoint is compromised.

For example:

```text
private executable memory
        +
thread start address in private executable memory
        +
loaded-module context
        ↓
injection correlation finding
        ↓
analyst review
```

This reflects the reality that many telemetry patterns have legitimate explanations.

---

## 7. Integrity and reporting

The reporting pipeline records:

- execution timestamps;
- endpoint identity;
- collector status;
- record counts;
- truncation;
- resource accounting;
- evidence hashes;
- finding identifiers;
- evidence references;
- source-script hash;
- bytecode hash when applicable;
- report hash;
- execution status;
- termination reason;
- bounded event timeline.

Encrypted export uses AES-256-GCM with RSA-OAEP/SHA-256 key wrapping.

---

## 8. Remote execution

The remote-agent subsystem provides:

- registration;
- per-agent authentication;
- capability reporting;
- polling;
- heartbeats;
- bounded jobs;
- expiry;
- cancellation;
- revocation;
- result submission/import.

The agent executes through the same JOCKY investigation pipeline rather than introducing a separate unrestricted command channel.

---

## 9. Web investigation experience

The frontend provides dedicated investigation workflows for:

- dashboard and case statistics;
- investigation creation;
- investigation details and evidence pagination;
- global search;
- network evidence;
- Windows telemetry;
- injection analysis;
- JOCKY bytecode;
- remote agents;
- investigator keys;
- sign-in/authentication.

The frontend obtains capability information from the backend catalog, reducing the risk of the UI advertising unsupported operations.

---

## 10. Validation status

The repository's regression suite was executed for the v1.9.2 documentation baseline:

**91 tests passed.**

This confirms the current automated regression baseline. It does not replace controlled endpoint validation, especially for Windows-specific evidence collection.

---

## 11. Current technical boundaries

RANDAR v1.9.2 should be described as a **forensic triage and investigation platform**.

It is not currently:

- a full EDR;
- a full SIEM;
- a complete memory-forensics framework;
- a packet-analysis replacement;
- a malware sandbox;
- a general-purpose reverse-engineering suite;
- a certified forensic acquisition appliance.

Those boundaries do not reduce the architectural value of the current prototype; they define its implemented scope.

---

## 12. Extension model

The platform can evolve by adding:

```text
New evidence source
       │
       ▼
Collector implementation
       │
       ▼
Collector registry
       │
       ▼
Evidence schema
       │
       ▼
Analysis rule(s)
       │
       ▼
Capability catalog
       │
       ▼
JOCKY script support
       │
       ▼
Frontend presentation
```

The language itself remains intentionally constrained while the evidence and analysis ecosystem grows around it.

---

## 13. SIH demonstration message

The strongest technical demonstration is not a claim that RANDAR bypasses security products.

It is:

> **RANDAR converts forensic investigation logic into a controlled, reproducible and auditable execution artifact, allowing analysts to compose endpoint and network investigations without giving the scripting layer unrestricted system access.**

That is the core engineering proposition demonstrated by the v1.9.2 implementation.
