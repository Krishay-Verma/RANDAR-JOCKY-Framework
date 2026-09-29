# RANDAR Architecture

## 1. System view

```text
┌─────────────────────────────────────────────────────────────┐
│                     RANDAR Web Console                      │
│ React + Vite                                                │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP/JSON + Bearer auth
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                         FastAPI API                         │
│ Auth · Investigations · Jobs · Catalog · Reports · Agents  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       JOCKY Engine                          │
│ Lexer → Parser → IR → Interpreter                          │
│                    ↘ signed bytecode                        │
└───────────────┬───────────────────────┬─────────────────────┘
                │                       │
                ▼                       ▼
       ┌────────────────┐      ┌────────────────────┐
       │  Collectors    │      │  Analysis Rules    │
       │  17 registered │      │  40 registered     │
       └───────┬────────┘      └──────────┬─────────┘
               │                          │
               └──────────┬───────────────┘
                          ▼
                  ┌───────────────┐
                  │ Report Builder│
                  │ + Integrity   │
                  └───────┬───────┘
                          ▼
                 ┌─────────────────┐
                 │ SQLite / Reports│
                 └─────────────────┘
```

---

## 2. Frontend

The frontend is a React/Vite application.

Current routes/pages include:

- sign-in;
- dashboard;
- investigations;
- new investigation;
- investigation detail;
- search;
- agents;
- network evidence;
- injection analysis;
- Windows telemetry;
- bytecode;
- investigator keys.

The frontend calls the backend through a centralized API client and receives the current collector/rule catalog from the backend.

---

## 3. API layer

The API is implemented with FastAPI.

Major route families:

```text
/api/health
/api/investigations/*
/api/validate
/api/compile
/api/catalog
/api/stats
/api/search
/api/keys/*
/api/network-sources/*
/api/agents/*
/api/bytecode/*
/api/audit
```

All protected operations use the bearer-token authentication dependency.

---

## 4. Authentication

The API uses a single-operator bearer token model.

The server stores only the SHA-256 digest of the token.

Verification uses constant-time digest comparison.

The launcher generates a token on first setup and writes only its digest to configuration.

This is appropriate for the current prototype but should be replaced with a stronger identity/authorization model for multi-operator production deployment.

---

## 5. Language engine

### Lexer

`jocky/language/lexer.py`

Responsibilities:

- tokenize JOCKY source;
- enforce lexical limits;
- reject unsupported characters;
- distinguish reserved words;
- handle comments;
- parse bounded integer literals.

### Parser

`jocky/language/parser.py`

Responsibilities:

- recursive-descent grammar;
- statement parsing;
- expression parsing;
- boolean condition trees;
- nested `if` blocks;
- analyst-authored rules.

### IR

`jocky/language/ir.py`

The IR uses dataclasses for:

- literals;
- variables;
- property access;
- conditions;
- collect commands;
- analysis commands;
- report commands;
- variable declarations;
- conditionals;
- analyst-authored rules.

The IR is the common representation used by the interpreter and bytecode path.

---

## 6. Interpreter

`jocky/language/interpreter.py`

The interpreter:

1. validates capability references;
2. evaluates variables and conditions;
3. dispatches collectors;
4. dispatches analysis rules;
5. tracks progress;
6. enforces runtime limits;
7. supports cancellation;
8. records collector status and resource information.

Collector calls execute through bounded worker threads so a stuck collector can be recorded as timed out without blocking the API process indefinitely.

---

## 7. Bytecode

`jocky/language/bytecode.py`

Bytecode contains a length-delimited header and body plus an HMAC-SHA256 signature.

The verifier checks:

- minimum structure;
- signature;
- magic value;
- format version;
- command count;
- opcode shape;
- collector/rule existence;
- condition structure;
- variable structure;
- branch bounds.

This is a **tamper-evident serialization of the investigation model**, not a general-purpose virtual machine.

---

## 8. Collector architecture

Collectors are explicitly registered in:

```text
jocky/collectors/registry.py
```

This registry is the execution boundary.

A collector receives no arbitrary JOCKY arguments. Operator configuration is kept outside the script where required, such as the fixed evidence directory used by `file_hash`.

This prevents the DSL from turning a controlled collector into an unrestricted file or command interface.

---

## 9. Analysis architecture

Analysis rules are explicitly registered in:

```text
jocky/analysis/registry.py
```

The intended contract is:

```text
evidence dictionary
       ↓
pure/bounded rule function
       ↓
list[Finding]
```

Rules do not execute binaries or modify processes.

---

## 10. Windows telemetry

The advanced Windows path is divided into independent evidence surfaces:

```text
processes
   │
   ├── modules
   ├── threads
   ├── memory_regions
   └── pe_metadata
            │
            ▼
       PE/injection rules
```

This makes the final finding a correlation of evidence rather than a single heuristic.

---

## 11. Network evidence

`network_artifacts` normalizes supported DNS/connection evidence.

The analysis layer can then evaluate patterns such as:

- entropy;
- rare domains;
- bursts;
- beaconing;
- scans;
- service discovery.

The collector deliberately does not retain arbitrary packet payloads.

---

## 12. Persistence

The case store uses SQLite.

Stored case information includes:

- investigation metadata;
- report JSON;
- status;
- notes;
- finding/severity summaries;
- timestamps;
- integrity metadata.

Evidence is stored inside the report structure rather than as a separate unrestricted blob store.

The audit layer maintains append-oriented audit events containing:

- timestamp;
- operator identity;
- action;
- investigation context;
- script hash;
- result/report hash;
- action details.

---

## 13. Report construction

`jocky/reports/builder.py` is the boundary between investigation results and the report model.

It adds:

- deterministic finding IDs;
- evidence references;
- collector evidence hashes;
- timeline events;
- source metadata;
- script/bytecode hashes;
- execution metadata;
- resource accounting.

This keeps report assembly separate from collection and analysis.

---

## 14. Report protection

`jocky/reports/encryptor.py` implements:

```text
random AES-256 key
        ↓
AES-256-GCM report encryption
        ↓
RSA-OAEP/SHA-256 wrapping
        ↓
encrypted report blob
```

The current server-side key store keeps the active investigator public key in process memory.

A production deployment should use an external key-management solution and explicit operator identity.

---

## 15. Remote agent

The agent communicates through the API using polling.

Core state:

```text
registered
    ↓
pending job
    ↓
claimed/running
    ├── complete
    ├── failed
    └── cancelled
```

The implementation provides:

- token hashing;
- registration;
- revocation;
- capability reporting;
- heartbeat;
- job signatures;
- nonce/expiry;
- bounded job count;
- cancellation.

The agent executes the same JOCKY pipeline as local execution.

---

## 16. Extension workflow

### New collector

1. implement collector;
2. keep collection bounded;
3. define unsupported-platform behavior;
4. register it;
5. add catalog metadata;
6. add tests;
7. document evidence schema.

### New rule

1. implement evidence-in/finding-out rule;
2. avoid side effects;
3. register it;
4. add catalog metadata;
5. add report evidence mapping where needed;
6. add regression tests;
7. document interpretation and limitations.

### New frontend capability

1. expose backend data through an authenticated route;
2. add API client support;
3. add the page/component;
4. use the live capability catalog where applicable;
5. preserve loading/error/cancellation behavior.

---

## 17. Architectural invariants

Future changes should preserve:

- no arbitrary JOCKY command execution;
- explicit collector/rule registration;
- bounded collection;
- read-only Windows advanced telemetry;
- common IR between source and bytecode;
- authenticated API routes;
- evidence-driven analysis;
- report integrity metadata;
- clear separation between evidence and conclusions.
