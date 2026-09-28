# JOCKY Architecture

## 1. System view

```text
                         ┌─────────────────────┐
                         │    Web Console       │
                         │ React + Vite         │
                         └──────────┬──────────┘
                                    │ HTTP/JSON
                                    ▼
                         ┌─────────────────────┐
                         │     FastAPI API      │
                         │ auth / cases / jobs  │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┴────────────────┐
                    ▼                                ▼
          ┌─────────────────┐              ┌─────────────────┐
          │ Language Engine │              │ Remote Agent    │
          │ lexer/parser/IR │              │ poll + execute  │
          └────────┬────────┘              └────────┬────────┘
                   │                                │
                   └──────────────┬─────────────────┘
                                  ▼
                       ┌────────────────────┐
                       │    Interpreter     │
                       │ allowlisted calls  │
                       └─────────┬──────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌────────────┐     ┌────────────┐     ┌─────────────┐
       │ Collectors │     │   Rules    │     │  Bytecode   │
       │ endpoint   │     │ evidence→ │     │ signed IR   │
       │ evidence   │     │ findings   │     │ execution   │
       └──────┬─────┘     └─────┬──────┘     └─────────────┘
              │                 │
              └────────┬────────┘
                       ▼
                ┌──────────────┐
                │ Report model │
                └──────┬───────┘
                       ▼
             ┌─────────────────────┐
             │ SQLite / HTML / ENC │
             └─────────────────────┘
```

---

## 2. Frontend

Location: `frontend/src/`

Technology:

- React
- React Router
- Vite
- Plain CSS

Major pages include:

- Dashboard
- Investigations
- New Investigation
- Investigation Detail
- Endpoint Agents
- Bytecode
- DLL / Injection
- Report Encryption

The frontend obtains capability metadata from `GET /api/catalog` rather than maintaining an independent hard-coded list of collectors and rules.

This reduces drift between the engine and the console.

---

## 3. API layer

Location: `jocky/api/`

The FastAPI layer provides:

- authentication
- investigation execution
- validation
- IR inspection
- investigation CRUD
- statistics
- report generation
- report encryption
- key registration
- bytecode operations
- remote-agent operations

The public router intentionally exposes only `/api/health`. Protected application routes use a router-level bearer-token dependency.

---

## 4. Language engine

Location: `jocky/language/`

### Lexer

`lexer.py` converts source text to tokens.

### Parser

`parser.py` implements the grammar and creates the IR.

### IR

`ir.py` contains the intermediate representation used by the interpreter and bytecode path.

### Interpreter

`interpreter.py` evaluates commands against the registered collectors and rules.

### Bytecode

`bytecode.py` serializes a controlled command representation, signs it, verifies it, and reconstructs the same IR before execution.

---

## 5. Collector architecture

Location: `jocky/collectors/`

Every collector is an explicit function registered in `collectors/registry.py`.

The registry is a security boundary:

```text
JOCKY script
    │
    │ collect modules;
    ▼
registry lookup
    │
    ├── known → invoke collector
    └── unknown → reject
```

Collectors should be:

- read-only
- bounded
- deterministic where practical
- explicit about unsupported platforms
- tolerant of per-field access failures
- serializable to JSON-compatible data

---

## 6. Analysis architecture

Location: `jocky/analysis/`

Rules are intended to be pure evidence-in/finding-out functions.

```text
collector results
       │
       ▼
 evidence dictionary
       │
       ▼
 analysis rule
       │
       ▼
 list[Finding]
```

This separation means an analysis rule does not need to open a socket, inspect a process directly, or invoke a shell command.

---

## 7. Windows advanced telemetry

### Modules

`modules.py` uses process memory-map metadata exposed by `psutil`. It bounds process/module enumeration and hashes only selected user-writable modules within configured limits.

### Threads

`threads.py` enumerates process threads and, on Windows, uses a native read-only query for thread start-address metadata.

### Memory regions

`memory_regions.py` uses `VirtualQueryEx` to obtain virtual-memory region metadata. It does not call `ReadProcessMemory` and does not modify memory.

### Injection rules

`injection_rules.py` correlates those evidence sources. The rules intentionally use cautious language because a single indicator can have legitimate explanations.

---

## 8. Persistence

Location: `jocky/storage/database.py`

SQLite stores one investigation row per case.

The complete report is stored as JSON. Case metadata is kept in separate columns.

This distinction is intentional:

```text
Immutable evidence/report JSON
          │
          ├── never changed by case editing
          │
Editable case metadata
          ├── display name
          ├── status
          └── analyst notes
```

The database uses WAL mode and additive migrations.

---

## 9. Reporting

Location: `jocky/reports/`

The report pipeline is split into:

- report model
- report builder
- JSON serialization
- HTML rendering
- encryption

The source script hash is included in the report model, allowing the analyst to connect the result to the exact source definition used to produce it.

---

## 10. Remote agent architecture

The agent is intentionally simple:

```text
Endpoint Agent
     │
     │ GET pending job
     ▼
Central API
     │
     │ job
     ▼
Agent executes locally
     │
     ├── lex
     ├── parse
     ├── interpret
     └── collect/analyze
     │
     ▼
POST result
```

The agent does not receive a separate privileged command language. It receives JOCKY source and executes it through the same engine.

---

## 11. Extension workflow

To add a collector:

1. Create `jocky/collectors/<name>.py`.
2. Keep it read-only and bounded.
3. Return JSON-compatible data.
4. Register it in `collectors/registry.py`.
5. Add a catalog description in `api/catalog.py`.
6. Add tests.

To add a rule:

1. Create or extend an analysis module.
2. Make the rule consume evidence rather than directly collecting new data.
3. Register it in `analysis/registry.py`.
4. Add catalog metadata.
5. Add regression tests.

The console automatically receives the registered capability through the catalog endpoint.
