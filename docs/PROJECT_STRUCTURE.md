# RANDAR Project Structure

## Root

```text
RANDAR/
├── jocky/
├── frontend/
├── docs/
├── examples/
├── tests/
├── sample_evidence/
├── network_evidence/
├── start.py
├── start.ps1
├── start.sh
├── requirements.txt
└── README.md
```

The repository's Python package is named `jocky/` because JOCKY is the investigation language/runtime inside the RANDAR product.

---

## Backend

### `jocky/language/`

Core Forensics-as-Code engine.

| File | Responsibility |
|---|---|
| `lexer.py` | Source tokenization |
| `parser.py` | Recursive-descent parsing |
| `ir.py` | Typed intermediate representation |
| `interpreter.py` | Controlled execution |
| `bytecode.py` | Compilation and verification |

### `jocky/collectors/`

Evidence acquisition.

Current registered surfaces:

```text
system_info
processes
network_connections
network_artifacts
windows_event_logs
sysmon_events
services
pe_metadata
logged_in_users
file_hash
scheduled_tasks
startup_items
open_files
local_users
modules
threads
memory_regions
```

### `jocky/analysis/`

Evidence-driven analysis.

Important modules:

- `rules.py`
- `rules_extended.py`
- `network_hunting.py`
- `windows_telemetry.py`
- `injection_rules.py`
- `pe_rules.py`
- `finding.py`
- `registry.py`

### `jocky/api/`

FastAPI application.

Includes:

- authentication;
- investigation routes;
- asynchronous investigation jobs;
- catalog;
- bytecode endpoints;
- agent endpoints;
- key registration;
- report download;
- audit endpoints.

### `jocky/reports/`

Report construction and export.

Includes:

- report model;
- builder;
- HTML writer;
- JSON writer;
- encryption;
- integrity hashing.

### `jocky/storage/`

SQLite persistence and network evidence source handling.

### `jocky/agent/`

Remote endpoint execution agent.

---

## Frontend

```text
frontend/src/
├── components/
├── pages/
├── api/
├── App.jsx
├── hooks.js
├── lib.js
└── index.css
```

Current pages include:

- Dashboard;
- Investigations;
- New Investigation;
- Investigation Detail;
- Search;
- Agents;
- Network Evidence;
- Injection Analysis;
- Windows Telemetry;
- Bytecode;
- Keys;
- Sign In.

---

## Adding a collector

1. create a module under `jocky/collectors/`;
2. implement a bounded collector function;
3. return a predictable dictionary schema;
4. explicitly handle unsupported platforms;
5. register the collector in `registry.py`;
6. add catalog description;
7. add tests;
8. document the evidence schema.

Example contract:

```python
def collect_example() -> dict:
    return {
        "supported": True,
        "items": [],
        "count": 0,
        "truncated": False,
    }
```

---

## Adding an analysis rule

1. implement the rule in the appropriate analysis module;
2. accept collected evidence;
3. return `list[Finding]`;
4. avoid side effects;
5. register the rule;
6. add catalog metadata;
7. add evidence-reference mapping if the report builder needs it;
8. add tests;
9. document interpretation and false-positive considerations.

---

## Adding a frontend capability

1. expose the data through an authenticated API route;
2. update the API client;
3. add the page/component;
4. consume `/api/catalog` when listing capabilities;
5. support loading/error/cancellation states;
6. preserve existing investigation behavior.

---

## Architectural rules for contributors

Do not introduce:

- arbitrary command execution into JOCKY;
- unrestricted file paths selected by scripts;
- process-memory modification;
- hidden collectors;
- analysis rules with endpoint side effects;
- unbounded collection loops;
- secrets in source code;
- capability names that are not registered.

---

## Verification

The current repository regression baseline is:

```text
91 passed
```

Run:

```bash
pytest -q
```
