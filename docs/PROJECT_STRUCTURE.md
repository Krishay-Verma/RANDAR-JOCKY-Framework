# JOCKY Project Structure

## Root

| Path | Responsibility |
|---|---|
| `start.py` | Cross-platform environment/setup/launch orchestration. |
| `start.ps1` | Windows launcher wrapper. |
| `start.sh` | Unix launcher wrapper. |
| `requirements.txt` | Python runtime dependencies. |
| `.env.example` | Environment configuration template. |
| `tests/` | Regression and security-boundary tests. |
| `sample_evidence/` | Controlled sample data for hashing/demo workflows. |
| `docs/` | Product, architecture, DFIR and operational documentation. |

## Backend

### `jocky/language/`

| File | Responsibility |
|---|---|
| `lexer.py` | Source-to-token conversion. |
| `parser.py` | Grammar validation and IR construction. |
| `ir.py` | Investigation command dataclasses. |
| `interpreter.py` | Executes IR against allowlisted capabilities. |
| `bytecode.py` | Signed bytecode serialization/verification/execution. |

### `jocky/collectors/`

Each module provides a bounded evidence collector. `registry.py` is the explicit capability registry.

### `jocky/analysis/`

Each module provides evidence-driven rules. `registry.py` is the explicit rule registry.

### `jocky/api/`

FastAPI routes, authentication, catalog, remote-agent APIs, key management and report operations.

### `jocky/reports/`

Structured report model, report builder, HTML renderer, JSON output and encryption.

### `jocky/storage/`

SQLite schema, persistence, case metadata and dashboard aggregation.

### `jocky/agent/`

Remote endpoint polling and job execution.

## Frontend

`frontend/src/` contains the React console.

Important areas:

- `pages/` — route-level views
- `components/` — reusable UI components
- `api/` — HTTP/token client helpers
- `lib.js` — templates/catalog-related helpers
- `index.css` — console design system

Public branding assets live under `frontend/public/`.

---

## Adding a new collector

```text
1. create collector module
2. implement bounded read-only collection
3. register collector
4. add catalog description
5. add evidence property if needed
6. add tests
7. update DFIR capability documentation
```

## Adding a new analysis rule

```text
1. implement evidence → Finding rule
2. register rule
3. add catalog metadata
4. add tests
5. add interpretation documentation
```

## Adding a frontend capability

The preferred approach is to consume the live `/api/catalog` instead of duplicating backend capability definitions in the UI.
