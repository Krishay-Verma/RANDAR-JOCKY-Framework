# JOCKY

**Host forensic triage platform built around a purpose-made investigation language.**
Smart India Hackathon 2026, problem statement SIH26148: *scripts and functions in a new programming language for computer and network forensic analysis.*

JOCKY lets an analyst describe an investigation in a small declarative language, executes it through a fixed allowlist of read-only collectors and deterministic analysis rules, stores the resulting evidence, and presents it in a web console. Investigations can run on the local host or be dispatched to remote endpoint agents. Reports can be exported as HTML or encrypted so that only the analyst's private key can open them.

---

## Contents

1. [Capabilities](#capabilities)
2. [Quick start](#quick-start)
3. [The JOCKY language](#the-jocky-language)
4. [Collectors and analysis rules](#collectors-and-analysis-rules)
5. [Web console](#web-console)
6. [Endpoint agents](#endpoint-agents)
7. [Signed bytecode](#signed-bytecode)
8. [Encrypted reports](#encrypted-reports)
9. [API reference](#api-reference)
10. [Configuration](#configuration)
11. [Security model](#security-model)
12. [Architecture](#architecture)
13. [Testing](#testing)
14. [Limitations](#limitations)
15. [Scope](#scope)
16. [Change log](#change-log)

---

## Capabilities

| Area | What it does |
|---|---|
| Language | Lexer, recursive-descent parser, IR and interpreter for the JOCKY DSL, including `let` variables and `if / else` branching on collected evidence. |
| Collection | Nine read-only collectors: system info, processes, network connections, logged-in users, file hashes, scheduled tasks, startup items, open files, local users. Windows and Linux. |
| Analysis | Seven deterministic rules producing findings on a five-level severity scale, each traceable to specific evidence. |
| Case management | Store, search, rename, set status (open / in review / closed), annotate and delete investigations. Collected evidence is immutable; only case metadata is editable. |
| Console | Dashboard, investigation list, script editor with live engine reference, evidence browser, agent management, bytecode workbench, key management. |
| Remote agents | Poll-based agents with per-agent tokens. Dispatch a script, review the result, save it as a stored investigation. |
| Bytecode | Compile scripts to HMAC-SHA256 signed bytecode, disassemble, and execute with signature verification. |
| Reporting | Self-contained HTML report; AES-256-GCM report export with the key wrapped by RSA-OAEP. |
| Operations | One-command installer and launcher (`start.py`), single-port deployment, automatic database migration. |

---

## Quick start

Requirements: **Python 3.10+**. **Node.js 18+** is needed once to build the console (the API runs without it).

```bash
git clone <your repository URL>
cd SIH26148-JOCKY

python start.py          # Windows: .\start.ps1     Linux/macOS: ./start.sh
```

On the first run the launcher will:

1. create a virtual environment and install the Python dependencies,
2. generate `.env` with an API token hash and a bytecode signing key,
3. **print your API token once**: store it in a password manager,
4. install and build the frontend,
5. start the API and console on `http://127.0.0.1:8000` and open your browser.

Sign in with the token. Later runs skip everything that is already done.

| Command | Purpose |
|---|---|
| `python start.py` | Set up if needed and run. |
| `python start.py --new-token` | Issue a new API token (the old one stops working). |
| `python start.py --dev` | Vite dev server with hot reload at `:5173`, API with auto-reload. |
| `python start.py --rebuild` | Force a frontend rebuild. |
| `python start.py --host 127.0.0.1 --port 9000 --no-browser` | Custom bind address and port. |

The console is rebuilt automatically when files under `frontend/src` change.

### Manual installation

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env                                  # then fill in the two secrets
python -c "import secrets,hashlib;t=secrets.token_urlsafe(32);print(t);print(hashlib.sha256(t.encode()).hexdigest())"
python -c "import secrets;print(secrets.token_urlsafe(48))"
uvicorn jocky.api.main:app
cd frontend && npm install && npm run build
```

---

## The JOCKY language

A script describes one investigation. It is never executed as Python: it is tokenised, parsed to an IR of plain dataclasses, and interpreted against fixed registries.

```text
investigation "Adaptive Full Triage" {
    let conn_threshold = 10;

    collect system_info;
    collect processes;
    collect network_connections;
    collect scheduled_tasks;

    // Run the network rule only when the host is unusually chatty.
    if network_connections.count > conn_threshold {
        analyze high_connection_processes;
    } else {
        analyze process_network_correlation;
    }

    analyze suspicious_processes;
    report "adaptive_triage";
}
```

### Grammar

```text
investigation := 'investigation' STRING '{' statement* '}'
statement     := 'collect' IDENT ';'
               | 'analyze' IDENT ';'
               | 'report'  STRING ';'
               | 'let' IDENT '=' expr ';'
               | 'if' expr op expr '{' statement* '}' ('else' '{' statement* '}')?
op            := '>' | '<' | '>=' | '<=' | '==' | '!='
expr          := INTEGER | STRING | 'true' | 'false' | IDENT | IDENT '.' IDENT
```

`//` starts a line comment. Integers only (at most 15 digits). Variable names match `[a-z_][a-z0-9_]*`.

### Evidence properties usable in conditions

`processes.count`, `network_connections.count`, `logged_in_users.count`, `file_hash.count`, `scheduled_tasks.count`, `startup_items.count`, `open_files.count`, `local_users.count`, `system_info.hostname`, `system_info.platform`, `system_info.cpu_count`.

A property of a collector that has not run (or failed) evaluates to `0`, so a condition never crashes an investigation. The live list is served by `GET /api/catalog`.

### Language limits

| Limit | Value |
|---|---|
| Script size | 20,000 characters |
| `if` nesting | 10 levels (enforced by the parser and the interpreter) |
| Variables per investigation | 50 |
| Integer literal length | 15 digits |

Unknown collectors, rules or properties are hard errors. Malformed scripts fail before any collector runs.

---

## Collectors and analysis rules

### Collectors

| Name | Evidence | Notes |
|---|---|---|
| `system_info` | Hostname, OS, version, architecture, CPU count, memory, current user | |
| `processes` | PID, name, executable path, owner, start time | Per-field failures (access denied) yield `null`, not an error. |
| `network_connections` | Protocol, local and remote address and port, state, PID | Needs elevation on some systems to see all sockets. |
| `logged_in_users` | Interactive sessions | |
| `file_hash` | SHA-256, size and mtime of files in the evidence directory | Non-recursive, at most 500 entries, 64 KiB streaming reads, symlinks refused. |
| `scheduled_tasks` | Task Scheduler (Windows) or cron files and user crontab (Linux) | Capped at 500. |
| `startup_items` | Run / RunOnce keys and Startup folders (Windows), systemd units and init.d (Linux) | Registry access is read-only. |
| `open_files` | Open file handles per process | Capped at 50 per process, 2,000 total. |
| `local_users` | `net user` (Windows) or `/etc/passwd` (Linux) | `/etc/shadow` is never read. |

`file_hash` reads only `sample_evidence/` unless the operator sets `JOCKY_EVIDENCE_DIR`. The directory is chosen by the environment, never by a script.

A collector that raises is recorded as an `error` result; the remaining collectors and their evidence are kept.

### Severity scale

`informational` < `review_recommended` < `medium` < `high` < `critical`

Findings are observations for analyst review, not verdicts.

### Rules

| Rule | Severity | Detects |
|---|---|---|
| `missing_paths` | informational | Processes whose executable path cannot be read. |
| `suspicious_processes` | review_recommended | Executables running from temp or download directories. |
| `process_network_correlation` | informational | Processes holding remote connections. |
| `unusual_scheduled_tasks` | high / critical | Tasks running from writable paths, double extensions (`.pdf.exe`), encoded PowerShell. |
| `suspicious_startup_items` | medium / high / critical | Persistence outside system directories, double extensions, encoded PowerShell. |
| `high_connection_processes` | medium / high | Processes with 15 or more connections; remote ports 4444, 4445, 5555, 1337, 31337, 6666, 8888, 9001, 9002. |
| `privileged_user_anomaly` | medium / high | Linux system accounts with interactive shells; Windows processes owned by accounts not in the local user list. |

A rule that throws is isolated: the investigation completes and records an informational finding naming the failed rule.

---

## Web console

Served by the API on the same origin after `npm run build` (no CORS configuration needed).

| Page | Function |
|---|---|
| **Dashboard** | Totals, severity distribution, case status, most-triggered rules, investigated endpoints, recent investigations. |
| **Investigations** | Search, filter by status, sort by recency or severity, edit case metadata, delete with confirmation. |
| **New investigation** | Script editor with line gutter and error-line highlighting, four templates, click-to-insert engine reference generated from the live registries, **Validate** (parse only), **Show IR**, **Run**. |
| **Investigation detail** | Findings filtered by severity with expandable reasoning and raw evidence; evidence browser with filtering and paging per collector; collector status; provenance (script SHA-256, timings, source); analyst notes; HTML and encrypted export; edit and delete. |
| **Endpoint agents** | Register agents, dispatch scripts, watch job state, view results, save a result as an investigation, delete jobs, revoke agents. |
| **Bytecode** | Compile and sign, verify and disassemble, verify and execute. |
| **Report encryption** | Register or remove the RSA public key, view its fingerprint. |

The bearer token is kept in `sessionStorage` (cleared when the tab closes), validated against the server on sign-in, and discarded on any `401`.

---

## Endpoint agents

Agents run on a target host, poll the API for jobs, execute them through the same pipeline and limits, and post results back.

1. In **Endpoint agents**, choose *Register agent*. The console shows the agent ID and a one-time token together with the exact launch command.
2. Run it on the endpoint (the agent needs this repository and its dependencies):

   ```bash
   python -m jocky.agent --api-url https://jocky.example.org --agent-id <id> --agent-token <token>
   ```

   Environment variables `JOCKY_API_URL`, `JOCKY_AGENT_ID`, `JOCKY_AGENT_TOKEN`, `JOCKY_POLL_INTERVAL` and `JOCKY_TLS_VERIFY` are also honoured.
3. Dispatch a script. It is lexed and parsed before queuing, claimed atomically by the agent, and marked `complete` or `failed`.
4. Review the result and use *Save as investigation* to persist it.

Agent tokens are stored as SHA-256 digests and compared in constant time. An agent token can reach only its own job endpoints. The agent backs off exponentially when the API is unreachable.

> The agent and job registry live in server memory (100 agents, 1,000 jobs; the oldest finished jobs are evicted at the cap). Restarting the API clears them. Save results you need to keep.

---

## Signed bytecode

`POST /api/bytecode/compile` flattens a script into a linear opcode list (`COLLECT`, `ANALYZE`, `REPORT`, `LET`, `IF`) wrapped in a header and signed with HMAC-SHA256 using `JOCKY_BYTECODE_KEY`.

Wire format (big-endian): `[4B header length][header JSON][4B body length][body JSON][32B signature]`.

Before disassembly or execution the signature is verified in constant time, then the magic value and version are checked. Executed bytecode is rebuilt into the IR and run through the ordinary interpreter, so it cannot reach anything a source script could not. All failure modes return one generic `BytecodeError`.

---

## Encrypted reports

Hybrid encryption: a fresh AES-256 key and 96-bit nonce per report; body encrypted with AES-GCM; the AES key wrapped with the analyst's RSA public key (OAEP, SHA-256). The server never holds the private key and cannot read an exported report.

```bash
python -m jocky.api.key_gen                         # writes jocky_investigator.key / .pub
# register the .pub contents in the console (Report encryption), then export from an investigation
python -m jocky.api.decrypt_report --key jocky_investigator.key \
       --input jocky_report_1.enc --output report.json
```

Keys of fewer than 2048 bits are refused. The registered public key is held in memory only and cleared on restart. Keep the `.key` file private.

---

## API reference

Interactive documentation is served at `/docs` (disable with `JOCKY_DOCS=false`). Every route except `/api/health` requires `Authorization: Bearer <token>`; agent routes use the per-agent token.

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness (public). |
| GET | `/api/catalog` | Collectors, rules, evidence properties, severities. |
| GET | `/api/stats` | Dashboard aggregates. |
| POST | `/api/investigations` | Validate, run, store. |
| GET | `/api/investigations` | Summaries, newest first. |
| GET | `/api/investigations/{id}` | Full record with report. |
| PATCH | `/api/investigations/{id}` | Edit name, status, notes. |
| DELETE | `/api/investigations/{id}` | Delete. |
| GET | `/api/investigations/{id}/report.html` | HTML report download. |
| GET | `/api/investigations/{id}/report.encrypted` | Encrypted report (requires a registered key). |
| POST | `/api/validate` | Parse only; nothing runs. |
| POST | `/api/compile` | Return the IR. |
| POST / GET / DELETE | `/api/keys/register`, `/api/keys/status` | Manage the public key. |
| POST | `/api/bytecode/compile`, `/disasm`, `/execute` | Bytecode workbench. |
| POST / GET | `/api/agents/register`, `/api/agents` | Register and list agents. |
| DELETE | `/api/agents/{agent_id}` | Revoke an agent. |
| POST / GET | `/api/agents/{agent_id}/jobs` | Dispatch and list jobs. |
| GET / DELETE | `/api/agents/{agent_id}/jobs/{job_id}[/result]` | Read or delete a job. |
| POST | `/api/agents/{agent_id}/jobs/{job_id}/import` | Save a completed job as an investigation. |
| GET / POST | `/api/agents/{agent_id}/jobs/pending`, `.../result`, `.../error`, `/heartbeat` | Agent-side endpoints (agent token). |

Editable case fields: `investigation_name` (1 to 200 characters), `status` (`open`, `in_review`, `closed`), `notes` (up to 10,000 characters).

---

## Configuration

`start.py` writes `.env` for you. All variables:

| Variable | Required | Meaning |
|---|---|---|
| `JOCKY_API_TOKEN_HASH` | yes | SHA-256 of the bearer token. The API refuses to start without it. |
| `JOCKY_BYTECODE_KEY` | for bytecode | HMAC key, at least 32 characters. Without it bytecode routes return `503`. |
| `JOCKY_CORS_ORIGINS` | no | Extra allowed origins. Unnecessary when the API serves the console. |
| `JOCKY_EVIDENCE_DIR` | no | Directory hashed by `file_hash`. Default `sample_evidence/`. |
| `JOCKY_DB_PATH` | no | SQLite file. Default `jocky.db` in the project root. |
| `JOCKY_DOCS` | no | `false` disables `/docs`. |

---

## Security model

- **Allowlisted execution.** Scripts select from fixed registries; there is no path from script text to arbitrary code, file, or command.
- **Authentication.** Single-operator bearer token; only its SHA-256 digest is stored; constant-time comparison; startup aborts if unset. Protected routes share a router-level dependency, so a new route cannot be left unauthenticated by omission.
- **Agent isolation.** Per-agent tokens, digest-only storage, constant-time checks with equalised timing for unknown IDs, atomic job claiming, and atomic `running` to `complete/failed` transitions so a job cannot be completed twice or failed after completion.
- **Input bounds.** Script (20,000 chars), bytecode, PEM, notes and name lengths are validated; request bodies over 20 MB are rejected; lexer, parser and interpreter limits are enforced.
- **Evidence integrity.** Reports are stored as immutable JSON. Each investigation records the SHA-256 of its script. Case edits touch metadata columns only.
- **File access.** `file_hash` is confined to one resolved directory, refuses symlinks, and is bounded in count and memory.
- **Transport and browser.** Security headers (`nosniff`, `X-Frame-Options: DENY`, `no-referrer`), `Cache-Control: no-store` on API responses, a locked-down CSP on downloaded HTML reports, all report content HTML-escaped, no secrets in the frontend bundle.
- **SQL.** Parameterised queries only; connections closed in `finally`.

Run behind a TLS-terminating reverse proxy for anything beyond localhost. The bundled launcher binds to `127.0.0.1` by default and warns if you change that.

---

## Architecture

```text
 React console  ──HTTP──▶  FastAPI  ──▶  lexer ─▶ parser ─▶ IR ─▶ interpreter
 (served from /)            │                                       │      │
                            │                             collector │      │ rule
                            │                             registry  ▼      ▼ registry
                            │                                  evidence ─▶ findings
                            ▼                                        │
   SQLite (jocky.db)  ◀── report builder ◀──────────────────────────┘
                            ▲
   Endpoint agents ──poll───┘   (job queue in memory; results importable to SQLite)
```

```text
jocky/
  language/    lexer, parser, ir, interpreter, bytecode
  collectors/  nine collectors + registry
  analysis/    finding model, rules, extended rules, registry
  reports/     builder, HTML writer, JSON writer, encryptor
  storage/     SQLite layer (migrations, CRUD, stats)
  api/         routes, auth, agent routes/store, bytecode routes, keys, catalog
  agent/       remote agent
frontend/      React 19 + Vite console
tests/         regression tests
start.py       installer and launcher
```

Design decisions that still apply: explicit registries over dynamic dispatch, a hand-written parser (the grammar is small), a data-only IR, SQLite with one JSON document per report, sequential collection for deterministic ordering, and findings phrased as observations.

---

## Testing

```bash
pip install pytest
python -m pytest tests -q          # regression suite
python test_lexer.py               # lexer sanity
python test_interpreter.py         # full local triage; writes JSON and HTML reports
python test_bytecode.py            # bytecode round trip
cd frontend && npm run lint && npm run build
```

---

## Limitations

- Collection and analysis are sequential and synchronous; long investigations hold a worker thread. There is no cancellation.
- The agent registry, job queue and registered public key are in memory.
- Scripts are delivered to agents over the agent's authenticated channel and are not signed; use TLS. (Signed bytecode is available but agents currently receive source.)
- Single operator: one bearer token, one active public key.
- `file_hash` is non-recursive and capped at 500 entries.
- SQLite is suited to local and small-team use. Reports are opaque JSON documents and are not individually indexed.
- The DSL has no loops, functions, or arithmetic.
- The `/tmp`-style path heuristics in the rules produce false positives on legitimate software; findings need analyst judgement.

---

## Scope

The original problem statement mentions evasion techniques such as process hollowing, reflective DLL injection, BYOVD and kernel-level security bypass. **These are intentionally not implemented.** JOCKY is an auditable, read-only triage framework.

---

## Change log

**1.0.0**

*Frontend*: rebuilt as a dark operations console (dashboard, case management, editor with engine reference, evidence browser, agents, bytecode, key management); same-origin deployment.

*Features added*: edit and delete investigations (status, notes, rename); agent revoke, job delete and save-to-investigation; `/api/catalog`, `/api/stats`, `/api/keys/status`; configurable evidence directory; one-command installer with token issuance.

*Bugs fixed*:
- `logged_in_users.count` always evaluated to 0 (the collector returns `sessions`).
- The suspicious-port rule never fired: it read `remote_port`, which the collector did not emit.
- Unicode digits (for example `²`) and very long integers crashed the lexer with an unhandled exception (HTTP 500).
- Unbounded `if` nesting could exhaust the parser stack; now capped at 10.
- A failing analysis rule aborted the whole investigation; it is now isolated.
- Extended rules emitted severities that the model did not define; one five-level scale is now shared everywhere.
- Quoted trusted startup paths (`"C:\Program Files\..."`) were flagged as untrusted.
- Non-numeric ports could crash `high_connection_processes`.
- Agent jobs could be completed twice, or failed after completion (check-then-act race); transitions are now atomic.
- The 1,000-job cap was never released, permanently blocking dispatch; finished jobs are now evicted.
- `file_hash` symlink entries bypassed the 500-file cap.
- The database path depended on the working directory; it is now anchored to the project root.
- `report.html` lost the script hash and only styled two of five severities.
- Missing bytecode key produced a bare 500; it now returns 503 with a clear message.
- Removed a truncated deprecated encryption shim and unused imports; replaced deprecated FastAPI startup hook.
- Removed committed generated reports from the repository and completed `.gitignore`.
