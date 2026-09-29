# RANDAR Deployment Guide

## 1. Supported deployment model

The repository is designed primarily for:

- local forensic triage;
- controlled Windows laboratory systems;
- SIH demonstration environments;
- authorized remote-agent experiments.

The current architecture is not intended to be exposed directly to the public Internet.

---

## 2. Prerequisites

### Python

Python 3.10 or newer.

### Node.js

Node.js 20.19+ or 22.12+ for the current Vite toolchain.

### Windows

Required for:

- modules;
- threads;
- memory regions;
- Windows Event Logs;
- Sysmon;
- services;
- PE metadata.

### Linux

Supported for the cross-platform collectors.

Windows-only collectors return explicit unsupported status.

---

## 3. Recommended first run

From the project root:

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

The launcher can:

1. create the virtual environment;
2. install Python dependencies;
3. create/update `.env`;
4. generate API-token material;
5. generate the JOCKY/RANDAR bytecode signing key;
6. install frontend dependencies;
7. build the frontend;
8. start Uvicorn;
9. open the console.

---

## 4. Development mode

```bash
python start.py --dev
```

This starts:

- API with reload;
- Vite development server.

The frontend normally runs on:

```text
http://localhost:5173
```

---

## 5. Useful commands

```bash
python start.py --new-token
python start.py --rebuild
python start.py --no-browser
python start.py --host 127.0.0.1 --port 9000
```

Binding to a non-loopback address should be treated as a network deployment and protected accordingly.

---

## 6. Configuration

Important environment settings include:

```text
RANDAR_API_TOKEN_HASH
RANDAR_BYTECODE_KEY
RANDAR_DB_PATH
JOCKY_EVIDENCE_DIR
RANDAR_OPERATOR_NAME
JOCKY_CORS_ORIGINS
```

Legacy `JOCKY_*` names remain accepted in selected compatibility paths.

Do not commit real secrets to source control.

---

## 7. Evidence directory

The `file_hash` collector is deliberately restricted to an operator-configured evidence directory.

The directory is resolved by the collector registry and cannot be selected dynamically by a JOCKY script.

This is a key security boundary.

---

## 8. Database

The primary SQLite database is created by the application.

It stores case and audit information.

Back up the database before upgrading a demonstration or laboratory deployment if the case history matters.

For production scale, a durable multi-user datastore would be preferable.

---

## 9. Remote agents

The agent model is:

```text
API
 │
 ├── register agent
 │
 ├── dispatch job
 │
 └── receive result
       ▲
       │ polling
       │
    Agent
       │
       ▼
   JOCKY runtime
```

Agent registration produces:

- agent ID;
- one-time token.

The server stores only the token digest.

Agents should be deployed only to authorized endpoints.

---

## 10. Encrypted reports

To export encrypted reports:

1. generate or load the investigator RSA key pair;
2. register the public key;
3. execute/export the investigation;
4. download the encrypted artifact;
5. retain the private key separately.

The current prototype keeps the active public key in process memory.

---

## 11. API documentation

After startup:

```text
http://127.0.0.1:8000/docs
```

The OpenAPI interface exposes the authenticated API surface.

---

## 12. Validation checklist

Before a demonstration:

- [ ] `pytest -q` passes.
- [ ] API starts successfully.
- [ ] Console loads.
- [ ] Authentication works.
- [ ] `/api/catalog` reports expected capabilities.
- [ ] A simple investigation validates.
- [ ] IR/bytecode inspection works.
- [ ] A controlled investigation completes.
- [ ] Evidence pagination works.
- [ ] HTML/JSON report export works.
- [ ] Integrity verification works.
- [ ] Encrypted export works if demonstrated.
- [ ] Windows-only demonstrations are performed on Windows.
