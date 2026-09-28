# JOCKY Deployment Guide

## 1. Supported deployment model

JOCKY currently works best as a local or controlled internal forensic console.

The primary development/demo target is **Windows**, because the advanced DLL/module/thread/memory telemetry is Windows-specific.

Cross-platform collectors also support Linux.

---

## 2. Prerequisites

### Windows

- Windows 10/11 or a compatible Windows Server environment
- Python 3.10+
- Node.js 20.19+ or 22.12+
- PowerShell for the provided wrapper script

### Linux

- Python 3.10+
- Node.js 20.19+ or 22.12+ for frontend builds
- standard build/runtime tooling

---

## 3. Recommended first run

```powershell
python start.py
```

If PowerShell is preferred:

```powershell
.\start.ps1
```

The launcher performs environment checks and builds the frontend when needed.

---

## 4. Development mode

```bash
python start.py --dev
```

Use this while editing the React console or Python API.

For a production-like local run:

```bash
python start.py
```

---

## 5. Configuration

The project uses `.env` and environment variables.

Important configuration areas include:

- API authentication token hash
- bytecode signing key
- database path
- evidence directory
- API documentation visibility
- frontend API configuration where applicable

Never commit `.env` or private investigator keys to source control.

---

## 6. Evidence directory

`file_hash` does not accept an arbitrary path from the DSL.

The directory is selected by the operator/environment using `JOCKY_EVIDENCE_DIR` or defaults to the project's `sample_evidence` directory.

This prevents a script from choosing arbitrary filesystem targets to hash.

---

## 7. Remote agent

Register an agent in the console and use the generated ID/token.

Example:

```bash
python -m jocky.agent \
  --api-url https://jocky.example.org \
  --agent-id <id> \
  --agent-token <token>
```

Environment variables are also supported:

```text
JOCKY_API_URL
JOCKY_AGENT_ID
JOCKY_AGENT_TOKEN
JOCKY_POLL_INTERVAL
JOCKY_TLS_VERIFY
```

Keep TLS verification enabled outside controlled development environments.

---

## 8. Encrypted report workflow

Generate an investigator key pair:

```bash
python -m jocky.api.key_gen
```

Register the public key in **Report encryption** in the console.

Export an encrypted report.

Decrypt it on the investigator workstation with the private key:

```bash
python -m jocky.api.decrypt_report \
  --key jocky_investigator.key \
  --input jocky_report_1.enc \
  --output report.json
```

Protect the private key as a high-value forensic secret.

---

## 9. API documentation

When enabled:

```text
http://127.0.0.1:8000/docs
```

The OpenAPI schema reflects the running API.

---

## 10. Operational checklist

Before an investigation:

- confirm the correct endpoint;
- confirm the analyst identity/session;
- verify required privileges;
- verify the JOCKY script;
- validate without executing;
- confirm collectors are appropriate for the platform;
- confirm storage capacity.

After an investigation:

- review collector errors;
- review high/critical indicators;
- inspect related evidence;
- preserve the investigation database/report;
- export/encrypt the report if required;
- record analyst conclusions separately from automated findings.
