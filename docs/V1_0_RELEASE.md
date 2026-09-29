# RANDAR v1.0 Release Definition

## Purpose

RANDAR v1.0 is the **Stable Forensic Triage** milestone. Its purpose is to freeze and stabilize the existing forensic-triage architecture before the later network, telemetry, DSL, provenance, UX, reliability, deployment, and hardening milestones.

## Acceptance matrix

| Area | v1.0 requirement | Status |
|---|---|---|
| API | FastAPI investigation API and authentication | Complete |
| Persistence | SQLite investigation storage | Complete |
| Language | Lexer, parser and IR | Complete |
| Execution | Controlled interpreter | Complete |
| Bytecode | Compile, sign, verify and execute | Complete |
| Collectors | 12 roadmap-defined collectors | Complete |
| Analysis | 13 registered v1.0 analysis rules | Complete |
| Reporting | HTML + JSON | Complete |
| Encryption | AES-256-GCM + RSA-OAEP report export | Complete |
| Integrity | Script and report SHA-256 verification | Complete |
| Remote operations | Registration, auth, jobs, polling, results, heartbeat, revocation | Complete |
| Tests | Unit/regression/integration acceptance coverage | Complete |
| Documentation | Architecture, security, deployment, DSL, example and changelog | Complete |

## Reference investigation

Run `examples/v1.0_endpoint_triage.jocky` through the console or API. It exercises every v1.0 collector and analysis rule without introducing later roadmap functionality.

## Evidence model

Collectors are read-only and bounded. Windows module, thread and memory collectors provide metadata-oriented telemetry only. JOCKY does not inject code, modify processes, disable security controls, or implement offensive behavior.

## Report integrity

Each report contains:

- source-script SHA-256
- canonical report SHA-256
- collector status/error information
- findings and related evidence
- collection timestamps
- endpoint hostname

The `/api/investigations/{id}/integrity` endpoint recomputes the report digest. JSON export refuses to export a report whose stored digest does not verify.

## Remote agent boundary

The v1.0 agent registry and job state remain in server memory, matching the documented product boundary. Persisted investigations survive API restarts; active agent state does not.

## Freeze rule

No V1.1+ capability should be added to the v1.0 release branch. Network evidence ingestion, DNS/beaconing/scanning analytics, expanded Windows telemetry, PE analysis, richer DSL features, provenance/audit expansion, persistent agents, UX expansion, performance work, deployment packaging and security-hardening work remain later roadmap milestones.
