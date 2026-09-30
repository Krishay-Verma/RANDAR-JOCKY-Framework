# RANDAR v3.0.0 Final

**Forensics-as-Code platform for controlled computer and network forensic triage**

> Smart India Hackathon 2026 · Problem Statement **SIH26148**

RANDAR is a digital-forensics and incident-triage platform built around **JOCKY v1.5**, a constrained investigation DSL. Investigations declare evidence to collect, analysis rules to run, correlations to perform, and the report to produce. The runtime executes those declarations through explicit registries, bounded execution, provenance tracking, and integrity checks.

## Final product scope

- **32 live collectors**
- **57 live analysis rules**
- Windows and Linux-aware collection architecture
- JOCKY lexer, parser, IR, compiler, signed bytecode, and bounded runtime
- Transformation/reproducibility research with build identity
- Windows memory and driver forensic detection
- Expanded Windows persistence forensics
- Network/DNS evidence and correlation
- Multi-endpoint authenticated investigation infrastructure
- Stable finding IDs and collector evidence references
- Report/evidence hashing, coverage and elevation reporting
- Software/security-product context and kernel-component evidence
- Privacy-bounded clipboard/browser metadata collection
- React/Vite investigation console

## SIH26148 alignment

The problem statement combines a forensic-language objective with research topics involving polymorphism, in-memory execution, BYOVD/kernel manipulation, and alternate network routing. RANDAR implements the **forensic, measurement, detection, and controlled-research portions** of those themes.

The production platform does **not** implement security-control bypass, vulnerable-driver exploitation, kernel subversion, stealth process injection, process hollowing, reflective injection, API unhooking, or covert transport/domain-fronting behavior. Corresponding behaviors can instead be represented through controlled research metadata and detected through forensic telemetry.

## Architecture

```text
JOCKY source
    ↓
Lexer / Parser / IR
    ↓
Compiler + signed bytecode
    ↓
Bounded interpreter
    ↓
Read-only collectors
    ↓
Evidence normalization + hashes
    ↓
Analysis + cross-surface correlation
    ↓
Deduplication + provenance
    ↓
Timeline + coverage/elevation
    ↓
Integrity-protected report
```

## Persistence forensics

The final Windows persistence pipeline covers:

- Run / RunOnce
- Startup folders, including local profiles
- Scheduled Tasks
- Services, ServiceDll and unquoted ImagePath
- WMI permanent event subscriptions
- IFEO debugger/verifier configuration
- Winlogon Shell/Userinit and related configuration
- AppInit_DLLs
- HKCU COM CLSID overrides
- BITS jobs
- Browser extensions
- Office add-ins
- LSA Authentication Packages

Persistence findings use multiple weak signals rather than path-only suspicion. Service write checks use ACL evidence where available and return `unknown` when they cannot be verified.

## User-context metadata

The final release includes three bounded collectors:

- `clipboard_metadata` — availability/format/length metadata; **clipboard contents are never returned or hashed**.
- `browser_history_metadata` — profile/timestamp metadata and redacted domain hashes; **URLs and titles are not returned**.
- `browser_cookie_metadata` — redacted host hashes plus expiry/Secure/HttpOnly metadata; **cookie values are never returned and cookies are not decrypted**.

## Evidence and integrity

Each collector can contribute an `evidence_hash`. Findings contain stable IDs and references to the collector and record that support them. Reports bind the investigation to `script_hash`, and bytecode-backed runs can also expose `bytecode_hash`. `report_hash` provides an independent integrity check over the canonical report representation.

Reports also explain incomplete coverage: elevation state, collector availability, confidence, access failures, missing Sysmon installation, event-query results, truncation, and termination reason are explicit rather than silently inferred.

## Verification

The final regression suite currently reports:

**165 passed, 0 failed**

The suite includes a regression for the exact Startup Items failure:

```text
bad escape \\W at position 2
```

That failure was caused by using a Windows path containing backslashes as a regular-expression replacement string. Environment-variable substitution now uses a literal replacement callback, and Windows fallback paths are normalized correctly.

## Documentation

The final product documentation is grouped under:

`docs/V3_0_FINAL/`

Start with:

- `docs/V3_0_FINAL/README.md`
- `docs/V3_0_FINAL/FINAL_PRODUCT.md`
- `docs/V3_0_FINAL/SIH26148_ALIGNMENT.md`
- `docs/V3_0_FINAL/PERSISTENCE_FINAL.md`
- `docs/V3_0_FINAL/PRIVACY_METADATA.md`
- `docs/V3_0_FINAL/VERIFICATION.md`
- `docs/V3_0_FINAL/RELEASE_NOTES.md`

Historical V1/V2 release notes remain in the repository as release history; the V3.0 directory is the authoritative final-product documentation.

## Build and run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -q
python start.py
```

The frontend is under `frontend/`. A production Vite build should be performed in an environment where the declared npm dependencies can be installed.

## Security model

RANDAR is designed as a controlled forensic platform. Collectors are read-only, capability names are allowlisted, execution is bounded, and evidence/report provenance is explicit. Advanced SIH26148 concepts are treated as controlled research/detection subjects rather than as production evasion mechanisms.
