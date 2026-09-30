# RANDAR v3.0.0 Final

RANDAR is a **Forensics-as-Code platform** built around the JOCKY v1.5 investigation DSL. It turns a reviewable investigation definition into bounded, read-only evidence collection, deterministic analysis, correlation, provenance, and an integrity-protected report.

## SIH26148 alignment

The SIH26148 statement describes a broad research direction: a new language/toolchain, representation diversity, in-memory execution, BYOVD/kernel research, multi-endpoint management, and network transport research.

RANDAR implements the **defensive and auditable side** of those requirements:

| SIH26148 theme | v3.0 Final | Product treatment |
|---|---|---|
| Independent JOCKY language | Yes | JOCKY v1.5 DSL, parser, IR, compiler, bytecode, runtime |
| Windows/Linux collection | Yes | Platform-aware collector registry |
| Transformation/polymorphism research | Yes | Controlled representation transformations with provenance |
| In-memory execution | Defensive | Memory telemetry and forensic detection; no stealth injection |
| BYOVD | Defensive | Driver inventory, signature/hash/version, vulnerability correlation |
| Persistence analysis | Yes | Expanded Windows persistence collectors and low-noise scoring |
| Multi-system management | Yes | Authenticated agent/investigation infrastructure |
| Network analysis | Yes | Network artifacts, DNS and connection correlation |
| Security-product context | Yes | Product flags and observed kernel-component evidence |
| Security-control bypass | No | Explicitly outside the production implementation |
| Kernel subversion | No | Detection/telemetry only |
| Process hollowing / reflective injection | No | Detection/forensic indicators only |
| Domain fronting / covert transport | No | Transport observability/research boundary only |

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
Analysis rules + cross-surface correlation
   ↓
Deduplication + finding provenance
   ↓
Timeline + coverage/elevation assessment
   ↓
Integrity-protected JSON / HTML report
```

## Final capability inventory

The release exposes **32 collectors** and **57 analysis rules** through the live registries.

Major Windows persistence surfaces include:

- Registry Run / RunOnce and Startup folders
- Scheduled Tasks
- Services / ServiceDll / unquoted service paths
- WMI permanent event subscriptions
- IFEO debugger/verifier configuration
- Winlogon Shell/Userinit
- AppInit_DLLs
- HKCU COM CLSID overrides
- BITS jobs
- Startup folders across local profiles
- Chromium-family browser extensions
- Office add-ins
- LSA Authentication Packages

Additional forensic surfaces include processes, modules, memory regions, threads, PE metadata, Windows Event Logs, Sysmon, drivers, network connections/artifacts, logged-in users, local users, and open files.

## User-context metadata

Three final collectors are deliberately privacy-bounded:

- `clipboard_metadata`: availability, format, and length metadata only. Clipboard contents are not returned or hashed.
- `browser_history_metadata`: browser/profile, redacted domain hash, and visit timestamp metadata. URLs and page titles are not returned.
- `browser_cookie_metadata`: browser/profile, redacted host hash, expiry and security flags. Cookie values are not returned and cookies are not decrypted.

These collectors are intended for forensic context, not credential/session extraction.

## Persistence quality goals

The final persistence pipeline is designed around:

1. ACL evidence instead of `os.access()` heuristics for service write checks.
2. `unknown` when ACL inspection cannot be performed.
3. Semantic deduplication by rule/subject.
4. Environment expansion and Windows path normalization.
5. Multi-signal startup and scheduled-task scoring.
6. Executable SHA-256, signature, publisher, version, and timestamps.
7. Optional hash-only VirusTotal lookup, disabled unless configured.
8. Stable finding IDs and collector evidence references.
9. Mandatory limitations and next-check guidance.
10. Timeline generation from persistence/process/file/event timestamps.
11. Explicit elevation state and per-collector coverage.
12. Distinct `not_installed`, `no_matching_events`, `access_denied`, and true error states.

## Verification

The final regression suite contains **165 passing tests**. The exact Startup Items failure reported in the UI (`bad escape \\W at position 2`) has a dedicated regression test.

See:

- `FINAL_PRODUCT.md` — complete product description
- `SIH26148_ALIGNMENT.md` — problem-statement mapping
- `PERSISTENCE_FINAL.md` — persistence coverage and scoring
- `PRIVACY_METADATA.md` — clipboard/browser collection boundaries
- `VERIFICATION.md` — test and integrity verification
- `RELEASE_NOTES.md` — v3.0.0 final changes
