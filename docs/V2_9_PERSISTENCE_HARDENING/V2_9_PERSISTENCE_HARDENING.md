# RANDAR V2.9.0 — Persistence Forensic Hardening

This update hardens the V2.9.0 persistence-forensics pipeline against false positives, duplicate findings, incomplete provenance, and misleading coverage claims.

## 1. Writable service paths

The previous implementation mixed path-name heuristics with `os.access()` and could report Windows system binaries as writable. The hardened collector uses the Windows DACL through `icacls` and evaluates write/modify/full-control grants for non-admin principals such as `Users`, `Everyone`, and `Authenticated Users`. File and parent-directory checks are separate. If the ACL cannot be inspected, the state is `unknown`, never `true`.

The result includes the ACL source, writable principals, denied principals, and separate file/parent evidence.

## 2. Finding deduplication

A general deduplication layer uses `(semantic_rule_family, subject)` as the key. Legacy aliases such as `suspicious_services` and `writable_service_paths` collapse to one service condition. Likewise `persistence_correlation` and `persistence_cross_surface_correlation` collapse when they describe the same executable path.

The retained finding records the merged rule names in `related_evidence.merged_rules`.

## 3. Windows path handling

Environment variables such as `%windir%`, `%systemroot%`, `%programfiles%`, `%appdata%`, and `%temp%` are expanded before comparison. Windows path normalization uses Windows semantics even when analysis is performed on Linux against a fixture.

## 4. Startup and scheduled-task scoring

A path outside `C:\Windows` is no longer suspicious by itself. Startup items are filtered to executable-capable targets; `.lnk` files are resolved without executing their target.

Risk scoring combines:

- path risk;
- signature validity;
- publisher/trusted-publisher status;
- recent creation;
- suspicious arguments/interpreters;
- double extensions;
- run-as account;
- target existence;
- service unquoted-path state.

A temporary/AppData path alone cannot produce `high` severity.

## 5. Executable verification

Flagged persistence objects can carry:

- SHA-256;
- Authenticode status;
- publisher/subject;
- file version;
- creation and modification times;
- trusted-publisher classification.

The trusted-publisher list only lowers risk when the signature is valid. It does not suppress an unsigned or invalidly signed executable.

VirusTotal is hash-only and disabled by default. Set `RANDAR_VT_API_KEY` to opt in.

## 6. Additional Windows persistence coverage

V2.9.0 now exposes read-only collectors for:

| Surface | Source | Typical normal state | Review condition |
|---|---|---|---|
| WMI permanent subscriptions | `root\\subscription` CIM classes | Few/no permanent filters/consumers | New consumer/filter/binding referencing a user-writable or untrusted target |
| IFEO | `HKLM\\...\\Image File Execution Options` | No debugger for ordinary applications | Debugger/VerifierDlls/GlobalFlag entry |
| Winlogon | `HKLM\\...\\Winlogon` | `explorer.exe`, standard `Userinit` | Non-default Shell/Userinit/Notify/Gina values |
| AppInit_DLLs | `HKLM\\...\\Windows` | Disabled/empty on modern Windows | DLL loading enabled or non-empty DLL list |
| COM hijacking | `HKCU\\Software\\Classes\\CLSID` | User overrides uncommon | InprocServer32/LocalServer32 override to unusual path |
| BITS | BITS job API | Expected enterprise/application transfers | Unusual owner, destination, or executable/script relationship |
| All-user Startup | `C:\\Users\\*\\...\\Startup` | Known application shortcuts/launchers | Untrusted executable/script in another profile |
| Browser extensions | Chromium profile `Extensions` trees | Installed known extensions | Unexpected profile/path/manifest/signature |
| Office add-ins | `HKCU\\Software\\Microsoft\\Office\\*\\Addins` | Installed enterprise/vendor add-ins | Unexpected add-in or untrusted binary |
| LSA authentication packages | `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa` | OS-default authentication packages | Non-default package requiring binary verification |
| Service configuration | Service SCM + `Parameters\\ServiceDll` | Quoted expected ImagePath | Unquoted path, changed/untrusted ServiceDll |

All collectors are read-only. No persistence mechanism is created, enabled, disabled, or executed.

## 7. Provenance and integrity

Every successful collector receives an evidence SHA-256. Every finding receives a deterministic ID based on:

```text
rule + semantic subject + investigation snapshot hash
```

`evidence_refs` point to the collector, its evidence hash, and the matching record index where possible.

The report integrity hash covers the report content excluding itself. Evidence hashes can be recomputed independently from the canonical JSON representation of each collector's data.

The report schema requires every finding to have:

- `finding_id`
- `evidence_refs`
- `limitations`
- `next_check`

A report is rejected by the builder if any finding violates those requirements.

## 8. Coverage honesty

Reports now include:

- `elevation.is_admin`
- `elevation.is_elevated`
- `elevation.integrity_level`
- `elevation.elevation_required_for`
- per-collector `status`
- per-collector `confidence`
- unavailable/degraded collector lists
- explicit `execution_status`
- explicit `termination_reason`

A missing Sysmon channel is reported as `not_installed`, not as a collection error. Windows Event Log collection distinguishes access failure, no matching events, and evidence truncation.

## 9. Timeline

The report timeline incorporates:

- scheduled-task creation/last-run times;
- service process start times when a service PID can be correlated to the process collector;
- service executable timestamps;
- startup executable timestamps;
- Windows event timestamps;
- process start times;
- network artifact timestamps.

## 10. Noise target

The regression suite contains a clean Windows persistence fixture and a planted-persistence fixture. The clean fixture is required to remain below 15 persistence findings and must not produce high/critical findings. The planted fixture contains a Run-key executable, a Temp scheduled task, an unsigned writable service, and a WMI subscription and must surface distinct leads.

## 11. External coverage comparison

Microsoft's Sysinternals Autoruns documents a broad set of autostart locations including Startup, Run/RunOnce, shell extensions, browser helper objects, Winlogon, AppInit DLLs, services, image hijacks and other categories.

PersistenceSniper documents checks covering scheduled tasks, Office startup, BITS, services, IFEO, AppInit, COM-related hijacks, WMI event subscriptions, LSA-related checks and many other ATT&CK persistence techniques. RANDAR's advantage is its JOCKY evidence/provenance pipeline and deterministic report model; the remaining gap is breadth of the very large Autoruns/PersistenceSniper check sets.

The benchmark should therefore be interpreted as a coverage matrix, not as a claim of feature-for-feature parity.
