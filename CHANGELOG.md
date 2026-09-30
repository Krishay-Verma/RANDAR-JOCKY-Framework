# V3.0.0 Final

- Finalized the RANDAR forensic platform on the V2.9 persistence-hardened baseline.
- Fixed Windows environment-variable expansion when replacement values contain backslashes (`bad escape \W`).
- Added regression coverage for the exact Startup Items failure shown in the UI.
- Added privacy-bounded clipboard metadata and browser history/cookie metadata collectors; no clipboard contents, URLs/titles, cookie values, or cookie decryption are returned.
- Synchronized the Domain Expansion templates with the live collector registry.
- Preserved the V2.9 persistence hardening: DACL-aware service write checks, deduplication, multi-signal startup/task scoring, executable verification, evidence references, stable finding IDs, coverage/elevation reporting, timeline construction, and expanded persistence collectors.
- Verified 165 regression tests with 0 failures.

## 2.9.0 — Persistence forensic hardening

- Replaced service writable-path heuristics with DACL-aware tri-state inspection (`true` / `false` / `unknown`).
- Added semantic finding deduplication and deterministic finding IDs.
- Added Windows environment-variable expansion and Windows-path normalization.
- Added multi-signal startup/scheduled-task scoring and `.lnk` target resolution.
- Added SHA-256, Authenticode/publisher/version/timestamp enrichment and opt-in VirusTotal hash lookup.
- Added WMI, IFEO, Winlogon, AppInit, COM, BITS, all-user Startup, browser extension, Office add-in and LSA authentication-package collectors.
- Added service unquoted-path and ServiceDll checks.
- Added evidence record references, mandatory limitations/next checks, evidence-hash verification and report schema validation.
- Added elevation state, per-collector coverage/confidence, explicit termination reasons, timeline enrichment and top-lead summary.
- Sysmon absence is now `not_installed`; Windows Event Log truncation/access/no-match states are separated.
- Added clean/planted Windows persistence fixtures and regression coverage.

## 2.9.0 — Software context flags, kernel-aware classification & execution reliability

- Added centralized defensive software classification for common endpoint-security/EDR products, including Microsoft Defender, Kaspersky, CrowdStrike, SentinelOne, Bitdefender, ESET, Sophos, Malwarebytes, Avast, McAfee and Trend Micro.
- Added anti-cheat context flags for Riot Vanguard, Easy Anti-Cheat, BattlEye, Denuvo Anti-Cheat and FACEIT Anti-Cheat.
- Added contextual flags for common VPN and virtualization software.
- Added explicit `KERNEL DRIVER` flags for collected driver records and `KERNEL COMPONENT` flags for processes only when matching driver evidence is actually observed. Product naming alone is never treated as proof of kernel activity.
- Added software classification metadata to persisted reports and the live capability catalog.
- Added a Security Software & Kernel Review investigation template.
- Registered `memory_forensics_correlation` as a live JOCKY analysis rule and synchronized the Memory/Domain Expansion templates.
- Increased bounded timeouts for legitimately slower Windows collectors such as driver inventory, services, scheduled tasks and local-user inventory.
- Converted the Injection / PE and Windows Telemetry sidebar hunts to server-side background investigation jobs so their HTTP request is no longer tied to the page lifetime or the 60-second request timeout.
- Fixed Injection / PE findings so PE-specific rules are included in the displayed result set.
- Fixed the investigation execution resource strip so metrics have readable separation and wrapping.
- Fixed a duplicated Evidence Context header in the investigation evidence drawer.
- Added regression coverage for software classification, kernel evidence correlation, template/registry synchronization, background hunt flow and report integrity metadata.

## 2.8.1 — Background forensic scan continuity

- Standalone Memory, Driver, and Persistence scans now execute in bounded server-side background workers.
- Added authenticated `/api/forensic-jobs/{scan_type}` create/status endpoints.
- Route changes no longer terminate an in-flight forensic scan or its persistence workflow.
- Forensic workspace pages persist active job IDs in session storage and resume polling when reopened.
- A transient API/polling failure no longer abandons the server-side job.
- Existing synchronous forensic scan endpoints remain available for automation/API compatibility.
- Added regression coverage for background job creation, completion, persistence, and frontend job recovery behavior.

## 2.8.0 — Forensic scan persistence & reliability
- Standalone Memory, Driver, and Persistence scans are persisted as investigations.
- Registered `driver_forensics_exposure` in the live analysis registry.
- Fixed investigation summary typography and forensic scan pivots.
- Added V2.8 regression coverage.

## 2.7.0 — Investigation navigation & cross-surface correlation

- Fixed Memory/Driver forensics visibility on investigation detail and list views.
- Added direct Memory/Driver/Persistence investigation pivots.
- Added wrapped investigation tabs for narrow and wide screens.
- Added Cross-Surface Correlation workspace.

## 2.6.0 — Persistence & Privilege Forensics

- Added read-only persistence/privilege correlation API, CLI and console workspace.
- Added cross-surface and privilege correlation rules.
- Integrated persistence findings into investigation details and list summaries.
- Fixed investigation-list memory/driver row-scope bug.

## 2.5.1 — Investigation UI and capability integration hotfix

- Added dedicated Memory Forensics and Driver Forensics tabs to stored investigations.
- Added memory/driver finding filters and investigation-list status summaries.
- Added lightweight SQLite JSON projections so the investigations list can surface specialized forensics without shipping full report bodies.
- Fixed the existing paginated DLL/PE summary, which previously depended on report JSON that the list endpoint intentionally omitted.
- Added Memory Forensics and Driver Forensics templates and added driver inventory/rules to Domain Expansion Triage.
- Fixed Engine Reference typography and wrapping so capability names and descriptions no longer run together.
- Added UI integration regression coverage.

## 2.5.0 — Driver / Kernel Forensics Research Track

- Added read-only Windows driver inventory enrichment: loaded state, signer,
  publisher, version, SHA-256, and vulnerable-driver catalog correlation.
- Added `/api/driver-forensics/scan` with kernel/security telemetry summary,
  snapshot hashing, findings, and diagnostics.
- Added Driver Forensics frontend workspace.
- Added `driver_forensics_exposure` finding and preserved the existing
  `byovd_driver_indicators` compatibility rule.
- Added V2.5 regression coverage.
- No driver exploitation, kernel modification, callback disabling, or security
  control manipulation is implemented.

## 2.4.1 — Memory Forensics Reliability & Reporting

- Added explicit memory-forensics correlation findings and diagnostics.
