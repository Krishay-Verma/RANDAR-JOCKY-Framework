# Changelog

## 1.9.2 — Documentation and v1.9.2 Current-State Baseline

This documentation revision aligns the repository documentation with the implementation present in the v1.9.2 source tree.

### Documentation alignment
- Documented the live **17-collector** registry.
- Documented the live **40-rule** analysis registry.
- Added the current JOCKY language surface, including `where`, boolean conditions and bounded analyst-authored rules.
- Documented PE metadata, Windows Event Logs, Sysmon, services and network evidence as implemented capabilities.
- Documented report/evidence integrity metadata and audit events.
- Documented the remote-agent lifecycle and security boundaries.
- Clarified that Windows advanced telemetry is read-only and metadata-oriented.
- Added a dedicated SIH 2026 technical brief.
- Updated deployment, architecture, DFIR capability, DSL and demonstration documentation.
- Recorded the current automated regression baseline: **91 tests passed**.

## 1.9.2 — RANDAR / Comprehensive Navigation & Cancellation Reliability

- Fixed intermittent route-render failures caused by stale asynchronous API requests surviving navigation.
- Added AbortController propagation to shared frontend data loading and cancelled obsolete requests on unmount, route changes and refresh cycles.
- Prevented overlapping polling requests from racing each other and overwriting current page state.
- Reworked local investigation cancellation so one polling owner controls the job lifecycle; Cancel no longer competes with the normal status poller.
- Hardened frontend handling of unexpected API response shapes before array iteration.
- Hardened modal/evidence callbacks so malformed optional callbacks cannot crash a route render.
- Extended Windows collector execution budgets to reduce routine PE/module timeout failures while retaining hard bounds.
- Raised the maximum investigation runtime to 10 minutes while preserving explicit partial-result and cancellation semantics.
- Added frontend reliability contract tests and retained the complete backend regression suite.

## 1.9.1 — RANDAR / Reliability Bug Fix

- Fixed local investigation cancellation races so queued jobs cannot resurrect as running jobs.
- Added a `cancelling` lifecycle state while an active bounded collector unwinds.
- Fixed the frontend cancellation poll so the analyst sees the terminal cancelled state instead of an overwritten stale status.
- Fixed an Investigation edit-modal callback bug that could trigger the page error recovery screen.
- Fixed collector status details so timeout/cancel/error states are never displayed as successful evidence collection.
- Raised the generic collector timeout to 30 seconds and added bounded 45–60 second profiles for heavier Windows telemetry collectors.
- Improved live progress reporting so the UI advances while a command is actively executing rather than remaining at the initial 5% marker.
- Added regression coverage for cancellation races, timeout profiles and active progress updates.

## 1.9.0 — RANDAR / Performance & Reliability

- Added bounded pagination for investigation archive listings.
- Added lazy, server-paged evidence retrieval for large collector datasets.
- Added per-collector execution timeouts and explicit timeout/cancellation statuses.
- Added maximum investigation runtime with preserved partial evidence when the runtime limit is reached.
- Added analyst cancellation for background investigation jobs.
- Added maximum record/evidence-size bounds with explicit truncation markers.
- Added execution/resource accounting: elapsed time, collector counts, record counts, evidence bytes, timeouts and truncation.
- Added V1.9 execution/resource visibility to the console and HTML reports.
- Added V1.9 regression coverage; full suite verified at 83 passing.

## 1.8.0 — RANDAR / Investigation Experience

- Added global evidence search across stored case metadata, findings and collected evidence.
- Added analyst finding filters for severity, network, injection/PE, persistence and PowerShell.
- Added contextual evidence drawer from finding evidence references.
- Added structured finding explanations: what happened, why it was flagged, limitations and recommended next check.
- Added investigation summary metrics for objects collected, indicators and major evidence domains.
- Added integrity-version compatibility so V1.6/V1.7 reports remain verifiable after the new explanation fields are introduced.
- Added V1.8 regression coverage; full suite verified at 78 passing.

## 1.7.0 — RANDAR / Remote Endpoint Operations

- Persistent remote-agent state, capability negotiation, secure job metadata and safe cancellation.
- Added remote agent capability dashboard and job expiry/signature visibility.
- RANDAR agent branding with JOCKY DSL compatibility.

## V1.6.0 — RANDAR / Evidence & Forensic Integrity

- RANDAR becomes the platform name; JOCKY remains the DSL/bytecode identity.
- Added evidence timeline, provenance chain, append-only audit log, stable finding IDs and evidence references.
- Added investigation integrity/audit UI.

## 1.5.0 — Forensics-as-Code DSL

- Added comments, variables, boolean `and` / `or` / `not`, and `where` evidence filtering.
- Added bounded analyst-authored `rule` blocks with allowlisted finding properties and severities.
- Extended signed bytecode to preserve and validate V1.5 DSL constructs.
- Added background execution for long-running investigations so Domain Expansion Triage is not limited by the browser request timeout.
- Added V1.5 DSL showcase template and regression coverage.

## 1.4.1 — Stability & Full Capability Visibility

- Hardened frontend navigation/data handling and stale async request behavior.
- Added explicit analysis execution coverage to reports and Investigation Detail, including zero-hit rules.
- Exposed all specialized investigation capability tabs with explicit not-collected states.
- Added live collector/rule registry coverage to Dashboard and Investigation Builder.
- Added the Domain Expansion Triage full-capability template and reproducible example.
- Preserved report integrity compatibility for pre-1.4.1 reports.

## 1.4.0 — Injection & PE Forensics

- Added bounded read-only `pe_metadata` collector for PE architecture, type, sections, imports, exports, entropy, signature metadata and SHA-256.
- Added V1.4 PE/module rules: unsigned loaded module, suspicious imports, high entropy, module/disk mismatch, and writable-risk modules.
- Strengthened injection correlation with static PE import evidence.
- Added PE / Module investigation view and expanded DLL/injection workspace.
- Added PE/module section to HTML reporting and V1.4 DSL example.
- Preserved the read-only safety boundary: no injection, remote-thread creation, arbitrary memory writes, or PE execution.

## 1.2.0 — Final V1.2 maintenance fixes

- Added route-level UI error recovery so a failed page render no longer leaves the console as an unexplained blank view.
- Network Forensics now displays the actual V1.2 DNS, beaconing, scanning, classification, and process/network findings with expandable supporting evidence.
- Added process/network correlation to the V1.2 UI and HTML hunting result set.
- Hardened process/network correlation for IPv6 local endpoints.
- Expanded regression coverage; full Python suite now passes 42/42 tests.

## [1.2.0] - Network Threat Hunting

- Added passive DNS hunting rules for suspicious queries, entropy, rare domains, TLD patterns, bursts, unusual query types, long/random labels, and tunneling indicators.
- Added DNS and network beaconing analysis with interval and jitter evidence.
- Added vertical port scan, horizontal scan, service discovery, and UDP scan indicators.
- Added network address classification and endpoint process/network/DNS correlation.
- Added V1.2 DSL example, catalog entries, human-readable UI coverage, and HTML report section.
- Preserved V1.1 payload-free network evidence boundary and controlled allowlist execution.

# Changelog

## 1.2.0 — Network Threat Hunting

- Added DNS threat-hunting rules, beaconing analysis, network scan/discovery analysis, network classification, and process/network correlation.
- Added direct V1.2 finding/evidence presentation in Investigation → Network Forensics.
- Added route-level rendering recovery and fixed a React hook-order defect in Investigation Detail that could trigger React error #310 during API state transitions.
- Added IPv6-safe process/network endpoint correlation and regression coverage.
- Verified the backend regression suite at 42/42 passing.

## 1.1.0 — Network Evidence

- Added normalized `network_artifacts` collector.
- Added Zeek conn.log/dns.log TSV ingestion.
- Added Zeek JSON-lines ingestion.
- Added bounded classic PCAP metadata extraction.
- Added bounded PCAPNG metadata extraction with interface timestamp resolution.
- Added persistent, content-addressed network evidence source registry.
- Added network evidence upload/list/delete API.
- Added request-scoped network source selection for the DSL.
- Added network source provenance to reports.
- Added network statistics to evidence and HTML reports.
- Added Network Forensics console page and investigation source selection.
- Added V1.1 regression and acceptance coverage.

# JOCKY Changelog

## 1.0.0 — Stable Forensic Triage

### Core
- Stabilized the FastAPI + SQLite investigation architecture.
- Preserved the controlled lexer → parser → IR → interpreter execution path.
- Added complete v1.0 acceptance coverage for all registered collectors and analysis rules.

### Evidence collection
- System information
- Processes
- Network connections
- Logged-in users
- Approved-directory file hashing
- Scheduled tasks / cron
- Startup items
- Open files
- Local users
- Windows modules
- Windows thread metadata
- Windows virtual-memory metadata

### Analysis
- Missing executable paths
- Suspicious executable locations
- Process/network correlation
- Scheduled-task anomalies
- Startup anomalies
- High-connection processes
- Privileged-user anomalies
- Windows module/injection indicators

### Bytecode
- HMAC-SHA256 signed bytecode
- Signature verification before disassembly/execution
- Structural and capability-boundary validation
- Controlled reconstruction back through the normal interpreter

### Reporting and integrity
- SQLite investigation persistence
- HTML reports
- JSON report downloads
- AES-256-GCM + RSA-OAEP encrypted reports
- Script SHA-256 provenance
- Report SHA-256 integrity verification
- Explicit collector-error preservation

### Remote operations
- Agent registration and scoped tokens
- Job dispatch/polling
- Result and error submission
- Heartbeats
- Job lifecycle protection
- Agent revocation
- Completed-job import into persisted investigations

### Scope boundary
V1.0 does not introduce the later roadmap capabilities for Zeek/PCAP ingestion, network threat hunting, expanded Windows telemetry, PE analysis, DSL filtering/boolean/user-rule features, persistent agents, or large-scale optimization.

## 1.3.1 — SPA Navigation Stability Hotfix

- Added an application-root React error boundary so rendering failures in the shell/router tree cannot leave the console blank.
- Kept route-level isolation and made recovery actions available without requiring a browser refresh.
- Hardened dashboard rendering against incomplete/empty aggregate API arrays.
- Preserved stale-request protection in the shared data-loading hook.
- JSX syntax checked across the complete frontend source tree.

## 1.3.0 — Windows Telemetry Expansion

- Added bounded read-only Windows Event Log collector with controlled process, logon, privilege, service-change and PowerShell event families.
- Added prioritized Sysmon event collector for Events 1, 3, 7, 8, 10, 11, 12/13/14 and 22.
- Expanded process evidence with parent PID and bounded command-line metadata for PowerShell analysis.
- Added PowerShell rules: encoded/hidden execution indicators, suspicious parent, network activity and child processes.
- Added Windows service inventory and service-path review rules.
- Added persistence correlation across startup/Registry Run keys, scheduled tasks and services.
- Added Windows Telemetry UI and investigation-detail telemetry tab.
- Added Windows telemetry HTML reporting and DSL example.
- Hardened SPA route recovery and removed the InvestigationDetail React hook-order crash path.
- 49 automated tests passing.

## 1.7.0 — Remote Endpoint Operations

- Persistent RANDAR remote-agent registry
- Capability negotiation via agent heartbeat
- Agent capability dashboard
- Secure job nonce/expiration/signature metadata
- Safe job cancellation and cancellation-aware result submission
- RANDAR agent branding with JOCKY compatibility aliases
- V1.7 regression coverage
