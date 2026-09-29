# RANDAR V1.4 — Injection & PE Forensics

## Objective

V1.4 strengthens JOCKY's existing Windows injection telemetry with bounded PE metadata and explicit module-to-disk correlation.

## New collector

### `pe_metadata`

Read-only, bounded metadata collection for executable files already observed through the Windows process/module inventory:

- architecture
- PE type (PE32 / PE32+)
- section names and sizes
- section entropy
- imports
- exports
- PE timestamp
- image size/base and subsystem metadata
- file entropy
- embedded signature presence
- extracted signer subject when the embedded PKCS#7 certificate set is parseable
- SHA-256

The collector does **not** execute, modify, inject, map for execution, or write PE files. It does not claim Windows trust-chain validation merely because a certificate is embedded.

## V1.4 rules

- `unsigned_loaded_module`
- `suspicious_imports`
- `high_entropy_module`
- `module_disk_mismatch`
- `suspicious_writable_module`

Existing injection rules remain available:

- `suspicious_module_loads`
- `dll_sideloading`
- `process_hollowing_indicators`
- `reflective_load_indicators`
- `thread_hijacking_indicators`
- `injection_correlation`

`injection_correlation` now incorporates static PE import evidence when it overlaps with runtime module/memory observations.

## DSL

```text
investigation "Windows Injection and PE Forensics" {
    collect system_info;
    collect processes;
    collect modules;
    collect threads;
    collect memory_regions;
    collect network_connections;
    collect pe_metadata;

    analyze suspicious_module_loads;
    analyze dll_sideloading;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;
    analyze unsigned_loaded_module;
    analyze suspicious_imports;
    analyze high_entropy_module;
    analyze module_disk_mismatch;
    analyze suspicious_writable_module;

    report "windows_injection_pe_forensics";
}
```

## UI

The DLL / injection workspace now includes:

- PE file count
- PE metadata table
- architecture and PE type
- section count and entropy
- signature metadata and signer when available
- SHA-256
- V1.4 PE/module findings

Investigation Detail exposes a **PE / Module** tab whenever the PE collector is present.

## Reporting

HTML reports include a dedicated **PE / module forensics** section containing bounded metadata and V1.4 findings. JSON reports retain the complete collector result and finding evidence under the existing report integrity mechanism.

## Safety boundary

V1.4 remains forensic and read-only. JOCKY does not:

- inject DLLs
- create remote threads
- suspend or hijack threads
- write arbitrary process memory
- disable security controls
- execute collected PE files
- perform active exploitation

PE/static and injection findings are investigation leads for human review, not definitive malware determinations.


## 1.4.1 — Stability & Full Capability Visibility

- Hardened navigation/data rendering against malformed or stale API response shapes.
- Added report-level analysis execution coverage: every executed rule is recorded with status and finding count, including zero-hit rules.
- Investigation Detail now exposes all capability tabs even when a collector was not selected, with explicit not-collected states.
- Added live registry coverage to the Dashboard and Investigation Builder so registered collectors/rules are visible rather than hidden behind version-specific UI lists.
- Added the **Domain Expansion Triage** template and example; it runs every currently registered collector and every currently registered analysis rule.
- Preserved report-hash compatibility with reports created before analysis execution coverage was introduced.
