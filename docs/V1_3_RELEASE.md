# RANDAR V1.3 — Windows Telemetry Expansion

**Version:** 1.3.1  
**Scope:** Windows endpoint telemetry and investigation leads

## Objective

V1.3 builds the focused Windows investigation pack defined by the roadmap: PowerShell indicators, controlled Windows Event Log telemetry, prioritized Sysmon events, Windows services, and persistence correlation.

The implementation is read-only. JOCKY does not execute user-supplied PowerShell, inject code, create remote threads, modify process memory, disable security controls, or install persistence.

## PowerShell analysis

The following rules are available:

- `encoded_powershell`
- `suspicious_powershell_parent`
- `powershell_network_activity`
- `powershell_child_processes`

The process collector now records a bounded command line and parent PID where the operating system permits access. PowerShell rules also consume controlled PowerShell Event Log evidence.

Indicators include:

- `powershell.exe` / `pwsh.exe`
- encoded-command switches with base64-like arguments
- hidden/non-interactive execution indicators
- PowerShell launched by selected document/script-host/management parents
- active remote network connections owned by PowerShell
- child processes spawned by PowerShell

These are review leads and require analyst context.

## Windows Event Log

Collector: `windows_event_logs`

The collector queries a fixed allowlist:

- `Security`
- `System`
- `Microsoft-Windows-PowerShell/Operational`

Controlled event families include:

- 4688 — process creation
- 4624/4625/4634/4647 — logon activity
- 4672 — special privilege assignment
- 7045 — service installation/change
- 4103/4104 — PowerShell activity

Only normalized metadata and named event fields are retained. Collection is bounded to prevent unbounded log retrieval.

For offline demonstrations and tests, an operator may set `JOCKY_WINDOWS_EVENT_LOG_FIXTURE` to a bounded XML export. The DSL cannot choose this path.

## Sysmon

Collector: `sysmon_events`

Prioritized event IDs:

- 1 — process creation
- 3 — network connection
- 7 — image load
- 8 — remote thread
- 10 — process access
- 11 — file creation
- 12/13/14 — registry
- 22 — DNS

The collector reads the fixed `Microsoft-Windows-Sysmon/Operational` channel and is bounded to 2,000 events. Offline fixture mode is available through the operator-controlled `JOCKY_SYSMON_EVENT_LOG_FIXTURE` environment variable.

## Services

Collector: `services`

Windows service evidence includes:

- service name
- display name
- executable
- command line
- account
- state
- start mode
- path existence
- writable-path indicator

Rules:

- `suspicious_services`
- `writable_service_paths`

The collector uses fixed read-only `sc.exe` queries and never executes a service command line.

## Persistence correlation

Rule: `persistence_correlation`

JOCKY correlates:

```text
Startup / Registry Run keys
          +
Scheduled Tasks
          +
Windows Services
          ↓
Common executable path
          ↓
Possible persistence correlation
```

Registry Run and RunOnce evidence is represented by the existing `startup_items` collector, which already reads those keys read-only.

## DSL

Example:

```text
investigation "Windows Telemetry Hunt" {
    collect system_info;
    collect processes;
    collect network_connections;
    collect windows_event_logs;
    collect sysmon_events;
    collect services;
    collect startup_items;
    collect scheduled_tasks;

    analyze encoded_powershell;
    analyze suspicious_powershell_parent;
    analyze powershell_network_activity;
    analyze powershell_child_processes;
    analyze suspicious_services;
    analyze writable_service_paths;
    analyze persistence_correlation;

    report "windows_telemetry_hunt";
}
```

## UI

V1.3 adds:

- dedicated **Windows Telemetry** workspace
- one-click Windows telemetry hunt
- investigation selector
- Event Log / Sysmon / service collection status
- PowerShell/service/persistence indicator counters
- per-finding supporting evidence
- Windows Telemetry tab inside investigation details
- catalog visibility for all V1.3 collectors and rules

## Reporting

HTML reports include a **Windows telemetry** section with collection counts and V1.3 findings.

JSON reports continue to use the existing report hash and integrity verification mechanism.

## Frontend stability maintenance

V1.3 also hardens the SPA route error boundary:

- route errors no longer leave the content area silently blank
- application-root render failures are contained by a second recovery boundary
- dashboard aggregate rendering tolerates incomplete/empty host and rule arrays
- navigation gets a fresh error-boundary instance using the router location key
- the existing InvestigationDetail hook-order defect is removed
- the application can retry a failed view without requiring a full browser refresh

## Tests

V1.3 acceptance coverage includes:

- Windows Event Log XML parsing
- Sysmon event filtering
- PowerShell encoded/hidden indicators
- PowerShell parent/child relationships
- PowerShell network correlation
- service rules
- persistence correlation
- collector/rule registration
- full V1.3 DSL validation
- HTML report generation
- V1.0–V1.2 regression coverage

Final automated result for this release: **49 tests passing**.

## Platform limitation

Live Windows Event Log, Sysmon and service collection require a Windows host and may require appropriate privileges. On non-Windows hosts the collectors return an explicit unsupported result rather than fabricating Windows telemetry.

## Product boundary

V1.3 remains forensic triage. PE static analysis and strengthened injection/PE correlation remain V1.4 scope; broader DSL filtering/boolean expressions remain V1.5 scope.
