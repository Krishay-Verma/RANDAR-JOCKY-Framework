# RANDAR V1.5 — Forensics-as-Code DSL

## Scope

V1.5 makes the controlled DSL a first-class investigation interface while retaining the allowlisted, non-shell-executing safety boundary.

## DSL capabilities

### Comments
```text
// Investigate PowerShell network activity
```

### Variables
```text
let target = "powershell.exe";
```

### Evidence filtering
```text
analyze network_beaconing
where destination.port == 443;
```

`where` evaluates only approved finding properties. Current finding properties include process name/PID, destination address/port/external classification, source address/port, module name/path, and source rule.

### Boolean logic
```text
analyze network_beaconing
where process.name == "powershell.exe"
and destination.is_external == true;
```

Supports `and`, `or`, and `not` with bounded condition trees.

### User-defined rules
```text
rule "PowerShell External Network Activity" {
    when process.name == "powershell.exe"
       and destination.is_external == true;

    severity high;
}
```

User rules operate only on findings already produced by registered JOCKY analysis rules. They cannot execute commands, Python, PowerShell, arbitrary code, or arbitrary evidence traversal.

## Long-running investigation execution

Domain Expansion Triage is submitted through a bounded background job endpoint. The browser polls job status rather than holding a single request open for the entire sweep. Existing short investigations retain synchronous execution.

## Safety

- No shell execution
- No arbitrary Python execution
- No unrestricted filesystem traversal
- Collector and analysis names remain registry-allowlisted
- Signed bytecode validates V1.5 conditions and user-rule structure before execution
- Background jobs are bounded to a small in-memory queue and worker pool

## Verification

The V1.5 regression suite contains 65 passing tests, including V1.0–V1.4 regressions, DSL parsing/evaluation, signed bytecode round-trip, and background investigation job execution.
