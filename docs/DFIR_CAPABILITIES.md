# JOCKY DFIR Capabilities Reference

## 1. Collector matrix

| Capability | Windows | Linux | Primary use |
|---|:---:|:---:|---|
| System information | ✓ | ✓ | Establish host context. |
| Processes | ✓ | ✓ | Identify running programs, owners and paths. |
| Network connections | ✓ | ✓ | Establish process/network relationships. |
| Logged-in users | ✓ | ✓ | Identify active sessions. |
| File hashing | ✓ | ✓ | Produce stable file identifiers in an approved evidence directory. |
| Scheduled tasks / cron | ✓ | ✓ | Identify persistence mechanisms. |
| Startup items | ✓ | ✓ | Identify startup/persistence entries. |
| Open files | ✓ | ✓ | Link processes to opened files/handles. |
| Local users | ✓ | ✓ | Establish account context. |
| Loaded modules | ✓ | — | Windows DLL/EXE/SYS inventory. |
| Threads | ✓ | — | Windows thread metadata. |
| Memory regions | ✓ | — | Windows virtual-memory metadata. |

A Windows-only collector returns an explicit unsupported result on other operating systems.

---

## 2. Analysis matrix

| Rule | Main evidence | Purpose |
|---|---|---|
| `missing_paths` | processes | Highlight processes whose executable path is unavailable. |
| `suspicious_processes` | processes | Flag executables from temporary/download-style locations. |
| `process_network_correlation` | processes + network | Connect network activity to processes. |
| `unusual_scheduled_tasks` | scheduled tasks | Identify persistence entries requiring review. |
| `suspicious_startup_items` | startup items | Identify unusual startup/persistence paths. |
| `high_connection_processes` | network + processes | Identify connection-count outliers and selected remote ports. |
| `privileged_user_anomaly` | users + processes | Identify account/ownership patterns requiring review. |
| `suspicious_module_loads` | modules | Identify modules loaded from user-writable paths. |
| `dll_sideloading` | modules + processes | Identify modules outside expected process directories. |
| `process_hollowing_indicators` | memory regions + processes | Identify private executable-memory patterns. |
| `reflective_load_indicators` | memory regions | Surface executable private memory as a review lead. |
| `thread_hijacking_indicators` | threads + memory regions | Correlate thread starts with private executable memory. |
| `injection_correlation` | modules + memory regions + processes | Combine independent injection-related indicators. |

---

## 3. Interpreting severity

JOCKY uses:

```text
informational
review_recommended
medium
high
critical
```

Severity describes the priority of human review, not certainty of maliciousness.

A `high` finding means the evidence pattern is important enough to investigate. It does not mean JOCKY has proven malware or compromise.

---

## 4. Windows DLL/injection interpretation

### Suspicious module load

A loaded module is associated with a path commonly writable by a non-administrator user.

**Why it matters:** writable module locations can be abused for module replacement or unexpected loading.

**Why it is not proof:** legitimate applications can load plugins or user-controlled modules from such locations.

### DLL sideloading

A DLL is observed outside the process executable directory and outside standard system paths.

**Why it matters:** unexpected search-path behavior can be relevant to sideloading investigations.

### Process hollowing indicator

A process has multiple private executable memory regions.

**Why it matters:** private executable memory can be associated with injected or unpacked code.

**Important caveat:** JIT engines, browsers, runtimes, debuggers, and security products can legitimately create executable private regions.

### Reflective-loading lead

Executable private memory exists without being represented as a conventional loaded module.

This is a lead for further analysis, not a standalone verdict.

### Thread anomaly

A thread start address falls within private executable memory.

This may deserve review in an injection investigation, while also having legitimate explanations in complex runtime environments.

### Injection correlation

The rule looks for multiple independent signals on the same process. Correlation is stronger than a single indicator, but it remains an analyst lead.

---

## 5. Evidence limits

The Windows advanced collectors intentionally use bounds to prevent runaway enumeration. They prioritize predictable collection over exhaustive memory acquisition.

Examples of bounded behavior include:

- maximum process counts;
- maximum module counts;
- maximum thread counts;
- maximum memory regions per process/overall;
- maximum module hashing volume;
- maximum module hash size.

These limits should be reviewed before production deployment if endpoint populations differ significantly from the project's test environment.

---

## 6. What the Windows memory collector does not do

The memory-region collector obtains metadata such as:

- base address
- region size
- state
- protection
- type
- executable/private classification

It does **not** dump arbitrary process memory or write to it.

This keeps the collector in the metadata/triage layer rather than turning it into a memory acquisition or process-manipulation tool.
