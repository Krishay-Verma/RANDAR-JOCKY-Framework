# RANDAR DFIR Capabilities Reference

**Implementation baseline:** v1.9.2

This document describes the capabilities currently registered in the source code.

## 1. Collector matrix

### Cross-platform collectors

| Collector | Evidence surface | Key boundaries |
|---|---|---|
| `system_info` | Host identity, OS, architecture, CPU, memory, current user | Host metadata only |
| `processes` | Running processes, paths, owners, start time | Access restrictions can hide fields |
| `network_connections` | Active network sockets | Point-in-time state |
| `network_artifacts` | Normalized DNS/connection evidence | Uses supported evidence sources; no payload retention |
| `logged_in_users` | Interactive sessions | Point-in-time state |
| `file_hash` | SHA-256 for operator-approved evidence directory | Directory is fixed by operator configuration |
| `scheduled_tasks` | Task Scheduler / cron | Platform-specific surfaces |
| `startup_items` | Startup/Run/system startup surfaces | Platform-specific surfaces |
| `open_files` | Bounded open-file/handle inventory | Access-dependent and bounded |
| `local_users` | Local accounts | Does not read `/etc/shadow` |

### Windows collectors

| Collector | Evidence surface | Key boundaries |
|---|---|---|
| `modules` | Loaded file-backed modules | Bounded inventory; selective hashing |
| `threads` | Process/thread metadata | No thread modification |
| `memory_regions` | Virtual-memory metadata | No memory contents read |
| `windows_event_logs` | Bounded Windows event metadata | Fixed event/channel scope |
| `sysmon_events` | Selected Sysmon event IDs | Bounded event collection |
| `services` | Service state/configuration metadata | Metadata only |
| `pe_metadata` | PE structure, imports, exports, entropy, hash, signature metadata | Bounded file count/size |

**Total: 17 registered collectors.**

---

## 2. Analysis matrix

### Endpoint/process

| Rule | Interpretation |
|---|---|
| `missing_paths` | Executable path could not be determined |
| `suspicious_processes` | Process executable is in a commonly user-writable/unusual location |
| `process_network_correlation` | Links process evidence with network connections |
| `high_connection_processes` | Connection-count outlier / configured network behavior lead |
| `privileged_user_anomaly` | Cross-correlates account privilege and process ownership |

### Persistence / Windows telemetry

| Rule | Interpretation |
|---|---|
| `unusual_scheduled_tasks` | Task persistence patterns requiring review |
| `suspicious_startup_items` | Startup entries outside expected locations |
| `encoded_powershell` | Encoded/hidden/non-interactive PowerShell indicators |
| `suspicious_powershell_parent` | PowerShell launched by a context requiring review |
| `powershell_network_activity` | PowerShell associated with active network activity |
| `powershell_child_processes` | PowerShell child-process relationships |
| `suspicious_services` | Service executable/path characteristics requiring review |
| `writable_service_paths` | Writable service executable or parent directory |
| `persistence_correlation` | Common executable observed across persistence surfaces |

### Network threat hunting

| Rule | Interpretation |
|---|---|
| `suspicious_dns_queries` | Configured DNS review patterns |
| `dns_entropy` | High-entropy labels |
| `rare_domains` | Low-prevalence domains in the supplied evidence |
| `suspicious_tld_patterns` | Configured review TLD patterns |
| `dns_bursts` | Repeated/high-volume DNS activity |
| `unusual_query_types` | Uncommon DNS query types |
| `long_random_labels` | Long/random-looking labels |
| `dns_tunneling_indicators` | Combined tunnelling characteristics |
| `dns_beaconing` | Repeated DNS intervals with low jitter |
| `network_beaconing` | Repeated network connection intervals |
| `port_scan` | One source contacting many ports |
| `horizontal_scan` | One source contacting one service across hosts |
| `service_discovery` | Systematic contact with common infrastructure ports |
| `udp_scan` | Repeated UDP probe pattern |
| `network_classification` | Descriptive address classification |

### Windows module/injection forensics

| Rule | Interpretation |
|---|---|
| `suspicious_module_loads` | Modules loaded from commonly writable paths |
| `dll_sideloading` | DLL location inconsistent with owning executable directory |
| `process_hollowing_indicators` | Private executable memory correlated with process evidence |
| `reflective_load_indicators` | Executable private memory without a corresponding module path |
| `thread_hijacking_indicators` | Thread start address associated with private executable memory |
| `injection_correlation` | Combines independent injection indicators |

### PE/module analysis

| Rule | Interpretation |
|---|---|
| `unsigned_loaded_module` | Loaded PE lacks embedded signature metadata |
| `suspicious_imports` | Imports APIs associated with process/memory manipulation |
| `high_entropy_module` | PE/section entropy requires file-level review |
| `module_disk_mismatch` | Loaded module and disk evidence disagree or cannot be correlated |
| `suspicious_writable_module` | Writable path or executable+writable PE characteristic |

**Total: 40 registered analysis rules.**

---

## 3. Severity semantics

RANDAR severity is a triage priority, not a probability of compromise.

| Severity | Meaning |
|---|---|
| `informational` | Contextual evidence |
| `review_recommended` | Evidence worth analyst review |
| `medium` | Higher-priority review lead |
| `high` | Significant correlation or anomaly requiring prompt validation |
| `critical` | Reserved for rules whose implementation explicitly assigns this level |

A finding can be high-severity without proving maliciousness.

---

## 4. Windows injection interpretation

### Suspicious module load

A module path falls into a commonly writable category.

**Interpretation:** review path, signer, hash and process context.

### DLL sideloading

A DLL is loaded outside the owning executable's directory.

**Interpretation:** this is a correlation lead, not proof of sideloading.

### Process-hollowing indicator

Private executable memory is correlated with process evidence.

**Interpretation:** validate with additional memory/process telemetry.

### Reflective-loading lead

Executable private memory exists without a corresponding module path.

**Interpretation:** investigate the memory/process context; legitimate software can allocate executable private memory.

### Thread anomaly

A thread start address lands in private executable memory.

**Interpretation:** investigate thread origin and process behavior.

### Injection correlation

Multiple independent indicators are combined.

**Interpretation:** stronger investigative context, still not a malware verdict.

---

## 5. PE metadata coverage

`pe_metadata` parses bounded PE structures without executing the file.

Current metadata includes:

- architecture;
- PE32/PE32+;
- image base;
- section information;
- section entropy;
- section permissions;
- imports;
- exports;
- SHA-256;
- overall entropy;
- embedded signature metadata;
- signer metadata when certificate extraction succeeds.

The collector is bounded by file count, file size, import/export count and section count.

---

## 6. Network evidence limits

Network hunting operates on normalized evidence supplied through the supported network evidence collector.

It should not be described as:

- full packet reconstruction;
- payload inspection;
- encrypted traffic decryption;
- enterprise-scale network detection.

The intended role is **repeatable evidence-driven network triage**.

---

## 7. Evidence interpretation

All rules should be treated as hypotheses generated from evidence.

The correct analyst workflow is:

```text
Finding
  ↓
Supporting evidence
  ↓
Context / baseline
  ↓
Additional pivot
  ↓
Analyst conclusion
```

RANDAR intentionally avoids converting a single telemetry pattern into an automatic malware verdict.
