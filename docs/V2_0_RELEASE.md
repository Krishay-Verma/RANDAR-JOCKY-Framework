# RANDAR v2.0.0 — Controlled Security Research & Detection

## Scope

V2.0 extends the v1.9.2 forensic foundation with two defensive research
surfaces requested by SIH26148:

1. **In-memory execution observation** — correlation of virtual-memory,
   thread-start, and loaded-module artifacts.
2. **BYOVD exposure detection** — read-only Windows driver inventory with an
   operator-supplied vulnerable-driver catalog.

The implementation is deliberately detection/measurement oriented. It does
not implement process hollowing, reflective DLL injection, API unhooking,
direct-syscall execution, thread hijacking, driver exploitation, callback
disabling, kernel-structure modification, or security-product bypass.

## New collector

`driver_inventory`

- Windows Service/driver metadata
- image path and existence
- SHA-256 for bounded driver images
- user-writable/system-path classification
- optional local vulnerability catalog correlation

Configure the optional catalog with `RANDAR_VULNERABLE_DRIVER_DB`. The file is
JSON keyed by driver filename or service name, for example:

```json
{
  "exampledriver.sys": {
    "known_vulnerable": true,
    "ids": ["LOCAL-LAB-001"],
    "source": "internal-lab-catalog"
  }
}
```

No remote exploit database is required for the collector to operate.

## New analysis rules

### `in_memory_execution_indicators`

Correlates:

- private executable memory;
- thread start addresses inside those regions;
- user-writable loaded modules.

A finding is a review lead, not proof that an in-memory technique occurred.

### `byovd_driver_indicators`

Flags:

- known-vulnerable catalog matches;
- driver images in user-writable paths;
- missing registered driver images.

The rule reports evidence and provenance without altering kernel state.

## V2.0 architecture

```text
JOCKY source
   ↓
Lexer → Parser → IR
   ↓
Controlled interpreter
   ├── Existing forensic collectors
   ├── memory_regions ───────┐
   ├── threads ──────────────┼→ in-memory correlation
   ├── modules ──────────────┘
   └── driver_inventory ─────→ BYOVD exposure detection
   ↓
Evidence + Findings + Provenance
```

## Validation

V2.0 keeps the existing allowlist model: JOCKY scripts can reference only
registered collectors and analysis rules. Research modules remain passive
observation components.

## Authorized laboratory scenario runner

V2.0 now includes `jocky.research.lab`, a deterministic synthetic-observation
runner for demonstrations and regression tests. It models the forensic
artifacts that RANDAR correlates for in-memory execution and BYOVD exposure;
it does not perform process injection, driver exploitation, kernel
modification, or security-control bypass.

Run:

```bash
python -m jocky.research.lab --scenario in-memory-byoVD-lab --output lab-result.json
```

A clean control scenario is also available:

```bash
python -m jocky.research.lab --scenario clean
```
