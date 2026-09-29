# RANDAR V1.6 — Evidence & Forensic Integrity

## Product identity
RANDAR is the forensic triage platform. JOCKY is RANDAR's controlled Forensics-as-Code investigation language.

## Product identity

RANDAR is the forensic triage platform. JOCKY is RANDAR’s controlled Forensics-as-Code DSL.

## Delivered
- Evidence timeline from timestamped endpoint/network metadata.
- Provenance chain: script → script hash → IR → signed bytecode → collection → evidence → analysis → finding → report.
- Append-only SQLite audit log recording user, timestamp, action, investigation, script hash and result/report hash.
- Report verification exposes script, bytecode and report hashes.
- Findings receive stable IDs and explicit evidence references for UI navigation.
- HTML/JSON reports include provenance, timeline and finding identifiers.
- Backward-compatible reconstruction of older reports.

## Acceptance
- Existing V1.0–V1.5 regression suite remains passing.
- Integrity verification remains mandatory for report export.
- No offensive execution behavior added.


## Compatibility

The platform now presents itself as RANDAR. Existing JOCKY environment variables remain accepted as backward-compatible aliases, and existing `.jocky` investigation scripts remain valid.
