# RANDAR v3.0.0 Final — Product Definition

## Purpose

RANDAR provides reproducible endpoint and network forensic triage through a small investigation language, JOCKY. A JOCKY investigation declares evidence surfaces, analysis rules, correlations, and a report. The runtime enforces explicit collector/rule registries and bounded execution.

## What makes the implementation functional

Every major capability produces machine-readable evidence and testable output rather than a documentation-only feature:

- collectors return structured records;
- collector evidence receives hashes;
- analysis rules produce typed findings;
- findings receive stable IDs and evidence references;
- correlation combines independent evidence surfaces;
- reports include execution status, coverage, elevation, timeline, provenance, and integrity data;
- the web console consumes the same report model used by the API/CLI.

## Forensic finding model

A finding contains:

```json
{
  "finding_id": "deterministic-id",
  "rule_name": "rule-name",
  "severity": "review_recommended",
  "summary": "human-readable lead",
  "reason": "evidence-based explanation",
  "related_evidence": {},
  "evidence_refs": [
    {"collector": "services", "evidence_hash": "...", "record_index": 4}
  ],
  "limitations": "what this evidence cannot prove",
  "next_check": "specific follow-up for an analyst"
}
```

A finding is a forensic lead, not an automatic malware verdict.

## Integrity

`script_hash` binds the report to the exact JOCKY source. `bytecode_hash` binds it to the compiled representation when bytecode execution is used. Each collector has an `evidence_hash`. `report_hash` covers the canonical report representation according to the current integrity version.

This allows a reviewer to validate the report as a whole and to validate collector evidence independently.

## Execution honesty

The report records:

- `execution_status`
- `termination_reason`
- elevation/admin state
- collectors that were unavailable or degraded
- collector confidence
- truncation status
- access/installation limitations

A standard-user run is therefore not represented as equivalent to an elevated full-coverage acquisition.
