# RANDAR V1.8 — Investigation Experience

## Objective

Improve investigation usability without repeatedly redesigning the core collection, analysis or JOCKY execution architecture.

## Global evidence search

The console now provides a protected global search endpoint and UI covering: PID, IP address, domain, hash, file/path, username, finding text and stored case metadata. Search results remain concise and link directly to the owning investigation.

The search is bounded and read-only; it does not modify forensic reports or expose complete evidence documents in the result list.

## Finding filters

Investigation findings can be filtered by: **All, High, Review, Network, Injection / PE, Persistence, PowerShell**, in addition to the existing severity filters.

## Evidence drawer

Finding evidence references can open a contextual drawer containing the exact collector/property/value reference and the corresponding collected evidence. Analysts can pivot without losing their place in the findings view.

## Explainable findings

Each newly generated finding now carries: 

- What happened
- Why it was flagged
- Supporting evidence
- Limitations
- Recommended next check

These remain indicators for human review, not definitive malware determinations.

## Investigation summary

The case view surfaces: 

- objects collected
- total indicators
- high-severity indicators
- network indicators
- injection / PE indicators
- persistence indicators
- PowerShell indicators

## Integrity compatibility

The report integrity model advances to version 3 for newly generated reports. Verification logic explicitly preserves compatibility with older V1.6/V1.7 report shapes so adding explanation metadata does not invalidate existing stored evidence.

## Verification

- 78/78 regression tests passing
- Python compilation passing
- frontend dependency lockfile dry-run resolves 172 packages
- production frontend build not verified because the environment could not complete `npm ci` before transport timeout
