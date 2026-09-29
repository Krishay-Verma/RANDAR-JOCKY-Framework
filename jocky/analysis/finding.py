"""
Finding: the output of an analysis rule.

A Finding is an observation about evidence, not an accusation. It must
always be traceable back to specific evidence (e.g. a PID or file path)
so a human investigator can verify it themselves. Severity is
informational by design — see SEVERITY note below.
"""

from dataclasses import dataclass, field


# Severity is deliberately limited to non-alarmist language. JOCKY does
# not have enough context to know if something is malicious - it can
# only say "this pattern is present and worth a human look."
SEVERITY_INFO = "informational"
SEVERITY_REVIEW = "review_recommended"

SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Ordered lowest to highest. The extended rules emit medium/high/critical,
# so the scale is defined once here and shared with the API and UI.
SEVERITY_ORDER = [
    SEVERITY_INFO, SEVERITY_REVIEW, SEVERITY_MEDIUM,
    SEVERITY_HIGH, SEVERITY_CRITICAL,
]
VALID_SEVERITIES = set(SEVERITY_ORDER)


@dataclass
class Finding:
    rule_name: str
    severity: str
    summary: str          # one-line human-readable description
    reason: str             # why this rule fired
    related_evidence: dict  # e.g. {"pid": 1234, "path": "..."}
    finding_id: str | None = None
    evidence_refs: list[dict] = field(default_factory=list)
    limitations: str | None = None
    next_check: str | None = None