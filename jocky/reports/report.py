"""
Report dataclass — the structured output of one completed investigation.

script_hash: SHA-256 of the JOCKY script source that produced this report.
             Provides a tamper-evident link between the script and its output.
report_hash: SHA-256 of canonical report content, excluding report_hash itself.
             Allows stored/exported reports to be independently integrity-checked.
"""

from dataclasses import asdict, dataclass, field
from typing import Optional
import hashlib
import json


@dataclass
class CollectorResult:
    target: str
    status: str        # "success" | "error" | "timeout" | "cancelled"
    data: Optional[dict] = None
    error: Optional[str] = None
    evidence_hash: Optional[str] = None
    duration_ms: int = 0
    record_count: int = 0
    truncated: bool = False
    resource_bytes: int = 0


@dataclass
class AnalysisResult:
    target: str
    status: str
    finding_count: int = 0
    error: Optional[str] = None


@dataclass
class Finding:
    rule_name: str
    severity: str
    summary: str
    reason: str
    related_evidence: dict = field(default_factory=dict)
    finding_id: str | None = None
    evidence_refs: list[dict] = field(default_factory=list)
    limitations: str | None = None
    next_check: str | None = None


@dataclass
class Report:
    investigation_name: str
    endpoint_hostname: str
    started_at: str
    finished_at: str
    collector_results: list
    analysis_results: list
    findings: list
    collector_errors: list
    report_name: Optional[str]  = None
    script_hash: Optional[str]  = None   # SHA-256 of the source script
    report_hash: Optional[str] = None   # SHA-256 of canonical report content
    source: dict = field(default_factory=dict)  # local/agent provenance metadata
    product_name: str = "RANDAR"
    product_version: str = "3.0.0"
    dsl_name: str = "JOCKY"
    dsl_version: str = "1.5"
    bytecode_hash: Optional[str] = None
    timeline: list = field(default_factory=list)
    execution_status: str = "complete"
    termination_reason: Optional[str] = None
    elapsed_ms: int = 0
    resource_usage: dict = field(default_factory=dict)
    software_summary: dict = field(default_factory=dict)
    elevation: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    integrity_version: int = 6


def compute_report_hash(report: "Report") -> str:
    """Return the SHA-256 digest of the report excluding its own digest."""
    data = asdict(report)
    data["report_hash"] = None
    integrity_version = data.get("integrity_version", 1)
    if integrity_version < 6:
        data.pop("elevation", None)
        data.pop("coverage", None)
        data.pop("summary", None)
    if integrity_version < 5:
        data.pop("software_summary", None)
    if integrity_version < 4:
        data.pop("execution_status", None)
        data.pop("termination_reason", None)
        data.pop("elapsed_ms", None)
        data.pop("resource_usage", None)
    if integrity_version < 2:
        data.pop("integrity_version", None)
        for finding in data.get("findings", []):
            finding.pop("finding_id", None)
            finding.pop("evidence_refs", None)
        for finding in data.get("findings", []):
            if integrity_version < 3:
                finding.pop("limitations", None)
                finding.pop("next_check", None)
        for collector in data.get("collector_results", []):
            collector.pop("evidence_hash", None)
            collector.pop("duration_ms", None)
            collector.pop("record_count", None)
            collector.pop("truncated", None)
            collector.pop("resource_bytes", None)
        for key in ("product_name", "product_version", "dsl_name", "dsl_version", "bytecode_hash", "timeline"):
            data.pop(key, None)
    # Empty source metadata is omitted for compatibility with reports created
    # before remote provenance was added; populated source metadata is hashed.
    if not data.get("source"):
        data.pop("source", None)
    # Empty analysis coverage is omitted for compatibility with reports created
    # before rule-execution coverage was recorded. New full investigations
    # populate this field and therefore bind it into the integrity hash.
    if not data.get("analysis_results"):
        data.pop("analysis_results", None)
    canonical = json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_report_integrity(report: "Report") -> bool:
    """Verify the stored report digest without modifying the report."""
    if not report.report_hash:
        return False
    return compute_report_hash(report) == report.report_hash
