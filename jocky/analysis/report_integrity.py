"""Report schema validation and evidence-reference helpers."""
from __future__ import annotations
import hashlib, json
from typing import Any

REQUIRED_FINDING_FIELDS = ("finding_id", "evidence_refs", "limitations", "next_check")

def canonical_snapshot_hash(collector_results) -> str:
    parts = [cr.evidence_hash for cr in collector_results if getattr(cr, "evidence_hash", None)]
    return hashlib.sha256("|".join(sorted(parts)).encode()).hexdigest()

def validate_report_schema(report) -> None:
    errors = []
    for idx, finding in enumerate(report.findings):
        for field in REQUIRED_FINDING_FIELDS:
            value = getattr(finding, field, None)
            if value is None or value == "" or (field == "evidence_refs" and not isinstance(value, list)):
                errors.append(f"finding[{idx}] missing {field}")
    if not report.execution_status:
        errors.append("execution_status is empty")
    if not report.termination_reason:
        errors.append("termination_reason is required")
    if errors:
        raise ValueError("Report schema validation failed: " + "; ".join(errors))

def record_refs(collector_name: str, data: dict[str, Any] | None, related: dict[str, Any], evidence_hash: str | None) -> list[dict[str, Any]]:
    if not data or not isinstance(data, dict):
        return []
    candidates = []
    for key in ("processes", "services", "tasks", "items", "events", "drivers", "modules", "connections", "users", "sessions", "records", "findings"):
        value = data.get(key)
        if isinstance(value, list):
            candidates = value
            break
    if not candidates:
        return []
    needles = {str(v).casefold() for k, v in related.items() if v not in (None, "") and k not in {"snapshot_hash", "merged_rules"}}
    refs = []
    for index, row in enumerate(candidates):
        if not isinstance(row, dict):
            continue
        def flatten(value):
            if isinstance(value, dict):
                for vv in value.values():
                    yield from flatten(vv)
            elif isinstance(value, list):
                for vv in value:
                    yield from flatten(vv)
            elif isinstance(value, (str, int, float)):
                yield str(value)
        hay = {v.casefold() for v in flatten(row)}
        if needles and not (needles & hay):
            continue
        refs.append({"collector": collector_name, "evidence_hash": evidence_hash, "record_index": index})
        if len(refs) >= 8:
            break
    return refs


def verify_evidence_hashes(report) -> dict[str, bool]:
    """Independently verify each stored collector evidence hash."""
    results = {}
    for cr in report.collector_results:
        if cr.status != "success" or not cr.evidence_hash:
            results[cr.target] = False if cr.status == "success" else True
            continue
        canonical = json.dumps(cr.data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        results[cr.target] = hashlib.sha256(canonical).hexdigest() == cr.evidence_hash
    return results
