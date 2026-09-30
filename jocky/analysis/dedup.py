"""Low-noise finding deduplication and stable subject identity."""
from __future__ import annotations
import json
import re
from typing import Any

_RULE_FAMILIES = {
    "suspicious_services": "service_writable",
    "writable_service_paths": "service_writable",
    "persistence_correlation": "persistence_shared_path",
    "persistence_cross_surface_correlation": "persistence_shared_path",
}

def _norm(value: Any) -> str:
    text = str(value or "").strip().replace("/", "\\")
    return re.sub(r"\\+", lambda _m: "\\", text).casefold()

def finding_subject(finding) -> str:
    e = finding.related_evidence or {}
    for key in ("subject", "service_name", "task_name", "name", "pid", "path", "executable", "command_line", "remote_address"):
        if key in e and e.get(key) not in (None, ""):
            return _norm(e.get(key))
    for container_key in ("service", "task", "item", "process", "record"):
        obj = e.get(container_key)
        if isinstance(obj, dict):
            for key in ("service_name", "task_name", "name", "pid", "path", "executable", "command", "task_to_run"):
                if obj.get(key) not in (None, ""):
                    return _norm(obj.get(key))
    return json.dumps(e, sort_keys=True, default=str, separators=(",", ":"))

def finding_key(finding) -> tuple[str, str]:
    return (_RULE_FAMILIES.get(finding.rule_name, finding.rule_name), finding_subject(finding))

def deduplicate_findings(findings: list) -> list:
    """Keep one finding per semantic rule family + subject.

    When two legacy rules describe the same condition, the higher-severity
    representative is retained and its reason records the merged rule names.
    """
    severity = {"informational": 0, "review_recommended": 1, "medium": 2, "high": 3, "critical": 4}
    out: dict[tuple[str, str], Any] = {}
    aliases: dict[tuple[str, str], set[str]] = {}
    for finding in findings:
        key = finding_key(finding)
        aliases.setdefault(key, set()).add(finding.rule_name)
        current = out.get(key)
        if current is None or severity.get(finding.severity, 0) > severity.get(current.severity, 0):
            out[key] = finding
    result = []
    for key, finding in out.items():
        names = sorted(aliases[key])
        if len(names) > 1:
            finding.related_evidence = dict(finding.related_evidence or {})
            finding.related_evidence["merged_rules"] = names
        result.append(finding)
    return sorted(result, key=lambda f: (severity.get(f.severity, 0), f.rule_name, finding_subject(f)))
