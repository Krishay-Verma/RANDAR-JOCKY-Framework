"""V1.4 PE and module-correlation analysis.

All functions are pure analysis over already-collected evidence. They do not
open files, execute binaries, or modify processes.
"""
from __future__ import annotations

import os
from typing import Any

from jocky.analysis.finding import Finding, SEVERITY_HIGH, SEVERITY_REVIEW

_SUSPICIOUS_IMPORTS = {
    "writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory",
    "virtualallocex", "virtualprotectex", "createremotethread",
    "ntcreatethreadex", "zwcreatethreadex", "queueuserapc", "setthreadcontext",
    "getthreadcontext", "openprocess", "duplicatehandle", "mapviewoffile",
}


def _pe_files(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return evidence.get("pe_metadata", {}).get("files", []) or []


def _modules(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return evidence.get("modules", {}).get("modules", []) or []


def _index(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("path", "")).lower(): item
        for item in _pe_files(evidence)
        if item.get("path")
    }


def rule_unsigned_loaded_module(evidence: dict[str, Any]) -> list[Finding]:
    """Flag non-system loaded PE modules without embedded signature metadata."""
    pe = _index(evidence)
    findings: list[Finding] = []
    for module in _modules(evidence):
        if module.get("is_system_path"):
            continue
        path = str(module.get("module_path") or "")
        item = pe.get(path.lower())
        if not item or item.get("signature_status") != "unsigned":
            continue
        findings.append(Finding(
            rule_name="unsigned_loaded_module",
            severity=SEVERITY_REVIEW,
            summary=f"Loaded module '{module.get('module_name')}' has no embedded signature",
            reason=(
                "The loaded PE has no embedded Authenticode signature metadata. "
                "Unsigned software can be legitimate, so this is a review lead rather than a trust verdict."
            ),
            related_evidence={
                "pid": module.get("pid"),
                "process_name": module.get("process_name"),
                "module_path": path,
                "sha256": item.get("sha256"),
                "signature_status": item.get("signature_status"),
            },
        ))
    return findings


def rule_suspicious_imports(evidence: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    modules_by_path = {str(m.get("module_path") or "").lower(): m for m in _modules(evidence)}
    for item in _pe_files(evidence):
        imports = [str(v).lower() for v in item.get("imports", [])]
        matches = sorted({name for name in imports if name in _SUSPICIOUS_IMPORTS})
        if not matches:
            continue
        module = modules_by_path.get(str(item.get("path") or "").lower(), {})
        findings.append(Finding(
            rule_name="suspicious_imports",
            severity=SEVERITY_REVIEW,
            summary=f"PE '{item.get('filename')}' imports process/memory manipulation APIs",
            reason=(
                "The static import table contains APIs commonly used for process or memory manipulation. "
                "These APIs also have legitimate uses in debuggers, compatibility tools and security software."
            ),
            related_evidence={
                "pid": module.get("pid"),
                "process_name": module.get("process_name"),
                "path": item.get("path"),
                "sha256": item.get("sha256"),
                "matched_imports": matches,
            },
        ))
    return findings


def rule_high_entropy_module(evidence: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    modules_by_path = {str(m.get("module_path") or "").lower(): m for m in _modules(evidence)}
    for item in _pe_files(evidence):
        section_hits = [
            {"name": s.get("name"), "entropy": s.get("entropy")}
            for s in item.get("sections", [])
            if isinstance(s.get("entropy"), (int, float)) and s["entropy"] >= 7.2
        ]
        file_entropy = item.get("entropy")
        if not section_hits and not (isinstance(file_entropy, (int, float)) and file_entropy >= 7.2):
            continue
        module = modules_by_path.get(str(item.get("path") or "").lower(), {})
        findings.append(Finding(
            rule_name="high_entropy_module",
            severity=SEVERITY_REVIEW,
            summary=f"PE '{item.get('filename')}' has unusually high entropy",
            reason=(
                "High entropy can be produced by compression, encryption or packed content. "
                "It is not sufficient by itself to establish packing or maliciousness."
            ),
            related_evidence={
                "pid": module.get("pid"),
                "path": item.get("path"),
                "sha256": item.get("sha256"),
                "file_entropy": file_entropy,
                "high_entropy_sections": section_hits,
            },
        ))
    return findings


def rule_module_disk_mismatch(evidence: dict[str, Any]) -> list[Finding]:
    """Correlate loaded-module metadata with the corresponding disk PE."""
    pe = _index(evidence)
    findings: list[Finding] = []
    for module in _modules(evidence):
        path = str(module.get("module_path") or "")
        if not path:
            continue
        item = pe.get(path.lower())
        if item is None:
            # The PE collector may be unable to inspect a locked/deleted file.
            findings.append(Finding(
                rule_name="module_disk_mismatch",
                severity=SEVERITY_HIGH,
                summary=f"Loaded module '{module.get('module_name')}' has no matching disk PE record",
                reason=(
                    "The loaded-module inventory contains a path that was not represented in the bounded PE metadata collection. "
                    "The file may have changed, disappeared, or been inaccessible at collection time."
                ),
                related_evidence={
                    "pid": module.get("pid"),
                    "process_name": module.get("process_name"),
                    "module_path": path,
                    "loaded_sha256": module.get("sha256"),
                },
            ))
            continue
        loaded_hash = module.get("sha256")
        disk_hash = item.get("sha256")
        if loaded_hash and disk_hash and loaded_hash.lower() != disk_hash.lower():
            findings.append(Finding(
                rule_name="module_disk_mismatch",
                severity=SEVERITY_HIGH,
                summary=f"Loaded module '{module.get('module_name')}' hash differs from disk evidence",
                reason=(
                    "The loaded-module hash and the separately collected disk PE hash disagree. "
                    "This can result from a file changing between observations or from different hashing scope and requires timeline review."
                ),
                related_evidence={
                    "pid": module.get("pid"),
                    "process_name": module.get("process_name"),
                    "module_path": path,
                    "loaded_sha256": loaded_hash,
                    "disk_sha256": disk_hash,
                },
            ))
    return findings


def rule_suspicious_writable_module(evidence: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    modules_by_path = {str(m.get("module_path") or "").lower(): m for m in _modules(evidence)}
    for item in _pe_files(evidence):
        module = modules_by_path.get(str(item.get("path") or "").lower())
        if not module:
            continue
        writable_sections = [s.get("name") for s in item.get("sections", []) if s.get("executable") and s.get("writable")]
        if not module.get("is_user_writable") and not writable_sections:
            continue
        findings.append(Finding(
            rule_name="suspicious_writable_module",
            severity=SEVERITY_REVIEW,
            summary=f"Loaded PE '{item.get('filename')}' has a writable-risk characteristic",
            reason=(
                "The module is loaded from a commonly writable location or contains an executable+writable PE section. "
                "Legitimate installers, plugins and runtimes can exhibit these properties."
            ),
            related_evidence={
                "pid": module.get("pid"),
                "process_name": module.get("process_name"),
                "path": item.get("path"),
                "sha256": item.get("sha256"),
                "user_writable_path": bool(module.get("is_user_writable")),
                "executable_writable_sections": writable_sections,
            },
        ))
    return findings
