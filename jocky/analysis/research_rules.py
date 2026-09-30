"""Defensive rules for the V2.0 controlled security-research track.

These rules detect observable indicators associated with in-memory execution
and vulnerable-driver exposure. They do not execute, exploit, inject, unhook,
or alter processes/drivers.
"""

from __future__ import annotations

from typing import Any

from jocky.analysis.finding import Finding, SEVERITY_REVIEW, SEVERITY_HIGH


def rule_in_memory_execution_indicators(evidence: dict[str, Any]) -> list[Finding]:
    """Correlate private executable memory with thread and module context."""
    regions = evidence.get("memory_regions", {}).get("regions", []) or []
    threads = evidence.get("threads", {}).get("threads", []) or []
    modules = evidence.get("modules", {}).get("modules", []) or []
    processes = {p.get("pid"): p for p in evidence.get("processes", {}).get("processes", [])}

    private_by_pid: dict[int, list[dict[str, Any]]] = {}
    for region in regions:
        if region.get("is_private_executable") and region.get("pid") is not None:
            private_by_pid.setdefault(region["pid"], []).append(region)

    thread_hits: dict[int, list[dict[str, Any]]] = {}
    for thread in threads:
        address = thread.get("start_address")
        pid = thread.get("pid")
        if address is None or pid not in private_by_pid:
            continue
        for region in private_by_pid[pid]:
            base = region.get("base_address")
            size = region.get("region_size") or 0
            if base is not None and base <= address < base + size:
                thread_hits.setdefault(pid, []).append(thread)
                break

    writable_modules = {}
    for module in modules:
        if module.get("is_user_writable"):
            writable_modules[module.get("pid")] = writable_modules.get(module.get("pid"), 0) + 1

    findings: list[Finding] = []
    for pid, pid_regions in private_by_pid.items():
        indicators = ["private_executable_memory"]
        if pid in thread_hits:
            indicators.append("thread_start_in_private_executable_memory")
        if writable_modules.get(pid):
            indicators.append("user_writable_loaded_module")
        if len(indicators) < 2:
            continue
        proc = processes.get(pid, {})
        findings.append(Finding(
            rule_name="in_memory_execution_indicators",
            severity=SEVERITY_HIGH,
            summary=f"PID {pid} has correlated in-memory execution indicators",
            reason=(
                "Independent memory, thread, and/or module observations overlap on one process. "
                "This is a forensic correlation lead only; JIT runtimes and other legitimate software "
                "can produce some of the same artifacts."
            ),
            related_evidence={
                "pid": pid,
                "process_name": proc.get("name"),
                "indicators": indicators,
                "private_executable_region_count": len(pid_regions),
                "thread_start_hit_count": len(thread_hits.get(pid, [])),
                "user_writable_module_count": writable_modules.get(pid, 0),
            },
            limitations="Detection-only V2.0 rule. No process-memory access or modification is performed.",
            next_check="Review module provenance, signer state, parent process, and endpoint telemetry.",
        ))
    return findings


def rule_byoVD_driver_indicators(evidence: dict[str, Any]) -> list[Finding]:
    """Flag driver exposure that warrants BYOVD-focused defensive review."""
    drivers = evidence.get("driver_inventory", {}).get("drivers", []) or []
    findings: list[Finding] = []
    for driver in drivers:
        reasons = []
        if driver.get("known_vulnerable"):
            reasons.append("matched operator-supplied vulnerable-driver catalog")
        if driver.get("is_user_writable_path"):
            reasons.append("driver path is user-writable")
        if not driver.get("file_exists"):
            reasons.append("registered driver image is missing")
        if not reasons:
            continue
        severity = SEVERITY_HIGH if driver.get("known_vulnerable") else SEVERITY_REVIEW
        findings.append(Finding(
            rule_name="byovd_driver_indicators",
            severity=severity,
            summary=f"Driver '{driver.get('service_name')}' requires kernel-driver review",
            reason=(
                "The driver inventory contains one or more risk indicators: " + "; ".join(reasons) + ". "
                "This rule identifies exposure and evidence; it does not load, exploit, disable, or modify the driver."
            ),
            related_evidence={
                "service_name": driver.get("service_name"),
                "display_name": driver.get("display_name"),
                "image_path": driver.get("image_path"),
                "sha256": driver.get("sha256"),
                "known_vulnerable": driver.get("known_vulnerable"),
                "vulnerability_ids": driver.get("vulnerability_ids", []),
                "catalog_source": driver.get("catalog_source"),
            },
            limitations="Vulnerability matching is only as current as the operator-supplied catalog.",
            next_check="Verify publisher/signature, version, vulnerability status, and whether the driver is required.",
        ))
    return findings
