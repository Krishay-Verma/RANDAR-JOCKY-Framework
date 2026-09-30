"""Read-only memory-forensics correlation for RANDAR V2.4.

The module analyzes virtual-memory *metadata* collected by the existing
Windows collector. It never reads or writes another process's memory and does
not attempt injection, hollowing, dumping, or code extraction.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from jocky.analysis.finding import Finding, SEVERITY_HIGH, SEVERITY_REVIEW


def build_memory_forensics(evidence: dict[str, Any]) -> dict[str, Any]:
    regions = evidence.get("memory_regions", {}).get("regions", []) or []
    processes = evidence.get("processes", {}).get("processes", []) or []
    modules = evidence.get("modules", {}).get("modules", []) or []
    threads = evidence.get("threads", {}).get("threads", []) or []

    proc_by_pid = {p.get("pid"): p for p in processes if p.get("pid") is not None}
    module_pids = {m.get("pid") for m in modules if m.get("pid") is not None}

    private_exec = [r for r in regions if r.get("is_private_executable")]
    writable_exec = [
        r for r in regions
        if r.get("is_executable") and r.get("protect") in {0x40, 0x80}
    ]

    thread_private_hits = []
    for thread in threads:
        address = thread.get("start_address")
        pid = thread.get("pid")
        if address is None or pid is None:
            continue
        for region in regions:
            if (
                region.get("pid") == pid
                and region.get("is_private_executable")
                and region.get("base_address") is not None
                and region.get("base_address") <= address < region.get("base_address", 0) + region.get("region_size", 0)
            ):
                thread_private_hits.append({
                    "pid": pid,
                    "process_name": thread.get("process_name"),
                    "thread_id": thread.get("thread_id"),
                    "start_address": address,
                    "region_base": region.get("base_address"),
                    "region_size": region.get("region_size"),
                })
                break

    by_pid: dict[int, dict[str, Any]] = {}
    for region in private_exec:
        pid = region.get("pid")
        if pid is None:
            continue
        item = by_pid.setdefault(pid, {"pid": pid, "private_executable_regions": 0, "writable_executable_regions": 0, "module_inventory_present": pid in module_pids})
        item["private_executable_regions"] += 1
    for region in writable_exec:
        pid = region.get("pid")
        if pid is None:
            continue
        item = by_pid.setdefault(pid, {"pid": pid, "private_executable_regions": 0, "writable_executable_regions": 0, "module_inventory_present": pid in module_pids})
        item["writable_executable_regions"] += 1

    for hit in thread_private_hits:
        item = by_pid.setdefault(hit["pid"], {"pid": hit["pid"], "private_executable_regions": 0, "writable_executable_regions": 0, "module_inventory_present": hit["pid"] in module_pids})
        item["thread_starts_in_private_executable"] = item.get("thread_starts_in_private_executable", 0) + 1

    processes_out = []
    for pid, item in sorted(by_pid.items()):
        proc = proc_by_pid.get(pid, {})
        item["process_name"] = proc.get("name") or "unknown"
        item["exe_path"] = proc.get("exe_path")
        item["correlation_level"] = _correlation_level(item)
        processes_out.append(item)

    normalized = {
        "region_count": len(regions),
        "private_executable_count": len(private_exec),
        "writable_executable_count": len(writable_exec),
        "thread_private_hits": thread_private_hits,
        "processes": processes_out,
    }
    snapshot_hash = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()

    return {
        "version": "3.0.0",
        "mode": "metadata-only",
        "supported": evidence.get("memory_regions", {}).get("supported", False),
        "snapshot_hash": snapshot_hash,
        "summary": {
            "regions": len(regions),
            "private_executable_regions": len(private_exec),
            "writable_executable_regions": len(writable_exec),
            "thread_starts_in_private_executable": len(thread_private_hits),
            "correlated_processes": len(processes_out),
        },
        "processes": processes_out,
        "thread_hits": thread_private_hits,
        "limitations": [
            "Only virtual-memory metadata is inspected.",
            "No process memory bytes are read or written.",
            "Indicators require contextual review and do not prove an injection technique.",
        ],
    }


def build_memory_forensics_findings(report: dict[str, Any]) -> list[Finding]:
    """Turn the metadata correlation report into explicit analyst-facing findings.

    The V2.4 endpoint previously delegated entirely to technique-specific rules.
    That meant a process with a single RWX/private-executable region could be
    visible in the correlation table but produce no finding at all.  This helper
    closes that reporting gap: every non-context correlation is represented by a
    conservative finding, while thread-start correlations remain higher priority.
    """
    findings: list[Finding] = []
    for item in report.get("processes", []) or []:
        level = item.get("correlation_level")
        private = int(item.get("private_executable_regions") or 0)
        writable = int(item.get("writable_executable_regions") or 0)
        thread_hits = int(item.get("thread_starts_in_private_executable") or 0)
        if level == "context" or not (private or writable or thread_hits):
            continue

        pid = item.get("pid")
        process_name = item.get("process_name") or "unknown"
        indicators: list[str] = []
        if private:
            indicators.append(f"{private} private executable region(s)")
        if writable:
            indicators.append(f"{writable} writable/executable region(s)")
        if thread_hits:
            indicators.append(f"{thread_hits} thread start(s) inside private executable memory")

        high_signal = thread_hits > 0
        findings.append(Finding(
            rule_name="memory_forensics_correlation",
            severity=SEVERITY_HIGH if high_signal else SEVERITY_REVIEW,
            summary=f"PID {pid} ({process_name}) has memory-execution indicators",
            reason=(
                "; ".join(indicators) + ". "
                "These observations are forensic correlation leads and can occur in legitimate "
                "software such as browsers, JIT runtimes, sandboxes, and application frameworks; "
                "they do not by themselves prove process injection, hollowing, or reflective loading."
            ),
            related_evidence={
                "pid": pid,
                "process_name": process_name,
                "private_executable_region_count": private,
                "writable_executable_region_count": writable,
                "thread_start_in_private_executable_count": thread_hits,
                "correlation_level": level,
                "snapshot_hash": report.get("snapshot_hash"),
            },
            limitations=(
                "Metadata-only scan. No process-memory bytes are read or modified, and the finding "
                "does not establish an injection technique."
            ),
            next_check="Review module provenance, signer state, parent process, and endpoint telemetry.",
        ))

    return findings


def _correlation_level(item: dict[str, Any]) -> str:
    private = item.get("private_executable_regions", 0)
    writable = item.get("writable_executable_regions", 0)
    threads = item.get("thread_starts_in_private_executable", 0)
    if threads and (writable or private >= 2):
        return "high-review"
    if writable or private >= 2:
        return "review"
    return "context"
