"""Windows injection-analysis rules.

These rules operate exclusively on collected evidence.  They never open,
write, suspend, inject, or otherwise modify a process.  Findings describe
observable indicators and deliberately avoid claiming that an injection
technique is proven from a single artifact.
"""

import os
from pathlib import PureWindowsPath
from typing import Any

from jocky.analysis.finding import Finding, SEVERITY_REVIEW, SEVERITY_HIGH


_USER_WRITABLE_MARKERS = (
    "\\appdata\\",
    "\\users\\public\\",
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\desktop\\",
)
_SYSTEM_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)


def _modules(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return evidence.get("modules", {}).get("modules", [])


def _processes(evidence: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {
        p.get("pid"): p
        for p in evidence.get("processes", {}).get("processes", [])
        if p.get("pid") is not None
    }


def rule_suspicious_module_loads(evidence: dict[str, Any]) -> list[Finding]:
    """Surface modules loaded from paths commonly writable by users."""
    findings: list[Finding] = []
    for module in _modules(evidence):
        if not module.get("is_user_writable"):
            continue
        path = module.get("module_path") or "unknown"
        findings.append(Finding(
            rule_name="suspicious_module_loads",
            severity=SEVERITY_REVIEW,
            summary=f"Module '{module.get('module_name')}' loaded from a user-writable path",
            reason=(
                "The module path is commonly writable by a non-administrator user. "
                "Legitimate software can load modules from such locations, so this "
                "is an investigation indicator rather than a maliciousness verdict."
            ),
            related_evidence={
                "pid": module.get("pid"),
                "process_name": module.get("process_name"),
                "module_path": path,
                "sha256": module.get("sha256"),
            },
        ))
    return findings


def rule_dll_sideloading(evidence: dict[str, Any]) -> list[Finding]:
    """Identify DLLs outside the owning executable's directory."""
    findings: list[Finding] = []
    for module in _modules(evidence):
        if module.get("is_main_image") or not str(module.get("module_name", "")).lower().endswith(".dll"):
            continue
        module_path = str(module.get("module_path") or "")
        process_exe = str(module.get("process_exe") or "")
        if not module_path or not process_exe:
            continue
        try:
            module_parent = str(PureWindowsPath(module_path).parent).lower()
            exe_parent = str(PureWindowsPath(process_exe).parent).lower()
        except Exception:
            continue
        if module_parent == exe_parent:
            continue
        if module.get("is_system_path"):
            continue

        findings.append(Finding(
            rule_name="dll_sideloading",
            severity=SEVERITY_REVIEW,
            summary=f"DLL '{module.get('module_name')}' loads outside the process directory",
            reason=(
                "The DLL is mapped from a directory different from the executable's "
                "directory and is not under a standard Windows application path. "
                "This can occur legitimately with plugins and shared libraries; "
                "the relationship should be verified against the application's design."
            ),
            related_evidence={
                "pid": module.get("pid"),
                "process_name": module.get("process_name"),
                "process_exe": process_exe,
                "module_path": module_path,
                "sha256": module.get("sha256"),
            },
        ))
    return findings


def rule_process_hollowing_indicators(evidence: dict[str, Any]) -> list[Finding]:
    """Correlate private executable memory with process inventory."""
    processes = _processes(evidence)
    regions = evidence.get("memory_regions", {}).get("regions", [])
    by_pid: dict[int, int] = {}
    for region in regions:
        if region.get("is_private_executable"):
            pid = region.get("pid")
            if pid is not None:
                by_pid[pid] = by_pid.get(pid, 0) + 1

    findings: list[Finding] = []
    for pid, count in by_pid.items():
        proc = processes.get(pid, {})
        if not proc:
            continue
        if count < 2:
            continue
        findings.append(Finding(
            rule_name="process_hollowing_indicators",
            severity=SEVERITY_HIGH,
            summary=f"Process '{proc.get('name')}' has private executable memory regions",
            reason=(
                f"PID {pid} has {count} committed private executable memory regions. "
                "JIT engines, browsers and other legitimate software can create such "
                "regions, so this indicator requires correlation with process/module "
                "evidence before an injection technique is assessed."
            ),
            related_evidence={
                "pid": pid,
                "process_name": proc.get("name"),
                "exe_path": proc.get("exe_path"),
                "private_executable_region_count": count,
            },
        ))
    return findings


def rule_reflective_load_indicators(evidence: dict[str, Any]) -> list[Finding]:
    """Look for executable private memory without a corresponding module path."""
    modules = _modules(evidence)
    mapped_pids = {m.get("pid") for m in modules if m.get("pid") is not None}
    regions = evidence.get("memory_regions", {}).get("regions", [])
    counts: dict[int, int] = {}
    for region in regions:
        pid = region.get("pid")
        if pid is not None and region.get("is_private_executable"):
            counts[pid] = counts.get(pid, 0) + 1

    findings: list[Finding] = []
    for pid, count in counts.items():
        if pid not in mapped_pids or count < 1:
            continue
        findings.append(Finding(
            rule_name="reflective_load_indicators",
            severity=SEVERITY_REVIEW,
            summary=f"PID {pid} has executable private memory requiring module correlation",
            reason=(
                "Executable private memory was observed alongside a process module "
                "inventory. This can have legitimate causes, including JIT/runtime "
                "behavior, and is retained as a correlation lead rather than proof of "
                "reflective DLL loading."
            ),
            related_evidence={"pid": pid, "private_executable_region_count": count},
        ))
    return findings


def rule_thread_hijacking_indicators(evidence: dict[str, Any]) -> list[Finding]:
    """Flag thread start addresses that land in private executable memory."""
    threads = evidence.get("threads", {}).get("threads", [])
    regions = [
        r for r in evidence.get("memory_regions", {}).get("regions", [])
        if r.get("is_private_executable") and r.get("base_address") is not None
    ]
    if not threads or not regions:
        return []

    findings: list[Finding] = []
    for thread in threads:
        address = thread.get("start_address")
        if address is None:
            continue
        pid = thread.get("pid")
        match = next(
            (r for r in regions
             if r.get("pid") == pid
             and r.get("base_address", 0) <= address < r.get("base_address", 0) + r.get("region_size", 0)),
            None,
        )
        if match is None:
            continue
        findings.append(Finding(
            rule_name="thread_hijacking_indicators",
            severity=SEVERITY_HIGH,
            summary=f"Thread {thread.get('thread_id')} starts in private executable memory",
            reason=(
                "The thread start address falls inside a private executable memory region. "
                "This can be produced by legitimate runtimes, JIT engines and other software, "
                "so the observation is an injection-like indicator that requires process context."
            ),
            related_evidence={
                "pid": pid,
                "process_name": thread.get("process_name"),
                "thread_id": thread.get("thread_id"),
                "start_address": address,
                "memory_region": {
                    "base_address": match.get("base_address"),
                    "region_size": match.get("region_size"),
                    "protect_name": match.get("protect_name"),
                },
            },
        ))
    return findings


def rule_injection_correlation(evidence: dict[str, Any]) -> list[Finding]:
    """Combine independent injection indicators into a single review finding."""
    modules = _modules(evidence)
    regions = evidence.get("memory_regions", {}).get("regions", [])
    module_by_pid: dict[int, int] = {}
    for module in modules:
        if module.get("is_user_writable"):
            pid = module.get("pid")
            if pid is not None:
                module_by_pid[pid] = module_by_pid.get(pid, 0) + 1

    private_exec: dict[int, int] = {}
    for region in regions:
        if region.get("is_private_executable"):
            pid = region.get("pid")
            if pid is not None:
                private_exec[pid] = private_exec.get(pid, 0) + 1

    # V1.4 PE evidence adds static context to the runtime correlation.
    pe_files = evidence.get("pe_metadata", {}).get("files", []) or []
    module_by_path = {str(m.get("module_path") or "").lower(): m for m in modules}
    pe_indicators: dict[int, list[str]] = {}
    for pe in pe_files:
        imports = {str(name).lower() for name in pe.get("imports", [])}
        static_hits = imports & {
            "writeprocessmemory", "ntwritevirtualmemory", "virtualallocex",
            "virtualprotectex", "createremotethread", "ntcreatethreadex",
            "queueuserapc", "setthreadcontext", "openprocess",
        }
        if not static_hits:
            continue
        module = module_by_path.get(str(pe.get("path") or "").lower())
        pid = module.get("pid") if module else None
        if pid is not None:
            pe_indicators.setdefault(pid, []).append("suspicious_pe_imports")

    findings: list[Finding] = []
    candidate_pids = sorted(set(module_by_pid) & (set(private_exec) | set(pe_indicators)))
    for pid in candidate_pids:
        indicators = []
        if pid in module_by_pid:
            indicators.append("user_writable_module")
        if pid in private_exec:
            indicators.append("private_executable_memory")
        if pid in pe_indicators:
            indicators.extend(pe_indicators[pid])
        if len(indicators) < 2:
            continue
        findings.append(Finding(
            rule_name="injection_correlation",
            severity=SEVERITY_HIGH,
            summary=f"PID {pid} has multiple injection-like indicators",
            reason=(
                "Independent module and memory observations overlap on the same process. "
                "This raises the priority for analyst review but does not establish that a "
                "specific injection technique occurred."
            ),
            related_evidence={
                "pid": pid,
                "indicators": indicators,
                "user_writable_module_count": module_by_pid[pid],
                "private_executable_region_count": private_exec.get(pid, 0),
                "pe_static_indicators": pe_indicators.get(pid, []),
                "platform": "Windows",
            },
        ))
    return findings
