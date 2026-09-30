"""
Analysis rules for JOCKY.

Each rule is a plain function: (collector_results: dict) -> list[Finding].
`collector_results` is a dict mapping collector target name (e.g.
"processes") to that collector's data dict, built from the interpreter's
CollectorResult list before rules run.

Rules only read evidence already collected - they never re-collect data
or touch the host themselves. This keeps analysis a pure "reasoning"
step, cleanly separated from collection.
"""

from pathlib import PureWindowsPath, PurePosixPath

from jocky.analysis.finding import Finding, SEVERITY_INFO, SEVERITY_REVIEW

# Directories considered "unusual" for an executable to run from.
# Deliberately small and conservative for a prototype: common temp/
# download locations on Windows and Linux. This is NOT a claim that
# software here is malicious - many legitimate installers and portable
# apps run from these paths too.
_UNUSUAL_DIR_MARKERS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\",  # Windows
    "/tmp/", "/var/tmp/", "/downloads/",       # Linux
]


def rule_missing_executable_path(collector_results: dict) -> list[Finding]:
    processes = collector_results.get("processes", {}).get("processes", [])
    missing = [p for p in processes if p.get("exe_path") is None]
    if not missing:
        return []
    return [Finding(
        rule_name="missing_executable_path", severity=SEVERITY_INFO,
        summary=f"Executable path unavailable for {len(missing)} process(es)",
        reason="Some process executable paths could not be read, typically because Windows protected-process or cross-user access restrictions blocked the field. The count is aggregated to avoid one finding per process.",
        related_evidence={"missing_count": len(missing), "sample_pids": [p.get("pid") for p in missing[:20]]},
    )]


def rule_unusual_executable_directory(collector_results: dict) -> list[Finding]:
    """
    Flag processes running from directories commonly associated with
    temporary or downloaded files (e.g. Temp, Downloads).

    Careful wording per JOCKY's design rules: this is a pattern
    observation, not a verdict. Many legitimate programs run from these
    locations.
    """
    findings = []
    processes = collector_results.get("processes", {}).get("processes", [])

    for proc in processes:
        path = proc.get("exe_path")
        if not path:
            continue
        lowered = path.lower()
        if any(marker in lowered for marker in _UNUSUAL_DIR_MARKERS):
            findings.append(Finding(
                rule_name="unusual_executable_directory",
                severity=SEVERITY_REVIEW,
                summary=f"Process '{proc.get('name')}' runs from a temp/downloads-style path",
                reason=(
                    "The executable is located in a directory commonly used for "
                    "temporary or downloaded files. This is common for installers "
                    "and portable apps, and is not by itself evidence of anything "
                    "malicious - listed here for investigator review."
                ),
                related_evidence={"pid": proc.get("pid"), "path": path},
            ))
    return findings


def rule_process_network_correlation(collector_results: dict) -> list[Finding]:
    processes = {p.get("pid"): p for p in collector_results.get("processes", {}).get("processes", []) if p.get("pid") is not None}
    connections = collector_results.get("network_connections", {}).get("connections", [])
    by_pid: dict[int, int] = {}
    destinations: dict[int, list[str]] = {}
    for conn in connections:
        pid = conn.get("pid")
        if pid is None or pid == 0 or pid not in processes or not conn.get("remote_address"):
            continue
        by_pid[pid] = by_pid.get(pid, 0) + 1
        destinations.setdefault(pid, []).append(str(conn.get("remote_address")))
    findings = []
    # Correlation is context, not a finding for every socket. Cap the output to
    # the ten most connected processes so a normal browser cannot flood a case.
    for pid, count in sorted(by_pid.items(), key=lambda x: (-x[1], x[0]))[:10]:
        proc = processes[pid]
        findings.append(Finding(
            rule_name="process_network_correlation", severity=SEVERITY_INFO,
            summary=f"Process '{proc.get('name')}' (PID {pid}) has {count} active remote connection(s)",
            reason="Aggregated process/network context for the highest-connection processes. Individual sockets remain available in the network evidence collector.",
            related_evidence={"pid": pid, "process_name": proc.get("name"), "connection_count": count, "remote_addresses": sorted(set(destinations.get(pid, [])))[:25]},
        ))
    return findings

