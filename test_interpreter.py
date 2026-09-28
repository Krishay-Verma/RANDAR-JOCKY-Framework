"""
Full Milestone 3 test — exercises all new collectors and rules.
"""

import hashlib
from datetime import datetime, timezone

from jocky.language.lexer import tokenize
from jocky.language.parser import parse
from jocky.language.interpreter import run_investigation
from jocky.reports.builder import build_report
from jocky.reports.html_writer import build_html_string
from jocky.reports.json_writer import write_json_report

SCRIPT = """
investigation "Full Forensic Triage" {
    let conn_threshold    = 10;
    let task_threshold    = 5;
    let startup_threshold = 3;

    // Baseline evidence
    collect system_info;
    collect processes;
    collect network_connections;
    collect local_users;

    // Conditional persistence evidence
    if scheduled_tasks.count > task_threshold {
        analyze unusual_scheduled_tasks;
    }

    collect scheduled_tasks;
    collect startup_items;
    collect open_files;

    // Persistence and privilege checks
    analyze unusual_scheduled_tasks;
    analyze suspicious_startup_items;
    analyze privileged_user_anomaly;

    // Process behaviour checks
    analyze suspicious_processes;
    analyze missing_paths;

    if network_connections.count > conn_threshold {
        analyze process_network_correlation;
        analyze high_connection_processes;
    }

    report "full_forensic_triage";
}
"""


def main() -> None:
    print("=== JOCKY Milestone 3 — Full Forensic Triage ===\n")

    tokens = tokenize(SCRIPT)
    print(f"Tokens:   {len(tokens)}")

    investigation = parse(tokens)
    print(f"Commands: {len(investigation.commands)}")
    print(f"Name:     {investigation.name}\n")

    print("Running investigation...")
    started_at = datetime.now(timezone.utc)
    result = run_investigation(investigation)
    finished_at = datetime.now(timezone.utc)

    print("\nCollectors:")
    for cr in result.collector_results:
        count_hint = ""
        if cr.data:
            for key in ("count", "processes", "connections", "users",
                        "tasks", "items", "open_files"):
                val = cr.data.get(key)
                if val is not None:
                    count_hint = (
                        f"  ({len(val)} items)"
                        if isinstance(val, list)
                        else f"  ({val})"
                    )
                    break
        print(f"  [{cr.status:7s}] {cr.target}{count_hint}")

    print(f"\nFindings: {len(result.findings)}")
    sev_counts: dict[str, int] = {}
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    for sev, cnt in sorted(sev_counts.items()):
        print(f"  {sev:15s}: {cnt}")

    print("\nTop findings:")
    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    sorted_findings = sorted(result.findings, key=lambda f: priority.get(f.severity, 9))
    for f in sorted_findings[:8]:
        print(f"  [{f.severity:13s}] {f.summary}")

    print("\nBuilding reports...")
    script_hash = hashlib.sha256(SCRIPT.encode()).hexdigest()
    report = build_report(result, started_at, finished_at, script_hash=script_hash)
    write_json_report(report, "full_forensic_triage")
    with open("full_forensic_triage.html", "w", encoding="utf-8") as fh:
        fh.write(build_html_string(report))

    elapsed = (finished_at - started_at).total_seconds()
    print(f"  full_forensic_triage.json written")
    print(f"  full_forensic_triage.html written")
    print(f"  Elapsed: {elapsed:.2f}s")
    print("\n=== Done ===")


if __name__ == "__main__":
    main()