"""
Standalone HTML report writer.

Plain string building with html.escape on every interpolated value; no
templating dependency. The document is self-contained (inline CSS, no
scripts) so it can be archived or attached to a case file as-is.
"""

from html import escape
import json
from pathlib import Path

from jocky.analysis.finding import SEVERITY_ORDER
from jocky.reports.report import Report

_REPORT_MARK = """<svg class="brand-mark" viewBox="0 0 96 96" aria-hidden="true"><path d="M48 4 82 16v27c0 23-13 39-34 49C27 82 14 66 14 43V16L48 4Z" fill="#20a36d" stroke="#0c5e3e" stroke-width="3"/><path d="M35 28h27v9H45v20c0 8-4 12-12 12h-4v-9h3c2 0 3-1 3-4V28Z" fill="#071712"/><circle cx="69" cy="27" r="5" fill="#e8fff4"/></svg>"""

_CSS = """
:root{--ink:#111827;--mute:#6b7280;--line:#e5e7eb;--bg:#f9fafb}
*{box-sizing:border-box}
body{font:14px/1.58 "Segoe UI Variable","Segoe UI",Inter,system-ui,-apple-system,BlinkMacSystemFont,Roboto,Arial,sans-serif;color:var(--ink);margin:0;background:#fff;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
header{background:#0b1220;color:#fff;padding:24px 48px 26px;display:flex;align-items:center;gap:14px}
.brand-mark{width:38px;height:38px;flex:0 0 38px}
header .brand-copy{min-width:0}
header small{display:block;color:#93a4c0;letter-spacing:.12em;text-transform:uppercase;font-size:10px;font-weight:600}
header h1{margin:4px 0 0;font-size:23px;line-height:1.25;font-weight:650;letter-spacing:-.01em}
main{max-width:1040px;margin:0 auto;padding:32px 48px 64px}
h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute);margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
dl{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;margin:0}
dt{color:var(--mute)}dd{margin:0;word-break:break-all}
.cards{display:flex;gap:10px;flex-wrap:wrap}
.card{border:1px solid var(--line);border-radius:6px;padding:10px 16px;min-width:112px;background:var(--bg)}
.card b{display:block;font-size:22px}.card span{font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--bg);color:var(--mute);font-size:10px;text-transform:uppercase;letter-spacing:.06em;font-weight:650}
td{line-height:1.48}
code{font-family:"Cascadia Mono",Consolas,Menlo,monospace;font-size:12px}
.b{display:inline-block;padding:1px 8px;border-radius:3px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.sev-informational{background:#e5e7eb;color:#374151}.sev-review_recommended{background:#dbeafe;color:#1e40af}
.sev-medium{background:#fef3c7;color:#92400e}.sev-high{background:#fed7aa;color:#9a3412}
.sev-critical{background:#fecaca;color:#991b1b}
.st-success{background:#d1fae5;color:#065f46}.st-error{background:#fecaca;color:#991b1b}
.inj{border:1px solid #b8d7c7;background:#f2faf6;padding:14px 16px;border-radius:5px}.inj strong{color:#174e37}
.inj .grid{display:flex;gap:24px;margin-top:10px}.inj .metric b{display:block;font-size:21px;color:#174e37}.inj .metric span{font-size:10px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
.inj.alert{border-color:#e0c18d;background:#fff9ed}.inj.alert strong{color:#8a4f00}
footer{color:var(--mute);font-size:12px;margin-top:40px}
@media print{header{background:#fff;color:#000;border-bottom:2px solid #000}}
"""


INJECTION_RULES = {
    "suspicious_module_loads", "dll_sideloading", "process_hollowing_indicators",
    "reflective_load_indicators", "thread_hijacking_indicators", "injection_correlation",
    "unsigned_loaded_module", "suspicious_imports", "high_entropy_module",
    "module_disk_mismatch", "suspicious_writable_module",
}


def build_html_string(report: Report) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    ordered = sorted(
        report.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else -1,
        reverse=True,
    )
    cards = "".join(
        f'<div class="card"><b>{n}</b><span>{escape(s.replace("_", " "))}</span></div>'
        for s, n in counts.items()
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RANDAR Report - {escape(report.investigation_name)}</title>
<style>{_CSS}</style></head>
<body>
<header>{_REPORT_MARK}<div class="brand-copy"><small>RANDAR &middot; Forensic Triage Platform</small>
<h1>{escape(report.investigation_name)}</h1></div></header>
<main>
<h2>Summary</h2>
<dl>
<dt>Endpoint</dt><dd>{escape(report.endpoint_hostname)}</dd>
<dt>Started</dt><dd>{escape(report.started_at)}</dd>
<dt>Finished</dt><dd>{escape(report.finished_at)}</dd>
<dt>Report name</dt><dd>{escape(report.report_name or "-")}</dd>
<dt>Script SHA-256</dt><dd><code>{escape(report.script_hash or "not recorded")}</code></dd>
<dt>Report SHA-256</dt><dd><code>{escape(report.report_hash or "not recorded")}</code></dd>
<dt>Product / version</dt><dd>{escape(report.product_name)} {escape(report.product_version)}</dd>
<dt>Investigation language</dt><dd>{escape(report.dsl_name)} {escape(report.dsl_version)}</dd>
<dt>Signed bytecode SHA-256</dt><dd><code>{escape(report.bytecode_hash or "not recorded")}</code></dd>
</dl>
<h2>Findings by severity</h2><div class="cards">{cards}</div>
{_injection_section(report)}
{_pe_section(report)}
{_network_section(report)}
{_network_hunting_section(report)}
{_windows_telemetry_section(report)}
{_analysis_coverage_section(report)}
{_provenance_section(report)}
{_resource_section(report)}
{_timeline_section(report)}
<h2>Collector status</h2>
<table><tr><th>Collector</th><th>Status</th><th>Duration</th><th>Records</th><th>Resource</th><th>Detail</th></tr>{_collector_rows(report)}</table>
<h2>Findings ({len(report.findings)})</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Summary</th><th>Reason</th></tr>{_finding_rows(ordered)}</table>
<footer>Findings are observations for analyst review, not verdicts.</footer>
</main></body></html>"""


def _provenance_section(report: Report) -> str:
    source = report.source or {}
    return f"""<h2>Forensic provenance</h2>
<table><tr><th>Stage</th><th>Value</th></tr>
<tr><td>Script SHA-256</td><td><code>{escape(report.script_hash or "not recorded")}</code></td></tr>
<tr><td>Signed bytecode SHA-256</td><td><code>{escape(report.bytecode_hash or "not recorded")}</code></td></tr>
<tr><td>Evidence source</td><td>{escape(str(source.get("type", "local")))}</td></tr>
<tr><td>Evidence metadata</td><td><code>{escape(json.dumps(source, sort_keys=True, ensure_ascii=False))}</code></td></tr>
<tr><td>Report SHA-256</td><td><code>{escape(report.report_hash or "not recorded")}</code></td></tr>
</table>"""



def _resource_section(report: Report) -> str:
    usage = report.resource_usage or {}
    status = report.execution_status or "complete"
    badge = "Completed" if status == "complete" else status.replace("_", " ").title()
    return f"""<h2>Execution & resource accounting</h2>
<div class="cards">
<div class="card"><b>{escape(badge)}</b><span>Execution status</span></div>
<div class="card"><b>{escape(str(usage.get('commands_completed', 0)))}/{escape(str(usage.get('commands_total', 0)))}</b><span>Commands</span></div>
<div class="card"><b>{escape(str(usage.get('records_collected', 0)))}</b><span>Records collected</span></div>
<div class="card"><b>{escape(str(usage.get('evidence_bytes', 0)))}</b><span>Evidence bytes</span></div>
<div class="card"><b>{escape(str(usage.get('timed_out_collectors', 0)))}</b><span>Collector timeouts</span></div>
<div class="card"><b>{escape(str(usage.get('truncated_collectors', 0)))}</b><span>Truncated collectors</span></div>
</div>
<p>{escape(report.termination_reason or 'No execution limit was reached.')}</p>"""

def _timeline_section(report: Report) -> str:
    rows = "".join(f"<tr><td>{escape(str(e.get('timestamp') or '-'))}</td><td>{escape(str(e.get('type') or '-'))}</td><td>{escape(str(e.get('collector') or '-'))}</td><td>{escape(str(e.get('summary') or '-'))}</td></tr>" for e in (report.timeline or [])[:10000])
    if not rows:
        rows='<tr><td colspan="4">No timestamped evidence was available to build a timeline.</td></tr>'
    return f"<h2>Evidence timeline</h2><table><tr><th>Timestamp</th><th>Event</th><th>Collector</th><th>Summary</th></tr>{rows}</table>"


def write_html_report(report: Report, output_path: str) -> None:
    Path(output_path).write_text(build_html_string(report), encoding="utf-8")


def _sev_class(sev: str) -> str:
    return f"sev-{sev}" if sev in SEVERITY_ORDER else "sev-informational"


def _injection_section(report: Report) -> str:
    findings = [f for f in report.findings if f.rule_name in INJECTION_RULES]
    collectors = {c.target: c for c in report.collector_results}

    def count(target: str) -> int:
        collector = collectors.get(target)
        data = collector.data if collector else None
        return int((data or {}).get("count") or 0)

    if not any(target in collectors for target in ("modules", "threads", "memory_regions")):
        return (
            '<h2>DLL / injection analysis</h2>'
            '<div class="inj alert"><strong>Windows injection telemetry not present in this report.</strong> '
            'Run the dedicated Windows injection hunt to collect module, thread and memory evidence.</div>'
        )

    finding_rows = "".join(
        f'<tr><td><span class="b {_sev_class(f.severity)}">{escape(f.severity.replace("_", " "))}</span></td>'
        f'<td><code>{escape(f.rule_name)}</code></td><td>{escape(f.summary)}</td><td>{escape(f.reason)}</td></tr>'
        for f in findings
    ) or '<tr><td colspan="4">No configured injection indicators were observed.</td></tr>'

    return f"""<h2>DLL / injection analysis</h2>
<div class="inj"><strong>Windows read-only injection telemetry</strong> · module, thread and virtual-memory evidence are correlated into injection-related review indicators.
<div class="grid">
<div class="metric"><b>{count("modules")}</b><span>Loaded modules</span></div>
<div class="metric"><b>{count("threads")}</b><span>Threads inspected</span></div>
<div class="metric"><b>{count("memory_regions")}</b><span>Memory regions</span></div>
<div class="metric"><b>{len(findings)}</b><span>Injection indicators</span></div>
</div></div>
<table style="margin-top:12px"><tr><th>Severity</th><th>Technique indicator</th><th>Summary</th><th>Reason</th></tr>{finding_rows}</table>"""



def _pe_section(report: Report) -> str:
    collector = next((c for c in report.collector_results if c.target == "pe_metadata" and c.status == "success"), None)
    if not collector or not collector.data:
        return ""
    data = collector.data
    files = data.get("files", []) or []
    findings = [f for f in report.findings if f.rule_name in INJECTION_RULES and f.rule_name not in {
        "suspicious_module_loads", "dll_sideloading", "process_hollowing_indicators",
        "reflective_load_indicators", "thread_hijacking_indicators", "injection_correlation"
    }]
    cards = "".join(
        f'<div class="card"><b>{escape(str(value))}</b><span>{escape(label)}</span></div>'
        for value, label in ((len(files), "PE files"), (sum(1 for x in files if x.get("signature_status") == "embedded_signature"), "Embedded signatures"), (len(findings), "PE indicators"))
    )
    rows = "".join(
        f'<tr><td><code>{escape(str(item.get("filename") or "-"))}</code></td>'
        f'<td>{escape(str(item.get("architecture") or "-"))}</td>'
        f'<td>{escape(str(item.get("pe_type") or "-"))}</td>'
        f'<td>{escape(str(item.get("signature_status") or "-"))}</td>'
        f'<td><code>{escape(str(item.get("sha256") or "-"))}</code></td></tr>'
        for item in files[:300]
    ) or '<tr><td colspan="5">No PE metadata was parsed.</td></tr>'
    finding_rows = "".join(
        f'<tr><td><span class="b {_sev_class(f.severity)}">{escape(f.severity.replace("_", " "))}</span></td>'
        f'<td><code>{escape(f.rule_name)}</code></td><td>{escape(f.summary)}</td><td>{escape(f.reason)}</td></tr>'
        for f in findings
    ) or '<tr><td colspan="4">No PE/module indicators were observed.</td></tr>'
    return (
        '<h2>PE / module forensics</h2>'
        '<div class="inj"><strong>Bounded read-only PE metadata</strong> · headers, sections, imports, exports, entropy, signature metadata and SHA-256 are correlated with loaded-module evidence.'
        f'<div class="cards" style="margin-top:12px">{cards}</div></div>'
        f'<table style="margin-top:12px"><tr><th>File</th><th>Architecture</th><th>PE type</th><th>Signature</th><th>SHA-256</th></tr>{rows}</table>'
        f'<table style="margin-top:12px"><tr><th>Severity</th><th>Rule</th><th>Summary</th><th>Reason</th></tr>{finding_rows}</table>'
    )


def _network_section(report: Report) -> str:
    collector = next((c for c in report.collector_results if c.target == "network_artifacts" and c.status == "success"), None)
    if not collector or not collector.data:
        return ""
    data = collector.data
    stats = data.get("statistics", {})
    src = data.get("source", {})
    cards = "".join(
        f'<div class="card"><b>{escape(str(stats.get(k) if stats.get(k) is not None else "-"))}</b><span>{escape(label)}</span></div>'
        for k, label in (("connection_count", "Artifacts"), ("unique_sources", "Sources"), ("unique_destinations", "Destinations"), ("unique_domains", "Domains"))
    )
    protocols = "".join(
        f'<tr><td><code>{escape(str(k))}</code></td><td>{v}</td></tr>'
        for k, v in stats.get("protocol_counts", {}).items()
    ) or '<tr><td colspan="2">No protocol metadata.</td></tr>'
    return (
        '<h2>Network forensics</h2>'
        f'<dl><dt>Source file</dt><dd>{escape(str(src.get("filename") or "-"))}</dd>'
        f'<dt>Source SHA-256</dt><dd><code>{escape(str(src.get("sha256") or "-"))}</code></dd>'
        f'<dt>First seen</dt><dd>{escape(str(stats.get("first_seen") or "-"))}</dd>'
        f'<dt>Last seen</dt><dd>{escape(str(stats.get("last_seen") or "-"))}</dd></dl>'
        f'<div class="cards" style="margin-top:12px">{cards}</div>'
        f'<table style="margin-top:12px"><tr><th>Protocol</th><th>Count</th></tr>{protocols}</table>'
    )


NETWORK_HUNT_RULES = {
    "suspicious_dns_queries", "dns_entropy", "rare_domains",
    "suspicious_tld_patterns", "dns_bursts", "unusual_query_types",
    "long_random_labels", "dns_tunneling_indicators", "dns_beaconing",
    "network_beaconing", "port_scan", "horizontal_scan",
    "service_discovery", "udp_scan", "network_classification",
    "process_network_correlation",
}

def _network_hunting_section(report: Report) -> str:
    findings = [f for f in report.findings if f.rule_name in NETWORK_HUNT_RULES]
    if not findings:
        return ""
    dns = sum(1 for f in findings if f.rule_name in {
        "suspicious_dns_queries", "dns_entropy", "rare_domains",
        "suspicious_tld_patterns", "dns_bursts", "unusual_query_types",
        "long_random_labels", "dns_tunneling_indicators", "dns_beaconing"})
    network = sum(1 for f in findings if f.rule_name in {"network_beaconing", "port_scan", "horizontal_scan", "service_discovery", "udp_scan"})
    correlation = sum(1 for f in findings if f.rule_name in {"process_network_correlation", "network_classification"})
    rows = _finding_rows(sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else -1, reverse=True))
    return f"""<h2>Network threat hunting</h2>
<div class="inj"><strong>V1.2 network hunting indicators</strong> · findings are explainable pattern observations generated from normalized network evidence.
<div class="grid">
<div class="metric"><b>{len(findings)}</b><span>Total hunt indicators</span></div>
<div class="metric"><b>{dns}</b><span>DNS indicators</span></div>
<div class="metric"><b>{network}</b><span>Network indicators</span></div>
<div class="metric"><b>{correlation}</b><span>Correlation / context</span></div>
</div></div>
<table style="margin-top:12px"><tr><th>Severity</th><th>Rule</th><th>Summary</th><th>Reason</th></tr>{rows}</table>
<p style="color:var(--mute);font-size:12px">Indicators such as beaconing, tunneling, scanning and unusual DNS behavior require analyst validation and environmental context.</p>"""


WINDOWS_TELEMETRY_RULES = {
    "encoded_powershell", "suspicious_powershell_parent",
    "powershell_network_activity", "powershell_child_processes",
    "suspicious_services", "writable_service_paths",
    "persistence_correlation",
}

def _windows_telemetry_section(report: Report) -> str:
    collectors = {c.target: c for c in report.collector_results}
    relevant = [f for f in report.findings if f.rule_name in WINDOWS_TELEMETRY_RULES]
    present = any(k in collectors for k in ("windows_event_logs", "sysmon_events", "services"))
    if not present:
        return ""
    def count(target: str) -> int:
        c = collectors.get(target)
        return int((c.data or {}).get("count") or 0) if c and c.status == "success" else 0
    rows = _finding_rows(sorted(relevant, key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else -1, reverse=True))
    return f"""<h2>Windows telemetry</h2>
<div class="inj"><strong>V1.3 Windows read-only telemetry</strong> · PowerShell, Windows Event Log, Sysmon and service evidence are collected through fixed allowlisted queries.
<div class="grid">
<div class="metric"><b>{count("windows_event_logs")}</b><span>Windows Event Log records</span></div>
<div class="metric"><b>{count("sysmon_events")}</b><span>Sysmon records</span></div>
<div class="metric"><b>{count("services")}</b><span>Services</span></div>
<div class="metric"><b>{len(relevant)}</b><span>V1.3 indicators</span></div>
</div></div>
<table style="margin-top:12px"><tr><th>Severity</th><th>Rule</th><th>Summary</th><th>Reason</th></tr>{rows}</table>
<p style="color:var(--mute);font-size:12px">PowerShell, service and persistence observations require analyst validation and environmental context.</p>"""


def _analysis_coverage_section(report: Report) -> str:
    rows = []
    for ar in getattr(report, "analysis_results", []) or []:
        status = ar.status or "unknown"
        cls = "st-success" if status == "success" else "st-error"
        detail = f"{ar.finding_count} finding(s)"
        if ar.error:
            detail += f" · {ar.error}"
        rows.append(
            f'<tr><td><code>{escape(ar.target)}</code></td>'
            f'<td><span class="b {cls}">{escape(status)}</span></td>'
            f'<td>{escape(detail)}</td></tr>'
        )
    if not rows:
        return '<h2>Analysis execution coverage</h2><div>No analysis execution records were stored for this report.</div>'
    return (
        f'<h2>Analysis execution coverage ({len(rows)})</h2>'
        '<table><tr><th>Rule</th><th>Status</th><th>Result</th></tr>'
        + "".join(rows) + '</table>'
    )

def _collector_rows(report: Report) -> str:
    rows = []
    for cr in report.collector_results:
        ok = cr.status == "success"
        detail = "OK" if ok else (cr.error or "error")
        evidence_hash = getattr(cr, "evidence_hash", None)
        if ok and evidence_hash:
            detail += f" · evidence SHA-256: {evidence_hash}"
        resource = f"{getattr(cr, 'resource_bytes', 0)} bytes" + (" · truncated" if getattr(cr, "truncated", False) else "")
        rows.append(
            f"<tr><td><code>{escape(cr.target)}</code></td>"
            f'<td><span class="b {"st-success" if ok else "st-error"}">{escape(cr.status)}</span></td>'
            f"<td>{getattr(cr, 'duration_ms', 0)} ms</td>"
            f"<td>{getattr(cr, 'record_count', 0)}</td>"
            f"<td>{escape(resource)}</td>"
            f"<td>{escape(str(detail))}</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan='6'>No collectors ran</td></tr>"


def _finding_rows(findings) -> str:
    rows = [
        f'<tr><td><span class="b {_sev_class(f.severity)}">{escape(f.severity.replace("_", " "))}</span></td>'
        f"<td><code>{escape(f.rule_name)}</code><div><code>{escape(f.finding_id or '-') }</code></div></td>"
        f"<td>{escape(f.summary)}</td><td>{escape(f.reason)}</td></tr>"
        for f in findings
    ]
    return "".join(rows) or "<tr><td colspan='4'>No findings</td></tr>"
