"""
Standalone HTML report writer.

Plain string building with html.escape on every interpolated value; no
templating dependency. The document is self-contained (inline CSS, no
scripts) so it can be archived or attached to a case file as-is.
"""

from html import escape
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
<title>JOCKY Report - {escape(report.investigation_name)}</title>
<style>{_CSS}</style></head>
<body>
<header>{_REPORT_MARK}<div class="brand-copy"><small>JOCKY &middot; Forensic Triage Console</small>
<h1>{escape(report.investigation_name)}</h1></div></header>
<main>
<h2>Summary</h2>
<dl>
<dt>Endpoint</dt><dd>{escape(report.endpoint_hostname)}</dd>
<dt>Started</dt><dd>{escape(report.started_at)}</dd>
<dt>Finished</dt><dd>{escape(report.finished_at)}</dd>
<dt>Report name</dt><dd>{escape(report.report_name or "-")}</dd>
<dt>Script SHA-256</dt><dd><code>{escape(report.script_hash or "not recorded")}</code></dd>
</dl>
<h2>Findings by severity</h2><div class="cards">{cards}</div>
{_injection_section(report)}
<h2>Collector status</h2>
<table><tr><th>Collector</th><th>Status</th><th>Detail</th></tr>{_collector_rows(report)}</table>
<h2>Findings ({len(report.findings)})</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Summary</th><th>Reason</th></tr>{_finding_rows(ordered)}</table>
<footer>Findings are observations for analyst review, not verdicts.</footer>
</main></body></html>"""


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


def _collector_rows(report: Report) -> str:
    rows = []
    for cr in report.collector_results:
        ok = cr.status != "error"
        detail = "OK" if ok else (cr.error or "error")
        rows.append(
            f"<tr><td><code>{escape(cr.target)}</code></td>"
            f'<td><span class="b {"st-success" if ok else "st-error"}">{escape(cr.status)}</span></td>'
            f"<td>{escape(str(detail))}</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan='3'>No collectors ran</td></tr>"


def _finding_rows(findings) -> str:
    rows = [
        f'<tr><td><span class="b {_sev_class(f.severity)}">{escape(f.severity.replace("_", " "))}</span></td>'
        f"<td><code>{escape(f.rule_name)}</code></td>"
        f"<td>{escape(f.summary)}</td><td>{escape(f.reason)}</td></tr>"
        for f in findings
    ]
    return "".join(rows) or "<tr><td colspan='4'>No findings</td></tr>"
