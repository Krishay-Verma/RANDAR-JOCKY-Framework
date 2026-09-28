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

_CSS = """
:root{--ink:#111827;--mute:#6b7280;--line:#e5e7eb;--bg:#f9fafb}
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:var(--ink);margin:0;background:#fff}
header{background:#0b1220;color:#fff;padding:28px 48px}
header small{color:#93a4c0;letter-spacing:.12em;text-transform:uppercase;font-size:11px}
header h1{margin:6px 0 0;font-size:22px;font-weight:600}
main{max-width:1040px;margin:0 auto;padding:32px 48px 64px}
h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute);margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
dl{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;margin:0}
dt{color:var(--mute)}dd{margin:0;word-break:break-all}
.cards{display:flex;gap:10px;flex-wrap:wrap}
.card{border:1px solid var(--line);border-radius:6px;padding:10px 16px;min-width:112px;background:var(--bg)}
.card b{display:block;font-size:22px}.card span{font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--bg);color:var(--mute);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
code{font-family:Consolas,Menlo,monospace;font-size:12px}
.b{display:inline-block;padding:1px 8px;border-radius:3px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.sev-informational{background:#e5e7eb;color:#374151}.sev-review_recommended{background:#dbeafe;color:#1e40af}
.sev-medium{background:#fef3c7;color:#92400e}.sev-high{background:#fed7aa;color:#9a3412}
.sev-critical{background:#fecaca;color:#991b1b}
.st-success{background:#d1fae5;color:#065f46}.st-error{background:#fecaca;color:#991b1b}
footer{color:var(--mute);font-size:12px;margin-top:40px}
@media print{header{background:#fff;color:#000;border-bottom:2px solid #000}}
"""


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
<header><small>JOCKY &middot; Investigation Report</small>
<h1>{escape(report.investigation_name)}</h1></header>
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
