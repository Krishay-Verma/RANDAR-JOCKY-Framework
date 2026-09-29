import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import { Empty, Loading, Notice, SevChips, Pill } from "../components/ui";
import { asArray, humanizeCollector, humanizeRule, SEVERITIES, SEV_COLOR, SEV_LABEL, fmtTime } from "../lib";

const INJECTION_RULES = new Set([
  "suspicious_module_loads", "dll_sideloading", "process_hollowing_indicators",
  "reflective_load_indicators", "thread_hijacking_indicators", "injection_correlation",
  "unsigned_loaded_module", "suspicious_imports", "high_entropy_module",
  "module_disk_mismatch", "suspicious_writable_module",
]);

function injectionSummary(record) {
  const report = record?.report_json;
  const findings = asArray(report?.findings).filter((f) => INJECTION_RULES.has(f.rule_name));
  const modules = asArray(report?.collector_results).find((c) => c.target === "modules")?.data?.count || 0;
  const threads = asArray(report?.collector_results).find((c) => c.target === "threads")?.data?.count || 0;
  const regions = asArray(report?.collector_results).find((c) => c.target === "memory_regions")?.data?.count || 0;
  const peFiles = asArray(report?.collector_results).find((c) => c.target === "pe_metadata")?.data?.count || 0;
  return { findings, modules, threads, regions, peFiles };
}

export default function Dashboard() {
  const stats = useLoad((signal) => api.stats(signal), [], 15_000);
  const list = useLoad((signal) => api.investigations(signal), []);
  const catalog = useLoad((signal) => api.catalog(signal), []);

  if (stats.loading && !stats.data) return <Loading />;
  if (stats.error) return <Notice>{stats.error.message}</Notice>;
  const s = stats.data;
  const sev = s.severity_totals || {};
  const hosts = Array.isArray(s.hosts) ? s.hosts : [];
  const topRules = Array.isArray(s.top_rules) ? s.top_rules : [];
  const statusTotals = s.status_totals || {};
  const total = s.total_findings || 0;
  const urgent = (sev.critical || 0) + (sev.high || 0);
  const maxRule = Math.max(1, ...topRules.map((r) => r.count || 0));
  const records = asArray(list.data);
  const recent = records.slice(0, 8);
  const injectionRuns = records.map((r) => ({ record: r, ...injectionSummary(r) }));
  const injectionFindingCount = injectionRuns.reduce((n, x) => n + x.findings.length, 0);
  const injectionTelemetryRuns = injectionRuns.filter((x) => x.modules || x.threads || x.regions).length;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Security overview</h2>
          <p>Aggregate results across all stored investigations.</p>
        </div>
        <Link to="/investigations/new" className="btn primary">New investigation</Link>
      </div>

      {s.total_investigations === 0 ? (
        <div className="panel">
          <Empty title="No investigations yet">
            Run your first triage to populate this dashboard.
            <div style={{ marginTop: 16 }}><Link to="/investigations/new" className="btn primary">Run investigation</Link></div>
          </Empty>
        </div>
      ) : (
        <>
          <div className="grid g4" style={{ marginBottom: 16 }}>
            <div className="panel kpi"><span>Investigations</span><b>{s.total_investigations}</b></div>
            <div className="panel kpi"><span>Total findings</span><b>{s.total_findings}</b></div>
            <div className={`panel kpi ${urgent ? "crit" : ""}`}><span>Critical + high</span><b>{urgent}</b></div>
            <div className="panel kpi"><span>Open cases</span><b>{(statusTotals.open || 0) + (statusTotals.in_review || 0)}</b></div>
          </div>

          <div className="grid g21" style={{ marginBottom: 16 }}>
            <div className="panel">
              <div className="panel-h"><h3>Findings by severity</h3></div>
              <div className="panel-b">
                <div className="stack" role="img" aria-label="Severity distribution">
                  {total > 0 && SEVERITIES.map((k) => (
                    <div key={k} style={{ width: `${(sev[k] / total) * 100}%`, background: SEV_COLOR[k] }} title={`${SEV_LABEL[k]}: ${sev[k]}`} />
                  ))}
                </div>
                <div className="legend">
                  {SEVERITIES.map((k) => (
                    <span key={k}><i style={{ background: SEV_COLOR[k] }} />{SEV_LABEL[k]} <b style={{ color: "var(--text)" }}>{sev[k]}</b></span>
                  ))}
                </div>
              </div>
            </div>
            <div className="panel">
              <div className="panel-h"><h3>Case status</h3></div>
              <div className="panel-b">
                {Object.entries(statusTotals).map(([k, v]) => (
                  <div key={k} className="row" style={{ justifyContent: "space-between", margin: "6px 0" }}>
                    <Pill value={k} /><b>{v}</b>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="grid g2" style={{ marginBottom: 16 }}>
            <div className="panel">
              <div className="panel-h"><h3>Top triggered rules (excl. informational)</h3></div>
              <div className="panel-b">
                {topRules.length === 0 && <span style={{ color: "var(--mute)" }}>No elevated findings.</span>}
                {topRules.map((r) => (
                  <div className="hbar" key={r.rule}>
                    <span title={r.rule}>{r.rule}</span>
                    <div className="tr"><div className="fl" style={{ width: `${(r.count / maxRule) * 100}%` }} /></div>
                    <b>{r.count}</b>
                  </div>
                ))}
              </div>
            </div>
            <div className="panel">
              <div className="panel-h"><h3>Investigated endpoints</h3></div>
              <div className="panel-b">
                {hosts.map((h) => (
                  <div className="hbar" key={h.host}>
                    <span title={h.host}>{h.host}</span>
                    <div className="tr"><div className="fl" style={{ width: `${(h.count / Math.max(1, hosts[0]?.count || 0)) * 100}%`, background: "var(--review)" }} /></div>
                    <b>{h.count}</b>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="panel injection-banner" style={{ marginBottom: 12 }}>
            <div className="panel-b">
              <div>
                <div className="injection-kicker">Windows endpoint telemetry</div>
                <div className="injection-title">DLL / injection analysis</div>
                <p className="injection-copy">RANDAR correlates loaded modules, thread start addresses and private executable memory to surface DLL sideloading, hollowing, reflective-loading and thread-hijacking indicators.</p>
                <div className="row" style={{ marginTop: 9 }}>
                  <Link to="/injection" className="btn primary sm">Open injection analysis</Link>
                  <span style={{ color: "var(--muted)", fontSize: 11 }}>{injectionFindingCount} injection indicator{injectionFindingCount === 1 ? "" : "s"} across stored cases</span>
                </div>
              </div>
              <div className="injection-coverage">
                <div className="coverage-cell"><b>{injectionTelemetryRuns}</b><span>Runs with telemetry</span></div>
                <div className="coverage-cell"><b>{injectionRuns.reduce((n,x) => n+x.modules,0)}</b><span>Modules observed</span></div>
                <div className="coverage-cell"><b>{injectionRuns.reduce((n,x) => n+x.regions,0)}</b><span>Memory regions</span></div>
                <div className="coverage-cell"><b>{injectionRuns.reduce((n,x) => n+x.peFiles,0)}</b><span>PE files inspected</span></div>
              </div>
            </div>
          </div>

          {catalog.data && <div className="panel" style={{ marginBottom: 12 }}><div className="panel-h"><div><h3>Full engine capability</h3><div className="panel-subtitle">Live registry coverage — every registered collector and analysis rule is available through the controlled DSL.</div></div><span className="badge">{asArray(catalog.data.collectors).length} collectors · {asArray(catalog.data.rules).length} rules</span></div><div className="panel-b"><div className="grid g2"><div><h4 style={{ marginTop: 0 }}>Collectors</h4><div className="capability-list">{asArray(catalog.data.collectors).map((c) => <div className="row" style={{ justifyContent: "space-between", borderBottom: "1px solid var(--line)", padding: "5px 0" }} key={c.name}><span className="mono">{c.name}</span><span style={{ color: "var(--muted)", fontSize: 11 }}>{humanizeCollector(c.name)}</span></div>)}</div></div><div><h4 style={{ marginTop: 0 }}>Analysis rules</h4><div className="capability-list">{asArray(catalog.data.rules).map((r) => <div className="row" style={{ justifyContent: "space-between", borderBottom: "1px solid var(--line)", padding: "5px 0" }} key={r.name}><span className="mono">{r.name}</span><span style={{ color: "var(--muted)", fontSize: 11 }}>{humanizeRule(r.name)}</span></div>)}</div></div></div><div className="row" style={{ marginTop: 12 }}><Link to="/investigations/new" className="btn primary sm">Run Domain Expansion Triage</Link><Link to="/bytecode" className="btn sm">Inspect bytecode</Link></div></div></div>}

          <div className="panel">
            <div className="panel-h"><h3>Recent investigations</h3><Link to="/investigations">View all</Link></div>
            <div className="tbl-wrap">
              <table className="t">
                <thead><tr><th>Name</th><th>Endpoint</th><th>Started</th><th>C / H / M</th><th>Findings</th><th>DLL / PE</th><th>Status</th></tr></thead>
                <tbody>
                  {recent.map((r) => (
                    <tr key={r.id}>
                      <td><Link to={`/investigations/${r.id}`}>{r.investigation_name}</Link></td>
                      <td className="mono">{r.endpoint_hostname}</td>
                      <td className="num">{fmtTime(r.started_at)}</td>
                      <td><SevChips counts={r.severity_counts} /></td>
                      <td className="num">{r.findings_count}</td>
                      <td>{injectionSummary(r).findings.length ? <span className="badge sev-high">{injectionSummary(r).findings.length} indicators</span> : injectionSummary(r).modules || injectionSummary(r).peFiles ? <span className="badge sev-review_recommended">Telemetry</span> : <span style={{ color: "var(--dim)" }}>—</span>}</td>
                      <td><Pill value={r.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}
