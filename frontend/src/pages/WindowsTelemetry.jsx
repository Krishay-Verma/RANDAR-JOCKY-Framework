import { useMemo, useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import { useInvestigationJob } from "../hooks/useInvestigationJob";
import ScriptEditor from "../components/ScriptEditor";
import { Loading, Notice, SevBadge } from "../components/ui";
import { asArray, TEMPLATES, humanizeCollector, humanizeRule, lineFromError } from "../lib";

const RULES = new Set([
  "encoded_powershell", "suspicious_powershell_parent", "powershell_network_activity",
  "powershell_child_processes", "suspicious_services", "writable_service_paths",
  "persistence_correlation",
]);

export default function WindowsTelemetry() {
  const list = useLoad((signal) => api.investigations(signal), []);
  const catalog = useLoad((signal) => api.catalog(signal), []);
  const [selected, setSelected] = useState("");
  const [script, setScript] = useState(TEMPLATES["Windows telemetry hunt"]);
  const [error, setError] = useState("");
  const { start, job, error: jobError } = useInvestigationJob("windows-telemetry");
  const running = Boolean(job && !["complete", "partial", "cancelled", "error"].includes(job.status));
  useEffect(() => { if (job?.status === "complete" && job.investigation_id) { setSelected(String(job.investigation_id)); list.reload(); } }, [job?.status, job?.investigation_id]);
  const records = asArray(list.data);
  const chosen = records.find((r) => String(r.id) === selected);
  const report = chosen?.report_json;
  const findings = useMemo(() => asArray(report?.findings).filter((f) => RULES.has(f.rule_name)), [report]);
  const collectors = asArray(report?.collector_results);
  const telemetryCollectors = ["windows_event_logs", "sysmon_events", "services"];

  async function run() {
    setError("");
    try { await start(script); } catch (e) { setError(e.message); }
  }

  if (list.loading && !list.data) return <Loading />;
  if (list.error) return <Notice>{list.error.message}</Notice>;

  return (
    <>
      <div className="page-head">
        <div><h2>Windows telemetry</h2><p>Read-only Windows PowerShell, Event Log, Sysmon, services and persistence telemetry.</p></div>
        <button className="btn primary" disabled={running} onClick={run}>{running ? "Running hunt…" : "Run Windows telemetry hunt"}</button>
      </div>
      <Notice kind="info">This pack does not execute user-supplied PowerShell. Collection uses fixed, allowlisted read-only queries; analysis operates only on collected evidence.</Notice>
      {(error || jobError) && <Notice>{error || jobError}</Notice>}
      {job && !["complete", "error", "partial", "cancelled"].includes(job.status) && <div className="panel" style={{ marginBottom: 12 }}><div className="panel-b"><strong>Windows telemetry hunt is running on the server.</strong><div className="muted-copy">You can change tabs without cancelling it. Status: {job.status} · {job.progress ?? 0}%</div></div></div>}
      <div className="grid g3">
        <div className="panel kpi"><span>PowerShell indicators</span><b>{findings.filter((f) => f.rule_name.startsWith("powershell") || f.rule_name === "encoded_powershell").length}</b></div>
        <div className="panel kpi"><span>Service indicators</span><b>{findings.filter((f) => f.rule_name.includes("service")).length}</b></div>
        <div className="panel kpi"><span>Persistence correlations</span><b>{findings.filter((f) => f.rule_name === "persistence_correlation").length}</b></div>
      </div>
      {catalog.data && <div className="panel" style={{ marginTop: 16 }}><div className="panel-h"><div><h3>Live capability coverage</h3><div className="panel-subtitle">Driven by the backend registry so newly registered capabilities cannot disappear from the UI.</div></div><span className="badge">{asArray(catalog.data.collectors).length} collectors · {asArray(catalog.data.rules).length} rules</span></div><div className="panel-b"><div className="row" style={{ flexWrap: "wrap" }}>{asArray(catalog.data.collectors).filter((c) => ["windows_event_logs", "sysmon_events", "services"].includes(c.name)).map((c) => <span className="badge" key={c.name}>{humanizeCollector(c.name)}</span>)}</div></div></div>}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-h"><div><h3>Investigation</h3><div className="panel-subtitle">Select a stored Windows telemetry investigation to inspect its findings.</div></div>
          <select className="select" value={selected} onChange={(e) => setSelected(e.target.value)}><option value="">Select investigation</option>{records.map((r) => <option key={r.id} value={r.id}>#{r.id} — {r.investigation_name}</option>)}</select>
        </div>
        {report ? <div className="panel-b">
          <div className="grid g3">{telemetryCollectors.map((target) => { const c = collectors.find((x) => x.target === target); return <div className="telemetry-status" key={target}><b>{humanizeCollector(target)}</b><span className={`badge ${c?.status === "success" ? "sev-review_recommended" : "sev-high"}`}>{c?.status || "not collected"}</span><small>{c?.status === "error" ? c.error : c?.data?.error || `${c?.data?.count || 0} records`}</small></div>; })}</div>
        </div> : <div className="empty"><h3>No investigation selected</h3><div>Run the Windows telemetry hunt or select an existing investigation.</div></div>}
      </div>
      {report && <div className="panel" style={{ marginTop: 16 }}><div className="panel-h"><div><h3>V1.3 findings</h3><div className="panel-subtitle">Indicators retain the exact supporting evidence used by each rule.</div></div><span className="badge">{findings.length} indicators</span></div>
        {findings.length ? <div className="tbl-wrap"><table className="t"><thead><tr><th>Severity</th><th>Rule</th><th>Observation</th><th>Evidence</th></tr></thead><tbody>{findings.map((f, i) => <tr key={`${f.rule_name}-${i}`}><td><SevBadge sev={f.severity} /></td><td><b>{humanizeRule(f.rule_name)}</b><div className="finding-code mono">{f.rule_name}</div></td><td><b>{f.summary}</b><div className="finding-reason">{f.reason}</div></td><td><pre className="json">{JSON.stringify(f.related_evidence || {}, null, 2)}</pre></td></tr>)}</tbody></table></div> : <div className="empty"><h3>No V1.3 indicators</h3><div>The configured rules ran without producing a matching observation.</div></div>}
      </div>}
      <div className="panel" style={{ marginTop: 16 }}><div className="panel-h"><div><h3>Windows telemetry script</h3><div className="panel-subtitle">The DSL artifact is reviewable, allowlisted and reproducible.</div></div></div><div className="panel-b"><ScriptEditor value={script} onChange={setScript} errorLine={lineFromError(error)} rows={18} /></div></div>
      <p className="muted-copy" style={{ marginTop: 10 }}><Link to="/investigations/new">Open the full investigation builder</Link> to choose another script or network evidence source.</p>
    </>
  );
}
