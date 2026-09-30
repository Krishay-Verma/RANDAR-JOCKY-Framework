import { useForensicJob } from "../hooks/useForensicJob";
import { useNavigate } from "react-router-dom";
import { Notice, Loading, SevBadge } from "../components/ui";

export default function PersistenceForensics() {
  const navigate = useNavigate();
  const { start, job, result, error } = useForensicJob("persistence");
  const busy = Boolean(job && !["complete", "error"].includes(job.status));
  const errorMessage = error;

  const scan = start;

  const summary = result?.summary || {};
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const cross = Array.isArray(result?.cross_surface) ? result.cross_surface : [];

  return <div className="forensics-workspace">
    <div className="page-head">
      <div><h2>Persistence &amp; Privilege Forensics</h2><p>Correlate read-only startup, scheduled-task, service, account, process and privilege telemetry.</p></div>
      <button className="btn primary" disabled={busy} onClick={scan}>{busy ? "Scanning…" : "Run forensic scan"}</button>
    </div>
    <Notice kind="info">The scan observes configuration and telemetry only. It does not create, modify, enable, disable or execute persistence mechanisms.</Notice>
    {errorMessage && <Notice>{errorMessage}</Notice>}
    {!result && !busy && <div className="empty"><h3>No scan has been run</h3><div>Run the bounded read-only scan to populate persistence and privilege evidence.</div></div>}
    {busy && !result && <div className="panel"><div className="panel-b"><Loading /> <span>Scan continues in the server background; you may change tabs safely.</span></div></div>}
    {result && <><div className="notice forensic-saved">Saved as investigation <b>#{result.investigation_id}</b>. <button className="btn sm" onClick={() => navigate(`/investigations/${result.investigation_id}?tab=persistence`)}>Open saved investigation</button></div>
      <div className="grid g4 persistence-metrics">
        {[['Startup items',summary.startup_items],['Scheduled tasks',summary.scheduled_tasks],['Services',summary.services],['Cross-surface paths',summary.cross_surface_paths],['Local users',summary.local_users],['Sessions',summary.logged_in_sessions],['Privilege events',summary.privilege_events],['Service-change events',summary.service_change_events]].map(([label,value])=><div className="panel kpi" key={label}><span>{label}</span><b>{value ?? 0}</b></div>)}
      </div>
      <div className="grid g2">
        <div className="panel"><div className="panel-h"><div><h3>Cross-surface persistence correlation</h3><div className="panel-subtitle">Normalized paths observed in more than one persistence surface.</div></div><span className="badge">{cross.length}</span></div>
          {cross.length ? <div className="tbl-wrap"><table className="t"><thead><tr><th>Path</th><th>Surfaces</th></tr></thead><tbody>{cross.map((x,i)=><tr key={`${x.path}-${i}`}><td className="mono wrap-cell">{x.path}</td><td>{(x.surfaces||[]).map(s=><span className="badge" key={s}>{s}</span>)}</td></tr>)}</tbody></table></div> : <div className="empty"><h3>No cross-surface matches</h3><div>No normalized executable path appeared across multiple persistence surfaces.</div></div>}
        </div>
        <div className="panel"><div className="panel-h"><div><h3>Scan identity</h3><div className="panel-subtitle">Deterministic identity and collection scope.</div></div></div><dl className="kv panel-b"><dt>Mode</dt><dd className="mono">{result.mode}</dd><dt>Version</dt><dd>{result.version}</dd><dt>Snapshot SHA-256</dt><dd className="mono wrap-cell">{result.snapshot_hash}</dd><dt>Elapsed</dt><dd>{result.elapsed_ms} ms</dd><dt>Findings</dt><dd>{result.finding_count}</dd></dl></div>
      </div>
      <div className="panel"><div className="panel-h"><div><h3>Detection findings</h3><div className="panel-subtitle">Indicators are investigative leads and retain their limitations and next checks.</div></div><span className="badge">{findings.length}</span></div>
        {findings.length ? <div className="tbl-wrap"><table className="t"><thead><tr><th>Severity</th><th>Rule</th><th>Observation</th><th>Next check</th></tr></thead><tbody>{findings.map((f,i)=><tr key={`${f.rule_name}-${i}`}><td><SevBadge sev={f.severity}/></td><td><strong>{f.rule_name}</strong></td><td><div className="finding-name">{f.summary}</div><div className="finding-reason">{f.reason}</div></td><td>{f.next_check || "Review supporting evidence."}</td></tr>)}</tbody></table></div> : <div className="empty"><h3>No persistence or privilege indicators</h3><div>The configured read-only rules did not produce a matching observation.</div></div>}
      </div>
      {result.collector_errors?.length ? <div className="panel"><div className="panel-h"><div><h3>Collector diagnostics</h3></div></div><div className="panel-b finding-list">{result.collector_errors.map((x,i)=><div className="finding-row" key={i}><strong>{x.collector}</strong><div className="finding-reason">{x.error}</div></div>)}</div></div> : null}
      <div className="panel"><div className="panel-h"><div><h3>Collection limitations</h3></div></div><ul className="compact-list">{(result.limitations||[]).map((x,i)=><li key={i}>{x}</li>)}</ul></div>
    </>}
  </div>;
}
