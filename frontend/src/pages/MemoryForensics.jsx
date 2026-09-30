import { useForensicJob } from "../hooks/useForensicJob";
import { useNavigate } from "react-router-dom";
import { Notice, SevBadge, Spinner, ProgramFlags } from "../components/ui";

export default function MemoryForensics() {
  const navigate = useNavigate();
  const { start, job, result, error } = useForensicJob("memory");
  const err = error;
  const busy = Boolean(job && !["complete", "error"].includes(job.status));

  const scan = start;

  const s = result?.summary || {};
  return <>
    <div className="page-head">
      <div><h2>Memory Forensics</h2><p>Inspect bounded Windows virtual-memory metadata and correlate executable private regions with process and thread evidence.</p></div>
      <button className="btn primary" onClick={scan} disabled={busy}>{busy ? <><Spinner /> Scanning…</> : "Run memory scan"}</button>
    </div>
    <Notice>{err}</Notice>
    <div className="notice" style={{marginBottom:12}}>Read-only analysis: RANDAR does not read or write process-memory bytes. Private executable memory, writable executable regions, and thread-start correlations are investigation indicators, not proof of injection.</div>
    {!result && !busy && <div className="panel"><div className="panel-b"><strong>Ready for scan.</strong><p className="muted-copy">The scan uses the existing bounded processes, modules, threads, and memory-region collectors.</p></div></div>}
    {busy && <div className="panel"><div className="panel-b"><Spinner /> Collecting process and memory metadata. This continues on the server if you change tabs.</div></div>}
    {result && <><div className="notice forensic-saved">Saved as investigation <b>#{result.investigation_id}</b>. <button className="btn sm" onClick={() => navigate(`/investigations/${result.investigation_id}?tab=memory`)}>Open saved investigation</button></div>
      <div className="grid g4 memory-metrics">
        <div className="kpi"><span>Memory regions</span><b>{s.regions ?? 0}</b></div>
        <div className="kpi"><span>Private executable</span><b>{s.private_executable_regions ?? 0}</b></div>
        <div className="kpi"><span>Writable executable</span><b>{s.writable_executable_regions ?? 0}</b></div>
        <div className="kpi"><span>Thread-start hits</span><b>{s.thread_starts_in_private_executable ?? 0}</b></div>
      </div>
      <div className="panel"><div className="panel-h"><div><h3>FORENSIC SNAPSHOT</h3><div className="panel-subtitle">Metadata-only snapshot identity and collection state</div></div></div><div className="panel-b detail-list">
        <dt>Mode</dt><dd>{result.mode}</dd><dt>Snapshot SHA-256</dt><dd className="mono">{result.snapshot_hash}</dd><dt>Elapsed</dt><dd>{result.elapsed_ms} ms</dd><dt>Correlated processes</dt><dd>{s.correlated_processes ?? 0}</dd>
      </div></div>
      <div className="panel"><div className="panel-h"><h3>PROCESS CORRELATION</h3></div><div className="panel-b tbl-wrap"><table className="t"><thead><tr><th>PID</th><th>Process</th><th>Program flags</th><th>Private EXEC</th><th>RWX/WRITABLE EXEC</th><th>Thread starts</th><th>Level</th></tr></thead><tbody>{(result.processes || []).map((p) => <tr key={p.pid}><td>{p.pid}</td><td>{p.process_name}</td><td><ProgramFlags flags={p.program_flags} kernelObserved={Boolean(p.kernel_component_observed)} compact /></td><td>{p.private_executable_regions}</td><td>{p.writable_executable_regions}</td><td>{p.thread_starts_in_private_executable || 0}</td><td><span className="badge">{p.correlation_level}</span></td></tr>)}</tbody></table></div></div>
      <div className="panel"><div className="panel-h"><div><h3>DETECTION FINDINGS</h3><div className="panel-subtitle">Explicit observations derived from the same memory correlation shown above</div></div><span className="badge">{result.finding_count ?? (result.findings || []).length}</span></div><div className="panel-b">{(result.findings || []).length === 0 ? <div className="finding-empty"><strong>No memory-execution indicators were produced.</strong><span>The scan completed, but no process crossed the configured correlation threshold. A clean result is different from a failed collection.</span></div> : <div className="finding-list">{result.findings.map((f, i) => <article className="finding-row" key={`${f.rule_name}-${f.related_evidence?.pid ?? "na"}-${f.related_evidence?.thread_id ?? "na"}-${i}`}><div className="finding-title"><SevBadge sev={f.severity} /> <strong>{f.summary}</strong></div><div className="finding-reason">{f.reason}</div>{f.next_check && <div className="finding-next"><b>Next check:</b> {f.next_check}</div>}</article>)}</div>}</div></div>
      {result.collector_errors?.length > 0 && <div className="panel"><div className="panel-h"><h3>SCAN DIAGNOSTICS</h3></div><div className="panel-b"><div className="finding-list">{result.collector_errors.map((x, i) => <div className="finding-row" key={`${x.collector || x.rule || "error"}-${i}`}><strong>{x.collector || x.rule || "scan component"}</strong><div className="finding-reason">{x.error}</div></div>)}</div></div></div>}
    </>}
  </>;
}
