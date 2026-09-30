import { useForensicJob } from "../hooks/useForensicJob";
import { useNavigate } from "react-router-dom";
import { Notice, SevBadge, Spinner, ProgramFlags } from "../components/ui";

export default function DriverForensics() {
  const navigate = useNavigate();
  const { start, job, result, error } = useForensicJob("driver");
  const err = error;
  const busy = Boolean(job && !["complete", "error"].includes(job.status));

  const scan = start;

  const s = result?.summary || {};
  return <>
    <div className="page-head">
      <div><h2>Driver Forensics</h2><p>Inventory Windows drivers, correlate vulnerable-driver exposure, and inspect available kernel/security telemetry without modifying kernel state.</p></div>
      <button className="btn primary" onClick={scan} disabled={busy}>{busy ? <><Spinner /> Scanning…</> : "Run driver scan"}</button>
    </div>
    <Notice>{err}</Notice>
    <div className="notice" style={{marginBottom:12}}>Read-only research boundary: RANDAR inventories driver metadata and security telemetry only. It does not load, unload, exploit, disable callbacks, alter kernel structures, or interact with vulnerable drivers beyond evidence collection.</div>
    {!result && !busy && <div className="panel"><div className="panel-b"><strong>Ready for scan.</strong><p className="muted-copy">On Windows, the scan collects registered kernel/file-system drivers, load state, hashes, best-effort signer/version metadata, and configured vulnerable-driver catalog matches.</p></div></div>}
    {busy && <div className="panel"><div className="panel-b"><Spinner /> Collecting driver and Windows security metadata. This continues on the server if you change tabs.</div></div>}
    {result && <><div className="notice forensic-saved">Saved as investigation <b>#{result.investigation_id}</b>. <button className="btn sm" onClick={() => navigate(`/investigations/${result.investigation_id}?tab=driver`)}>Open saved investigation</button></div>
      <div className="grid g4 driver-metrics">
        <div className="kpi"><span>Drivers</span><b>{s.drivers ?? 0}</b></div>
        <div className="kpi"><span>Loaded</span><b>{s.loaded_drivers ?? 0}</b></div>
        <div className="kpi"><span>Known vulnerable</span><b>{s.known_vulnerable_drivers ?? 0}</b></div>
        <div className="kpi"><span>Unsigned</span><b>{s.unsigned_drivers ?? 0}</b></div>
      </div>
      <div className="panel"><div className="panel-h"><div><h3>DRIVER FORENSIC SNAPSHOT</h3><div className="panel-subtitle">Inventory identity and kernel-observation boundary</div></div></div><div className="panel-b detail-list">
        <dt>Mode</dt><dd>{result.mode}</dd><dt>Snapshot SHA-256</dt><dd className="mono">{result.snapshot_hash}</dd><dt>Catalog source</dt><dd className="mono">{result.catalog_source || "Operator catalog not configured"}</dd><dt>Elapsed</dt><dd>{result.elapsed_ms} ms</dd>
      </div></div>
      <div className="panel"><div className="panel-h"><div><h3>DRIVER INVENTORY</h3><div className="panel-subtitle">Registered and loaded driver metadata</div></div><span className="badge">{result.drivers?.length || 0} records</span></div><div className="panel-b tbl-wrap"><table className="t"><thead><tr><th>Service</th><th>Program flags</th><th>Driver</th><th>State</th><th>Version</th><th>Publisher</th><th>Signature</th><th>SHA-256</th><th>Vulnerability</th></tr></thead><tbody>{(result.drivers || []).map((d, i) => <tr key={`${d.service_name}-${i}`}><td><b>{d.service_name}</b><div className="finding-code mono">{d.image_path || "path unavailable"}</div></td><td><ProgramFlags flags={d.program_flags} kernelObserved={Boolean(d.kernel_component_observed)} kernelLabel="KERNEL DRIVER" compact /></td><td>{d.display_name || "—"}</td><td><span className="badge">{d.loaded ? "loaded" : "registered"}</span></td><td>{d.version || "—"}</td><td>{d.publisher || "—"}</td><td>{d.signature_status || "unknown"}</td><td className="mono">{d.sha256 || "—"}</td><td>{d.known_vulnerable ? <span className="badge sev-high">Matched</span> : "—"}</td></tr>)}</tbody></table>{!result.drivers?.length && <div className="finding-empty"><strong>No driver records returned.</strong><span>{result.supported ? "The endpoint returned an empty inventory." : "Driver inventory is not supported on this platform."}</span></div>}</div></div>
      <div className="panel"><div className="panel-h"><div><h3>KERNEL / SECURITY TELEMETRY</h3><div className="panel-subtitle">Availability of supporting evidence; absence is not treated as proof of a clean kernel</div></div></div><div className="panel-b"><div className="grid g2">{Object.entries(result.kernel_observation?.security_telemetry || {}).map(([name, v]) => <div className="telemetry-status" key={name}><b>{name.replaceAll("_", " ")}</b><span className={`badge ${v.supported ? "st-success" : "st-error"}`}>{v.supported ? "available" : "unavailable"}</span><small>{v.error || `${v.count ?? 0} records`}</small></div>)}</div><div className="notice" style={{marginTop:12}}>Kernel state modified: <b>{String(result.kernel_observation?.kernel_state_modified ?? false)}</b>. Kernel objects read directly: <b>{String(result.kernel_observation?.kernel_objects_read ?? false)}</b>.</div></div></div>
      <div className="panel"><div className="panel-h"><div><h3>DETECTION FINDINGS</h3><div className="panel-subtitle">Exposure indicators derived from driver metadata and catalog correlation</div></div><span className="badge">{result.finding_count ?? (result.findings || []).length}</span></div><div className="panel-b">{(result.findings || []).length === 0 ? <div className="finding-empty"><strong>No driver exposure indicators were produced.</strong><span>The scan completed without a configured rule match. This does not establish that the endpoint is free of vulnerable drivers; catalog coverage and signature availability matter.</span></div> : <div className="finding-list">{result.findings.map((f, i) => <article className="finding-row" key={`${f.rule_name}-${i}`}><div className="finding-title"><SevBadge sev={f.severity} /><strong>{f.summary}</strong></div><div className="finding-reason">{f.reason}</div>{f.next_check && <div className="finding-next"><b>Next check:</b> {f.next_check}</div>}</article>)}</div>}</div></div>
      {result.collector_errors?.length > 0 && <div className="panel"><div className="panel-h"><h3>SCAN DIAGNOSTICS</h3></div><div className="panel-b"><div className="finding-list">{result.collector_errors.map((x, i) => <div className="finding-row" key={`${x.collector || x.rule || "error"}-${i}`}><strong>{x.collector || x.rule || "scan component"}</strong><div className="finding-reason">{x.error}</div></div>)}</div></div></div>}
    </>}
  </>;
}
