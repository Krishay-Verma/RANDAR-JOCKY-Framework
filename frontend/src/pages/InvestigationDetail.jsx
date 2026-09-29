import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, saveBlob } from "../api/client";
import { useLoad } from "../hooks";
import EvidenceTable from "../components/EvidenceTable";
import { EditCaseModal } from "./Investigations";
import { Confirm, Loading, Notice, Pill, SevBadge } from "../components/ui";
import { asArray, humanizeCollector, humanizeRule, SEVERITIES, SEV_LABEL, fmtDuration, fmtTime } from "../lib";

const NETWORK_HUNT_RULES = new Set([
  "suspicious_dns_queries", "dns_entropy", "rare_domains", "suspicious_tld_patterns",
  "dns_bursts", "unusual_query_types", "long_random_labels", "dns_tunneling_indicators",
  "dns_beaconing", "network_beaconing", "port_scan", "horizontal_scan",
  "service_discovery", "udp_scan", "network_classification", "process_network_correlation",
]);

const WINDOWS_TELEMETRY_RULES = new Set([
  "encoded_powershell", "suspicious_powershell_parent", "powershell_network_activity",
  "powershell_child_processes", "suspicious_services", "writable_service_paths",
  "persistence_correlation",
]);

const INJECTION_RULES = new Set([
  "suspicious_module_loads", "dll_sideloading", "process_hollowing_indicators",
  "reflective_load_indicators", "thread_hijacking_indicators", "injection_correlation",
]);

const PE_RULES = new Set([
  "unsigned_loaded_module", "suspicious_imports", "high_entropy_module",
  "module_disk_mismatch", "suspicious_writable_module",
]);

const PERSISTENCE_RULES = new Set(["unusual_scheduled_tasks", "suspicious_startup_items", "privileged_user_anomaly", "persistence_correlation", "suspicious_services", "writable_service_paths"]);
const FINDING_FILTERS = ["all", "high", "review", "network", "injection", "persistence", "powershell"];

function findingMatchesFilter(f, filter) {
  if (filter === "all") return true;
  if (filter === "high") return f.severity === "high";
  if (filter === "review") return f.severity === "review_recommended";
  if (filter === "network") return NETWORK_HUNT_RULES.has(f.rule_name);
  if (filter === "injection") return INJECTION_RULES.has(f.rule_name) || PE_RULES.has(f.rule_name);
  if (filter === "persistence") return PERSISTENCE_RULES.has(f.rule_name);
  if (filter === "powershell") return WINDOWS_TELEMETRY_RULES.has(f.rule_name) && (f.rule_name.includes("powershell") || f.rule_name === "encoded_powershell");
  return false;
}

function evidenceObjectCount(collector) {
  if (!collector?.data) return 0;
  if (Number.isFinite(collector.data.count)) return Number(collector.data.count);
  const data = collector.data;
  for (const key of ["processes", "connections", "artifacts", "events", "modules", "threads", "regions", "files", "users", "tasks", "items"]) {
    if (Array.isArray(data[key])) return data[key].length;
  }
  return collector.status === "success" ? 1 : 0;
}

function EvidenceDrawer({ reference, collector, onClose }) {
  if (!reference) return null;
  const data = collector?.data || {};
  return <div className="evidence-drawer-bg" role="presentation" onClick={onClose}>
    <aside className="evidence-drawer" role="dialog" aria-modal="true" aria-label="Evidence context" onClick={(e) => e.stopPropagation()}>
      <div className="evidence-drawer-h"><div><div className="detail-label">Evidence context</div><h3>{reference.label || `${reference.key}=${reference.value}`}</h3></div><button className="btn sm" onClick={onClose}>Close</button></div>
      <div className="evidence-drawer-b">
        <div className="panel drawer-ref"><div className="panel-h"><div><h4>Referenced object</h4><div className="panel-subtitle">Exact reference retained with the finding.</div></div></div><dl className="kv panel-b"><dt>Collector</dt><dd className="mono">{reference.collector || "-"}</dd><dt>Property</dt><dd className="mono">{reference.key || "-"}</dd><dt>Value</dt><dd className="mono">{reference.value || "-"}</dd></dl></div>
        <div className="panel"><div className="panel-h"><div><h4>{humanizeCollector(reference.collector || "Evidence")}</h4><div className="panel-subtitle">Collected evidence from the same investigation.</div></div></div><div className="panel-b">{reference.collector ? <EvidenceTable data={data} investigationId={reference.investigationId} collectorTarget={reference.collector} /> : <pre className="json drawer-json">{JSON.stringify(data, null, 2)}</pre>}</div></div>
      </div>
    </aside>
  </div>;
}

function networkEvidence(report) {
  const collector = asArray(report?.collector_results).find((c) => c.target === "network_artifacts" && c.status === "success");
  const data = collector?.data || {};
  return { collector, data, stats: data.statistics || {}, source: data.source || {} };
}

function windowsTelemetryEvidence(report) {
  const collectors = asArray(report?.collector_results);
  const findings = asArray(report?.findings).filter((f) => WINDOWS_TELEMETRY_RULES.has(f.rule_name));
  const byTarget = (target) => collectors.find((c) => c.target === target);
  return {
    findings,
    eventLogs: byTarget("windows_event_logs"),
    sysmon: byTarget("sysmon_events"),
    services: byTarget("services"),
  };
}

function injectionEvidence(report) {
  const collectors = asArray(report?.collector_results);
  const count = (target) => collectors.find((c) => c.target === target)?.data?.count || 0;
  const findings = asArray(report?.findings).filter((f) => INJECTION_RULES.has(f.rule_name));
  return { findings, modules: count("modules"), threads: count("threads"), regions: count("memory_regions") };
}

function peEvidence(report) {
  const collectors = asArray(report?.collector_results);
  const collector = collectors.find((c) => c.target === "pe_metadata");
  const findings = asArray(report?.findings).filter((f) => PE_RULES.has(f.rule_name));
  return { collector, findings, files: collector?.data?.files || [] };
}

function FindingRow({ f, onEvidence }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="click" onClick={() => setOpen((o) => !o)}>
        <td><SevBadge sev={f.severity} /></td>
        <td><div className="finding-name">{humanizeRule(f.rule_name)}</div><div className="finding-code mono">{f.rule_name}</div></td>
        <td>{f.summary}</td>
        <td className="table-action">{open ? "Hide details" : "View details"}</td>
      </tr>
      {open && (
        <tr><td colSpan={4} style={{ padding: 0 }}>
          <div className="expand">
            <div className="explanation-grid">
              <div><div className="detail-label">What happened?</div><div>{f.summary}</div></div>
              <div><div className="detail-label">Why was it flagged?</div><div>{f.reason}</div></div>
              <div><div className="detail-label">Limitations</div><div>{f.limitations || "This is an investigation indicator and requires human validation."}</div></div>
              <div><div className="detail-label">Recommended next check</div><div>{f.next_check || "Pivot to the supporting evidence and validate the observation."}</div></div>
            </div>
            {f.related_evidence && Object.keys(f.related_evidence).length > 0 && (<><div className="detail-label">Supporting evidence</div><pre className="json">{JSON.stringify(f.related_evidence, null, 2)}</pre></>)}{asArray(f.evidence_refs).length > 0 && <div className="row" style={{ marginTop: 8, flexWrap: "wrap" }}>{f.evidence_refs.map((r, i) => <button key={i} className="btn sm" onClick={(e) => { e.stopPropagation(); if (typeof onEvidence === "function") onEvidence(r); }}>Open evidence: {r.label}</button>)}</div>}
          </div>
        </td></tr>
      )}
    </>
  );
}

function NetworkFindingRow({ f, onEvidence }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="click" onClick={() => setOpen((v) => !v)}>
        <td><SevBadge sev={f.severity} /></td>
        <td>
          <div className="finding-name">{humanizeRule(f.rule_name)}</div>
          <div className="finding-code mono">{f.rule_name}</div>
        </td>
        <td><strong>{f.summary}</strong><div className="finding-reason">{f.reason}</div></td>
        <td className="table-action">{open ? "Hide evidence" : "View evidence"}</td>
      </tr>
      {open && (
        <tr><td colSpan={4} style={{ padding: 0 }}>
          <div className="expand network-finding-expand">
            <div className="detail-label">Supporting evidence</div>
            <pre className="json">{JSON.stringify(f.related_evidence || {}, null, 2)}</pre>
            {asArray(f.evidence_refs).length > 0 && <div className="row" style={{ marginTop: 8, flexWrap: "wrap" }}>{f.evidence_refs.map((r, i) => <button key={i} className="btn sm" onClick={(e) => { e.stopPropagation(); if (typeof onEvidence === "function") onEvidence(r); }}>Open evidence: {r.label}</button>)}</div>}
          </div>
        </td></tr>
      )}
    </>
  );
}

function InjectionFindingRow({ f, onEvidence }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="click" onClick={() => setOpen((v) => !v)}>
        <td><SevBadge sev={f.severity} /></td>
        <td>
          <div className={f.rule_name.includes("dll") || f.rule_name.includes("module") ? "rule-dll finding-name" : "rule-injection finding-name"}>{humanizeRule(f.rule_name)}</div>
          <div className="finding-code mono">{f.rule_name}</div>
        </td>
        <td>
          <div>{f.summary}</div>
          <div className="finding-reason">{f.reason}</div>
        </td>
        <td className="table-action">{open ? "Hide details" : "View details"}</td>
      </tr>
      {open && (
        <tr><td colSpan={4} style={{ padding: 0 }}>
          <div className="expand">
            <div className="detail-label">Collected evidence</div>
            <pre className="json">{JSON.stringify(f.related_evidence || {}, null, 2)}</pre>
            {asArray(f.evidence_refs).length > 0 && <div className="row" style={{ marginTop: 8, flexWrap: "wrap" }}>{f.evidence_refs.map((r, i) => <button key={i} className="btn sm" onClick={(e) => { e.stopPropagation(); if (typeof onEvidence === "function") onEvidence(r); }}>Open evidence: {r.label}</button>)}</div>}
          </div>
        </td></tr>
      )}
    </>
  );
}

export default function InvestigationDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: rec, error, loading, reload } = useLoad((signal) => api.investigation(id, false, signal), [id]);
  const keys = useLoad((signal) => api.keyStatus(signal), []);
  const integrity = useLoad((signal) => api.integrity(id, signal), [id]);
  const audit = useLoad((signal) => api.audit(id, signal), [id]);
  const [tab, setTab] = useState("findings");
  const [sevFilter, setSevFilter] = useState("all");
  const [findingFilter, setFindingFilter] = useState("all");
  const [evTarget, setEvTarget] = useState(null);
  const [drawerRef, setDrawerRef] = useState(null);
  const [edit, setEdit] = useState(false);
  const [del, setDel] = useState(false);
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState({ kind: "ok", text: "" });

  const report = rec?.report_json;
  const findings = useMemo(() => {
    const order = (s) => SEVERITIES.indexOf(SEVERITIES.includes(s) ? s : "informational");
    return [...asArray(report?.findings)].sort((a, b) => order(a.severity) - order(b.severity));
  }, [report]);

  // Keep every hook unconditional. React error #310 can occur if the API
  // transitions between loading/error/data states and a hook is skipped.
  const networkHuntFindings = useMemo(() => {
    const order = (s) => SEVERITIES.indexOf(SEVERITIES.includes(s) ? s : "informational");
    return asArray(report?.findings)
      .filter((f) => NETWORK_HUNT_RULES.has(f.rule_name))
      .sort((a, b) => order(a.severity) - order(b.severity));
  }, [report]);

  if (loading && !rec) return <Loading />;
  if (error) return <Notice>{error.message} <Link to="/investigations">Back to investigations</Link></Notice>;

  const counts = rec.severity_counts || {};
  const injection = injectionEvidence(report);
  const windowsTelemetry = windowsTelemetryEvidence(report);
  const network = networkEvidence(report);
  const pe = peEvidence(report);
  const visible = findings.filter((f) => (sevFilter === "all" || f.severity === sevFilter) && findingMatchesFilter(f, findingFilter));
  const collectors = asArray(report.collector_results);
  const activeTarget = evTarget || collectors.find((c) => c.status === "success")?.target;
  const activeResult = collectors.find((c) => c.target === activeTarget);
  const successfulCollectors = collectors.filter((c) => c.status === "success");
  const objectsCollected = collectors.reduce((sum, c) => sum + evidenceObjectCount(c), 0);
  const categoryCounts = {
    all: findings.length, high: findings.filter((f) => f.severity === "high").length, review: findings.filter((f) => f.severity === "review_recommended").length,
    network: findings.filter((f) => findingMatchesFilter(f, "network")).length, injection: findings.filter((f) => findingMatchesFilter(f, "injection")).length,
    persistence: findings.filter((f) => findingMatchesFilter(f, "persistence")).length, powershell: findings.filter((f) => findingMatchesFilter(f, "powershell")).length,
  };
  const drawerCollector = drawerRef?.collector ? collectors.find((c) => c.target === drawerRef.collector) : null;

  async function download(kind) {
    setBusy(kind); setMsg({ kind: "ok", text: "" });
    try {
      if (kind === "html") saveBlob(await api.htmlReport(id), `randar_report_${id}.html`);
      else if (kind === "json") saveBlob(await api.jsonReport(id), `randar_report_${id}.json`);
      else saveBlob(await api.encryptedReport(id), `randar_report_${id}.enc`);
    } catch (e) { setMsg({ kind: "err", text: e.message }); }
    setBusy("");
  }

  async function remove() {
    setBusy("del");
    try { await api.remove(id); navigate("/investigations", { replace: true }); }
    catch (e) { setMsg({ kind: "err", text: e.message }); setDel(false); setBusy(""); }
  }

  const tabs = [
    ["findings", `Findings (${findings.length})`],
    ["network", `Network Forensics${network.collector ? ` (${networkHuntFindings.length})` : " · not collected"}`],
    ["windows", `Windows Telemetry${windowsTelemetry.eventLogs || windowsTelemetry.sysmon || windowsTelemetry.services ? ` (${windowsTelemetry.findings.length})` : " · not collected"}`],
    ["pe", `PE / Module${pe.collector ? ` (${pe.findings.length})` : " · not collected"}`],
    ["injection", `DLL / injection (${injection.findings.length})`],
    ["evidence", "Evidence"],
    ["collectors", `Collectors (${collectors.length})`],
    ["meta", "Case details"],
    ["integrity", "Integrity & provenance"],
    ["timeline", `Timeline (${asArray(report?.timeline).length})`],
    ["audit", `Audit log (${asArray(audit.data).length})`],
  ];

  return (
    <>
      <div className="page-head investigation-head">
        <div>
          <div className="breadcrumb"><Link to="/investigations">Investigations</Link> / Investigation #{rec.id}</div>
          <h2>{rec.investigation_name} <Pill value={rec.status} /></h2>
          <p className="case-meta"><span>{rec.endpoint_hostname}</span><span>{fmtTime(rec.started_at)}</span><span>{fmtDuration(rec.started_at, rec.finished_at)}</span></p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => setEdit(true)}>Edit investigation</button>
          <button className="btn" disabled={!!busy} onClick={() => download("html")}>HTML report</button>
          <button className="btn" disabled={!!busy} onClick={() => download("json")}>JSON report</button>
          <button className="btn" disabled={!!busy || !keys.data?.registered} onClick={() => download("enc")}
            title={keys.data?.registered ? "" : "Register a public key first"}>Encrypted report</button>
          <button className="btn danger" onClick={() => setDel(true)}>Delete</button>
        </div>
      </div>

      <Notice kind={msg.kind}>{msg.text}</Notice>
      {keys.data && !keys.data.registered && (
        <Notice kind="info">Encrypted export is unavailable until an RSA public key is registered. <Link to="/keys">Register a key</Link></Notice>
      )}

      <div className="panel v18-summary">
        <div className="panel-h"><div><h3>Investigation summary</h3><div className="panel-subtitle">A compact view of the evidence and indicators available for this case.</div></div><span className="badge">{successfulCollectors.length} successful collectors</span></div>
        <div className="panel-b"><div className="grid g3">
          <div className="kpi"><span>Objects collected</span><b>{objectsCollected}</b></div>
          <div className="kpi"><span>Indicators</span><b>{findings.length}</b></div>
          <div className="kpi"><span>High severity</span><b>{categoryCounts.high + (counts.critical || 0)}</b></div>
        </div><div className="grid g4 v18-summary-secondary">
          <div><span>Network</span><b>{categoryCounts.network}</b></div><div><span>Injection / PE</span><b>{categoryCounts.injection}</b></div><div><span>Persistence</span><b>{categoryCounts.persistence}</b></div><div><span>PowerShell</span><b>{categoryCounts.powershell}</b></div>
        </div><div className="panel-b v19-resource-strip"><span>Execution: <b>{report.execution_status || "complete"}</b></span><span>Elapsed: <b>{report.elapsed_ms || 0} ms</b></span><span>Records: <b>{report.resource_usage?.records_collected ?? 0}</b></span><span>Evidence: <b>{report.resource_usage?.evidence_bytes ?? 0} bytes</b></span><span>Timeouts: <b>{report.resource_usage?.timed_out_collectors ?? 0}</b></span><span>Truncated: <b>{report.resource_usage?.truncated_collectors ?? 0}</b></span></div></div>
      </div>

      <div className="panel injection-banner injection-summary">
        <div className="panel-b">
          <div>
            <div className="injection-kicker">Windows endpoint coverage</div>
            <div className="injection-title">DLL / injection analysis</div>
            <p className="injection-copy">Read-only checks for unusual DLL loading, executable memory and thread activity. Review the dedicated tab when you want the detailed indicators.</p>
            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn primary sm" onClick={() => setTab("injection")}>Open DLL / injection details</button>
              <span className={`badge ${injection.findings.length ? "sev-high" : "sev-review_recommended"}`}>
                {injection.findings.length ? `${injection.findings.length} indicators to review` : "No indicators"}
              </span>
            </div>
          </div>
          <div className="injection-coverage">
            <div className="coverage-cell"><b>{injection.modules}</b><span>Loaded DLLs / modules</span></div>
            <div className="coverage-cell"><b>{injection.threads}</b><span>Threads inspected</span></div>
            <div className="coverage-cell"><b>{injection.regions}</b><span>Memory regions</span></div>
          </div>
        </div>
      </div>

      <div className="grid g4 case-severity-grid">
        {["critical", "high", "medium", "review_recommended"].map((k) => (
          <div key={k} className={`panel kpi ${counts[k] ? (k === "critical" ? "crit" : k === "high" ? "warn" : "") : ""}`}>
            <span>{SEV_LABEL[k]}</span><b>{counts[k] || 0}</b>
          </div>
        ))}
      </div>

      <div className="tabs detail-tabs" role="tablist" aria-label="Investigation sections">
        {tabs.map(([k, l]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? "on" : ""} ${k === "injection" ? "tab-injection" : ""}`} onClick={() => setTab(k)}>
            {l}
          </button>
        ))}
      </div>

      {tab === "findings" && (
        <div className="findings-workspace">
        {asArray(report.analysis_results).length > 0 && <div className="panel" style={{ marginBottom: 12 }}><div className="panel-h"><div><h3>Analysis execution coverage</h3><div className="panel-subtitle">Every analysis command is recorded, including rules that produced no findings.</div></div><span className="badge">{asArray(report.analysis_results).length} rules executed</span></div><div className="tbl-wrap"><table className="t"><thead><tr><th>Rule</th><th>Status</th><th>Findings</th><th>Detail</th></tr></thead><tbody>{asArray(report.analysis_results).map((ar, i) => <tr key={`${ar.target}-${i}`}><td><div className="finding-name">{humanizeRule(ar.target)}</div><div className="finding-code mono">{ar.target}</div></td><td><Pill value={ar.status} label={ar.status} /></td><td className="num">{ar.finding_count ?? 0}</td><td>{ar.error || (ar.finding_count ? "Finding(s) generated." : "Executed successfully; no matching observation.")}</td></tr>)}</tbody></table></div></div>}
        <div className="panel">
          <div className="panel-h">
            <div>
              <h3>Investigation findings</h3>
              <div className="panel-subtitle">Review the observations produced by the investigation rules.</div>
            </div>
            <div className="filter-stack">
              <div className="row filter-row">{FINDING_FILTERS.map((k) => <button key={k} className={`btn sm ${findingFilter === k ? "primary" : ""}`} onClick={() => setFindingFilter(k)}>{k === "all" ? "All" : k === "review" ? "Review" : k === "high" ? "High" : k[0].toUpperCase() + k.slice(1)} {categoryCounts[k]}</button>)}</div>
              <div className="row filter-row"><span className="filter-label">Severity:</span>{["all", ...SEVERITIES].map((k) => <button key={k} className={`btn sm ${sevFilter === k ? "primary" : ""}`} onClick={() => setSevFilter(k)}>{k === "all" ? "All" : SEV_LABEL[k]} {k === "all" ? findings.length : counts[k] || 0}</button>)}</div>
            </div>
          </div>
          {visible.length === 0 ? (
            <div className="empty"><h3>No findings</h3><div>{sevFilter !== "all" ? "There are no findings at this severity." : "This investigation did not produce any findings."}</div></div>
          ) : (
            <div className="tbl-wrap"><table className="t">
              <thead><tr><th style={{ width: 110 }}>Severity</th><th>Finding</th><th>What was observed</th><th /></tr></thead>
              <tbody>{visible.map((f, i) => <FindingRow key={i} f={f} onEvidence={(r) => { setEvTarget(r.collector || null); setDrawerRef({ ...r, investigationId: id }); }} />)}</tbody>
            </table></div>
          )}
        </div>
        </div>
      )}

      {tab === "windows" && (
        <div className="windows-telemetry-workspace">
          <div className="grid g3">
            {[
              ["PowerShell indicators", windowsTelemetry.findings.filter((f) => f.rule_name.startsWith("powershell") || f.rule_name === "encoded_powershell").length],
              ["Service indicators", windowsTelemetry.findings.filter((f) => f.rule_name.includes("service")).length],
              ["Persistence correlations", windowsTelemetry.findings.filter((f) => f.rule_name === "persistence_correlation").length],
            ].map(([label, value]) => <div className="panel kpi" key={label}><span>{label}</span><b>{value}</b></div>)}
          </div>
          <div className="grid g3" style={{ marginTop: 14 }}>
            {[
              ["Windows Event Logs", windowsTelemetry.eventLogs],
              ["Sysmon", windowsTelemetry.sysmon],
              ["Services", windowsTelemetry.services],
            ].map(([label, collector]) => (
              <div className="panel telemetry-status" key={label}>
                <div className="panel-h"><h3>{label}</h3><span className={`badge ${collector?.status === "success" ? "sev-review_recommended" : "sev-high"}`}>{collector?.status || "not collected"}</span></div>
                <div className="panel-b"><b>{collector?.data?.count || 0}</b> records{collector?.data?.error ? <div className="finding-reason">{collector.data.error}</div> : null}</div>
              </div>
            ))}
          </div>
          <div className="panel" style={{ marginTop: 14 }}>
            <div className="panel-h"><div><h3>V1.3 Windows telemetry findings</h3><div className="panel-subtitle">Read-only indicators generated from process, Event Log, Sysmon, service and persistence evidence.</div></div><span className="badge">{windowsTelemetry.findings.length} indicators</span></div>
            {windowsTelemetry.findings.length ? (
              <div className="tbl-wrap"><table className="t"><thead><tr><th>Severity</th><th>Rule</th><th>Observation</th><th>Supporting evidence</th></tr></thead><tbody>{windowsTelemetry.findings.map((f, i) => <tr key={`${f.rule_name}-${i}`}><td><SevBadge sev={f.severity} /></td><td><div className="finding-name">{humanizeRule(f.rule_name)}</div><div className="finding-code mono">{f.rule_name}</div></td><td><b>{f.summary}</b><div className="finding-reason">{f.reason}</div></td><td><pre className="json">{JSON.stringify(f.related_evidence || {}, null, 2)}</pre></td></tr>)}</tbody></table></div>
            ) : <div className="empty"><h3>No V1.3 indicators</h3><div>The configured Windows telemetry rules did not produce a matching observation.</div></div>}
          </div>
        </div>
      )}

      {tab === "pe" && (
        <div className="injection-workspace">
          <div className="grid g3">
            <div className="panel kpi"><span>PE files inspected</span><b>{pe.files.length}</b></div>
            <div className="panel kpi"><span>PE indicators</span><b>{pe.findings.length}</b></div>
            <div className="panel kpi"><span>Embedded signatures</span><b>{pe.files.filter((f) => f.signature_status === "embedded_signature").length}</b></div>
          </div>
          <div className="panel" style={{ marginTop: 14 }}>
            <div className="panel-h"><div><h3>PE metadata</h3><div className="panel-subtitle">Read-only metadata from process/module files; binaries are never executed.</div></div></div>
            {pe.files.length ? (
              <div className="tbl-wrap"><table className="t"><thead><tr><th>File</th><th>Architecture</th><th>Type</th><th>Sections</th><th>Entropy</th><th>Signature</th><th>SHA-256</th></tr></thead><tbody>{pe.files.map((f, i) => <tr key={`${f.path}-${i}`}><td><div className="finding-name">{f.filename || "-"}</div><div className="finding-code mono">{f.path || "-"}</div></td><td>{f.architecture || "-"}</td><td>{f.pe_type || "-"}</td><td>{f.section_count ?? "-"}</td><td>{f.entropy ?? "-"}</td><td>{f.signature_status || "-"}{f.signer ? <div className="finding-reason">{f.signer}</div> : null}</td><td className="mono">{f.sha256 || "-"}</td></tr>)}</tbody></table></div>
            ) : <div className="empty"><h3>No PE metadata</h3><div>This investigation did not collect PE metadata.</div></div>}
          </div>
          <div className="panel" style={{ marginTop: 14 }}>
            <div className="panel-h"><div><h3>PE / module findings</h3><div className="panel-subtitle">Static indicators are contextual review leads, not proof of malicious behavior.</div></div><span className="badge">{pe.findings.length} indicators</span></div>
            {pe.findings.length ? <div className="tbl-wrap"><table className="t"><thead><tr><th>Severity</th><th>Rule</th><th>Observation</th><th /></tr></thead><tbody>{pe.findings.map((f, i) => <FindingRow key={`${f.rule_name}-${i}`} f={f} />)}</tbody></table></div> : <div className="empty"><h3>No PE/module indicators</h3><div>The configured V1.4 rules did not produce a matching observation.</div></div>}
          </div>
        </div>
      )}

      {tab === "injection" && (
        <div className="injection-workspace">
          <div className="grid g3 injection-metrics">
            <div className="panel kpi"><span>Loaded DLLs / modules</span><b>{injection.modules}</b></div>
            <div className="panel kpi"><span>Threads inspected</span><b>{injection.threads}</b></div>
            <div className={`panel kpi ${injection.findings.length ? "warn" : ""}`}><span>Indicators to review</span><b>{injection.findings.length}</b></div>
          </div>
          <div className="panel injection-findings">
            <div className="panel-h">
              <div><h3>DLL / injection indicators</h3><div className="panel-subtitle">Evidence that deserves analyst review — not an automatic malware verdict.</div></div>
              <span className={`badge ${injection.findings.length ? "sev-high" : "sev-review_recommended"}`}>{injection.findings.length} {injection.findings.length === 1 ? "indicator" : "indicators"}</span>
            </div>
            {injection.findings.length === 0 ? (
              <div className="injection-empty"><strong>No DLL / injection indicators were found.</strong><div>This analysis ran successfully, but the configured checks did not produce a matching observation in this evidence set.</div></div>
            ) : (
              <div className="tbl-wrap"><table className="t">
                <thead><tr><th>Severity</th><th>Indicator</th><th>What was observed</th><th /></tr></thead>
                <tbody>{injection.findings.map((f, i) => <InjectionFindingRow key={i} f={f} onEvidence={(r) => { setEvTarget(r.collector || null); setDrawerRef({ ...r, investigationId: id }); }} />)}</tbody>
              </table></div>
            )}
          </div>
          <div className="panel injection-note">
            <div className="panel-h"><h3>How to read these results</h3></div>
            <div className="panel-b help-grid">
              <div><b>Observed evidence</b><p>RANDAR records module paths, thread start addresses and virtual-memory metadata.</p></div>
              <div><b>Correlation</b><p>Multiple independent observations can be combined into a stronger investigation lead.</p></div>
              <div><b>Analyst review</b><p>Legitimate software, runtimes and JIT engines can create some of the same patterns.</p></div>
            </div>
          </div>
        </div>
      )}

      {tab === "network" && (
        <div className="network-workspace">
          <div className="grid g4 case-severity-grid">
            {[
              ["Artifacts", network.stats.connection_count || 0],
              ["Sources", network.stats.unique_sources || 0],
              ["Destinations", network.stats.unique_destinations || 0],
              ["Domains", network.stats.unique_domains || 0],
            ].map(([label, value]) => (
              <div className="panel kpi" key={label}><span>{label}</span><b>{value}</b></div>
            ))}
          </div>

          <div className="panel network-hunt-panel">
            <div className="panel-hunt-head panel-h">
              <div>
                <h3>V1.2 threat-hunting results</h3>
                <div className="panel-subtitle">Actual findings generated from the normalized network evidence. Click a finding to inspect the evidence that triggered it.</div>
              </div>
              <span className={`badge ${networkHuntFindings.length ? "sev-high" : "sev-review_recommended"}`}>{networkHuntFindings.length} indicators</span>
            </div>
            {networkHuntFindings.length === 0 ? (
              <div className="empty"><h3>No V1.2 network-hunting indicators</h3><div>The configured V1.2 rules ran against this evidence set but did not produce a matching pattern.</div></div>
            ) : (
              <div className="tbl-wrap"><table className="t">
                <thead><tr><th style={{ width: 110 }}>Severity</th><th style={{ width: 210 }}>Rule</th><th>Observed pattern</th><th /></tr></thead>
                <tbody>{networkHuntFindings.map((f, i) => <NetworkFindingRow key={`${f.rule_name}-${i}`} f={f} onEvidence={(r) => { setEvTarget(r.collector || null); setDrawerRef({ ...r, investigationId: id }); }} />)}</tbody>
              </table></div>
            )}
          </div>

          <div className="grid g4 network-hunt-summary">
            {[
              ["DNS", new Set(["suspicious_dns_queries", "dns_entropy", "rare_domains", "suspicious_tld_patterns", "dns_bursts", "unusual_query_types", "long_random_labels", "dns_tunneling_indicators", "dns_beaconing"]),],
              ["Beaconing / network", new Set(["network_beaconing"]),],
              ["Scanning / discovery", new Set(["port_scan", "horizontal_scan", "service_discovery", "udp_scan"]),],
              ["Correlation / context", new Set(["process_network_correlation", "network_classification"]),],
            ].map(([label, rules]) => (
              <div className="panel kpi network-hunt-kpi" key={label}><span>{label}</span><b>{networkHuntFindings.filter((f) => rules.has(f.rule_name)).length}</b></div>
            ))}
          </div>

          <div className="panel" style={{ marginBottom: 14 }}>
            <div className="panel-h"><div><h3>Network source</h3><div className="panel-subtitle">Normalized evidence imported without retaining packet payloads.</div></div></div>
            <dl className="kv panel-b"><dt>File</dt><dd>{network.source.filename || "-"}</dd><dt>Format</dt><dd className="mono">{network.source.format || "-"}</dd><dt>SHA-256</dt><dd className="mono">{network.source.sha256 || "-"}</dd><dt>First seen</dt><dd>{network.stats.first_seen || "-"}</dd><dt>Last seen</dt><dd>{network.stats.last_seen || "-"}</dd></dl>
          </div>

          <div className="grid g2">
            <div className="panel"><div className="panel-h"><div><h3>Protocols</h3><div className="panel-subtitle">Normalized protocol distribution.</div></div></div><table className="t"><thead><tr><th>Protocol</th><th>Count</th></tr></thead><tbody>{Object.entries(network.stats.protocol_counts || {}).map(([p, n]) => <tr key={p}><td className="mono">{p}</td><td>{n}</td></tr>)}</tbody></table></div>
            <div className="panel"><div className="panel-h"><div><h3>Connection evidence</h3><div className="panel-subtitle">Source, destination, ports and DNS metadata.</div></div></div><EvidenceTable data={network.data} investigationId={id} collectorTarget="network_artifacts" /></div>
          </div>
        </div>
      )}

      {tab === "evidence" && (
        <div className="panel">
          <div className="panel-h">
            <div><h3>Collected evidence</h3><div className="panel-subtitle">Choose a collection source to inspect its raw evidence.</div></div>
            <select className="select" style={{ width: 260 }} value={activeTarget || ""} onChange={(e) => setEvTarget(e.target.value)} aria-label="Evidence source">
              {successfulCollectors.map((c) => <option key={c.target}>{c.target}</option>)}
            </select>
          </div>
          {activeResult?.data ? <EvidenceTable key={activeTarget} data={activeResult.data} investigationId={id} collectorTarget={activeTarget} /> : <div className="empty"><h3>No collected evidence</h3><div>This investigation did not return a successful evidence collection.</div></div>}
        </div>
      )}

      {tab === "collectors" && (
        <div className="panel">
          <div className="panel-h"><div><h3>Collection status</h3><div className="panel-subtitle">Each collector reports whether its evidence was collected successfully.</div></div></div>
          <table className="t">
            <thead><tr><th>Evidence source</th><th>Status</th><th>Evidence SHA-256</th><th>Details</th></tr></thead>
            <tbody>{collectors.map((c, i) => (
              <tr key={i}><td><div className="finding-name">{humanizeCollector(c.target)}</div><div className="finding-code mono">{c.target}</div></td><td><Pill value={c.status} label={c.status} /></td>
                <td className="mono">{c.evidence_hash || "-"}</td><td>{c.status === "success" ? (c.data?.error || "Evidence collected successfully.") : (c.error || `Collector ${c.status}.`)}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}

      {tab === "integrity" && (
        <div className="grid g2">
          <div className="panel"><div className="panel-h"><div><h3>Report verification</h3><div className="panel-subtitle">The stored report is checked against its canonical SHA-256 digest.</div></div><span className={`badge ${integrity.data?.valid ? "sev-review_recommended" : "sev-high"}`}>{integrity.loading ? "checking" : integrity.data?.valid ? "verified" : "not verified"}</span></div><div className="panel-b"><dl className="detail-list"><dt>Report SHA-256</dt><dd className="mono">{report.report_hash || "not recorded"}</dd><dt>Script SHA-256</dt><dd className="mono">{report.script_hash || "not recorded"}</dd><dt>Signed bytecode SHA-256</dt><dd className="mono">{report.bytecode_hash || "not recorded"}</dd><dt>Product</dt><dd>{report.product_name} {report.product_version}</dd><dt>DSL</dt><dd>{report.dsl_name} {report.dsl_version}</dd></dl></div></div>
          <div className="panel"><div className="panel-h"><div><h3>Provenance chain</h3><div className="panel-subtitle">Trace the investigation from source script to final report.</div></div></div><div className="panel-b"><div className="provenance-chain">{["SCRIPT", "SCRIPT HASH", "IR", "SIGNED BYTECODE", "COLLECTION", "EVIDENCE", "ANALYSIS", "FINDING", "REPORT"].map((x,i)=><div key={x} className="prov-node"><b>{x}</b>{i<8 && <span>↓</span>}</div>)}</div></div></div>
        </div>
      )}

      {tab === "timeline" && (
        <div className="panel"><div className="panel-h"><div><h3>Evidence timeline</h3><div className="panel-subtitle">Timestamped events reconstructed from collected endpoint and network metadata.</div></div><span className="badge">{asArray(report?.timeline).length} events</span></div>{asArray(report?.timeline).length ? <div className="timeline">{asArray(report.timeline).map((e,i)=><div className="timeline-row" key={`${e.timestamp}-${i}`}><div className="timeline-time mono">{e.timestamp || "No timestamp"}</div><div className="timeline-dot" /><div><div className="finding-name">{e.summary}</div><div className="finding-code mono">{e.type} · {e.collector}</div><pre className="json">{JSON.stringify(e.evidence || {}, null, 2)}</pre></div></div>)}</div> : <div className="empty"><h3>No timestamped evidence</h3><div>The available collectors did not provide timestamps.</div></div>}</div>
      )}

      {tab === "audit" && (
        <div className="panel"><div className="panel-h"><div><h3>Audit log</h3><div className="panel-subtitle">Append-only investigation actions and integrity references.</div></div></div>{asArray(audit.data).length ? <div className="tbl-wrap"><table className="t"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Script hash</th><th>Result hash</th></tr></thead><tbody>{audit.data.map((a)=><tr key={a.id}><td>{fmtTime(a.timestamp)}</td><td>{a.user_name}</td><td>{a.action}</td><td className="mono">{a.script_hash || "-"}</td><td className="mono">{a.result_hash || "-"}</td></tr>)}</tbody></table></div> : <div className="empty"><h3>No audit events</h3><div>No recorded actions are available for this investigation.</div></div>}</div>
      )}

      {tab === "meta" && (
        <div className="grid g2">
          <div className="panel"><div className="panel-h"><div><h3>Provenance</h3><div className="panel-subtitle">How this investigation was created and recorded.</div></div></div><dl className="kv panel-b">
            <dt>Report name</dt><dd>{report.report_name || "-"}</dd>
            <dt>Started</dt><dd>{fmtTime(rec.started_at)}</dd>
            <dt>Finished</dt><dd>{fmtTime(rec.finished_at)}</dd>
            <dt>Last edited</dt><dd>{fmtTime(rec.updated_at)}</dd>
            <dt>Script SHA-256</dt><dd className="mono">{report.script_hash || "Not recorded"}</dd>
            <dt>Report SHA-256</dt><dd className="mono">{report.report_hash || "Not recorded"}</dd>
            <dt>Integrity</dt><dd>{integrity.loading ? "Checking…" : integrity.error ? "Unavailable" : integrity.data?.valid ? "Verified" : "FAILED"}</dd>
            <dt>Source</dt><dd>{report.source?.type === "agent" ? `Remote agent ${report.source.agent_id}` : "Local run"}</dd>
          </dl></div>
          <div className="panel"><div className="panel-h"><div><h3>Analyst notes</h3><div className="panel-subtitle">Case notes can be edited without changing collected evidence.</div></div><button className="btn sm" onClick={() => setEdit(true)}>Edit notes</button></div>
            <div className={`panel-b ${rec.notes ? "" : "muted-copy"}`} style={{ whiteSpace: "pre-wrap" }}>{rec.notes || "No analyst notes have been added yet."}</div></div>
        </div>
      )}

      {drawerRef && <EvidenceDrawer reference={drawerRef} collector={drawerCollector} onClose={() => setDrawerRef(null)} />}
      {edit && <EditCaseModal record={rec} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); reload(); }} />}
      {del && <Confirm title="Delete investigation" busy={busy === "del"} onCancel={() => setDel(false)} onConfirm={remove}
        message={`Permanently delete "${rec.investigation_name}" and all of its evidence?`} />}
    </>
  );
}
