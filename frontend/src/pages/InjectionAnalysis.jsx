import { useMemo, useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import { useInvestigationJob } from "../hooks/useInvestigationJob";
import { Loading, Notice, SevBadge } from "../components/ui";
import { humanizeRule } from "../lib";

const SCRIPT = `investigation "Windows Injection Forensics" {
    collect system_info;
    collect processes;
    collect modules;
    collect threads;
    collect memory_regions;
    collect network_connections;
    collect pe_metadata;

    analyze suspicious_module_loads;
    analyze dll_sideloading;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;
    analyze unsigned_loaded_module;
    analyze suspicious_imports;
    analyze high_entropy_module;
    analyze module_disk_mismatch;
    analyze suspicious_writable_module;
    report "windows_injection_forensics";
}`;

const RULES = new Set([
  "suspicious_module_loads", "dll_sideloading", "process_hollowing_indicators",
  "reflective_load_indicators", "thread_hijacking_indicators", "injection_correlation",
  "unsigned_loaded_module", "suspicious_imports", "high_entropy_module",
  "module_disk_mismatch", "suspicious_writable_module",
]);

function collector(report, target) {
  return report?.collector_results?.find((c) => c.target === target);
}
function count(report, target) { return collector(report, target)?.data?.count || 0; }
function findingsFor(report) { return (report?.findings || []).filter((f) => RULES.has(f.rule_name)); }

export default function InjectionAnalysis() {
  const list = useLoad((signal) => api.investigations(signal), []);
  const [selected, setSelected] = useState("");
  const [message, setMessage] = useState("");
  const { start, job, error: jobError } = useInvestigationJob("injection-pe");
  const running = Boolean(job && !["complete", "partial", "cancelled", "error"].includes(job.status));
  useEffect(() => { if (job?.status === "complete" && job.investigation_id) { setSelected(String(job.investigation_id)); list.reload(); setMessage(`Windows injection hunt #${job.investigation_id} completed.`); } }, [job?.status, job?.investigation_id]);

  const records = Array.isArray(list.data) ? list.data : [];
  const chosen = records.find((r) => String(r.id) === selected);
  const report = chosen?.report_json;
  const findings = useMemo(() => findingsFor(report), [report]);
  const modules = count(report, "modules");
  const threads = count(report, "threads");
  const regions = count(report, "memory_regions");
  const peFiles = count(report, "pe_metadata");
  const telemetryAvailable = Boolean(collector(report, "modules") || collector(report, "threads") || collector(report, "memory_regions") || collector(report, "pe_metadata"));

  async function run() {
    setMessage("");
    try { await start(SCRIPT); } catch (e) { setMessage(e.message); }
  }

  if (list.loading && !list.data) return <Loading />;
  if (list.error) return <Notice>{list.error.message}</Notice>;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Injection / PE forensics</h2>
          <p>Review Windows evidence that may point to unusual DLL loading, executable memory, or thread activity.</p>
        </div>
        <button className="btn primary" onClick={run} disabled={running}>{running ? "Running hunt…" : "Run Windows injection hunt"}</button>
      </div>

      {(message || jobError) && <Notice kind={(message || jobError).includes("completed") ? "ok" : "err"}>{message || jobError}</Notice>}
      {job && !["complete", "error", "partial", "cancelled"].includes(job.status) && <div className="panel" style={{ marginBottom: 12 }}><div className="panel-b"><strong>Windows injection hunt is running on the server.</strong><div className="muted-copy">You can change tabs without cancelling it. Status: {job.status} · {job.progress ?? 0}%</div></div></div>}

      <div className="injection-alert">
        <span className="badge sev-high">DLL / INJECTION</span>
        <div><strong>Windows injection telemetry is enabled.</strong> RANDAR collects module paths, thread start addresses, and virtual-memory metadata, then compares those observations for investigation leads. It does not inject code or modify processes.</div>
      </div>

      <div className="panel injection-banner" style={{ marginBottom: 12 }}>
        <div className="panel-b">
          <div>
            <div className="injection-kicker">Windows forensic hunt</div>
            <div className="injection-title">Correlate DLL, memory, thread and PE evidence</div>
            <p className="injection-copy">The hunt keeps DLL, memory, and thread evidence together so an analyst can review the context instead of relying on a single process anomaly.</p>
            <div className="row" style={{ marginTop: 9 }}>
              <span className="badge sev-review_recommended">Read-only collectors</span>
              <span className="badge sev-review_recommended">Evidence correlation</span>
              <span className="badge sev-review_recommended">Case report</span>
            </div>
          </div>
          <div className="injection-coverage">
            <div className="coverage-cell"><b>{findings.length}</b><span>Indicators to review</span></div>
            <div className="coverage-cell"><b>{modules}</b><span>Loaded modules</span></div>
            <div className="coverage-cell"><b>{regions}</b><span>Memory regions</span></div>
            <div className="coverage-cell"><b>{peFiles}</b><span>PE files</span></div>
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 12 }}>
        <div className="panel-h">
          <h3>Investigation to review</h3>
          <span style={{ color: "var(--muted)", fontSize: 11 }}>{records.length} stored investigations</span>
        </div>
        <div className="panel-b">
          <div className="row">
            <select className="select" style={{ maxWidth: 520 }} value={selected} onChange={(e) => setSelected(e.target.value)}>
              <option value="">Choose a Windows investigation</option>
              {records.map((r) => <option key={r.id} value={r.id}>#{r.id} — {r.investigation_name} — {r.endpoint_hostname}</option>)}
            </select>
            {chosen && <Link className="btn" to={`/investigations/${chosen.id}`}>Open investigation</Link>}
          </div>
        </div>
      </div>

      {chosen ? (
        <>
          <div className="grid g4" style={{ marginBottom: 12 }}>
            <div className="panel kpi"><span>Loaded DLLs / modules</span><b>{modules}</b></div>
            <div className="panel kpi"><span>Threads inspected</span><b>{threads}</b></div>
            <div className="panel kpi"><span>Memory regions</span><b>{regions}</b></div>
            <div className={`panel kpi ${findings.length ? "warn" : ""}`}><span>Indicators to review</span><b>{findings.length}</b></div>
          </div>

          {!telemetryAvailable && <Notice kind="warn">This selected case does not contain the Windows injection collectors. Run the dedicated hunt on the Windows endpoint to populate DLL, thread and memory evidence.</Notice>}

          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panel-h"><h3>Forensic pipeline</h3></div>
            <div className="pipeline">{["SCRIPT", "PARSE", "COLLECT", "CORRELATE", "FINDINGS", "REPORT"].map((x, i) => <span key={x}><b>{x}</b>{i < 5 && <i>→</i>}</span>)}</div>
          </div>

          <div className={`panel ${findings.length ? "injection-findings" : ""}`}>
            <div className="panel-h"><div><h3>Injection / PE indicators</h3><div className="panel-subtitle">Evidence that deserves analyst review — not an automatic malware verdict.</div></div><span style={{ color: findings.length ? "#8a4f00" : "var(--muted)" }}>{findings.length} {findings.length === 1 ? "indicator" : "indicators"}</span></div>
            {findings.length === 0 ? (
              <div className="injection-empty"><strong>No DLL / injection indicators were found.</strong><div style={{ marginTop: 3 }}>The analysis ran successfully, but the configured checks did not produce a matching observation in this evidence set.</div></div>
            ) : (
              <div className="tbl-wrap"><table className="t">
                <thead><tr><th>Severity</th><th>Technique indicator</th><th>Analyst interpretation</th><th>Evidence</th></tr></thead>
                <tbody>{findings.map((f, i) => (
                  <tr key={i}>
                    <td><SevBadge sev={f.severity} /></td>
                    <td><div className={f.rule_name.includes("dll") || f.rule_name.includes("module") ? "rule-dll finding-name" : "rule-injection finding-name"}>{humanizeRule(f.rule_name)}</div><div className="finding-code mono">{f.rule_name}</div></td>
                    <td><strong>{f.summary}</strong><div style={{ color: "var(--muted)", marginTop: 3 }}>{f.reason}</div></td>
                    <td><pre className="json">{JSON.stringify(f.related_evidence || {}, null, 2)}</pre></td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </div>

          <div className="panel" style={{ marginTop: 12 }}>
            <div className="panel-h"><div><h3>PE metadata</h3><div className="panel-subtitle">Bounded static metadata from files already observed in the Windows process/module inventory.</div></div><span className="badge">{peFiles} files</span></div>
            {collector(report, "pe_metadata")?.data?.files?.length ? (
              <div className="tbl-wrap"><table className="t"><thead><tr><th>File</th><th>Architecture</th><th>PE type</th><th>Entropy</th><th>Signature</th><th>SHA-256</th></tr></thead><tbody>
                {collector(report, "pe_metadata").data.files.map((f, i) => <tr key={`${f.path}-${i}`}><td><div className="finding-name">{f.filename || "-"}</div><div className="finding-code mono">{f.path || "-"}</div></td><td>{f.architecture || "-"}</td><td>{f.pe_type || "-"}</td><td>{f.entropy ?? "-"}</td><td>{f.signature_status || "-"}{f.signer ? <div className="finding-reason">{f.signer}</div> : null}</td><td className="mono">{f.sha256 || "-"}</td></tr>)}
              </tbody></table></div>
            ) : <div className="empty"><h3>No PE metadata collected</h3><div>Run the Windows injection / PE hunt on a Windows endpoint to populate bounded PE evidence.</div></div>}
          </div>
        </>
      ) : (
        <div className="panel"><div className="empty"><h3>Select or run a Windows injection investigation</h3><div>The dedicated hunt writes its module, thread, memory and correlation results into the normal immutable investigation output.</div></div></div>
      )}

      <div className="panel" style={{ marginTop: 12 }}>
        <div className="panel-h"><div><h3>How this hunt works</h3><div className="panel-subtitle">Read-only evidence collection and correlation.</div></div></div>
        <div className="panel-b" style={{ color: "var(--muted)" }}>RANDAR observes evidence only. The Windows collectors do not write to process memory, create remote threads, suspend or hijack threads, inject DLLs, or disable security controls. Findings are investigation leads for analyst review, not proof that a technique occurred.</div>
      </div>
    </>
  );
}
