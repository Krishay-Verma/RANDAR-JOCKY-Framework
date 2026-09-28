import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, saveBlob } from "../api/client";
import { useLoad } from "../hooks";
import EvidenceTable from "../components/EvidenceTable";
import { EditCaseModal } from "./Investigations";
import { Confirm, Loading, Notice, Pill, SevBadge } from "../components/ui";
import { humanizeCollector, humanizeRule, SEVERITIES, SEV_LABEL, fmtDuration, fmtTime } from "../lib";

const INJECTION_RULES = new Set([
  "suspicious_module_loads", "dll_sideloading", "process_hollowing_indicators",
  "reflective_load_indicators", "thread_hijacking_indicators", "injection_correlation",
]);

function injectionEvidence(report) {
  const collectors = report?.collector_results || [];
  const count = (target) => collectors.find((c) => c.target === target)?.data?.count || 0;
  const findings = (report?.findings || []).filter((f) => INJECTION_RULES.has(f.rule_name));
  return { findings, modules: count("modules"), threads: count("threads"), regions: count("memory_regions") };
}

function FindingRow({ f }) {
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
            <div className="detail-label">Why this was flagged</div>
            <div>{f.reason}</div>
            {f.related_evidence && Object.keys(f.related_evidence).length > 0 && (
              <pre className="json">{JSON.stringify(f.related_evidence, null, 2)}</pre>
            )}
          </div>
        </td></tr>
      )}
    </>
  );
}

function InjectionFindingRow({ f }) {
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
          </div>
        </td></tr>
      )}
    </>
  );
}

export default function InvestigationDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: rec, error, loading, reload } = useLoad(() => api.investigation(id), [id]);
  const keys = useLoad(() => api.keyStatus(), []);
  const [tab, setTab] = useState("findings");
  const [sevFilter, setSevFilter] = useState("all");
  const [evTarget, setEvTarget] = useState(null);
  const [edit, setEdit] = useState(false);
  const [del, setDel] = useState(false);
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState({ kind: "ok", text: "" });

  const report = rec?.report_json;
  const findings = useMemo(() => {
    const order = (s) => SEVERITIES.indexOf(SEVERITIES.includes(s) ? s : "informational");
    return [...(report?.findings || [])].sort((a, b) => order(a.severity) - order(b.severity));
  }, [report]);

  if (loading && !rec) return <Loading />;
  if (error) return <Notice>{error.message} <Link to="/investigations">Back to investigations</Link></Notice>;

  const counts = rec.severity_counts || {};
  const injection = injectionEvidence(report);
  const visible = sevFilter === "all" ? findings : findings.filter((f) => f.severity === sevFilter);
  const collectors = report.collector_results || [];
  const activeTarget = evTarget || collectors.find((c) => c.status === "success")?.target;
  const activeResult = collectors.find((c) => c.target === activeTarget);
  const successfulCollectors = collectors.filter((c) => c.status === "success");

  async function download(kind) {
    setBusy(kind); setMsg({ kind: "ok", text: "" });
    try {
      if (kind === "html") saveBlob(await api.htmlReport(id), `jocky_report_${id}.html`);
      else saveBlob(await api.encryptedReport(id), `jocky_report_${id}.enc`);
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
    ["injection", `DLL / injection (${injection.findings.length})`],
    ["evidence", "Evidence"],
    ["collectors", "Collectors"],
    ["meta", "Case details"],
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
          <button className="btn" disabled={!!busy || !keys.data?.registered} onClick={() => download("enc")}
            title={keys.data?.registered ? "" : "Register a public key first"}>Encrypted report</button>
          <button className="btn danger" onClick={() => setDel(true)}>Delete</button>
        </div>
      </div>

      <Notice kind={msg.kind}>{msg.text}</Notice>
      {keys.data && !keys.data.registered && (
        <Notice kind="info">Encrypted export is unavailable until an RSA public key is registered. <Link to="/keys">Register a key</Link></Notice>
      )}

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
        <div className="panel">
          <div className="panel-h">
            <div>
              <h3>Investigation findings</h3>
              <div className="panel-subtitle">Review the observations produced by the investigation rules.</div>
            </div>
            <div className="row">
              {["all", ...SEVERITIES].map((k) => (
                <button key={k} className={`btn sm ${sevFilter === k ? "primary" : ""}`} onClick={() => setSevFilter(k)}>
                  {k === "all" ? "All" : SEV_LABEL[k]} {k === "all" ? findings.length : counts[k] || 0}
                </button>
              ))}
            </div>
          </div>
          {visible.length === 0 ? (
            <div className="empty"><h3>No findings</h3><div>{sevFilter !== "all" ? "There are no findings at this severity." : "This investigation did not produce any findings."}</div></div>
          ) : (
            <div className="tbl-wrap"><table className="t">
              <thead><tr><th style={{ width: 110 }}>Severity</th><th>Finding</th><th>What was observed</th><th /></tr></thead>
              <tbody>{visible.map((f, i) => <FindingRow key={i} f={f} />)}</tbody>
            </table></div>
          )}
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
                <tbody>{injection.findings.map((f, i) => <InjectionFindingRow key={i} f={f} />)}</tbody>
              </table></div>
            )}
          </div>
          <div className="panel injection-note">
            <div className="panel-h"><h3>How to read these results</h3></div>
            <div className="panel-b help-grid">
              <div><b>Observed evidence</b><p>JOCKY records module paths, thread start addresses and virtual-memory metadata.</p></div>
              <div><b>Correlation</b><p>Multiple independent observations can be combined into a stronger investigation lead.</p></div>
              <div><b>Analyst review</b><p>Legitimate software, runtimes and JIT engines can create some of the same patterns.</p></div>
            </div>
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
          {activeResult?.data ? <EvidenceTable key={activeTarget} data={activeResult.data} /> : <div className="empty"><h3>No collected evidence</h3><div>This investigation did not return a successful evidence collection.</div></div>}
        </div>
      )}

      {tab === "collectors" && (
        <div className="panel">
          <div className="panel-h"><div><h3>Collection status</h3><div className="panel-subtitle">Each collector reports whether its evidence was collected successfully.</div></div></div>
          <table className="t">
            <thead><tr><th>Evidence source</th><th>Status</th><th>Details</th></tr></thead>
            <tbody>{collectors.map((c, i) => (
              <tr key={i}><td><div className="finding-name">{humanizeCollector(c.target)}</div><div className="finding-code mono">{c.target}</div></td><td><Pill value={c.status} label={c.status} /></td>
                <td>{c.status === "error" ? c.error : c.data?.error || "Evidence collected successfully."}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}

      {tab === "meta" && (
        <div className="grid g2">
          <div className="panel"><div className="panel-h"><div><h3>Provenance</h3><div className="panel-subtitle">How this investigation was created and recorded.</div></div></div><dl className="kv panel-b">
            <dt>Report name</dt><dd>{report.report_name || "-"}</dd>
            <dt>Started</dt><dd>{fmtTime(rec.started_at)}</dd>
            <dt>Finished</dt><dd>{fmtTime(rec.finished_at)}</dd>
            <dt>Last edited</dt><dd>{fmtTime(rec.updated_at)}</dd>
            <dt>Script SHA-256</dt><dd className="mono">{report.script_hash || "Not recorded"}</dd>
            <dt>Source</dt><dd>{report.source?.type === "agent" ? `Remote agent ${report.source.agent_id}` : "Local run"}</dd>
          </dl></div>
          <div className="panel"><div className="panel-h"><div><h3>Analyst notes</h3><div className="panel-subtitle">Case notes can be edited without changing collected evidence.</div></div><button className="btn sm" onClick={() => setEdit(true)}>Edit notes</button></div>
            <div className={`panel-b ${rec.notes ? "" : "muted-copy"}`} style={{ whiteSpace: "pre-wrap" }}>{rec.notes || "No analyst notes have been added yet."}</div></div>
        </div>
      )}

      {edit && <EditCaseModal record={rec} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); reload(); }} />}
      {del && <Confirm title="Delete investigation" busy={busy === "del"} onCancel={() => setDel(false)} onConfirm={remove}
        message={`Permanently delete "${rec.investigation_name}" and all of its evidence?`} />}
    </>
  );
}
