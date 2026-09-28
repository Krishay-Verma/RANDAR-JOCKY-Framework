import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, saveBlob } from "../api/client";
import { useLoad } from "../hooks";
import EvidenceTable from "../components/EvidenceTable";
import { EditCaseModal } from "./Investigations";
import { Confirm, Loading, Notice, Pill, SevBadge } from "../components/ui";
import { SEVERITIES, SEV_LABEL, fmtDuration, fmtTime } from "../lib";

function FindingRow({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="click" onClick={() => setOpen((o) => !o)}>
        <td><SevBadge sev={f.severity} /></td>
        <td className="mono">{f.rule_name}</td>
        <td>{f.summary}</td>
        <td style={{ color: "var(--dim)", textAlign: "right" }}>{open ? "Hide" : "Details"}</td>
      </tr>
      {open && (
        <tr><td colSpan={4} style={{ padding: 0 }}>
          <div className="expand">
            <div style={{ color: "var(--mute)", marginBottom: 6 }}>Why this fired</div>
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
  const visible = sevFilter === "all" ? findings : findings.filter((f) => f.severity === sevFilter);
  const collectors = report.collector_results || [];
  const activeTarget = evTarget || collectors.find((c) => c.status === "success")?.target;
  const activeResult = collectors.find((c) => c.target === activeTarget);

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

  return (
    <>
      <div className="page-head">
        <div>
          <div style={{ color: "var(--mute)", fontSize: 12.5 }}><Link to="/investigations">Investigations</Link> / #{rec.id}</div>
          <h2 style={{ marginTop: 4 }}>{rec.investigation_name} <Pill value={rec.status} /></h2>
          <p className="mono">{rec.endpoint_hostname} &middot; {fmtTime(rec.started_at)} &middot; {fmtDuration(rec.started_at, rec.finished_at)}</p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => setEdit(true)}>Edit case</button>
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

      <div className="grid g4" style={{ marginBottom: 20 }}>
        {[["critical", "crit"], ["high", "warn"], ["medium", ""], ["review_recommended", ""]].map(([k, cls]) => (
          <div key={k} className={`panel kpi ${counts[k] ? cls : ""}`}><span>{SEV_LABEL[k]}</span><b>{counts[k] || 0}</b></div>
        ))}
      </div>

      <div className="tabs" role="tablist">
        {[["findings", `Findings (${findings.length})`], ["evidence", "Evidence"], ["collectors", "Collectors"], ["meta", "Case details"]].map(([k, l]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? "on" : ""}`} onClick={() => setTab(k)}>{l}</button>
        ))}
      </div>

      {tab === "findings" && (
        <div className="panel">
          <div className="panel-h">
            <div className="row">
              {["all", ...SEVERITIES].map((k) => (
                <button key={k} className={`btn sm ${sevFilter === k ? "primary" : ""}`} onClick={() => setSevFilter(k)}>
                  {k === "all" ? "All" : SEV_LABEL[k]} {k === "all" ? findings.length : counts[k] || 0}
                </button>
              ))}
            </div>
          </div>
          {visible.length === 0 ? <div className="empty">No findings{sevFilter !== "all" ? " at this severity" : ""}.</div> : (
            <div className="tbl-wrap"><table className="t">
              <thead><tr><th style={{ width: 110 }}>Severity</th><th>Rule</th><th>Summary</th><th /></tr></thead>
              <tbody>{visible.map((f, i) => <FindingRow key={i} f={f} />)}</tbody>
            </table></div>
          )}
        </div>
      )}

      {tab === "evidence" && (
        <div className="panel">
          <div className="panel-h">
            <select className="select" style={{ width: 240 }} value={activeTarget || ""} onChange={(e) => setEvTarget(e.target.value)} aria-label="Collector">
              {collectors.filter((c) => c.status === "success").map((c) => <option key={c.target}>{c.target}</option>)}
            </select>
          </div>
          {activeResult?.data ? <EvidenceTable key={activeTarget} data={activeResult.data} /> : <div className="empty">No collected evidence.</div>}
        </div>
      )}

      {tab === "collectors" && (
        <div className="panel"><table className="t">
          <thead><tr><th>Collector</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>{collectors.map((c, i) => (
            <tr key={i}><td className="mono">{c.target}</td><td><Pill value={c.status} label={c.status} /></td>
              <td>{c.status === "error" ? c.error : c.data?.error || "Collected"}</td></tr>
          ))}</tbody>
        </table></div>
      )}

      {tab === "meta" && (
        <div className="grid g2">
          <div className="panel"><div className="panel-h"><h3>Provenance</h3></div><dl className="kv panel-b">
            <dt>Report name</dt><dd>{report.report_name || "-"}</dd>
            <dt>Started</dt><dd>{fmtTime(rec.started_at)}</dd>
            <dt>Finished</dt><dd>{fmtTime(rec.finished_at)}</dd>
            <dt>Last edited</dt><dd>{fmtTime(rec.updated_at)}</dd>
            <dt>Script SHA-256</dt><dd className="mono">{report.script_hash || "not recorded"}</dd>
            <dt>Source</dt><dd>{report.source?.type === "agent" ? `Remote agent ${report.source.agent_id}` : "Local run"}</dd>
          </dl></div>
          <div className="panel"><div className="panel-h"><h3>Analyst notes</h3><button className="btn sm" onClick={() => setEdit(true)}>Edit</button></div>
            <div className="panel-b" style={{ whiteSpace: "pre-wrap", color: rec.notes ? "var(--text)" : "var(--dim)" }}>{rec.notes || "No notes."}</div></div>
        </div>
      )}

      {edit && <EditCaseModal record={rec} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); reload(); }} />}
      {del && <Confirm title="Delete investigation" busy={busy === "del"} onCancel={() => setDel(false)} onConfirm={remove}
        message={`Permanently delete "${rec.investigation_name}" and all of its evidence?`} />}
    </>
  );
}
