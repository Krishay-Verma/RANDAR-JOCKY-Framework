import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";

import ScriptEditor from "../components/ScriptEditor";
import { Confirm, Empty, Loading, Modal, Notice, Pill, SevBadge } from "../components/ui";
import { TEMPLATES, copyText, fmtTime, lineFromError } from "../lib";

const ONLINE_MS = 90_000;
const isOnline = (a) => a.last_seen && Date.now() - new Date(a.last_seen) < ONLINE_MS;

function RegisterModal({ onClose, onDone }) {
  const [hostname, setHostname] = useState("");
  const [platform, setPlatform] = useState("Linux");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(null);
  const [copied, setCopied] = useState(false);

  async function submit() {
    setBusy(true); setErr("");
    try { setCreated(await api.registerAgent(hostname.trim(), platform)); onDone(); }
    catch (e) { setErr(e.message); }
    setBusy(false);
  }
  const origin = window.location.origin.includes(":5173") ? "http://127.0.0.1:8000" : window.location.origin;
  const cmd = created && `python -m jocky.agent --api-url ${origin} --agent-id ${created.agent_id} --agent-token ${created.agent_token}`;

  return (
    <Modal title={created ? "Agent registered" : "Register agent"} onClose={onClose}
      footer={created ? <button className="btn primary" onClick={onClose}>Done</button> : <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={busy || !hostname.trim()} onClick={submit}>Register</button></>}>
      {!created ? (<>
        <Notice>{err}</Notice>
        <label className="f"><span>Endpoint hostname</span><input className="input" maxLength={253} value={hostname} onChange={(e) => setHostname(e.target.value)} autoFocus /></label>
        <label className="f"><span>Platform</span>
          <select className="select" value={platform} onChange={(e) => setPlatform(e.target.value)}><option>Linux</option><option>Windows</option></select></label>
      </>) : (<>
        <Notice kind="warn">The agent token is shown once and cannot be recovered. Copy it now.</Notice>
        <p style={{ margin: "0 0 6px", color: "var(--mute)" }}>Run on the endpoint (from the JOCKY directory):</p>
        <pre className="json" style={{ maxHeight: "none" }}>{cmd}</pre>
        <button className="btn sm" style={{ marginTop: 10 }} onClick={async () => setCopied(await copyText(cmd))}>{copied ? "Copied" : "Copy command"}</button>
      </>)}
    </Modal>
  );
}

function DispatchModal({ agent, onClose, onDone }) {
  const [script, setScript] = useState(TEMPLATES["Quick endpoint triage"]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function send() {
    setBusy(true); setErr("");
    try { await api.dispatch(agent.agent_id, script); onDone(); }
    catch (e) { setErr(e.message); setBusy(false); }
  }
  return (
    <Modal wide title={`Dispatch job to ${agent.hostname}`} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy} onClick={send}>Dispatch</button></>}>
      <Notice>{err}</Notice>
      <ScriptEditor value={script} onChange={setScript} errorLine={lineFromError(err)} rows={14} />
      <p style={{ color: "var(--dim)", fontSize: 12, marginBottom: 0 }}>The script is validated before it is queued. The agent picks it up on its next poll.</p>
    </Modal>
  );
}

function ResultModal({ agent, job, onClose }) {
  const { data, error, loading } = useLoad(() => api.jobResult(agent.agent_id, job.job_id), []);
  const r = data?.result;
  return (
    <Modal wide title={`Job ${job.job_id.slice(0, 8)}`} onClose={onClose}>
      {loading ? <Loading /> : error ? <Notice>{error.message}</Notice> : data.error ? <Notice>{data.error}</Notice> : !r ? <Empty title="No result yet" /> : (<>
        <p style={{ color: "var(--mute)", marginTop: 0 }}>{r.collector_results.length} collectors &middot; {r.findings.length} findings &middot; finished {fmtTime(r.finished_at)}</p>
        <table className="t"><thead><tr><th>Severity</th><th>Rule</th><th>Summary</th></tr></thead>
          <tbody>{r.findings.slice(0, 200).map((f, i) => (<tr key={i}><td><SevBadge sev={f.severity} /></td><td className="mono">{f.rule_name}</td><td>{f.summary}</td></tr>))}
            {r.findings.length === 0 && <tr><td colSpan={3} style={{ color: "var(--mute)" }}>No findings.</td></tr>}</tbody></table>
      </>)}
    </Modal>
  );
}

function Jobs({ agent, onMessage }) {
  const navigate = useNavigate();
  const { data, error, loading, reload } = useLoad(() => api.jobs(agent.agent_id), [agent.agent_id], 6000);
  const [view, setView] = useState(null);
  const [del, setDel] = useState(null);

  async function importJob(j) {
    try { const r = await api.importJob(agent.agent_id, j.job_id); navigate(`/investigations/${r.id}`); }
    catch (e) { onMessage({ kind: "err", text: e.message }); }
  }
  async function remove() {
    try { await api.deleteJob(agent.agent_id, del.job_id); reload(); }
    catch (e) { onMessage({ kind: "err", text: e.message }); }
    setDel(null);
  }
  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-h"><h3>Jobs &mdash; {agent.hostname}</h3><button className="btn sm" onClick={reload}>Refresh</button></div>
      {loading && !data ? <Loading /> : error ? <div className="panel-b"><Notice>{error.message}</Notice></div> :
        data.length === 0 ? <Empty title="No jobs">Dispatch a script to this agent.</Empty> : (
          <div className="tbl-wrap"><table className="t">
            <thead><tr><th>Job</th><th>Status</th><th>Created</th><th>Completed</th><th /></tr></thead>
            <tbody>{data.map((j) => (
              <tr key={j.job_id}>
                <td className="mono">{j.job_id.slice(0, 10)}</td>
                <td><Pill value={j.status} label={j.status} />{j.error && <div style={{ color: "#ff8a8a", fontSize: 12 }}>{j.error.slice(0, 90)}</div>}</td>
                <td className="num">{fmtTime(j.created_at)}</td><td className="num">{fmtTime(j.completed_at)}</td>
                <td><div className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                  {j.has_result && <button className="btn sm" onClick={() => setView(j)}>View</button>}
                  {j.has_result && <button className="btn sm primary" onClick={() => importJob(j)}>Save as investigation</button>}
                  <button className="btn sm danger" onClick={() => setDel(j)}>Delete</button>
                </div></td>
              </tr>))}</tbody></table></div>)}
      {view && <ResultModal agent={agent} job={view} onClose={() => setView(null)} />}
      {del && <Confirm title="Delete job" message="Remove this job and its result? Save it as an investigation first to keep it." onCancel={() => setDel(null)} onConfirm={remove} />}
    </div>
  );
}

export default function Agents() {
  const { data, error, loading, reload } = useLoad(() => api.agents(), [], 8000);
  const [reg, setReg] = useState(false);
  const [dispatch, setDispatch] = useState(null);
  const [sel, setSel] = useState(null);
  const [revoke, setRevoke] = useState(null);
  const [msg, setMsg] = useState({ kind: "ok", text: "" });
  const selected = data?.find((a) => a.agent_id === sel);

  async function doRevoke() {
    try { await api.revokeAgent(revoke.agent_id); if (sel === revoke.agent_id) setSel(null); reload(); setMsg({ kind: "ok", text: `Agent ${revoke.hostname} revoked.` }); }
    catch (e) { setMsg({ kind: "err", text: e.message }); }
    setRevoke(null);
  }

  return (
    <>
      <div className="page-head">
        <div><h2>Endpoint agents</h2><p>Dispatch investigations to remote hosts and collect their results.</p></div>
        <button className="btn primary" onClick={() => setReg(true)}>Register agent</button>
      </div>
      <Notice kind="info">The agent registry is held in server memory. After the API restarts, agents must be registered again; save important results as investigations.</Notice>
      <Notice kind={msg.kind}>{msg.text}</Notice>
      <div className="panel">
        {loading && !data ? <Loading /> : error ? <div className="panel-b"><Notice>{error.message}</Notice></div> :
          data.length === 0 ? <Empty title="No agents registered">Register an agent to run investigations on another endpoint.</Empty> : (
            <div className="tbl-wrap"><table className="t">
              <thead><tr><th>Hostname</th><th>Platform</th><th>Agent ID</th><th>State</th><th>Last seen</th><th /></tr></thead>
              <tbody>{data.map((a) => (
                <tr key={a.agent_id} className="click" onClick={() => setSel(a.agent_id)} style={sel === a.agent_id ? { background: "#121b2b" } : null}>
                  <td>{a.hostname}</td><td>{a.platform}</td><td className="mono">{a.agent_id}</td>
                  <td>{isOnline(a) ? <Pill value="online" label="Online" /> : <Pill value="offline" label={a.last_seen ? "Offline" : "Never seen"} />}</td>
                  <td className="num">{fmtTime(a.last_seen)}</td>
                  <td onClick={(e) => e.stopPropagation()}><div className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                    <button className="btn sm primary" onClick={() => setDispatch(a)}>Dispatch</button>
                    <button className="btn sm danger" onClick={() => setRevoke(a)}>Revoke</button></div></td>
                </tr>))}</tbody></table></div>)}
      </div>
      {selected && <Jobs agent={selected} onMessage={setMsg} />}
      {reg && <RegisterModal onClose={() => setReg(false)} onDone={reload} />}
      {dispatch && <DispatchModal agent={dispatch} onClose={() => setDispatch(null)} onDone={() => { setSel(dispatch.agent_id); setDispatch(null); setMsg({ kind: "ok", text: "Job queued." }); }} />}
      {revoke && <Confirm title="Revoke agent" confirmLabel="Revoke" message={`Revoke ${revoke.hostname}? Its token stops working immediately and its job history is removed.`} onCancel={() => setRevoke(null)} onConfirm={doRevoke} />}
    </>
  );
}
