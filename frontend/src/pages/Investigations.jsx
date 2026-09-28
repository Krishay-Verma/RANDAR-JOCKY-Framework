import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import { Confirm, Empty, Loading, Modal, Notice, Pill, SevChips } from "../components/ui";
import { STATUS_LABEL, fmtTime } from "../lib";

export function EditCaseModal({ record, onClose, onSaved }) {
  const [name, setName] = useState(record.investigation_name);
  const [status, setStatus] = useState(record.status);
  const [notes, setNotes] = useState(record.notes || "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function save() {
    setBusy(true); setErr("");
    try {
      onSaved(await api.update(record.id, { investigation_name: name, status, notes }));
    } catch (e) { setErr(e.message); setBusy(false); }
  }
  return (
    <Modal title={`Edit case #${record.id}`} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={busy || !name.trim()} onClick={save}>{busy ? "Saving" : "Save changes"}</button></>}>
      <Notice>{err}</Notice>
      <label className="f"><span>Case name</span><input className="input" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} /></label>
      <label className="f"><span>Status</span>
        <select className="select" value={status} onChange={(e) => setStatus(e.target.value)}>
          {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select></label>
      <label className="f"><span>Analyst notes</span><textarea className="textarea" rows={6} maxLength={10000} value={notes} onChange={(e) => setNotes(e.target.value)} /></label>
      <p style={{ color: "var(--dim)", fontSize: 12, margin: 0 }}>Collected evidence and findings are immutable; only case metadata can be changed.</p>
    </Modal>
  );
}

export default function Investigations() {
  const { data, error, loading, reload } = useLoad(() => api.investigations(), []);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState("newest");
  const [edit, setEdit] = useState(null);
  const [del, setDel] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState({ kind: "ok", text: "" });

  const rows = useMemo(() => {
    let r = (data || []).filter((x) =>
      (status === "all" || x.status === status) &&
      `${x.investigation_name} ${x.endpoint_hostname} ${x.id}`.toLowerCase().includes(q.trim().toLowerCase()));
    const sev = (x) => (x.severity_counts.critical || 0) * 1e6 + (x.severity_counts.high || 0) * 1e3 + (x.severity_counts.medium || 0);
    if (sort === "severity") r = [...r].sort((a, b) => sev(b) - sev(a));
    if (sort === "oldest") r = [...r].reverse();
    return r;
  }, [data, q, status, sort]);

  async function confirmDelete() {
    setBusy(true);
    try {
      await api.remove(del.id);
      setMsg({ kind: "ok", text: `Investigation #${del.id} deleted.` });
      setDel(null); reload();
    } catch (e) { setMsg({ kind: "err", text: e.message }); setDel(null); }
    setBusy(false);
  }

  return (
    <>
      <div className="page-head">
        <div><h2>Investigations</h2><p>All stored investigation reports.</p></div>
        <Link to="/investigations/new" className="btn primary">New investigation</Link>
      </div>
      <Notice kind={msg.kind}>{msg.text}</Notice>
      <div className="panel">
        <div className="panel-h">
          <div className="row" style={{ flex: 1 }}>
            <input className="input" style={{ maxWidth: 300 }} placeholder="Search name, endpoint or ID" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search" />
            <select className="select" style={{ width: 150 }} value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status filter">
              <option value="all">All statuses</option>
              {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select className="select" style={{ width: 150 }} value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort">
              <option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="severity">Highest severity</option>
            </select>
          </div>
          <span style={{ color: "var(--mute)" }}>{rows.length} shown</span>
        </div>
        {loading && !data ? <Loading /> : error ? <div className="panel-b"><Notice>{error.message}</Notice></div> :
          rows.length === 0 ? <Empty title={data.length ? "No matches" : "No investigations yet"}>{data.length ? "Adjust the filters." : "Run an investigation to see it here."}</Empty> : (
            <div className="tbl-wrap">
              <table className="t">
                <thead><tr><th>ID</th><th>Name</th><th>Endpoint</th><th>Started</th><th>C / H / M</th><th>Findings</th><th>Status</th><th /></tr></thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id}>
                      <td className="num">#{r.id}</td>
                      <td><Link to={`/investigations/${r.id}`}>{r.investigation_name}</Link></td>
                      <td className="mono">{r.endpoint_hostname}</td>
                      <td className="num">{fmtTime(r.started_at)}</td>
                      <td><SevChips counts={r.severity_counts} /></td>
                      <td className="num">{r.findings_count}</td>
                      <td><Pill value={r.status} /></td>
                      <td><div className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                        <button className="btn sm" onClick={() => setEdit(r)}>Edit</button>
                        <button className="btn sm danger" onClick={() => setDel(r)}>Delete</button>
                      </div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>
      {edit && <EditCaseModal record={edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); setMsg({ kind: "ok", text: "Case updated." }); reload(); }} />}
      {del && <Confirm title="Delete investigation" busy={busy} onCancel={() => setDel(null)} onConfirm={confirmDelete}
        message={`Permanently delete "${del.investigation_name}" (#${del.id}) and its evidence? This cannot be undone.`} />}
    </>
  );
}
