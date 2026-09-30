import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import { Confirm, Empty, Loading, Modal, Notice, Pill, SevChips } from "../components/ui";
import { STATUS_LABEL, fmtTime } from "../lib";


const INJECTION_RULES = new Set([
  "suspicious_module_loads", "dll_sideloading", "process_hollowing_indicators",
  "reflective_load_indicators", "thread_hijacking_indicators", "injection_correlation",
  "unsigned_loaded_module", "suspicious_imports", "high_entropy_module",
  "module_disk_mismatch", "suspicious_writable_module",
]);
function injectionState(record) {
  return {
    findings: Number(record?.injection_forensics_findings || 0),
    modules: Number(record?.module_records || 0),
    peFiles: Number(record?.pe_records || 0),
  };
}

const MEMORY_RULES = new Set([
  "process_hollowing_indicators", "reflective_load_indicators", "thread_hijacking_indicators",
  "injection_correlation", "in_memory_execution_indicators", "memory_forensics_correlation",
]);
const DRIVER_RULES = new Set(["byovd_driver_indicators", "driver_forensics_exposure"]);
const PERSISTENCE_RULES = new Set(["unusual_scheduled_tasks", "suspicious_startup_items", "privileged_user_anomaly", "persistence_correlation", "suspicious_services", "writable_service_paths", "persistence_cross_surface_correlation", "persistence_privilege_correlation"]);
function specializedForensics(record) {
  return {
    memory: {
      collected: Boolean(record?.memory_forensics_collected),
      count: Number(record?.memory_forensics_findings || 0),
    },
    driver: {
      collected: Boolean(record?.driver_forensics_collected),
      count: Number(record?.driver_forensics_findings || 0),
    },
    persistence: {
      collected: Boolean(record?.persistence_forensics_collected),
      count: Number(record?.persistence_forensics_findings || 0),
    },
  };
}

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
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState("newest");
  const [page, setPage] = useState(1);
  const [queryState, setQueryState] = useState({ q: "", status: "all", sort: "newest", page: 1 });
  const { data: pageData, error, loading, reload } = useLoad((signal) => api.investigationsPage(queryState.page, 25, queryState.q, queryState.status, queryState.sort, signal), [queryState]);
  const data = Array.isArray(pageData?.items) ? pageData.items : [];
  const [edit, setEdit] = useState(null);
  const [del, setDel] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState({ kind: "ok", text: "" });

  const rows = useMemo(() => data || [], [data]);

  function applyFilters(next = {}) {
    const nextState = {
      q: next.q ?? q, status: next.status ?? status, sort: next.sort ?? sort, page: next.page ?? 1,
    };
    setPage(nextState.page);
    setQueryState(nextState);
  }

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
            <input className="input" style={{ maxWidth: 300 }} placeholder="Search name, endpoint or ID" value={q} onChange={(e) => { setQ(e.target.value); applyFilters({ q: e.target.value }); }} aria-label="Search" />
            <select className="select" style={{ width: 150 }} value={status} onChange={(e) => { setStatus(e.target.value); applyFilters({ status: e.target.value }); }} aria-label="Status filter">
              <option value="all">All statuses</option>
              {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select className="select" style={{ width: 150 }} value={sort} onChange={(e) => applyFilters({ sort: e.target.value })} aria-label="Sort">
              <option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="severity">Highest severity</option>
            </select>
          </div>
          <span style={{ color: "var(--mute)" }}>{pageData?.total ?? rows.length} cases · page {pageData?.page ?? 1}</span>
        </div>
        {loading && !data ? <Loading /> : error ? <div className="panel-b"><Notice>{error.message}</Notice></div> :
          rows.length === 0 ? <Empty title={pageData?.total ? "No matches" : "No investigations yet"}>{pageData?.total ? "Adjust the filters." : "Run an investigation to see it here."}</Empty> : (
            <div className="tbl-wrap">
              <table className="t">
                <thead><tr><th>ID</th><th>Name</th><th>Endpoint</th><th>Started</th><th>C / H / M</th><th>Findings</th><th>Forensics</th><th>DLL / PE</th><th>Memory</th><th>Drivers</th><th>Persistence</th><th>Status</th><th /></tr></thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id}>
                      <td className="num">#{r.id}</td>
                      <td><Link to={`/investigations/${r.id}`}>{r.investigation_name}</Link></td>
                      <td className="mono">{r.endpoint_hostname}</td>
                      <td className="num">{fmtTime(r.started_at)}</td>
                      <td><SevChips counts={r.severity_counts} /></td>
                      <td className="num">{r.findings_count}</td>
                      <td><div className="forensics-list-links">
                        {specializedForensics(r).memory.collected && <Link className="forensics-link" to={`/investigations/${r.id}?tab=memory`}>Memory</Link>}
                        {specializedForensics(r).driver.collected && <Link className="forensics-link" to={`/investigations/${r.id}?tab=driver`}>Driver</Link>}
                        {specializedForensics(r).persistence.collected && <Link className="forensics-link" to={`/investigations/${r.id}?tab=persistence`}>Persistence</Link>}
                        {!specializedForensics(r).memory.collected && !specializedForensics(r).driver.collected && !specializedForensics(r).persistence.collected && <span style={{ color: "var(--dim)" }}>—</span>}
                      </div></td>
                      <td>{injectionState(r).findings ? <span className="badge sev-high">{injectionState(r).findings} indicators</span> : injectionState(r).modules || injectionState(r).peFiles ? <span className="badge sev-review_recommended">Telemetry</span> : <span style={{ color: "var(--dim)" }}>—</span>}</td>
                      <td>{(() => { const x = specializedForensics(r).memory; return x.collected ? <span className={`badge ${x.count ? "sev-high" : "sev-review_recommended"}`}>{x.count ? `${x.count} indicators` : `${Number(r?.memory_forensics_records || 0)} regions`}</span> : <span style={{ color: "var(--dim)" }}>—</span>; })()}</td>
                      <td>{(() => { const x = specializedForensics(r).driver; return x.collected ? <span className={`badge ${x.count ? "sev-high" : "sev-review_recommended"}`}>{x.count ? `${x.count} indicators` : `${Number(r?.driver_forensics_records || 0)} drivers`}</span> : <span style={{ color: "var(--dim)" }}>—</span>; })()}</td>
                      <td>{(() => { const x = specializedForensics(r).persistence; return x.collected ? <span className={`badge ${x.count ? "sev-high" : "sev-review_recommended"}`}>{x.count ? `${x.count} indicators` : "Collected"}</span> : <span style={{ color: "var(--dim)" }}>—</span>; })()}</td>
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
        {pageData && pageData.total > 25 && <div className="panel-b row" style={{ justifyContent: "space-between" }}>
          <button className="btn sm" disabled={!pageData.has_previous} onClick={() => applyFilters({ page: Math.max(1, page - 1) })}>Previous</button>
          <span className="muted-copy">Showing {(pageData.page - 1) * pageData.limit + 1}–{Math.min(pageData.page * pageData.limit, pageData.total)} of {pageData.total}</span>
          <button className="btn sm" disabled={!pageData.has_next} onClick={() => applyFilters({ page: page + 1 })}>Next</button>
        </div>}
      </div>
      {edit && <EditCaseModal record={edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); setMsg({ kind: "ok", text: "Case updated." }); reload(); }} />}
      {del && <Confirm title="Delete investigation" busy={busy} onCancel={() => setDel(null)} onConfirm={confirmDelete}
        message={`Permanently delete "${del.investigation_name}" (#${del.id}) and its evidence? This cannot be undone.`} />}
    </>
  );
}
