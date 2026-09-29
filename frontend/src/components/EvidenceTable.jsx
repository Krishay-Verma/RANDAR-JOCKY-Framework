import { Fragment, useEffect, useMemo, useState } from "react";
import { fmtTime } from "../lib";
import { api } from "../api/client";
import { Loading, Notice } from "./ui";

const PAGE = 100;
const isTime = (k) => /(_at|time|started)$/.test(k);

function cell(k, v) {
  if (v === null || v === undefined || v === "") return <span style={{ color: "var(--dim)" }}>-</span>;
  if (typeof v === "number" && k === "start_time") return fmtTime(v * 1000);
  if (typeof v === "string" && isTime(k)) return fmtTime(v);
  if (typeof v === "object") return <code>{JSON.stringify(v)}</code>;
  if (typeof v === "number" && /bytes/.test(k)) return `${(v / 1048576).toFixed(1)} MiB`;
  return String(v);
}

/**
 * Renders a collector's scalar metadata plus its evidence list.
 * V1.9 supports lazy server-side paging when investigationId/collectorTarget
 * are supplied, so opening a large evidence source does not download the
 * complete collector payload into the browser.
 */
export default function EvidenceTable({ data, investigationId = null, collectorTarget = null }) {
  const remote = Boolean(investigationId && collectorTarget);
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [remoteState, setRemoteState] = useState({ data: null, error: null, loading: false });

  useEffect(() => {
    if (!remote) return undefined;
    let alive = true;
    setRemoteState((s) => ({ ...s, loading: true, error: null }));
    api.evidencePage(investigationId, collectorTarget, page, PAGE, q)
      .then((value) => alive && setRemoteState({ data: value, error: null, loading: false }))
      .catch((error) => alive && setRemoteState({ data: null, error, loading: false }));
    return () => { alive = false; };
  }, [remote, investigationId, collectorTarget, page, q]);

  const localListKey = useMemo(() => Object.keys(data || {}).find((k) => Array.isArray(data[k])), [data]);
  const localRows = useMemo(() => (localListKey ? data[localListKey] : []), [data, localListKey]);
  const localScalars = useMemo(() => Object.entries(data || {}).filter(([k]) => k !== localListKey).reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {}), [data, localListKey]);
  const listKey = remote ? remoteState.data?.list_key : localListKey;
  const rows = remote ? (Array.isArray(remoteState.data?.rows) ? remoteState.data.rows : []) : localRows;
  const scalars = remote ? (remoteState.data?.scalars || {}) : localScalars;
  const cols = useMemo(() => {
    const seen = [];
    rows.slice(0, 25).forEach((r) => Object.keys(r || {}).forEach((k) => !seen.includes(k) && seen.push(k)));
    return seen.slice(0, 7);
  }, [rows]);
  const filtered = useMemo(() => {
    if (remote) return rows;
    const n = q.trim().toLowerCase();
    return n ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(n)) : rows;
  }, [remote, rows, q]);
  const total = remote ? (remoteState.data?.total || 0) : filtered.length;
  const hasNext = remote ? Boolean(remoteState.data?.has_next) : filtered.length > page * PAGE;

  function changeQuery(value) {
    setQ(value);
    setPage(1);
  }

  return (
    <div>
      {Object.entries(scalars).length > 0 && (
        <dl className="kv" style={{ padding: "12px 16px", borderBottom: listKey ? "1px solid var(--line)" : 0 }}>
          {Object.entries(scalars).map(([k, v]) => (<Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd className="mono">{cell(k, v)}</dd></Fragment>))}
        </dl>
      )}
      {remoteState.error && <Notice>{remoteState.error.message}</Notice>}
      {remoteState.loading && !remoteState.data && <Loading />}
      {listKey && (
        <>
          <div className="panel-h">
            <input className="input" style={{ maxWidth: 280 }} placeholder={`Filter ${listKey}`} value={q}
              onChange={(e) => changeQuery(e.target.value)} aria-label="Filter evidence" />
            <span style={{ color: "var(--mute)" }}>{remote ? `${total} records` : `${filtered.length} of ${rows.length}`}</span>
          </div>
          <div className="tbl-wrap">
            <table className="t">
              <thead><tr>{cols.map((c) => <th key={c}>{c.replace(/_/g, " ")}</th>)}</tr></thead>
              <tbody>
                {filtered.map((r, i) => (
                  <tr key={i}>{cols.map((c) => <td key={c} className="mono" style={{ wordBreak: "break-all" }}>{cell(c, r?.[c])}</td>)}</tr>
                ))}
                {!remoteState.loading && filtered.length === 0 && <tr><td colSpan={cols.length || 1} style={{ color: "var(--mute)" }}>No entries.</td></tr>}
              </tbody>
            </table>
          </div>
          {(remote ? (hasNext || page > 1) : (filtered.length > page * PAGE || page > 1)) && (
            <div className="panel-b row" style={{ justifyContent: "space-between" }}>
              <button className="btn sm" disabled={page <= 1 || remoteState.loading} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</button>
              <span className="muted-copy">Page {page} · {remote ? total : filtered.length} records</span>
              <button className="btn sm" disabled={!hasNext || remoteState.loading} onClick={() => setPage((p) => p + 1)}>Next</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
