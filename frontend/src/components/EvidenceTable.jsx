import { Fragment, useMemo, useState } from "react";
import { fmtTime } from "../lib";


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

/** Renders a collector's data: scalar fields as key/value, the first list as a filterable table. */
export default function EvidenceTable({ data }) {
  const [q, setQ] = useState("");
  const [shown, setShown] = useState(PAGE);
  const listKey = useMemo(() => Object.keys(data || {}).find((k) => Array.isArray(data[k])), [data]);
  const rows = useMemo(() => (listKey ? data[listKey] : []), [data, listKey]);
  const scalars = Object.entries(data || {}).filter(([k]) => k !== listKey);
  const cols = useMemo(() => {
    const seen = [];
    rows.slice(0, 25).forEach((r) => Object.keys(r || {}).forEach((k) => !seen.includes(k) && seen.push(k)));
    return seen.slice(0, 7);
  }, [rows]);
  const filtered = useMemo(() => {
    const n = q.trim().toLowerCase();
    return n ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(n)) : rows;
  }, [rows, q]);

  return (
    <div>
      {scalars.length > 0 && (
        <dl className="kv" style={{ padding: "12px 16px", borderBottom: listKey ? "1px solid var(--line)" : 0 }}>
          {scalars.map(([k, v]) => (<Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd className="mono">{cell(k, v)}</dd></Fragment>))}
        </dl>
      )}
      {listKey && (
        <>
          <div className="panel-h">
            <input className="input" style={{ maxWidth: 280 }} placeholder={`Filter ${listKey}`} value={q}
              onChange={(e) => { setQ(e.target.value); setShown(PAGE); }} aria-label="Filter evidence" />
            <span style={{ color: "var(--mute)" }}>{filtered.length} of {rows.length}</span>
          </div>
          <div className="tbl-wrap">
            <table className="t">
              <thead><tr>{cols.map((c) => <th key={c}>{c.replace(/_/g, " ")}</th>)}</tr></thead>
              <tbody>
                {filtered.slice(0, shown).map((r, i) => (
                  <tr key={i}>{cols.map((c) => <td key={c} className="mono" style={{ wordBreak: "break-all" }}>{cell(c, r?.[c])}</td>)}</tr>
                ))}
                {filtered.length === 0 && <tr><td colSpan={cols.length || 1} style={{ color: "var(--mute)" }}>No entries.</td></tr>}
              </tbody>
            </table>
          </div>
          {filtered.length > shown && (
            <div style={{ padding: 12, textAlign: "center" }}>
              <button className="btn sm" onClick={() => setShown((n) => n + PAGE)}>Show more ({filtered.length - shown} remaining)</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
