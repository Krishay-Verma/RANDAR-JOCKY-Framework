import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Loading, Notice, Pill, SevBadge } from "../components/ui";
import { humanizeCollector, humanizeRule, fmtTime } from "../lib";

export default function Search() {
  const [params] = useSearchParams();
  const query = (params.get("q") || "").trim();
  const [state, setState] = useState({ data: null, error: null, loading: Boolean(query) });

  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    if (!query) { setState({ data: { query: "", results: [] }, error: null, loading: false }); return () => { alive = false; controller.abort(); }; }
    setState((s) => ({ ...s, loading: true, error: null }));
    api.search(query, 75, controller.signal).then((data) => alive && setState({ data, error: null, loading: false }))
      .catch((error) => alive && error?.name !== "AbortError" && setState({ data: null, error, loading: false }));
    return () => { alive = false; controller.abort(); };
  }, [query]);

  const results = Array.isArray(state.data?.results) ? state.data.results : [];
  return (
    <>
      <div className="page-head">
        <div><div className="breadcrumb">Investigation workspace</div><h2>Evidence search</h2><p>Search stored investigation metadata, findings and collected evidence without opening every case.</p></div>
      </div>
      {!query && <div className="panel"><div className="empty"><h3>Search the investigation archive</h3><div>Use the search bar above for a PID, IP address, domain, hash, file path, username or finding.</div></div></div>}
      {state.loading && <Loading />}
      {state.error && <Notice>{state.error.message}</Notice>}
      {!state.loading && !state.error && query && (
        <div className="panel">
          <div className="panel-h"><div><h3>Results for <span className="mono">{query}</span></h3><div className="panel-subtitle">Matches are limited to concise contextual results; original evidence remains in the investigation report.</div></div><span className="badge">{results.length} matches</span></div>
          {results.length === 0 ? <div className="empty"><h3>No matches</h3><div>Try a PID, IP, domain, hash, filename, username or finding name.</div></div> : <div className="search-results">
            {results.map((r, i) => (
              <Link className="search-result" to={`/investigations/${r.investigation_id}`} key={`${r.investigation_id}-${r.kind}-${r.path || r.finding_id || i}`}>
                <div className="search-result-top"><span className="badge">{r.kind === "investigation" ? "Case" : r.kind === "finding" ? "Finding" : "Evidence"}</span>{r.severity && <SevBadge sev={r.severity} />}<Pill value={r.status} /></div>
                <div className="finding-name">{r.title}</div>
                <div className="search-result-meta"><span>Case #{r.investigation_id} · {r.endpoint_hostname}</span><span>{fmtTime(r.started_at)}</span>{r.collector && <span>{humanizeCollector(r.collector)}</span>}{r.rule_name && <span className="mono">{humanizeRule(r.rule_name)}</span>}</div>
                {r.path && <div className="search-match"><span className="mono">{r.path}</span> = <strong>{r.matched_value}</strong></div>}
                {r.reason && <div className="finding-reason">{r.reason}</div>}
              </Link>
            ))}
          </div>}
        </div>
      )}
    </>
  );
}
