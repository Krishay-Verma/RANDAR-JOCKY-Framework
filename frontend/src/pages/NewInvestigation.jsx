import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import ScriptEditor from "../components/ScriptEditor";
import { Loading, Notice, Spinner } from "../components/ui";
import { TEMPLATES, lineFromError } from "../lib";


export default function NewInvestigation() {
  const navigate = useNavigate();
  const cat = useLoad(() => api.catalog(), []);
  const ta = useRef(null);
  const [script, setScript] = useState(TEMPLATES["Quick endpoint triage"]);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null); // {kind, data|message}

  function insert(text) {
    const el = ta.current;
    if (!el) return setScript((s) => s + text);
    const { selectionStart: a, selectionEnd: b } = el;
    const next = script.slice(0, a) + text + script.slice(b);
    setScript(next);
    requestAnimationFrame(() => { el.focus(); el.selectionStart = el.selectionEnd = a + text.length; });
  }

  async function act(kind) {
    setBusy(kind); setResult(null);
    try {
      if (kind === "validate") setResult({ kind, data: await api.validate(script) });
      if (kind === "compile") setResult({ kind, data: await api.compile(script) });
      if (kind === "run") {
        const r = await api.run(script);
        navigate(`/investigations/${r.id}`);
        return;
      }
    } catch (e) { setResult({ kind: "error", message: e.message }); }
    setBusy("");
  }

  const errLine = result?.kind === "error" ? lineFromError(result.message) : null;

  return (
    <>
      <div className="page-head">
        <div><h2>New investigation</h2><p>Write a JOCKY script, validate it, then run it against this host.</p></div>
        <select className="select" style={{ width: 220 }} aria-label="Template" value=""
          onChange={(e) => e.target.value && setScript(TEMPLATES[e.target.value])}>
          <option value="">Load template</option>
          {Object.keys(TEMPLATES).map((k) => <option key={k}>{k}</option>)}
        </select>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "minmax(0,1fr) 300px", alignItems: "start" }}>
        <div>
          <ScriptEditor value={script} onChange={setScript} errorLine={errLine} taRef={ta} />
          <div className="row" style={{ margin: "14px 0" }}>
            <button className="btn" disabled={!!busy} onClick={() => act("validate")}>{busy === "validate" ? <Spinner /> : null} Validate</button>
            <button className="btn" disabled={!!busy} onClick={() => act("compile")}>{busy === "compile" ? <Spinner /> : null} Show IR</button>
            <span className="sp" />
            <button className="btn primary" disabled={!!busy} onClick={() => act("run")}>{busy === "run" ? <><Spinner /> Running</> : "Run investigation"}</button>
          </div>

          {result?.kind === "error" && <Notice>{result.message}</Notice>}
          {result?.kind === "validate" && (
            <Notice kind="ok">
              Valid script &ldquo;{result.data.investigation_name}&rdquo;: {result.data.total_commands} commands
              ({result.data.collect_count} collect, {result.data.analyze_count} analyze
              {result.data.has_report ? ", report set" : ", no report name"}). Nothing was executed.
            </Notice>
          )}
          {result?.kind === "compile" && (
            <div className="panel">
              <div className="panel-h"><h3>Intermediate representation</h3>
                <span style={{ color: "var(--mute)" }}>{result.data.token_count} tokens &middot; {result.data.command_count} commands</span></div>
              <table className="t"><thead><tr><th>#</th><th>Command</th><th>Target</th></tr></thead>
                <tbody>{result.data.commands.map((c, i) => (
                  <tr key={i}><td className="num">{i + 1}</td><td className="mono">{c.type}</td><td className="mono">{c.target ?? "-"}</td></tr>
                ))}</tbody></table>
            </div>
          )}
        </div>

        <div className="panel" style={{ position: "sticky", top: 0 }}>
          <div className="panel-h"><h3>Engine reference</h3></div>
          {cat.loading ? <Loading /> : cat.error ? <div className="panel-b"><Notice>{cat.error.message}</Notice></div> : (
            <div style={{ maxHeight: 520, overflow: "auto" }}>
              <div className="nav-sec" style={{ padding: "10px 14px 4px" }}>Collectors</div>
              {cat.data.collectors.map((c) => (
                <button key={c.name} className="ref-item" onClick={() => insert(`    collect ${c.name};\n`)}>
                  <b>{c.name}</b><small>{c.description}</small></button>
              ))}
              <div className="nav-sec" style={{ padding: "10px 14px 4px" }}>Analysis rules</div>
              {cat.data.rules.map((r) => (
                <button key={r.name} className="ref-item" onClick={() => insert(`    analyze ${r.name};\n`)}>
                  <b>{r.name}</b><small>{r.description}</small></button>
              ))}
              <div className="nav-sec" style={{ padding: "10px 14px 4px" }}>Condition properties</div>
              {cat.data.properties.map((p) => (
                <button key={p} className="ref-item" onClick={() => insert(p)}><b>{p}</b></button>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
