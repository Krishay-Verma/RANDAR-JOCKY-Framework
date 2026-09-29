import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import ScriptEditor from "../components/ScriptEditor";
import { Loading, Notice, Spinner } from "../components/ui";
import { asArray, TEMPLATES, lineFromError } from "../lib";


export default function NewInvestigation() {
  const navigate = useNavigate();
  const cat = useLoad((signal) => api.catalog(signal), []);
  const ta = useRef(null);
  const [script, setScript] = useState(TEMPLATES["Quick endpoint triage"]);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null); // {kind, data|message}
  const cancelRequested = useRef(false);
  const activeJobId = useRef(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [networkSources, setNetworkSources] = useState([]);
  const [networkSourceId, setNetworkSourceId] = useState("");
  const [sourceBusy, setSourceBusy] = useState(false);
  const [sourceMsg, setSourceMsg] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    api.networkSources(controller.signal).then((items) => mounted.current && setNetworkSources(Array.isArray(items) ? items : [])).catch((e) => { if (e?.name !== "AbortError") return; });
    return () => controller.abort();
  }, []);

  function insert(text) {
    const el = ta.current;
    if (!el) return setScript((s) => s + text);
    const { selectionStart: a, selectionEnd: b } = el;
    const next = script.slice(0, a) + text + script.slice(b);
    setScript(next);
    requestAnimationFrame(() => { el.focus(); el.selectionStart = el.selectionEnd = a + text.length; });
  }

  async function uploadSource(file) {
    if (!file) return;
    setSourceBusy(true); setSourceMsg("");
    try {
      const reader = new FileReader();
      const encoded = await new Promise((resolve, reject) => {
        reader.onerror = () => reject(new Error("Unable to read the evidence file."));
        reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
        reader.readAsDataURL(file);
      });
      const source = await api.uploadNetworkSource(file.name, encoded);
      setNetworkSources((items) => [source, ...items]);
      setNetworkSourceId(source.id);
      setSourceMsg(`Loaded ${source.filename} (${source.format}).`);
    } catch (e) { setSourceMsg(e.message); }
    finally { setSourceBusy(false); }
  }

  async function pollInvestigationJob(jobId) {
    const deadline = Date.now() + 30 * 60 * 1000;
    while (Date.now() < deadline && mounted.current && activeJobId.current === jobId) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      if (!mounted.current || activeJobId.current !== jobId) return;
      const job = await api.investigationJob(jobId);
      if (!mounted.current || activeJobId.current !== jobId) return;
      setResult({ kind: "job", data: job });
      if (job.status === "complete" || job.status === "partial") {
        activeJobId.current = null;
        if (job.investigation_id && !cancelRequested.current) {
          navigate(`/investigations/${job.investigation_id}`);
        }
        return;
      }
      if (job.status === "cancelled") {
        activeJobId.current = null;
        return;
      }
      if (job.status === "error") {
        activeJobId.current = null;
        throw new Error(job.error || "Investigation job failed.");
      }
    }
    if (mounted.current && activeJobId.current === jobId) {
      activeJobId.current = null;
      throw new Error("Investigation status polling timed out. The bounded server job may still be active.");
    }
  }

  async function runLongInvestigation() {
    cancelRequested.current = false;
    setBusy("run"); setResult(null);
    try {
      const queued = await api.runAsync(script, networkSourceId || null);
      if (!mounted.current) return;
      activeJobId.current = queued.job_id;
      setResult({ kind: "job", data: queued });
      await pollInvestigationJob(queued.job_id);
    } catch (e) {
      if (mounted.current && !cancelRequested.current) setResult({ kind: "error", message: e.message });
    } finally {
      if (mounted.current) setBusy("");
    }
  }

  async function cancelRun() {
    const jobId = activeJobId.current || result?.data?.job_id;
    if (!jobId || cancelRequested.current) return;
    cancelRequested.current = true;
    setBusy("cancel");
    try {
      const job = await api.cancelInvestigationJob(jobId);
      if (!mounted.current) return;
      setResult({ kind: "job", data: job });
      // The single polling loop owns job state. Do not start a second poller here;
      // that race previously allowed cancellation and normal polling to overwrite each other.
      if (["complete", "partial", "cancelled", "error"].includes(job.status)) {
        activeJobId.current = null;
        setBusy("");
      }
    } catch (e) {
      cancelRequested.current = false;
      if (mounted.current) {
        setResult({ kind: "error", message: e.message });
        setBusy("run");
      }
    }
  }

  async function act(kind) {
    setBusy(kind); setResult(null);
    try {
      if (kind === "validate") setResult({ kind, data: await api.validate(script) });
      if (kind === "compile") setResult({ kind, data: await api.compile(script) });
      if (kind === "run") {
        // V1.9 uses the bounded background path for every run so progress,
        // cancellation, collector timeouts and partial results behave the same
        // for small and full-sweep investigations.
        await runLongInvestigation();
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

      <div className="panel" style={{ marginBottom: 14 }}>
        <div className="panel-h"><div><h3>Network evidence source</h3><div className="panel-subtitle">V1.1/V1.2 accepts Zeek conn.log/dns.log, JSON-lines, PCAP and PCAPNG metadata. Packet payloads are never retained.</div></div></div>
        <div className="panel-b">
          <div className="row">
            <input type="file" accept=".log,.tsv,.json,.jsonl,.pcap,.pcapng" disabled={sourceBusy} onChange={(e) => uploadSource(e.target.files?.[0])} />
            <select className="select" value={networkSourceId} onChange={(e) => setNetworkSourceId(e.target.value)} aria-label="Network evidence source" style={{ minWidth: 300 }}>
              <option value="">No network source selected</option>
              {asArray(networkSources).map((src) => <option key={src.id} value={src.id}>{src.filename} · {src.format}</option>)}
            </select>
          </div>
          {sourceMsg && <div className="muted-copy" style={{ marginTop: 8 }}>{sourceMsg}</div>}
        </div>
      </div>

      {cat.data && <div className="panel" style={{ marginBottom: 12 }}><div className="panel-h"><div><h3>Engine capability coverage</h3><div className="panel-subtitle">Counts come from the live collector/rule registry.</div></div></div><div className="panel-b"><div className="grid g3"><div className="kpi"><span>Collectors</span><b>{asArray(cat.data.collectors).length}</b></div><div className="kpi"><span>Analysis rules</span><b>{asArray(cat.data.rules).length}</b></div><div className="kpi"><span>Evidence properties</span><b>{asArray(cat.data.properties).length}</b></div></div><p className="muted-copy" style={{ marginBottom: 0 }}>Use <strong>Domain Expansion Triage</strong> to execute every registered collector and analysis rule in one reproducible investigation. Select network evidence above for the network collector.</p></div></div>}
      <div className="grid" style={{ gridTemplateColumns: "minmax(0,1fr) 300px", alignItems: "start" }}>
        <div>
          <ScriptEditor value={script} onChange={setScript} errorLine={errLine} taRef={ta} />
          <div className="row" style={{ margin: "14px 0" }}>
            <button className="btn" disabled={!!busy} onClick={() => act("validate")}>{busy === "validate" ? <Spinner /> : null} Validate</button>
            <button className="btn" disabled={!!busy} onClick={() => act("compile")}>{busy === "compile" ? <Spinner /> : null} Show IR</button>
            <span className="sp" />
            <button className="btn primary" disabled={!!busy} onClick={() => act("run")}>{busy === "run" ? <><Spinner /> Running</> : "Run investigation"}</button>
            {busy === "run" && result?.kind === "job" && !["complete", "partial", "cancelled", "cancelling", "error"].includes(result.data?.status) && <button className="btn danger" onClick={cancelRun}>{cancelRequested.current ? "Cancelling…" : "Cancel run"}</button>}
          {busy === "cancel" && result?.kind === "job" && ["cancelling", "running", "queued"].includes(result.data?.status) && <span className="badge">Cancelling…</span>}
          </div>

          {result?.kind === "error" && <Notice>{result.message}</Notice>}
          {result?.kind === "job" && <div className="panel" style={{ marginBottom: 12 }}><div className="panel-h"><div><h3>Investigation execution</h3><div className="panel-subtitle">V1.9 bounded background execution with progress, collector timeouts, resource accounting and cancellation.</div></div><span className="badge">{result.data.status}</span></div><div className="panel-b"><div className="progress"><div className="progress-fill" style={{ width: `${Math.max(0, Math.min(100, result.data.progress || 0))}%` }} /></div><p className="muted-copy" style={{ marginBottom: 6 }}>{result.data.message} {result.data.progress ?? 0}%</p>{result.data.resource_usage && <div className="muted-copy">Collectors: {result.data.resource_usage.collector_count ?? 0} · Records: {result.data.resource_usage.records_collected ?? 0} · Evidence: {result.data.resource_usage.evidence_bytes ?? 0} bytes</div>}</div></div>}
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
                <tbody>{asArray(result.data?.commands).map((c, i) => (
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
              {asArray(cat.data.collectors).map((c) => (
                <button key={c.name} className="ref-item" onClick={() => insert(`    collect ${c.name};\n`)}>
                  <b>{c.name}</b><small>{c.description}</small></button>
              ))}
              <div className="nav-sec" style={{ padding: "10px 14px 4px" }}>Analysis rules</div>
              {asArray(cat.data.rules).map((r) => (
                <button key={r.name} className="ref-item" onClick={() => insert(`    analyze ${r.name};\n`)}>
                  <b>{r.name}</b><small>{r.description}</small></button>
              ))}
              <div className="nav-sec" style={{ padding: "10px 14px 4px" }}>Condition properties</div>
              {asArray(cat.data.properties).map((p) => (
                <button key={p} className="ref-item" onClick={() => insert(p)}><b>{p}</b></button>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
