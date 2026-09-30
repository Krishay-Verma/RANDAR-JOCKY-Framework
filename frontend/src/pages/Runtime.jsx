import { useState } from "react";
import { api } from "../api/client";
import ScriptEditor from "../components/ScriptEditor";
import { Notice, SevBadge, Spinner } from "../components/ui";
import { TEMPLATES, fmtTime } from "../lib";

export default function Runtime() {
  const [script, setScript] = useState(TEMPLATES["Quick endpoint triage"]);
  const [target, setTarget] = useState("portable");
  const [profile, setProfile] = useState("none");
  const [seed, setSeed] = useState("");
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function execute() {
    setBusy(true); setErr(""); setResult(null);
    try {
      setResult(await api.runtimeExecute(script, target, "jocky-interpreter", profile, seed || null));
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  const rt = result?.runtime;
  return <>
    <div className="page-head"><div><h2>Runtime</h2>
      <p>Run validated JOCKY through the controlled runtime adapter and inspect execution telemetry.</p></div></div>
    <Notice>{err}</Notice>
    <div className="grid g2" style={{ alignItems: "start" }}>
      <div>
        <ScriptEditor value={script} onChange={setScript} rows={14} />
        <div className="panel" style={{ marginTop: 12 }}>
          <div className="panel-b">
            <div className="grid g2">
              <label>Target<select className="select" value={target} onChange={e => setTarget(e.target.value)}><option>portable</option><option>windows</option><option>ubuntu</option></select></label>
              <label>Adapter<select className="select" value="jocky-interpreter" disabled><option>jocky-interpreter</option></select></label>
              <label>Transformation profile<select className="select" value={profile} onChange={e => setProfile(e.target.value)}><option>none</option><option>deterministic</option><option>reproducible-randomized</option><option>compatibility-preserving</option><option>automated-obfuscation</option></select></label>
              <label>Seed <span style={{ color: "var(--dim)" }}>(optional)</span><input className="input" value={seed} onChange={e => setSeed(e.target.value)} placeholder="reproducible experiment seed" /></label>
            </div>
            <div style={{ marginTop: 10, color: "var(--dim)", fontSize: 12 }}>Runtime execution is bounded server-side; Windows memory/process collectors can take several minutes.</div>
            <div className="row" style={{ marginTop: 12 }}><button className="btn primary" disabled={busy || !script.trim()} onClick={execute}>{busy && <Spinner />} {busy ? "Running…" : "Run controlled runtime"}</button></div>
          </div>
        </div>
      </div>
      <div className="panel">
        <div className="panel-h"><h3>Runtime identity</h3></div>
        <div className="panel-b">
          {!result && <div style={{ color: "var(--mute)" }}>Execute a validated script to populate runtime telemetry.</div>}
          {result && <dl className="kv"><dt>Status</dt><dd>{result.execution_status}</dd><dt>Elapsed</dt><dd>{result.elapsed_ms} ms</dd><dt>Build ID</dt><dd className="mono">{result.build_id}</dd><dt>Artifact SHA-256</dt><dd className="mono">{result.artifact_hash}</dd><dt>Profile</dt><dd>{result.transformation_profile}</dd><dt>Host</dt><dd>{rt?.host_target}</dd><dt>Platform</dt><dd>{rt?.platform}</dd><dt>Process context</dt><dd>{rt?.process_context}</dd></dl>}
        </div>
      </div>
    </div>
    {rt && <div className="panel" style={{ marginTop: 16 }}><div className="panel-h"><h3>Execution telemetry</h3><span style={{ color: "var(--mute)" }}>{result.collector_count} collectors · {result.findings_count} findings</span></div>
      <table className="t"><thead><tr><th>#</th><th>Event</th><th>Adapter</th><th>Target</th><th>Status</th><th>Detail</th></tr></thead><tbody>{rt.events.map(e => <tr key={e.sequence}><td>{e.sequence}</td><td className="mono">{e.event}</td><td>{e.adapter}</td><td>{e.target}</td><td>{e.status}</td><td>{e.detail || "—"}</td></tr>)}</tbody></table>
    </div>}
    {result?.findings?.length > 0 && <div className="panel" style={{ marginTop: 16 }}><div className="panel-h"><h3>Findings</h3></div><table className="t"><thead><tr><th>Severity</th><th>Rule</th><th>Summary</th></tr></thead><tbody>{result.findings.map((f, i) => <tr key={i}><td><SevBadge sev={f.severity} /></td><td className="mono">{f.rule_name}</td><td>{f.summary}</td></tr>)}</tbody></table></div>}
    {rt?.forensic_artifacts?.length > 0 && <div className="panel" style={{ marginTop: 16 }}><div className="panel-h"><h3>Forensic artifacts</h3></div><div className="panel-b"><div className="chips">{rt.forensic_artifacts.map((a, i) => <span className="badge" key={i}>{a}</span>)}</div></div></div>}
  </>;
}
