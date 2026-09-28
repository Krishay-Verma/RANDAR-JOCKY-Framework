import { useState } from "react";
import { api, saveBlob } from "../api/client";
import ScriptEditor from "../components/ScriptEditor";

import { Notice, SevBadge, Spinner } from "../components/ui";
import { TEMPLATES, copyText, fmtTime, lineFromError } from "../lib";

export default function Bytecode() {
  const [script, setScript] = useState(TEMPLATES["Quick endpoint triage"]);
  const [b64, setB64] = useState("");
  const [meta, setMeta] = useState(null);
  const [disasm, setDisasm] = useState("");
  const [exec, setExec] = useState(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const [copied, setCopied] = useState(false);

  async function run(kind, fn) {
    setBusy(kind); setErr("");
    try { await fn(); } catch (e) { setErr(e.message); }
    setBusy("");
  }
  const compile = () => run("compile", async () => {
    const r = await api.bcCompile(script);
    setMeta(r); setB64(r.bytecode_b64); setExec(null);
    setDisasm((await api.bcDisasm(r.bytecode_b64)).disassembly);
  });
  const disassemble = () => run("disasm", async () => { setDisasm((await api.bcDisasm(b64.trim())).disassembly); setMeta(null); });
  const execute = () => run("exec", async () => setExec(await api.bcExecute(b64.trim())));

  return (
    <>
      <div className="page-head"><div><h2>Bytecode</h2>
        <p>Compile scripts to HMAC-signed bytecode, inspect it, and execute it. Tampered blobs are rejected before anything runs.</p></div></div>
      <Notice>{err}</Notice>
      <div className="grid g2" style={{ alignItems: "start" }}>
        <div>
          <ScriptEditor value={script} onChange={setScript} errorLine={lineFromError(err)} rows={14} />
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn primary" disabled={!!busy} onClick={compile}>{busy === "compile" && <Spinner />} Compile &amp; sign</button>
          </div>
        </div>
        <div className="panel">
          <div className="panel-h"><h3>Bytecode (base64)</h3>
            <div className="row" style={{ gap: 6 }}>
              <button className="btn sm" disabled={!b64} onClick={async () => { setCopied(await copyText(b64)); setTimeout(() => setCopied(false), 1500); }}>{copied ? "Copied" : "Copy"}</button>
              <button className="btn sm" disabled={!b64} onClick={() => saveBlob(new Blob([b64], { type: "text/plain" }), "investigation.jockyb64")}>Download</button>
            </div></div>
          <div className="panel-b">
            <textarea className="textarea" rows={7} value={b64} placeholder="Compile a script, or paste bytecode here" onChange={(e) => setB64(e.target.value)} aria-label="Bytecode base64" />
            <div className="row" style={{ marginTop: 10 }}>
              <button className="btn" disabled={!b64.trim() || !!busy} onClick={disassemble}>Verify &amp; disassemble</button>
              <button className="btn" disabled={!b64.trim() || !!busy} onClick={execute}>{busy === "exec" && <Spinner />} Verify &amp; execute</button>
            </div>
            {meta && <dl className="kv" style={{ marginTop: 14 }}>
              <dt>Investigation</dt><dd>{meta.investigation_name}</dd><dt>Size</dt><dd>{meta.bytecode_size_bytes} bytes</dd>
              <dt>Opcodes</dt><dd>{meta.opcode_count}</dd><dt>Signature</dt><dd>{meta.signature}</dd><dt>Compiled</dt><dd>{fmtTime(meta.compiled_at)}</dd></dl>}
          </div>
        </div>
      </div>
      {disasm && <div className="panel" style={{ marginTop: 16 }}><div className="panel-h"><h3>Disassembly</h3></div><pre className="json" style={{ margin: 0, border: 0, maxHeight: 320 }}>{disasm}</pre></div>}
      {exec && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-h"><h3>Execution result &mdash; {exec.investigation_name}</h3>
            <span style={{ color: "var(--mute)" }}>{exec.collector_count} collectors &middot; {exec.findings_count} findings</span></div>
          <table className="t"><thead><tr><th>Severity</th><th>Rule</th><th>Summary</th></tr></thead>
            <tbody>{exec.findings.map((f, i) => (<tr key={i}><td><SevBadge sev={f.severity} /></td><td className="mono">{f.rule_name}</td><td>{f.summary}</td></tr>))}
              {exec.findings.length === 0 && <tr><td colSpan={3} style={{ color: "var(--mute)" }}>No findings.</td></tr>}</tbody></table>
          <p style={{ color: "var(--dim)", fontSize: 12, margin: 12 }}>Bytecode execution returns a summary and does not store an investigation. Use New investigation to keep a report.</p>
        </div>)}
    </>
  );
}
