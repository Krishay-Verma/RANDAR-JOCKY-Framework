import { useState } from "react";
import { api } from "../api/client";
import { useLoad } from "../hooks";
import { Loading, Notice, Pill } from "../components/ui";

export default function Keys() {
  const { data, error, loading, reload } = useLoad((signal) => api.keyStatus(signal), []);
  const [pem, setPem] = useState("");
  const [msg, setMsg] = useState({ kind: "ok", text: "" });
  const [busy, setBusy] = useState(false);

  async function act(fn, ok) {
    setBusy(true); setMsg({ kind: "ok", text: "" });
    try { await fn(); setMsg({ kind: "ok", text: ok }); setPem(""); reload(); }
    catch (e) { setMsg({ kind: "err", text: e.message }); }
    setBusy(false);
  }

  return (
    <>
      <div className="page-head"><div><h2>Report encryption</h2>
        <p>Encrypted exports use AES-256-GCM with the session key wrapped by your RSA public key (RSA-OAEP, SHA-256). The server cannot decrypt them.</p></div></div>
      <Notice kind={msg.kind}>{msg.text}</Notice>
      <div className="grid g2" style={{ alignItems: "start" }}>
        <div className="panel">
          <div className="panel-h"><h3>Active public key</h3>
            {data && <Pill value={data.registered ? "complete" : "offline"} label={data.registered ? "Registered" : "Not registered"} />}</div>
          <div className="panel-b">
            {loading ? <Loading /> : error ? <Notice>{error.message}</Notice> : data.registered ? (<>
              <dl className="kv"><dt>Algorithm</dt><dd>RSA-{data.key_bits}</dd><dt>SHA-256 fingerprint</dt><dd className="mono">{data.fingerprint_sha256}</dd></dl>
              <button className="btn danger" style={{ marginTop: 16 }} disabled={busy} onClick={() => act(api.clearKey, "Key removed from this server session.")}>Remove key</button>
            </>) : <p style={{ margin: 0, color: "var(--mute)" }}>No key registered. Encrypted report export is disabled.</p>}
            <p style={{ color: "var(--dim)", fontSize: 12, marginBottom: 0 }}>The key lives in server memory only and is cleared when the API restarts.</p>
          </div>
        </div>
        <div className="panel">
          <div className="panel-h"><h3>Register a public key</h3></div>
          <div className="panel-b">
            <textarea className="textarea" rows={8} value={pem} onChange={(e) => setPem(e.target.value)} spellCheck={false}
              placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"} aria-label="Public key PEM" />
            <div className="row" style={{ marginTop: 12 }}>
              <button className="btn primary" disabled={busy || !pem.trim()} onClick={() => act(() => api.registerKey(pem.trim()), "Public key registered.")}>Register key</button>
            </div>
          </div>
        </div>
      </div>
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-h"><h3>Key generation and decryption</h3></div>
        <div className="panel-b">
          <p style={{ marginTop: 0 }}>Generate an RSA-2048 key pair on your workstation. Keep the <code>.key</code> file private; paste only the <code>.pub</code> contents above.</p>
          <pre className="json">python -m jocky.api.key_gen</pre>
          <p>Decrypt a downloaded report:</p>
          <pre className="json">{"python -m jocky.api.decrypt_report --key jocky_investigator.key --input jocky_report_1.enc --output report.json"}</pre>
        </div>
      </div>
    </>
  );
}
