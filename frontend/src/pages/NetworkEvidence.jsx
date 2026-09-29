import { useEffect, useState } from "react";
import { api } from "../api/client";
import { Loading, Notice } from "../components/ui";

export default function NetworkEvidence() {
  const [sources, setSources] = useState([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const load = (signal) => api.networkSources(signal).then((items) => setSources(Array.isArray(items) ? items : [])).catch((e) => { if (e?.name !== "AbortError") setMessage(e.message); });
  useEffect(() => { const controller = new AbortController(); void load(controller.signal); return () => controller.abort(); }, []);
  async function upload(file) {
    if (!file) return;
    setBusy(true); setMessage("");
    try {
      const reader = new FileReader();
      const b64 = await new Promise((resolve, reject) => {
        reader.onerror = () => reject(new Error("Unable to read evidence file."));
        reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
        reader.readAsDataURL(file);
      });
      await api.uploadNetworkSource(file.name, b64); await load();
    } catch (e) { setMessage(e.message); } finally { setBusy(false); }
  }
  async function remove(id) {
    if (!window.confirm("Delete this network evidence source?")) return;
    try { await api.removeNetworkSource(id); await load(); } catch (e) { setMessage(e.message); }
  }
  return <>
    <div className="page-head"><div><h2>Network Forensics</h2><p>Register bounded network evidence for V1.1/V1.2 investigations.</p></div></div>
    <div className="panel" style={{ marginBottom: 16 }}><div className="panel-h"><div><h3>V1.2 hunting coverage</h3><div className="panel-subtitle">After import, investigations can run DNS, beaconing, scanning, classification and process/network correlation rules through the controlled DSL.</div></div></div>
      <div className="panel-b help-grid"><div><b>DNS hunting</b><p>Entropy, rarity, TLD patterns, bursts, unusual query types, long/random labels, tunneling indicators and DNS beaconing.</p></div><div><b>Network hunting</b><p>Network beaconing, vertical/horizontal scans, service discovery and UDP scan indicators.</p></div><div><b>Explainability</b><p>Findings retain the source, domain/destination, interval, count or scan evidence that caused the rule to fire.</p></div></div>
    </div>
    <div className="panel" style={{ marginBottom: 16 }}><div className="panel-h"><div><h3>Import evidence</h3><div className="panel-subtitle">Supported: Zeek conn.log, Zeek dns.log, Zeek JSON-lines, PCAP and PCAPNG. Payloads are not retained.</div></div></div>
      <div className="panel-b"><input type="file" accept=".log,.tsv,.json,.jsonl,.pcap,.pcapng" disabled={busy} onChange={(e) => upload(e.target.files?.[0])} />{message && <div style={{ marginTop: 10 }}><Notice>{message}</Notice></div>}</div>
    </div>
    <div className="panel"><div className="panel-h"><div><h3>Source files</h3><div className="panel-subtitle">Every source is content-addressed and retained in the controlled evidence directory.</div></div><span className="badge">{sources.length} sources</span></div>
      {sources.length === 0 ? <div className="empty"><h3>No network sources</h3><div>Import a Zeek log or PCAP to begin a network-evidence investigation.</div></div> : <div className="tbl-wrap"><table className="t"><thead><tr><th>File</th><th>Format</th><th>Size</th><th>SHA-256</th><th /></tr></thead><tbody>{sources.map((s) => <tr key={s.id}><td className="finding-name">{s.filename}</td><td className="mono">{s.format}</td><td>{(s.size_bytes / 1024).toFixed(1)} KiB</td><td className="mono" style={{ wordBreak: "break-all" }}>{s.sha256}</td><td><button className="btn sm danger" onClick={() => remove(s.id)}>Delete</button></td></tr>)}</tbody></table></div>}
    </div>
  </>;
}
