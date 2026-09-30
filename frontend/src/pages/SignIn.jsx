import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { getToken, setToken, isValidTokenFormat } from "../api/token";
import { verifyTokenWithServer } from "../api/client";
import { Notice, Spinner } from "../components/ui";

export default function SignIn() {
  const navigate = useNavigate();
  const location = useLocation();
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (getToken()) return <Navigate to="/" replace />;
  const dest = location.state?.from?.pathname || "/";

  async function submit(e) {
    e.preventDefault();
    const candidate = value.trim();
    setError("");
    if (!isValidTokenFormat(candidate)) {
      setError("That does not look like a RANDAR token (letters, digits, - and _ only).");
      return;
    }
    setBusy(true);
    try {
      if (!(await verifyTokenWithServer(candidate))) {
        setError("The server rejected this token.");
        return;
      }
      setToken(candidate);
      navigate(dest, { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="signin">
      <div className="signin-shell">
        <section className="signin-aside" aria-label="RANDAR platform overview">
          <div className="signin-brand">
            <img src="/randar-icon.svg" alt="" />
            <div className="signin-wordmark"><strong>RANDAR</strong><span>FORENSIC TRIAGE</span></div>
          </div>
          <div className="signin-hero">
            <span className="signin-eyebrow"><i /> INVESTIGATE WITH CLARITY</span>
            <h1>See the signals.<br /><em>Understand the evidence.</em></h1>
            <p>A focused workspace for endpoint telemetry, forensic evidence, and incident triage.</p>
          </div>
          <div className="signin-capabilities" aria-label="Platform capabilities">
            <div><span className="signin-cap-icon" aria-hidden="true">⌁</span><span><b>Correlate evidence</b><small>Bring endpoint and network signals together.</small></span></div>
            <div><span className="signin-cap-icon" aria-hidden="true">◎</span><span><b>Investigate confidently</b><small>Keep findings traceable and reviewable.</small></span></div>
          </div>
          <div className="signin-aside-foot"><span className="signin-live-dot" /> LOCAL FORENSIC WORKSPACE <span className="signin-foot-sep">/</span> SECURE SESSION</div>
        </section>
        <section className="signin-main">
          <form className="signin-card" onSubmit={submit}>
            <div className="signin-mobile-brand">
              <img src="/randar-icon.svg" alt="" />
              <div className="signin-wordmark"><strong>RANDAR</strong><span>FORENSIC TRIAGE</span></div>
            </div>
            <div className="signin-step">OPERATOR ACCESS</div>
            <h2>Welcome back</h2>
            <p className="signin-intro">Sign in with the API token generated during setup.</p>
            {error && <Notice>{error}</Notice>}
            <label className="f signin-field">
              <span>API token</span>
              <input className="input mono" type="password" autoComplete="off" autoFocus spellCheck={false}
                value={value} onChange={(e) => setValue(e.target.value)} placeholder="Paste your API token" aria-describedby="token-help" />
            </label>
            <button className="btn primary signin-submit" disabled={busy || !value.trim()}>
              {busy ? <><Spinner /> Verifying token…</> : <>Sign in securely <span aria-hidden="true">→</span></>}
            </button>
            <div className="signin-security"><span className="signin-lock" aria-hidden="true">◆</span><span>Token verification is performed by your RANDAR server.</span></div>
            <div className="signin-help" id="token-help">
              <b>Need a new token?</b>
              <p>Run <code>python start.py --new-token</code> from the RANDAR directory. Your token is kept for this browser tab only.</p>
            </div>
          </form>
          <footer className="signin-main-foot">RANDAR <span>•</span> FORENSIC TRIAGE PLATFORM</footer>
        </section>
      </div>
    </main>
  );
}
