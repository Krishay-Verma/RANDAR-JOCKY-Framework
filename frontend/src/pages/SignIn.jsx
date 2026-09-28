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
      setError("That does not look like a JOCKY token (letters, digits, - and _ only).");
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
    <div className="signin">
      <form className="card" onSubmit={submit}>
        <div className="brand">
          <div className="brand-mark">J</div>
          <div><b>JOCKY</b><small>Forensic triage console</small></div>
        </div>
        <h2 style={{ fontSize: 18, marginBottom: 4 }}>Sign in</h2>
        <p style={{ color: "var(--mute)", marginTop: 0 }}>Enter the API token generated during setup.</p>
        <Notice>{error}</Notice>
        <label className="f">
          <span>API token</span>
          <input className="input mono" type="password" autoComplete="off" autoFocus spellCheck={false}
            value={value} onChange={(e) => setValue(e.target.value)} placeholder="Paste token" />
        </label>
        <button className="btn primary" style={{ width: "100%", justifyContent: "center" }} disabled={busy || !value.trim()}>
          {busy ? <><Spinner /> Verifying</> : "Sign in"}
        </button>
        <p style={{ color: "var(--dim)", fontSize: 12, marginTop: 16, marginBottom: 0 }}>
          Lost the token? Run <code>python start.py --new-token</code> to issue a new one.
          The token is kept for this browser tab only.
        </p>
      </form>
    </div>
  );
}
