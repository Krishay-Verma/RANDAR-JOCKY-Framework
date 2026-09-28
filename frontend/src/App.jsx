import { useEffect } from "react";
import { BrowserRouter, NavLink, Navigate, Outlet, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Investigations from "./pages/Investigations";
import NewInvestigation from "./pages/NewInvestigation";
import InvestigationDetail from "./pages/InvestigationDetail";
import Agents from "./pages/Agents";
import Bytecode from "./pages/Bytecode";
import Keys from "./pages/Keys";
import InjectionAnalysis from "./pages/InjectionAnalysis";
import SignIn from "./pages/SignIn";
import { getToken, clearToken } from "./api/token";
import { AUTH_FAILED_EVENT, api } from "./api/client";
import { useLoad } from "./hooks";

const TITLES = [
  ["/investigations/new", "New investigation"], ["/investigations", "Investigations"],
  ["/agents", "Endpoint agents"], ["/bytecode", "Bytecode"], ["/keys", "Report encryption"],
  ["/injection", "DLL / injection analysis"], ["/", "Dashboard"],
];

const NAV = [
  ["/", "⌂", "Dashboard", true], ["/investigations", "▤", "Investigations", true],
  ["/investigations/new", "+", "New investigation"], ["/agents", "◎", "Endpoint agents"],
  ["/bytecode", "⌘", "Bytecode"], ["/injection", "⚠", "DLL / injection", false, true],
  ["/keys", "▣", "Report encryption"],
];

function Shell() {
  const location = useLocation();
  const navigate = useNavigate();
  const { error } = useLoad(() => api.stats(), [], 30_000);

  useEffectAuth(navigate, location);
  if (!getToken()) return <Navigate to="/signin" replace state={{ from: location }} />;
  const exact = new Set(["/", "/investigations"]);
  const title = (TITLES.find(([p]) => (exact.has(p) ? location.pathname === p : location.pathname.startsWith(p))) || [])[1] || "Investigation detail";

  const link = ([to, icon, label, end, accent]) => (
    <NavLink key={to} to={to} end={end} className={({ isActive }) => `${isActive ? "active" : ""}${accent ? " nav-injection" : ""}`}>
      <span className="nav-icon">{icon}</span><span>{label}</span>
    </NavLink>
  );

  return (
    <div className="shell">
      <aside className="rail" aria-label="Console rail">
        <div className="rail-brand"><img src="/jocky-icon.svg" alt="JOCKY" /></div>
        {NAV.slice(0, 2).map(([to, icon, label, end]) => <NavLink key={to} to={to} title={label} className={({ isActive }) => `rail-btn ${isActive ? "on" : ""}`} end={end}>{icon}</NavLink>)}
        <div className="rail-spacer" />
        <NavLink to="/injection" title="DLL / injection analysis" className={({ isActive }) => `rail-btn ${isActive ? "on" : ""}`}>⚠</NavLink>
        <button className="rail-btn" title="Sign out" onClick={() => { clearToken(); navigate("/signin", { replace: true }); }}>↪</button>
      </aside>
      <aside className="nav-panel">
        <div className="brand"><div className="brand-mark"><img src="/jocky-icon.svg" alt="JOCKY" /></div><div><b>JOCKY</b><small>Forensic triage</small></div></div>
        <nav className="nav" aria-label="Primary">
          <div className="nav-sec">Monitor</div>{NAV.slice(0, 2).map(link)}
          <div className="nav-sec">Operate</div>{NAV.slice(2, 6).map(link)}
          <div className="nav-sec">Administration</div>{NAV.slice(6).map(link)}
        </nav>
        <div className="side-foot">JOCKY forensic console<br /><span>Local operator session</span></div>
      </aside>
      <div className="main">
        <header className="top">
          <div className="top-title">{title}</div>
          <div className="top-search"><input placeholder="Search investigations, endpoints, rules…" aria-label="Console search" /></div>
          <div className="top-meta"><div className="conn"><span className={`dot ${error ? "off" : "on"}`} />{error ? "API offline" : "Connected"}</div><span className="mono">admin</span></div>
        </header>
        <main className="content"><Outlet /></main>
      </div>
    </div>
  );
}

function useEffectAuth(navigate, location) {
  useEffect(() => {
    const onFail = () => navigate("/signin", { replace: true, state: { from: location } });
    window.addEventListener(AUTH_FAILED_EVENT, onFail);
    return () => window.removeEventListener(AUTH_FAILED_EVENT, onFail);
  }, [navigate, location]);
}

export default function App() {
  return <BrowserRouter><Routes>
    <Route path="/signin" element={<SignIn />} />
    <Route element={<Shell />}>
      <Route index element={<Dashboard />} /><Route path="investigations" element={<Investigations />} />
      <Route path="investigations/new" element={<NewInvestigation />} /><Route path="investigations/:id" element={<InvestigationDetail />} />
      <Route path="agents" element={<Agents />} /><Route path="injection" element={<InjectionAnalysis />} /><Route path="bytecode" element={<Bytecode />} />
      <Route path="keys" element={<Keys />} /><Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes></BrowserRouter>;
}
