import React, { useEffect } from "react";
import { BrowserRouter, NavLink, Navigate, Outlet, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Investigations from "./pages/Investigations";
import NewInvestigation from "./pages/NewInvestigation";
import InvestigationDetail from "./pages/InvestigationDetail";
import Agents from "./pages/Agents";
import Bytecode from "./pages/Bytecode";
import Runtime from "./pages/Runtime";
import MemoryForensics from "./pages/MemoryForensics";
import DriverForensics from "./pages/DriverForensics";
import PersistenceForensics from "./pages/PersistenceForensics";
import Keys from "./pages/Keys";
import InjectionAnalysis from "./pages/InjectionAnalysis";
import NetworkEvidence from "./pages/NetworkEvidence";
import WindowsTelemetry from "./pages/WindowsTelemetry";
import Search from "./pages/Search";
import SignIn from "./pages/SignIn";
import { getToken, clearToken } from "./api/token";
import { AUTH_FAILED_EVENT, api } from "./api/client";
import { useLoad } from "./hooks";


class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error("RANDAR application render error", error, info);
  }

  reset = () => this.setState({ error: null });

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="app-fatal-error" role="alert">
        <div className="panel">
          <div className="panel-h">
            <div>
              <h2>RANDAR console recovered from a page error</h2>
              <div className="panel-subtitle">The application shell is still available. You can retry the current view without refreshing the browser.</div>
            </div>
          </div>
          <div className="panel-b">
            <p className="route-error-message">{this.state.error?.message || "Unexpected rendering error."}</p>
            <div className="row">
              <button className="btn primary" onClick={this.reset}>Retry current view</button>
              <button className="btn" onClick={() => window.location.assign("/")}>Return to dashboard</button>
              <button className="btn" onClick={() => window.location.reload()}>Reload application</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

class RouteErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error("RANDAR route render error", error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="route-error panel" role="alert">
        <div className="panel-h"><div><h3>This console view could not be rendered</h3><div className="panel-subtitle">The API session is still active. You can retry the view without refreshing the entire application.</div></div></div>
        <div className="panel-b">
          <p className="route-error-message">{this.state.error?.message || "Unexpected rendering error."}</p>
          <div className="row">
            <button className="btn primary" onClick={() => this.setState({ error: null })}>Retry view</button>
            <button className="btn" onClick={() => window.location.assign("/investigations")}>Back to investigations</button>
            <button className="btn" onClick={() => window.location.reload()}>Reload application</button>
          </div>
        </div>
      </div>
    );
  }
}

const TITLES = [
  ["/investigations/new", "New investigation"], ["/investigations", "Investigations"],
  ["/search", "Evidence search"], ["/agents", "Endpoint agents"], ["/runtime", "Runtime"], ["/memory-forensics", "Memory Forensics"], ["/driver-forensics", "Driver Forensics"], ["/persistence-forensics", "Persistence & Privilege Forensics"], ["/bytecode", "Bytecode"], ["/keys", "Report encryption"],
  ["/injection", "DLL / injection analysis"], ["/network", "Network Forensics"], ["/windows", "Windows Telemetry"], ["/", "Dashboard"],
];

const NAV = [
  ["/", "⌂", "Dashboard", true], ["/investigations", "▤", "Investigations", true],
  ["/investigations/new", "+", "New investigation"], ["/agents", "◎", "Endpoint agents"], ["/runtime", "▶", "Runtime"], ["/memory-forensics", "◉", "Memory Forensics"], ["/driver-forensics", "◈", "Driver Forensics"], ["/persistence-forensics", "⌁", "Persistence & Privilege"],
  ["/network", "◌", "Network Forensics"], ["/windows", "▦", "Windows Telemetry"],
  ["/bytecode", "⌘", "Bytecode"], ["/injection", "⚠", "DLL / injection", false, true],
  ["/keys", "▣", "Report encryption"],
];

function Shell() {
  const location = useLocation();
  const navigate = useNavigate();
  const { error } = useLoad((signal) => api.stats(signal), [], 30_000);

  // Keep this hook unconditional. Auth state can change during a navigation
  // or after a 401; placing the hook after the guard can change hook order.
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
        <div className="rail-brand"><img src="/randar-icon.svg" alt="RANDAR" /></div>
        {NAV.slice(0, 2).map(([to, icon, label, end]) => <NavLink key={to} to={to} title={label} className={({ isActive }) => `rail-btn ${isActive ? "on" : ""}`} end={end}>{icon}</NavLink>)}
        <div className="rail-spacer" />
        <NavLink to="/injection" title="DLL / injection analysis" className={({ isActive }) => `rail-btn ${isActive ? "on" : ""}`}>⚠</NavLink>
        <button className="rail-btn" title="Sign out" onClick={() => { clearToken(); navigate("/signin", { replace: true }); }}>↪</button>
      </aside>
      <aside className="nav-panel">
        <div className="brand"><div className="brand-mark"><img src="/randar-icon.svg" alt="RANDAR" /></div><div><b>RANDAR</b><small>Forensic triage</small></div></div>
        <nav className="nav" aria-label="Primary">
          <div className="nav-sec">Monitor</div>{NAV.slice(0, 2).map(link)}
          <div className="nav-sec">Operate</div>{NAV.slice(2, 9).map(link)}
          <div className="nav-sec">Administration</div>{NAV.slice(9).map(link)}
        </nav>
        <div className="side-foot">RANDAR forensic console<br /><span>Local operator session</span></div>
      </aside>
      <div className="main">
        <header className="top">
          <div className="top-title">{title}</div>
          <form className="top-search" onSubmit={(e) => { e.preventDefault(); const q = e.currentTarget.elements.search?.value.trim(); if (q) navigate(`/search?q=${encodeURIComponent(q)}`); }}>
            <input name="search" defaultValue={new URLSearchParams(location.search).get("q") || ""} placeholder="Search PID, IP, domain, hash, file, user, finding…" aria-label="Global evidence search" />
          </form>
          <div className="top-meta"><div className="conn"><span className={`dot ${error ? "off" : "on"}`} />{error ? "API offline" : "Connected"}</div><span className="mono">admin</span></div>
        </header>
        <main className="content"><RouteErrorBoundary key={location.key}><Outlet /></RouteErrorBoundary></main>
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
  return <AppErrorBoundary><BrowserRouter><Routes>
    <Route path="/signin" element={<SignIn />} />
    <Route element={<Shell />}>
      <Route index element={<Dashboard />} /><Route path="investigations" element={<Investigations />} />
      <Route path="investigations/new" element={<NewInvestigation />} /><Route path="investigations/:id" element={<InvestigationDetail />} />
      <Route path="search" element={<Search />} /><Route path="agents" element={<Agents />} /><Route path="runtime" element={<Runtime />} /><Route path="memory-forensics" element={<MemoryForensics />} /><Route path="driver-forensics" element={<DriverForensics />} /><Route path="persistence-forensics" element={<PersistenceForensics />} /><Route path="network" element={<NetworkEvidence />} /><Route path="injection" element={<InjectionAnalysis />} /><Route path="windows" element={<WindowsTelemetry />} /><Route path="bytecode" element={<Bytecode />} />
      <Route path="keys" element={<Keys />} /><Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes></BrowserRouter></AppErrorBoundary>;
}
