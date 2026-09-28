import { useEffect } from "react";
import {
  BrowserRouter, Routes, Route, Navigate, Outlet, NavLink,
  useLocation, useNavigate,
} from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Investigations from "./pages/Investigations";
import NewInvestigation from "./pages/NewInvestigation";
import InvestigationDetail from "./pages/InvestigationDetail";
import Agents from "./pages/Agents";
import Bytecode from "./pages/Bytecode";
import Keys from "./pages/Keys";
import SignIn from "./pages/SignIn";
import { getToken, clearToken } from "./api/token";
import { AUTH_FAILED_EVENT, api } from "./api/client";
import { useLoad } from "./hooks";

const TITLES = [
  ["/investigations/new", "New investigation"],
  ["/investigations", "Investigations"],
  ["/agents", "Endpoint agents"],
  ["/bytecode", "Bytecode"],
  ["/keys", "Report encryption"],
  ["/", "Dashboard"],
];

function Shell() {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const onFail = () => navigate("/signin", { replace: true, state: { from: location } });
    window.addEventListener(AUTH_FAILED_EVENT, onFail);
    return () => window.removeEventListener(AUTH_FAILED_EVENT, onFail);
  }, [navigate, location]);

  // Lightweight reachability probe for the status indicator.
  const { error } = useLoad(() => api.stats(), [], 30_000);

  if (!getToken()) return <Navigate to="/signin" replace state={{ from: location }} />;

  const exact = new Set(["/", "/investigations"]);
  const title = (TITLES.find(([p]) => (exact.has(p) ? location.pathname === p : location.pathname.startsWith(p))) || [])[1]
    || "Investigation detail";

  const link = (to, label, end) => (
    <NavLink to={to} end={end} className={({ isActive }) => (isActive ? "active" : "")}>{label}</NavLink>
  );

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <div className="brand-mark">J</div>
          <div><b>JOCKY</b><small>Forensic triage</small></div>
        </div>
        <nav className="nav" aria-label="Primary">
          <div className="nav-sec">Monitor</div>
          {link("/", "Dashboard", true)}
          {link("/investigations", "Investigations", true)}
          <div className="nav-sec">Operate</div>
          {link("/investigations/new", "New investigation")}
          {link("/agents", "Endpoint agents")}
          {link("/bytecode", "Bytecode")}
          <div className="nav-sec">Administration</div>
          {link("/keys", "Report encryption")}
        </nav>
        <div className="side-foot">
          <button className="btn sm" onClick={() => { clearToken(); navigate("/signin", { replace: true }); }}>
            Sign out
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="top">
          <h1>{title}</h1>
          <div className="conn">
            <span className={`dot ${error ? "off" : "on"}`} />
            {error ? "API unreachable" : "API connected"}
          </div>
        </header>
        <main className="content"><Outlet /></main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/signin" element={<SignIn />} />
        <Route element={<Shell />}>
          <Route index element={<Dashboard />} />
          <Route path="investigations" element={<Investigations />} />
          <Route path="investigations/new" element={<NewInvestigation />} />
          <Route path="investigations/:id" element={<InvestigationDetail />} />
          <Route path="agents" element={<Agents />} />
          <Route path="bytecode" element={<Bytecode />} />
          <Route path="keys" element={<Keys />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
