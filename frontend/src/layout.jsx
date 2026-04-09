import { NavLink, Outlet, Navigate } from "react-router-dom";
import { useAuth } from "./auth";

export function ProtectedRoute() {
  const { token } = useAuth();
  return token ? <Outlet /> : <Navigate to="/login" replace />;
}

export function AppLayout() {
  const { user, logout } = useAuth();

  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Intelligent Web Application Vulnerability Detection</p>
          <h1>VulnSight AI</h1>
          <p className="hero-copy">Authenticated scan orchestration, OWASP ZAP analysis, scan history, and exportable reports.</p>
        </div>
        <div className="hero-panel">
          <div className="metric">
            <span>Operator</span>
            <strong>{user?.name || "Unknown"}</strong>
          </div>
          <div className="metric">
            <span>Identity</span>
            <strong>{user?.email || "No session"}</strong>
          </div>
        </div>
      </header>

      <nav className="top-nav">
        <NavLink to="/dashboard">Dashboard</NavLink>
        <NavLink to="/history">History</NavLink>
        <NavLink to="/reports">Reports</NavLink>
        <button type="button" className="nav-button" onClick={logout}>Logout</button>
      </nav>

      <Outlet />
    </div>
  );
}
