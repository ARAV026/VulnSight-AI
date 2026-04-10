import { NavLink, Outlet } from "react-router-dom";

export function AppLayout() {
  return (
    <div className="app-shell app-layout">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">
            <span className="brand-dot brand-green" />
            <span className="brand-dot brand-yellow" />
            <span className="brand-dot brand-red" />
          </div>
          <p className="eyebrow">VulnSight AI</p>
          <h1 className="sidebar-title">Security Ops Console</h1>
          <p className="sidebar-copy">
            Intelligent vulnerability detection and real-time threat analysis dashboard.
          </p>
        </div>

        <nav className="sidebar-nav">
          <NavLink to="/">
            <span>Overview</span>
            <small>Metrics</small>
          </NavLink>
          <NavLink to="/scan">
            <span>Scan</span>
            <small>Live Analysis</small>
          </NavLink>
          <NavLink to="/history">
            <span>History</span>
            <small>Run Archive</small>
          </NavLink>
          <NavLink to="/reports">
            <span>Reports</span>
            <small>Exports</small>
          </NavLink>
        </nav>
      </aside>

      <div className="content-area">
        <Outlet />
      </div>
    </div>
  );
}