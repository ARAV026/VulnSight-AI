import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="auth-shell">
      <section className="panel auth-panel">
        <h2>Page not found</h2>
        <p className="empty-copy">The requested route does not exist.</p>
        <Link to="/dashboard" className="report-link">Return to dashboard</Link>
      </section>
    </div>
  );
}
