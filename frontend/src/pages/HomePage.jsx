import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getHistory } from "../api";

export function HomePage() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    getHistory().then(setHistory).catch(() => setHistory([]));
  }, []);

  const recent = history.slice(0, 3);
  const totalFindings = history.reduce((sum, item) => sum + item.total_findings, 0);
  const averageScore = history.length ? Math.round(history.reduce((sum, item) => sum + item.score, 0) / history.length) : 0;

  return (
    <div className="page-stack">
      <header className="hero slim-hero">
        <div>
          <p className="eyebrow">Overview</p>
          <h1>Intelligent Web Application Vulnerability Detection & Analysis Platform</h1>
          <p className="hero-copy">Initiate intelligent background scanning with flexible authentication support, enabling continuous discovery of vulnerabilities across the application. Monitor the evolving threat surface in real time with dynamic analysis and insights.</p>
        </div>
        <div className="hero-panel">
          <div className="metric"><span>Average Score</span><strong>{averageScore}</strong></div>
          <div className="metric"><span>Total Findings Logged</span><strong>{totalFindings}</strong></div>
        </div>
      </header>

      <section className="panel">
        <div className="section-row">
          <h2>Recent Activity</h2>
          <Link className="report-link" to="/scan">Launch New Scan</Link>
        </div>
        <div className="activity-list">
          {recent.length === 0 ? <p className="empty-copy">No scans yet. Run your first authenticated scan.</p> : recent.map((item) => (
            <article className="activity-card" key={item.scan_id}>
              <strong>{item.target_url}</strong>
              <span>{item.profile} profile via {item.engine}</span>
              <span>Score {item.score} with {item.total_findings} findings at {item.progress}% progress</span>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
