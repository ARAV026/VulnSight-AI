import { useEffect, useState } from "react";
import { downloadReport, getHistory } from "../api";

export function ReportsPage() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    getHistory().then(setHistory).catch(() => setHistory([]));
  }, []);

  return (
    <div className="page-stack">
      <header className="hero slim-hero">
        <div>
          <p className="eyebrow">Reports</p>
          <h1>Download report packages from completed scans</h1>
          <p className="hero-copy">Generated PDFs stay tied to each persisted scan so exported evidence matches the dashboard state seen by judges and reviewers.</p>
        </div>
      </header>
      <section className="panel">
        <h2>Available Reports</h2>
        <div className="activity-list">
          {history.length === 0 ? <p className="empty-copy">No reports available yet.</p> : history.map((item) => (
            <article className="activity-card report-card" key={item.scan_id}>
              <div>
                <strong>{item.target_url}</strong>
                <span>{item.engine} engine</span>
              </div>
              <button type="button" className="report-link button-link" onClick={() => downloadReport(item.scan_id)}>Download PDF</button>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
