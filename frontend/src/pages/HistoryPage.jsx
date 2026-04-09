import { useEffect, useState } from "react";
import { getHistory } from "../api";

export function HistoryPage() {
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getHistory().then(setHistory).catch((requestError) => setError(requestError.message));
  }, []);

  return (
    <div className="page-stack">
      <header className="hero slim-hero">
        <div>
          <p className="eyebrow">History</p>
          <h1>Persisted scan history and progress tracking</h1>
          <p className="hero-copy">Review completed runs, queued jobs, and engine metadata in a structured operations table.</p>
        </div>
      </header>
      <section className="panel">
        <h2>Recent Scans</h2>
        {error ? <p className="error-text">{error}</p> : null}
        <div className="findings-table">
          <div className="table-head history-head">
            <span>Target</span>
            <span>Status</span>
            <span>Engine</span>
            <span>Score</span>
          </div>
          {history.length === 0 ? <p className="empty-copy">No history available.</p> : history.map((item) => (
            <article className="table-row history-row" key={item.scan_id}>
              <div>
                <strong>{item.target_url}</strong>
                <p>{item.profile} profile</p>
              </div>
              <span>{item.status}</span>
              <span>{item.engine}</span>
              <span>{item.score} / {item.progress}%</span>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
