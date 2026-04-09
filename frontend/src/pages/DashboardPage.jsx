import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getReportUrl, getResults, startScan } from "../api";
import { useAuth } from "../auth";

const severityColors = {
  critical: "#f04438",
  high: "#f79009",
  medium: "#fdb022",
  low: "#17b26a",
  info: "#6172f3"
};

const emptyState = {
  summary: { score: 0, total_findings: 0, exploitability: 0, false_positive_risk: 0, attack_surface: 0 },
  risk_distribution: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  attack_patterns: [],
  recommendations: []
};

export default function DashboardPage() {
  const { token } = useAuth();
  const [targetUrl, setTargetUrl] = useState("http://testphp.vulnweb.com/");
  const [profile, setProfile] = useState("balanced");
  const [scanId, setScanId] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const analysis = result?.analysis ?? emptyState;
  const findings = result?.findings ?? [];
  const pieData = Object.entries(analysis.risk_distribution).map(([name, value]) => ({ name, value }));
  const scoreData = [
    { label: "Security Score", value: analysis.summary.score },
    { label: "Exploitability", value: analysis.summary.exploitability },
    { label: "Attack Surface", value: analysis.summary.attack_surface }
  ];

  async function handleScan(event) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const scanResponse = await startScan(token, { target_url: targetUrl, profile });
      setScanId(scanResponse.scan_id);
      const data = await pollResults(token, scanResponse.scan_id);
      setResult(data);
    } catch (scanError) {
      setError(scanError.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="dashboard-grid">
      <section className="panel panel-form">
        <h2>Start New Scan</h2>
        <form onSubmit={handleScan}>
          <label>
            Target URL
            <input type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="https://example.com" required />
          </label>
          <label>
            Scan Profile
            <select value={profile} onChange={(event) => setProfile(event.target.value)}>
              <option value="quick">Quick</option>
              <option value="balanced">Balanced</option>
              <option value="deep">Deep</option>
            </select>
          </label>
          <button type="submit" disabled={loading}>{loading ? "Scanning..." : "Launch Scan"}</button>
        </form>
        {scanId ? <p className="scan-meta">Latest Scan ID: {scanId}</p> : null}
        {error ? <p className="error-text">{error}</p> : null}
      </section>

      <section className="panel score-panel">
        <h2>Risk Overview</h2>
        <div className="score-cards">
          <StatCard label="Exploitability" value={analysis.summary.exploitability} />
          <StatCard label="False Positive Risk" value={analysis.summary.false_positive_risk} />
          <StatCard label="Attack Surface" value={analysis.summary.attack_surface} />
        </div>
        <div className="chart-grid">
          <div className="chart-box">
            <h3>Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={90}>
                  {pieData.map((entry) => <Cell key={entry.name} fill={severityColors[entry.name]} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-box">
            <h3>Exposure Metrics</h3>
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={scoreData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="label" stroke="#98a2b3" />
                <YAxis stroke="#98a2b3" />
                <Tooltip />
                <Bar dataKey="value" radius={[12, 12, 0, 0]} fill="#36cfc9" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="panel findings-panel">
        <div className="section-row">
          <h2>Detected Findings</h2>
          {scanId ? <a className="report-link" href={getReportUrl(scanId, token)} target="_blank" rel="noreferrer">Download PDF Report</a> : null}
        </div>
        <div className="findings-table">
          <div className="table-head">
            <span>Title</span>
            <span>Severity</span>
            <span>Endpoint</span>
            <span>CWE</span>
          </div>
          {findings.length === 0 ? (
            <p className="empty-copy">Run a scan to view findings.</p>
          ) : (
            findings.map((finding) => (
              <article className="table-row" key={`${finding.title}-${finding.endpoint}`}>
                <div>
                  <strong>{finding.title}</strong>
                  <p>{finding.description}</p>
                </div>
                <span className={`severity-pill severity-${finding.severity}`}>{finding.severity}</span>
                <span>{finding.endpoint}</span>
                <span>{finding.cwe}</span>
              </article>
            ))
          )}
        </div>
      </section>

      <section className="panel recommendations-panel">
        <h2>AI Recommendations</h2>
        <div className="recommendation-list">
          {analysis.recommendations.length === 0 ? (
            <p className="empty-copy">Recommendations will appear after a scan.</p>
          ) : (
            analysis.recommendations.map((item) => (
              <article className="recommendation-card" key={`${item.title}-${item.priority}`}>
                <span className={`priority priority-${item.priority}`}>{item.priority}</span>
                <h3>{item.title}</h3>
                <p>{item.action}</p>
              </article>
            ))
          )}
        </div>
        <h2>Observed Attack Patterns</h2>
        <div className="pattern-list">
          {analysis.attack_patterns.map((pattern) => <span className="pattern-chip" key={pattern}>{pattern}</span>)}
        </div>
      </section>
    </main>
  );
}

function StatCard({ label, value }) {
  return (
    <div className="stat-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

async function pollResults(token, scanId, attempt = 0) {
  try {
    return await getResults(token, scanId);
  } catch (error) {
    if (error.status === 202 && attempt < 60) {
      await new Promise((resolve) => setTimeout(resolve, 2500));
      return pollResults(token, scanId, attempt + 1);
    }
    throw error;
  }
}
