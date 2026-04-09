import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { discoverAuth, downloadReport, getHistory, getResults, listAuthProfiles, saveAuthProfile, startScan } from "../api";

const severityColors = { critical: "#f04438", high: "#f79009", medium: "#fdb022", low: "#17b26a", info: "#6172f3" };
const emptyState = {
  summary: { score: 0, total_findings: 0, exploitability: 0, false_positive_risk: 0, attack_surface: 0 },
  risk_distribution: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  attack_patterns: [],
  recommendations: [],
  technologies: [],
  attack_surface_summary: { risky_parameters: [], forms_discovered: 0, get_forms: 0, anomaly_observations: [] },
  remediation_status: [],
  ports: [],
  ai_summary: { model_version: "hybrid-v1", threshold: 0.85, high_confidence_findings: 0, feedback_samples: 0, notes: [] }
};

export function ScanPage() {
  const [targetUrl, setTargetUrl] = useState("http://testphp.vulnweb.com/");
  const [profile, setProfile] = useState("balanced");
  const [scanId, setScanId] = useState("");
  const [result, setResult] = useState(null);
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState("Ready to scan");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [discovery, setDiscovery] = useState(null);
  const [discovering, setDiscovering] = useState(false);
  const [profileName, setProfileName] = useState("");
  const [context, setContext] = useState({
    auth_mode: "none",
    bearer_token: "",
    username: "",
    password: "",
    login_url: "",
    username_field: "username",
    password_field: "password",
    headers_json: "{}",
    cookies_json: "{}",
    login_steps_json: "[]"
  });
  const [compareWithScanId, setCompareWithScanId] = useState("");

  const analysis = result?.analysis ?? emptyState;
  const findings = result?.findings ?? [];
  const pieData = Object.entries(analysis.risk_distribution).map(([name, value]) => ({ name, value }));
  const scoreData = [
    { label: "Security Score", value: analysis.summary.score },
    { label: "Exploitability", value: analysis.summary.exploitability },
    { label: "Attack Surface", value: analysis.summary.attack_surface }
  ];

  useEffect(() => {
    getHistory().then(setHistory).catch(() => setHistory([]));
  }, []);

  useEffect(() => {
    if (!targetUrl) return;
    listAuthProfiles(targetUrl).then(setProfiles).catch(() => setProfiles([]));
  }, [targetUrl]);

  useEffect(() => {
    if (!scanId) return undefined;
    const interval = setInterval(async () => {
      try {
        const data = await getResults(scanId);
        setResult(data);
        setProgress(data.progress ?? 0);
        setMessage(data.message ?? "Processing scan");
        if (data.status === "completed" || data.status === "failed") {
          setBusy(false);
          clearInterval(interval);
        }
      } catch (pollError) {
        setError(pollError.message);
        setBusy(false);
        clearInterval(interval);
      }
    }, 2500);
    return () => clearInterval(interval);
  }, [scanId]);

  async function handleScan(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const scanResponse = await startScan({
        target_url: targetUrl,
        profile,
        context: {
          auth_mode: context.auth_mode,
          bearer_token: context.bearer_token || null,
          username: context.username || null,
          password: context.password || null,
          login_url: context.login_url || null,
          username_field: context.username_field,
          password_field: context.password_field,
          headers: safeParseJson(context.headers_json),
          cookies: safeParseJson(context.cookies_json),
          login_steps: safeParseArray(context.login_steps_json)
        },
        compare_with_scan_id: compareWithScanId || null
      });
      setScanId(scanResponse.scan_id);
      setProgress(scanResponse.progress ?? 0);
      setMessage(scanResponse.message ?? "Scan queued");
      setResult(null);
    } catch (scanError) {
      setError(scanError.message);
      setBusy(false);
    }
  }

  async function handleDiscoverAuth() {
    setDiscovering(true);
    setError("");
    try {
      const data = await discoverAuth({
        target_url: targetUrl,
        headers: safeParseJson(context.headers_json),
        cookies: safeParseJson(context.cookies_json)
      });
      setDiscovery(data);
      if (data.candidates?.length) {
        applyCandidate(data.candidates[0]);
      }
    } catch (discoverError) {
      setError(discoverError.message);
    } finally {
      setDiscovering(false);
    }
  }

  function applyCandidate(candidate) {
    setContext((current) => ({
      ...current,
      auth_mode: "form",
      login_url: candidate.login_url || "",
      username_field: candidate.username_field || "username",
      password_field: candidate.password_field || "password",
      login_steps_json: JSON.stringify([
        {
          method: candidate.method?.toUpperCase() || "POST",
          url: candidate.login_url,
          username_field: candidate.username_field || "username",
          password_field: candidate.password_field || "password",
          static_fields: candidate.hidden_fields || {}
        }
      ], null, 2)
    }));
  }

  async function handleSaveProfile() {
    if (!profileName.trim()) {
      setError("Enter a profile name before saving.");
      return;
    }
    try {
      await saveAuthProfile({
        target_url: targetUrl,
        profile_name: profileName,
        context: {
          auth_mode: context.auth_mode,
          bearer_token: context.bearer_token || null,
          username: context.username || null,
          password: context.password || null,
          login_url: context.login_url || null,
          username_field: context.username_field,
          password_field: context.password_field,
          headers: safeParseJson(context.headers_json),
          cookies: safeParseJson(context.cookies_json),
          login_steps: safeParseArray(context.login_steps_json)
        }
      });
      const items = await listAuthProfiles(targetUrl);
      setProfiles(items);
      setProfileName("");
    } catch (saveError) {
      setError(saveError.message);
    }
  }

  function loadProfile(profile) {
    const saved = profile.context;
    setContext({
      auth_mode: saved.auth_mode || "none",
      bearer_token: saved.bearer_token || "",
      username: saved.username || "",
      password: saved.password || "",
      login_url: saved.login_url || "",
      username_field: saved.username_field || "username",
      password_field: saved.password_field || "password",
      headers_json: JSON.stringify(saved.headers || {}, null, 2),
      cookies_json: JSON.stringify(saved.cookies || {}, null, 2),
      login_steps_json: JSON.stringify(saved.login_steps || [], null, 2)
    });
  }

  return (
    <div className="page-stack">
      <header className="hero slim-hero">
        <div>
          <p className="eyebrow">Scanner</p>
          <h1>Intelligent Web Application Vulnerability Detection & Analysis Platform</h1>
          <p className="hero-copy">Initiate intelligent background scanning with flexible authentication support, enabling continuous discovery of vulnerabilities across the application. Monitor the evolving threat surface in real time with dynamic analysis and insights.</p>
        </div>
      </header>

      <div className="dashboard-grid">
        <section className="panel panel-form">
          <h2>Start New Scan</h2>
          <form onSubmit={handleScan}>
            <label>
              Target URL
              <input type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} required />
            </label>
            <label>
              Scan Profile
              <select value={profile} onChange={(event) => setProfile(event.target.value)}>
                <option value="quick">Quick</option>
                <option value="balanced">Balanced</option>
                <option value="deep">Deep</option>
              </select>
            </label>
            <label>
              Session/Auth Mode
              <select value={context.auth_mode} onChange={(event) => setContext({ ...context, auth_mode: event.target.value })}>
                <option value="none">None</option>
                <option value="bearer">Bearer Token</option>
                <option value="basic">Basic Auth</option>
                <option value="form">Form Login</option>
              </select>
            </label>
            <div className="inline-actions">
              <button type="button" onClick={handleDiscoverAuth} disabled={discovering}>{discovering ? "Discovering..." : "Discover Auth"}</button>
            </div>
            {profiles.length ? (
              <label>
                Saved Auth Profile
                <select onChange={(event) => {
                  const profile = profiles.find((item) => item.id === event.target.value);
                  if (profile) loadProfile(profile);
                }} defaultValue="">
                  <option value="">Select saved profile</option>
                  {profiles.map((item) => <option key={item.id} value={item.id}>{item.profile_name}</option>)}
                </select>
              </label>
            ) : null}
            {discovery?.candidates?.length ? (
              <div className="recommendation-list">
                {discovery.candidates.map((candidate) => (
                  <article className="recommendation-card" key={`${candidate.login_url}-${candidate.username_field}`}>
                    <h3>{candidate.login_url}</h3>
                    <p>Method: {candidate.method}</p>
                    <p>User Field: {candidate.username_field || "unknown"}</p>
                    <p>Password Field: {candidate.password_field || "unknown"}</p>
                    <p>CSRF: {(candidate.csrf_fields || []).join(", ") || "None"}</p>
                    <button type="button" onClick={() => applyCandidate(candidate)}>Use This</button>
                  </article>
                ))}
              </div>
            ) : null}
            {context.auth_mode === "bearer" ? (
              <label>
                Bearer Token
                <input value={context.bearer_token} onChange={(event) => setContext({ ...context, bearer_token: event.target.value })} />
              </label>
            ) : null}
            {context.auth_mode === "basic" || context.auth_mode === "form" ? (
              <>
                <label>
                  Username
                  <input value={context.username} onChange={(event) => setContext({ ...context, username: event.target.value })} />
                </label>
                <label>
                  Password
                  <input type="password" value={context.password} onChange={(event) => setContext({ ...context, password: event.target.value })} />
                </label>
              </>
            ) : null}
            {context.auth_mode === "form" ? (
              <>
                <label>
                  Login URL
                  <input type="url" value={context.login_url} onChange={(event) => setContext({ ...context, login_url: event.target.value })} />
                </label>
                <label>
                  Username Field
                  <input value={context.username_field} onChange={(event) => setContext({ ...context, username_field: event.target.value })} />
                </label>
                <label>
                  Password Field
                  <input value={context.password_field} onChange={(event) => setContext({ ...context, password_field: event.target.value })} />
                </label>
              </>
            ) : null}
            <label>
              Extra Headers JSON
              <textarea value={context.headers_json} onChange={(event) => setContext({ ...context, headers_json: event.target.value })} rows={4} />
            </label>
            <label>
              Cookies JSON
              <textarea value={context.cookies_json} onChange={(event) => setContext({ ...context, cookies_json: event.target.value })} rows={3} />
            </label>
            <label>
              Multi-Step Login JSON
              <textarea value={context.login_steps_json} onChange={(event) => setContext({ ...context, login_steps_json: event.target.value })} rows={5} />
            </label>
            <label>
              Save Current Auth Profile As
              <input value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder="Example: Admin Login" />
            </label>
            <div className="inline-actions">
              <button type="button" onClick={handleSaveProfile}>Save Auth Profile</button>
            </div>
            <label>
              Compare With Previous Scan
              <select value={compareWithScanId} onChange={(event) => setCompareWithScanId(event.target.value)}>
                <option value="">None</option>
                {history.map((item) => <option key={item.scan_id} value={item.scan_id}>{item.target_url} [{item.scan_id.slice(0, 8)}]</option>)}
              </select>
            </label>
            <button type="submit" disabled={busy}>{busy ? "Scanning..." : "Launch Scan"}</button>
          </form>
          {scanId ? <p className="scan-meta">Latest Scan ID: {scanId}</p> : null}
          <p className="scan-meta">Progress: {progress}%</p>
          <p className="scan-meta">{message}</p>
          <div className="scan-progress">
            <div className="scan-progress-bar" style={{ width: `${progress}%` }} />
          </div>
          {busy ? <p className="scan-ai-status">AI analysis in progress...</p> : null}
          {error ? <p className="error-text">{error}</p> : null}
        </section>

        <section className="panel score-panel">
          <h2>Risk Overview</h2>
          <div className="score-cards">
            <StatCard label="Total Vulnerabilities" value={analysis.summary.total_findings} />
            <StatCard label="Critical Issues" value={analysis.risk_distribution.critical} />
            <StatCard label="Scan Status" value={result?.status || "idle"} />
            <StatCard label="Risk Score" value={analysis.summary.score} />
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
            {scanId ? <button type="button" className="report-link button-link" onClick={() => downloadReport(scanId)}>Download PDF Report</button> : null}
          </div>
          <div className="findings-table">
            <div className="table-head">
              <span>Title</span>
              <span>Severity</span>
              <span>Endpoint</span>
              <span>CWE</span>
            </div>
            {findings.length === 0 ? <p className="empty-copy">Run a scan to view findings.</p> : findings.map((finding) => (
              <article className="table-row" key={`${finding.title}-${finding.endpoint}`}>
                <div>
                  <strong>{finding.title}</strong>
                  <p>{finding.description}</p>
                  {finding.references?.length ? <p>Refs: {finding.references.join(" | ")}</p> : null}
                </div>
                <span className={`severity-pill severity-${finding.severity}`}>{finding.severity}</span>
                <span>{finding.endpoint}</span>
                <span>{finding.cwe}</span>
              </article>
            ))}
          </div>
        </section>

        <section className="panel recommendations-panel">
          <h2>AI Recommendations</h2>
          <div className="recommendation-list">
            {analysis.recommendations.length === 0 ? <p className="empty-copy">Recommendations will appear after a scan.</p> : analysis.recommendations.map((item) => (
              <article className="recommendation-card" key={`${item.title}-${item.priority}`}>
                <span className={`priority priority-${item.priority}`}>{item.priority}</span>
                <h3>{item.title}</h3>
                <p>{item.action}</p>
              </article>
            ))}
          </div>
          <h2>Observed Attack Patterns</h2>
          <div className="pattern-list">
            {analysis.attack_patterns.map((pattern) => <span className="pattern-chip" key={pattern}>{pattern}</span>)}
          </div>
          <h2>Technology Fingerprints</h2>
          <div className="recommendation-list">
            {analysis.technologies?.length ? analysis.technologies.map((item) => (
              <article className="recommendation-card" key={item.name}>
                <h3>{item.name}</h3>
                <p>{item.evidence}</p>
                <p>{item.hardening_advice}</p>
              </article>
            )) : <p className="empty-copy">No technology fingerprints detected.</p>}
          </div>
          <h2>SQLi Attack Surface</h2>
          <div className="recommendation-card">
            <p>Risky Parameters: {(analysis.attack_surface_summary?.risky_parameters || []).join(", ") || "None"}</p>
            <p>Forms Discovered: {analysis.attack_surface_summary?.forms_discovered || 0}</p>
            <p>GET Forms: {analysis.attack_surface_summary?.get_forms || 0}</p>
            <p>Anomalies: {(analysis.attack_surface_summary?.anomaly_observations || []).map((item) => `${item.parameter}:${item.anomaly_score}`).join(" | ") || "None"}</p>
          </div>
          <h2>Per-Page Risk Map</h2>
          <div className="recommendation-list">
            {analysis.page_risk_map?.length ? analysis.page_risk_map.map((item) => (
              <article className="recommendation-card" key={item.url}>
                <h3>{item.url}</h3>
                <p>Status: {item.status_code}</p>
                <p>Risk Score: {item.risk_score}</p>
                <p>Forms: {item.forms}</p>
                <p>Params: {(item.risky_parameters || []).join(", ") || "None"}</p>
              </article>
            )) : <p className="empty-copy">No page map available.</p>}
          </div>
          <h2>Asset Inventory</h2>
          <div className="recommendation-list">
            {analysis.assets?.length ? analysis.assets.slice(0, 20).map((item) => (
              <article className="recommendation-card" key={`${item.source_page}-${item.url}`}>
                <h3>{item.asset_type}</h3>
                <p>{item.url}</p>
                <p>Source: {item.source_page}</p>
                <p>{item.external ? "External" : "Internal"}</p>
              </article>
            )) : <p className="empty-copy">No assets inventoried.</p>}
          </div>
          <h2>Port Exposure Inventory</h2>
          <div className="recommendation-list">
            {analysis.ports?.length ? analysis.ports.map((item) => (
              <article className="recommendation-card" key={item.port}>
                <h3>{item.port}/tcp</h3>
                <p>State: {item.state}</p>
                <p>Service: {item.service_hint || "unknown"}</p>
                <p>{item.note}</p>
              </article>
            )) : <p className="empty-copy">No port inventory available.</p>}
          </div>
          <h2>Scan Diff</h2>
          <div className="recommendation-card">
            <p>Baseline: {analysis.diff?.baseline_scan_id || "None"}</p>
            <p>Score Delta: {analysis.diff?.score_delta ?? 0}</p>
            <p>Findings Delta: {analysis.diff?.total_findings_delta ?? 0}</p>
            <p>New Findings: {(analysis.diff?.new_findings || []).slice(0, 5).join(" | ") || "None"}</p>
            <p>Resolved Findings: {(analysis.diff?.resolved_findings || []).slice(0, 5).join(" | ") || "None"}</p>
          </div>
          <h2>Remediation Status</h2>
          <div className="recommendation-list">
            {analysis.remediation_status?.length ? analysis.remediation_status.map((item) => (
              <article className="recommendation-card" key={item.area}>
                <h3>{item.area}</h3>
                <p>Status: {item.status}</p>
                <p>{item.note}</p>
              </article>
            )) : <p className="empty-copy">No remediation status yet.</p>}
          </div>
          <h2>AI Detection Summary</h2>
          <div className="recommendation-card">
            <p>Model: {analysis.ai_summary?.model_version}</p>
            <p>Precision: {analysis.ai_summary?.precision ?? "n/a"}</p>
            <p>Recall: {analysis.ai_summary?.recall ?? "n/a"}</p>
            <p>F1 Score: {analysis.ai_summary?.f1_score ?? "n/a"}</p>
            <p>Threshold: {analysis.ai_summary?.threshold}</p>
            <p>High-Confidence Findings: {analysis.ai_summary?.high_confidence_findings}</p>
            <p>Feedback Samples: {analysis.ai_summary?.feedback_samples}</p>
            <p>Notes: {(analysis.ai_summary?.notes || []).join(" | ") || "None"}</p>
          </div>
        </section>
      </div>
    </div>
  );
}

function StatCard({ label, value }) {
  return <div className="stat-card"><span>{label}</span><strong>{value}</strong></div>;
}

function safeParseJson(value) {
  try {
    return value ? JSON.parse(value) : {};
  } catch {
    return {};
  }
}

function safeParseArray(value) {
  try {
    const parsed = value ? JSON.parse(value) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
