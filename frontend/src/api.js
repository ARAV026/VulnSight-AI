const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const token = localStorage.getItem("vulnsight_token");
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    let detail = "Request failed";
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch {
      detail = response.statusText || detail;
    }
    throw new Error(detail);
  }

  if (response.status === 204) {
    return null;
  }

  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return response.json();
  }
  return response;
}

export function register(payload) {
  return request("/auth/register", { method: "POST", body: JSON.stringify(payload) });
}

export function login(payload) {
  return request("/auth/login", { method: "POST", body: JSON.stringify(payload) });
}

export function getCurrentUser() {
  return request("/auth/me");
}

export function discoverAuth(payload) {
  return request("/auth/discover", { method: "POST", body: JSON.stringify(payload) });
}

export function saveAuthProfile(payload) {
  return request("/auth/profiles", { method: "POST", body: JSON.stringify(payload) });
}

export function listAuthProfiles(targetUrl) {
  const query = targetUrl ? `?target_url=${encodeURIComponent(targetUrl)}` : "";
  return request(`/auth/profiles${query}`);
}

export function startScan(payload) {
  return request("/scan", { method: "POST", body: JSON.stringify(payload) });
}

export function getResults(scanId) {
  return request(`/results/${scanId}`);
}

export function getHistory() {
  return request("/history");
}

export function analyzePayload(payload) {
  return request("/analyze", { method: "POST", body: JSON.stringify(payload) });
}

export async function downloadReport(scanId) {
  const token = localStorage.getItem("vulnsight_token");
  const response = await fetch(`${API_BASE}/report/${scanId}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  if (!response.ok) {
    throw new Error("Failed to download report");
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `vulnsight-report-${scanId}.pdf`;
  link.click();
  URL.revokeObjectURL(url);
}
