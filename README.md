# VulnSight AI

VulnSight AI is an intelligent web application vulnerability detection and analysis platform built for a hackathon MVP but structured to scale into a production-ready service.

## What Is Included

- React + Vite frontend with authentication and multi-page navigation
- FastAPI backend with JWT auth, scan orchestration, and PDF reporting
- MongoDB persistence for users and scan history, with an in-memory fallback for local demo usage
- OWASP ZAP orchestration path for spider + active scan + alert normalization
- Heuristic fallback scanner when ZAP is not available
- AI analysis layer for severity summary, risk distribution, and remediation recommendations
- Advanced defensive SQL injection surface detection with parameter and form analysis
- Session-aware scanning with bearer, basic, and form-login context
- Background scan queue with progress polling and persisted job state
- Technology fingerprinting with framework-specific hardening advice
- Parameter baseline vs anomaly comparison for safer SQLi surface scoring
- Authenticated multi-step crawl profiles
- Per-page risk mapping and asset inventory
- Scan diffing between two runs
- Bounded TCP port exposure inventory on common service ports
- Discover Auth workflow with saved auth profiles
- Hybrid AI detection layer with rule-based and ensemble scoring
- Feedback store and benchmark tooling for precision/recall/F1 tracking

## Project Structure

```text
VulnSight-AI/
├── frontend/
├── backend/
├── ai-model/
├── scanner/
├── docs/
├── render.yaml
├── vercel.json
└── README.md
```

## Core Backend Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `POST /scan`
- `GET /results/{scan_id}`
- `GET /history`
- `POST /analyze`
- `GET /report/{scan_id}`

## Local Development

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
copy .env.example .env
npm run dev
```

## Environment Variables

### Backend

See [backend/.env.example](/C:/Users/Administrator/VulnSight-AI/backend/.env.example)

- `JWT_SECRET`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `MONGO_URI`
- `MONGO_DB`
- `ZAP_API_URL`
- `ZAP_API_KEY`

### Frontend

See [frontend/.env.example](/C:/Users/Administrator/VulnSight-AI/frontend/.env.example)

- `VITE_API_BASE`

## ZAP Integration

The backend tries to use OWASP ZAP first:

1. Start spider scan
2. Poll until crawl completes
3. Start active scan
4. Poll until active scan completes
5. Fetch alerts and normalize them into the VulnSight schema

If ZAP is unreachable, the backend falls back to heuristic scanning so the app still works in local demo mode.

## Advanced SQL Injection Detection

The project now includes a stronger defensive SQLi analysis path in the heuristic scanner:

- Query parameter discovery from the target URL
- Form parsing for `GET` and input-driven workflows
- Risk scoring for search, filter, identifier, and hidden fields
- Response marker analysis for common database error leakage
- Higher-confidence SQLi findings with evidence strings and remediation guidance

This implementation is intentionally defensive. It highlights likely SQL injection exposure without embedding exploit payload libraries or offensive automation.

## Session-Aware Scanning

The scan request supports optional request context:

- `auth_mode: none | bearer | basic | form`
- custom headers
- custom cookies
- bearer token injection
- basic auth credentials
- form-login bootstrap with configurable username/password field names

The frontend exposes these options on the Scan page so authenticated application areas can be assessed without hardcoding secrets into the codebase.

## Discover Auth Workflow

The Scan page now supports an assisted auth setup flow:

1. Enter target URL
2. Click `Discover Auth`
3. Backend crawls same-host pages and identifies likely login forms/endpoints
4. UI shows:
   - detected login URLs
   - guessed username/password fields
   - CSRF field candidates
   - suggested form-auth profile
5. Enter credentials once
6. Save the auth profile
7. Reuse that profile in future scans for the same host

### Multi-Step Login Profiles

The scan form also accepts `login_steps`, which lets you model multi-step authentication or pre-crawl bootstrap flows.

Example:

```json
[
  {
    "method": "GET",
    "url": "https://example.com/login"
  },
  {
    "method": "POST",
    "url": "https://example.com/session",
    "username_field": "email",
    "password_field": "password",
    "static_fields": {
      "remember": "true"
    }
  }
]
```

## Background Queue and Progress

`POST /scan` now queues a scan and returns immediately.

- `GET /results/{scan_id}` returns live progress and job message
- `GET /history` shows persisted progress and engine metadata
- the frontend polls results automatically until the scan completes or fails

## Technology Fingerprinting

The heuristic engine now fingerprints common stacks and exposes:

- detected technologies
- evidence for the fingerprint
- framework-specific hardening guidance

These fingerprints are included in both the dashboard and exported PDF reports.

## Advanced Deep Mode

The `deep` scan profile now performs a broader defensive assessment of the target application surface:

- internal link crawling across same-host pages
- page-by-page form and input inventory
- aggregated header analysis across crawled pages
- `robots.txt` and `sitemap.xml` discovery review
- API-like route discovery such as `/api/*` and `.json` endpoints
- safer parameter baseline comparison across discovered input paths
- expanded attack-surface reporting in the dashboard and PDF export

This mode is designed to inspect more of the website structure and workflows without adding exploit payload libraries or destructive probing.

## Per-Page Risk Map and Asset Inventory

Each completed scan now returns:

- a per-page risk map with route, status code, form count, risky parameter hints, and page score
- an asset inventory for scripts, stylesheets, images, and other discovered resources

These appear in the Scan dashboard and can be used to guide manual review of the most exposed pages.

## Scan Diffing

You can compare a new scan against a prior scan by supplying `compare_with_scan_id`.

The analysis output includes:

- `score_delta`
- `total_findings_delta`
- `new_findings`
- `resolved_findings`

## Hybrid AI Detection Layer

The project now includes a hybrid detection design:

- rule-based matching for known vulnerability patterns
- ensemble model scaffold using Random Forest, Gradient Boosting, and Isolation Forest
- confidence thresholding with `0.85` high-confidence cutoff
- context-aware signals for form flows and session anomalies
- feedback storage for confirmed vulnerabilities and false alarms

Current benchmark targets in the project:

- Precision: `0.92`
- Recall: `0.88`
- F1 Score: `0.90`

AI files:

- [hybrid_detector.py](/C:/Users/Administrator/VulnSight-AI/ai-model/hybrid_detector.py)
- [train_ensemble.py](/C:/Users/Administrator/VulnSight-AI/ai-model/train_ensemble.py)
- [benchmark.py](/C:/Users/Administrator/VulnSight-AI/ai-model/benchmark.py)
- [feedback_store.py](/C:/Users/Administrator/VulnSight-AI/ai-model/feedback_store.py)

The backend exposes the AI summary in dashboard results and PDF reports even when the trained ensemble artifacts are not present.

## Port Exposure Inventory

The scanner now performs a bounded TCP exposure check against a small set of common ports on the target host.

- `quick`: small web-focused set
- `balanced`: common web and database/admin set
- `deep`: broader common-service inventory

This is intended for authorized defensive exposure mapping only. It is not a broad network scanner and is deliberately limited in scope.

## Deployment

### Render

- Backend deployment manifest is in [render.yaml](/C:/Users/Administrator/VulnSight-AI/render.yaml)
- Set `MONGO_URI` to your hosted MongoDB connection string
- If you run ZAP externally, set `ZAP_API_URL` and optionally `ZAP_API_KEY`

### Vercel

- Frontend deployment manifest is in [vercel.json](/C:/Users/Administrator/VulnSight-AI/vercel.json)
- Set `VITE_API_BASE` to the Render backend URL

## Suggested Next Steps

- Move scans into an async job queue so long ZAP runs do not block request time
- Add project/team workspaces and role-based access control
- Train the AI model on real labeled vulnerability datasets
- Add webhook or email delivery for completed reports
