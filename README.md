# VulnSight AI

VulnSight AI is an intelligent web application vulnerability detection and analysis platform built for a hackathon MVP but structured to scale into a production-ready service.

## What Is Included

- React + Vite frontend with authentication and multi-page navigation
- FastAPI backend with JWT auth, scan orchestration, and PDF reporting
- MongoDB persistence for users and scan history, with an in-memory fallback for local demo usage
- OWASP ZAP orchestration path for spider + active scan + alert normalization
- Heuristic fallback scanner when ZAP is not available
- AI analysis layer for severity summary, risk distribution, and remediation recommendations

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
