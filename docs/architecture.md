# VulnSight AI Architecture

## Flow

1. User submits a target URL from the frontend.
2. FastAPI creates a scan job and runs the scanner service.
3. Scanner returns normalized findings.
4. AI analysis enriches findings with severity confidence, impact, and remediation priority.
5. Results are exposed to the dashboard.
6. Report generator builds a PDF artifact.

## Future Improvements

- Replace in-memory storage with MongoDB
- Queue long scans with Celery or RQ
- Persist scan histories and compare deltas
- Add authenticated users and projects
