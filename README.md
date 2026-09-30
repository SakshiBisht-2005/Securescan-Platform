# SecureScan — Defensive Code Security Scanning Platform

SecureScan is a full-stack application security platform: create projects, upload
source code (ZIP or Git import), run SAST / SCA / secret-detection / IaC /
container-configuration scans, browse and fix findings in an in-browser code
editor, track scan history, and generate JSON/PDF reports.

This is a **defensive** security tool. It analyzes code you own or are
authorized to analyze; it never executes uploaded/cloned code, and it
contains no offensive/exploitation tooling.

- Backend: Django + Django REST Framework + MySQL + Celery + Redis + JWT
- Frontend: HTML5 + CSS3 + vanilla JavaScript (no framework, no npm build step)
- Scanning: modular adapter architecture (`backend/scanner_engine/`) —
  Bandit and a built-in rule engine always work out of the box; Semgrep,
  Gitleaks, Checkov, Trivy, and OWASP-style dependency auditing are used
  automatically when installed, and skipped gracefully when not.
- **No Docker.** The app runs directly with Python/Django/MySQL/Redis/Celery/
  Gunicorn/Nginx, on both Windows (dev) and Linux (production).

---

## 1. Repository layout

```
backend/
  manage.py
  config/            Django settings, urls, celery app, wsgi/asgi
  apps/              accounts, projects, repositories, scanner,
                      vulnerabilities, reports, notifications, dashboard, audit
  common/            pagination, permissions, exceptions, utilities, constants
  scanner_engine/    manager, normalizer, severity, deduplicator, rules,
                      adapters/ (bandit, semgrep, gitleaks, dependency_check,
                      checkov, trivy)
  requirements.txt
  .env.example
  run_dev.py         one-command local start (API + Celery + frontend)
frontend/
  *.html             16 pages (landing, auth, dashboard, projects, editor, ...)
  assets/css/main.css
  assets/js/         api.js, auth.js, utils.js, notifications.js, websocket.js,
                      dashboard.js, projects.js, project-detail.js, scanner.js,
                      editor.js, vulnerabilities.js, reports.js, admin.js
start.py             from repo root: python start.py
start.ps1            Windows helper (uses backend\\venv)
docs/
  API.md             endpoint reference
  EMAIL.md           Gmail SMTP for verification / password reset
  CI.md              GitHub Action, webhook, and weekly Celery beat scans
  SCANNERS.md         installing optional external scanners (Windows + Linux)
  DEPLOYMENT.md       Linux production deployment (systemd, nginx, gunicorn)
examples/
  github-actions/securescan.yml   copy into source repos as .github/workflows/
```

---

## 2. Prerequisites

- Python 3.11+
- MySQL 8.x (or MariaDB 10.6+)
- Redis 6+
- Node is **not** required for the frontend (plain static files). It is only
  useful if you want a local static file server — any static server works.

Optional external scanners (auto-detected, see `docs/SCANNERS.md`):
Semgrep, Gitleaks, Checkov, Trivy. The app works fully without them —
Bandit, pip-audit, and the built-in secret/IaC/Dockerfile rule engines
require no extra installation.

---

## 3. Windows development setup

```powershell
# 1. Clone / open the project, then from the backend/ folder:
cd backend
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create the MySQL database (using the MySQL shell or Workbench)
#    CREATE DATABASE securescan CHARACTER SET utf8mb4;
#    CREATE USER 'securescan_user'@'localhost' IDENTIFIED BY 'change-me';
#    GRANT ALL PRIVILEGES ON securescan.* TO 'securescan_user'@'localhost';

# 4. Configure environment
copy .env.example .env
# edit .env: set SECRET_KEY, DATABASE_*, REDIS_URL, etc.

# 5. Run migrations
python manage.py makemigrations
python manage.py migrate

# 6. Create an admin user
python manage.py createsuperuser

# 7. Start everything with one command (Redis check, Celery, frontend :5500, API :8000)
python start.py
# Windows (uses backend\venv automatically):
.\start.ps1
# Or from backend/:
python run_dev.py

Then open http://127.0.0.1:5500  (API is http://127.0.0.1:8000)
Ctrl+C in that terminal stops the API, Celery, and the frontend.

# Manual alternative (only if you want separate terminals):
python manage.py runserver
celery -A config worker -l info --pool=solo
cd ..\frontend
python -m http.server 5500 --bind 127.0.0.1

# Redis on Windows: Docker Desktop is started automatically by run_dev.py
# when possible. Otherwise use Memurai, WSL, or a Redis-for-Windows binary.
```

Set `window.SECURESCAN_API_BASE` in the browser (or edit `assets/js/api.js`'s
default) if your backend isn't on `http://<frontend-host>:8000`.

---

## 4. Linux development / production setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

sudo -u postgres true 2>/dev/null # (placeholder no-op; using MySQL below)
mysql -u root -p <<'SQL'
CREATE DATABASE securescan CHARACTER SET utf8mb4;
CREATE USER 'securescan_user'@'localhost' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON securescan.* TO 'securescan_user'@'localhost';
FLUSH PRIVILEGES;
SQL

cp .env.example .env   # edit values; DEBUG=False in production

python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py collectstatic --noinput

# Run Redis (apt/yum install redis-server, or your package manager) and
# ensure it's started: sudo systemctl enable --now redis-server

# Development:
python start.py
# or: python backend/run_dev.py
# UI: http://127.0.0.1:5500   API: http://127.0.0.1:8000

# Production: see docs/DEPLOYMENT.md for gunicorn + nginx + systemd units.
```

For optional scanner CLI installation on Linux (Semgrep, Gitleaks, Checkov,
Trivy), see `docs/SCANNERS.md`.

---

## 5. Running tests

```bash
cd backend
pytest                      # full suite (unit + API tests)
pytest apps/projects        # a single app
pytest -k "zip"             # by keyword, e.g. ZIP security tests
```

Tests cover: authentication & JWT, permissions/object ownership, project
creation, ZIP upload security (path traversal, zip-bomb-style ratio
limits, bad archives, oversized files, extension checks), editor path
traversal protection, Git URL validation (SSRF-adjacent scheme rejection),
scan creation & API validation, scanner-engine normalization/severity/
deduplication/diffing, finding persistence & status transitions, report
generation (JSON + PDF) with secret masking, and admin-only permissions
(user management, audit log).

---

## 6. Key environment variables (`.env`)

See `backend/.env.example` for the full list with comments. Never commit a
real `.env` file — `.gitignore` already excludes it. At minimum, set:
`SECRET_KEY`, `DATABASE_*`, `REDIS_URL`, `JWT_SIGNING_KEY` (or leave blank to
reuse `SECRET_KEY`), and `CORS_ALLOWED_ORIGINS` to match wherever you serve
`frontend/`.

For Gmail verification and password-reset mail, set `EMAIL_HOST=smtp.gmail.com`
plus `EMAIL_HOST_USER` and `EMAIL_HOST_PASSWORD` (a Gmail **App Password**, not
your login password). Steps are in `docs/EMAIL.md`. Leave the password empty
and the API will not send mail; in DEBUG it still returns a one-time link.

---

## 7. API documentation

Interactive schema (via drf-spectacular) once the server is running:
`GET /api/schema/` and `GET /api/docs/` (Swagger UI).

A written endpoint reference is also in `docs/API.md`.

---

## 8. Security notes

- Uploaded/cloned code is **never executed**. ZIP extraction rejects
  path-traversal entries, absolute paths, symlinks, and enforces size/entry
  limits (`apps/projects/upload_service.py`). Git import only accepts
  `https://` URLs and clones (never executes) into an isolated temp dir.
- Scanner subprocesses are invoked as argument arrays with `shell=False`
  and a timeout (`scanner_engine/process_runner.py`) — never as shell
  strings built from user input.
- Secrets are always masked before storage/display (`common/utilities.py:
  mask_secret`); raw secret values are never persisted.
- JWT auth, per-endpoint throttling, object-level ownership checks
  (`common/permissions.py`), a centralized error handler that never leaks
  tracebacks (`common/exceptions.py`), and an append-only audit log
  (`apps/audit/`) are all wired in from the start.

---

## 9. What's intentionally scoped down

Being upfront about a few places this implementation trades completeness
for a working, coherent whole:

- **Optional scanners** (Semgrep, Gitleaks, Checkov, Trivy) integrate via
  their real CLIs when installed, with a dependable built-in rule-based
  fallback when they aren't — see `docs/SCANNERS.md` for install steps.
- **SCA for non-Python/npm ecosystems** (Maven, Composer, Go, RubyGems)
  currently inventories dependencies (name/version/manifest) without a
  bundled offline vulnerability database; wire in OWASP Dependency-Check
  for CVE coverage there (adapter hook already in place).
- **Real-time scan progress** uses polling (`GET /scans/{id}/status/`)
  rather than WebSockets/Django Channels, per the spec's own guidance to
  avoid unneeded complexity — `assets/js/websocket.js` isolates this
  behind a small interface so a Channels-backed transport can be swapped
  in later without touching call sites.
- **Per-file scans** in the editor trigger a full project scan (the same
  secure pipeline) rather than a separate single-file scan mode.
- **CI and weekly scans** are included: GitHub Action + webhook (`docs/CI.md`)
  and a Sunday 02:00 UTC Celery beat job when a project enables weekly scans.
- Migrations for the non-`accounts` apps are generated via
  `manage.py makemigrations` rather than hand-written, since Django can
  produce them correctly and reliably from the models already in the repo.
