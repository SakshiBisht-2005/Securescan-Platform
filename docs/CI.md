# CI and scheduled scans

SecureScan can scan without anyone clicking **Run Scan** in the UI.

1. **GitHub Action** — on every push, the action calls the API, waits, and fails the job if findings are at or above a severity gate.
2. **GitHub webhook** — GitHub POSTs `push` events directly to SecureScan (same CI token as HMAC secret).
3. **Weekly Celery beat** — Sunday 02:00 UTC, every project with **Weekly scheduled scan** enabled.

CI/webhook/scheduled runs re-clone `repository_url` when it is set (using the owner’s stored Git credential if the repo is private). ZIP-only projects scan the current working tree.

## 1. Project setup

1. Import the Git repo (or upload a ZIP) on the project page.
2. Open **Settings**.
3. Click **Generate CI token**. Copy it once.
4. Optionally enable **Weekly scheduled scan**.

`python start.py` already starts a Celery worker **and** Celery beat.

## 2. GitHub Action

Copy [`examples/github-actions/securescan.yml`](../examples/github-actions/securescan.yml) to `.github/workflows/securescan.yml` in the **source** repository (the one you want scanned, not necessarily this platform repo).

Add repository secrets:

| Secret | Value |
|---|---|
| `SECURESCAN_URL` | API origin, e.g. `https://scan.example.com` (no trailing slash) |
| `SECURESCAN_TOKEN` | The project CI token |
| `SECURESCAN_PROJECT_ID` | Numeric id from the project URL (`project.html?id=3` → `3`) |
| `SECURESCAN_FAIL_ON` | Optional. `critical`, `high` (default), `medium`, `low`, or `never` |

The job POSTs `/api/ci/projects/{id}/scan/` with `Authorization: Bearer <token>`, then polls `/api/ci/projects/{id}/scans/{scan_id}/` until the scan is terminal. Exit code 1 if the scan failed or the severity gate fired.

GitHub-hosted runners cannot reach `http://127.0.0.1:8000`. Use a public HTTPS URL in production, or a tunnel for local tests.

## 3. GitHub webhook (no Action)

Repo **Settings → Webhooks → Add webhook**:

- Payload URL: `{SECURESCAN_URL}/api/webhooks/github/{project_id}/`
- Content type: `application/json`
- Secret: the same CI token
- Events: **Just the push event**

`ping` is acknowledged. Branch deletions are ignored. Push events queue a scan of the pushed branch.

## 4. Weekly schedule

Beat crontab: Sunday 02:00 UTC (`scanner.run_weekly_scheduled_scans`). Projects with `weekly_scan_enabled` and status `active` are queued. An in-progress scan is skipped for that project until the next week.

Production: run `celery -A config beat` (see `docs/DEPLOYMENT.md`).

## 5. API

| Method | Path | Auth |
|---|---|---|
| GET/POST | `/api/projects/{id}/ci-token/` | JWT (owner/admin). POST rotates and returns plaintext once |
| POST | `/api/ci/projects/{id}/scan/` | Bearer CI token |
| GET | `/api/ci/projects/{id}/scans/{scan_id}/` | Bearer CI token |
| POST | `/api/webhooks/github/{id}/` | HMAC `X-Hub-Signature-256` or Bearer CI token |
