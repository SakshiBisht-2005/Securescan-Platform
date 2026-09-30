# API Reference

Base URL: `/api/`. All authenticated endpoints require
`Authorization: Bearer <access_token>`. Interactive schema is also
available at `/api/schema/` and `/api/docs/` (Swagger UI) once the server
is running.

## Response envelope

Success:
```json
{"success": true, "data": { ... }}
```
Error:
```json
{"success": false, "error": {"code": "VALIDATION_ERROR", "message": "...", "details": {}}}
```
List endpoints wrap results in `data.results` with `count`, `num_pages`,
`current_page`, `next`, `previous` for pagination.

---

## Auth (`/api/auth/`)

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/register/` | none | Create an account |
| POST | `/auth/login/` | none | Returns `access` + `refresh` JWTs |
| POST | `/auth/logout/` | user | Blacklists the refresh token |
| POST | `/auth/token/refresh/` | none (refresh token) | Rotates access token |
| GET/PATCH | `/auth/me/` | user | Get/update own profile |
| POST | `/auth/change-password/` | user | Change password |
| POST | `/auth/password-reset/` | none | Request reset email |
| POST | `/auth/password-reset/confirm/` | none | Confirm reset with token |
| POST | `/auth/verify-email/` | none | Verify email with token |
| POST | `/auth/verify-email/resend/` | none | Resend verification email (`{email}`) |
| GET | `/auth/admin/users/` | admin | List all users |
| POST | `/auth/admin/users/{id}/disable/` | admin | Disable a user |
| POST | `/auth/admin/users/{id}/enable/` | admin | Enable a user |
| POST | `/auth/admin/users/{id}/set-role/` | admin | Change a user's role |

## Projects (`/api/projects/`)

| Method | Path | Description |
|---|---|---|
| GET/POST | `/projects/` | List / create projects (owner-scoped) |
| GET/PUT/PATCH/DELETE | `/projects/{id}/` | Retrieve / update / delete |
| POST | `/projects/{id}/upload/` | Upload ZIP (`multipart/form-data`, field `file`) |
| GET | `/projects/{id}/files/` | List indexed files |
| GET | `/projects/{id}/editor/tree/` | File-explorer tree |
| GET/PUT/DELETE | `/projects/{id}/editor/file/?path=...` | Read / save / delete a file |
| POST | `/projects/{id}/editor/create/` | Create file or directory |
| POST | `/projects/{id}/editor/rename/` | Rename/move a path |
| GET | `/projects/{id}/editor/search/?q=...` | In-project text search |
| GET | `/projects/{id}/statistics/` | Per-project dashboard stats |
| POST | `/projects/{id}/scan/` | Start a scan (see Scanner below) |
| GET/POST | `/projects/{id}/ci-token/` | Show prefix / rotate CI token (plaintext on POST only) |
| POST | `/projects/{id}/repository/` | Import from Git |
| GET | `/projects/{id}/repository/history/` | Import history |

## Repositories (`/api/`)

| Method | Path | Description |
|---|---|---|
| GET/POST | `/git-credentials/` | List / add a stored Git credential (token encrypted at rest) |
| DELETE | `/git-credentials/{id}/` | Remove a credential |

## Scanner (`/api/`)

| Method | Path | Description |
|---|---|---|
| POST | `/projects/{id}/scan/` | Body: `scan_type`, `enable_sast`, `enable_sca`, `enable_secrets`, `enable_iac`, `enable_container`, `branch`, `exclusions[]`, `severity_threshold`, `generate_report` |
| GET | `/scans/` | List scans (filter: `project`, `status`, `scan_type`) |
| GET | `/scans/{id}/` | Scan detail incl. per-scanner run info |
| GET | `/scans/{id}/status/` | Lightweight polling endpoint (status, progress) |
| GET | `/scans/{id}/findings/` | Findings for this scan (filter: `severity`, `category`) |
| POST | `/scans/{id}/cancel/` | Cancel an active scan |
| GET | `/scans/compare/?scan_a=&scan_b=` | New / resolved / unchanged findings between two scans |
| POST | `/ci/projects/{id}/scan/` | CI token: queue a scan (`ref`, `sha`, `fail_on`) |
| GET | `/ci/projects/{id}/scans/{scan_id}/` | CI token: poll scan + severity gate (`fail_on`) |
| POST | `/webhooks/github/{id}/` | GitHub push webhook (HMAC secret = CI token) |

See `docs/CI.md` for GitHub Action setup and weekly Celery beat.

## Vulnerabilities (`/api/`)

| Method | Path | Description |
|---|---|---|
| GET | `/findings/` | Filter: `severity`, `scanner`, `category`, `status`, `project`, `scan`; search: `title`, `file_path`, `rule_id`, `cwe` |
| GET | `/findings/{id}/` | Finding detail |
| PATCH | `/findings/{id}/status/` | Body: `{"status": "resolved"}` |
| GET | `/dependencies/` | SCA findings |
| GET | `/secret-findings/` | Secret-detection findings (values always masked) |

## Reports (`/api/`)

| Method | Path | Description |
|---|---|---|
| GET | `/reports/` | List generated reports |
| POST | `/reports/{scan_id}/generate/` | Body: `{"report_type": "json"|"pdf"}` |
| GET | `/reports/{id}/download/` | Streams the file (owner or admin/analyst only) |

## Dashboard (`/api/`)

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/summary/` | Global stats across the user's projects |
| GET | `/dashboard/trend/?project=` | Security-score trend over recent scans |
| GET | `/projects/{id}/statistics/` | Per-project stats + trend |
| GET | `/dashboard/admin/system-health/` | Admin/analyst only: users, scans, scanner availability |

## Notifications (`/api/`)

| Method | Path | Description |
|---|---|---|
| GET | `/notifications/` | List (filter `is_read`, `notification_type`) |
| POST | `/notifications/{id}/read/` | Mark one read |
| POST | `/notifications/read-all/` | Mark all read |
| GET | `/notifications/unread-count/` | Badge count |

## Audit (`/api/`)

| Method | Path | Description |
|---|---|---|
| GET | `/audit-logs/` | Admin/analyst only |

---

## Permissions summary

- **USER**: full access to their own projects/scans/findings/reports only.
- **SECURITY_ANALYST**: read access across all projects/scans/findings/
  reports/audit logs; cannot modify projects they don't own.
- **ADMIN**: full access everywhere, plus user management and system
  health.

## Rate limiting

Scoped throttles: `auth` (10/min), `upload` (20/hour), `scan` (30/hour),
`report` (60/hour), configured in `config/settings.py`.
