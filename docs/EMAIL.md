# Email (SMTP) for verification and password reset

SecureScan sends account mail through Django’s SMTP backend when all three of
these are set in `backend/.env`:

- `EMAIL_HOST`
- `EMAIL_HOST_USER`
- `EMAIL_HOST_PASSWORD`

If any of them is empty, the API does **not** pretend mail was delivered. In
`DEBUG` it returns `dev_verify_link` / `dev_reset_link` so you can still finish
the flow locally.

Restart `python start.py` after changing `.env`. Django only reads it at process
start.

## Gmail (recommended for local use)

1. Turn on [2-Step Verification](https://myaccount.google.com/signinoptions/two-step-verification) for the Gmail account that will send mail.
2. Create an [App Password](https://myaccount.google.com/apppasswords) (Google Account → Security → App passwords). Choose Mail / Windows Computer. Google shows a 16-character password once.
3. Put that App Password in `.env`. Do **not** use your normal Gmail password.

```
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
EMAIL_TIMEOUT=20
EMAIL_HOST_USER=you@gmail.com
EMAIL_HOST_PASSWORD=xxxx xxxx xxxx xxxx
DEFAULT_FROM_EMAIL=you@gmail.com
FRONTEND_BASE_URL=http://127.0.0.1:5500
```

Spaces in the App Password are fine. Quotes around the value are stripped.

`DEFAULT_FROM_EMAIL` should be the same Gmail address as `EMAIL_HOST_USER`.
Gmail rejects sending as a different From address unless that alias is
configured in the Google account.

## After it is configured

1. Register (or resend from `verify-email.html`).
2. Open the message in the inbox of the **account you registered with**.
3. Click **Verify email**. That hits `frontend/verify-email.html?token=...`,
   which calls `POST /api/auth/verify-email/`.

Password reset uses the same SMTP settings.

## Common failures

| Symptom | Likely cause |
|---|---|
| Register toast says SMTP is not configured | `.env` still has empty `EMAIL_HOST_USER` or `EMAIL_HOST_PASSWORD`, or you did not restart the API |
| Gmail 535 / Username and Password not accepted | Used the account password instead of an App Password, or 2FA is off |
| Mail never arrives | Spam folder; From address differs from `EMAIL_HOST_USER`; App Password revoked |
| Link opens the API on port 8000 | Set `FRONTEND_BASE_URL` to the UI origin (`http://127.0.0.1:5500`) |

Never commit a real App Password. `backend/.env` is gitignored; keep secrets
out of `docs/` and `.env.example`.
