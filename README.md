# Vuln Notify (prototype)

Loads vulnerability scan exports (CSV or Excel) into PostgreSQL, tracks App ID owners, and emails each
owner a summary plus a full CSV of their open vulnerabilities.

## Run

```bash
docker compose up -d --build
docker compose exec app python -m app.seed      # optional: 5 demo applications
python3 sample/generate_sample.py 500           # optional: fake CSV -> sample/vulnerabilities_sample.csv
```

- App: http://localhost:5000
- Mailpit (catches every outgoing email): http://localhost:8025

To send real email, change the `SMTP_*` and `MAIL_FROM` variables in `docker-compose.yml`
(e.g. `SMTP_HOST=smtp.office365.com`, `SMTP_PORT=587`, `SMTP_USE_TLS=true`, plus user/password).

### Without Docker
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export DATABASE_URL=postgresql+psycopg2://user:pass@localhost:5432/vulnnotify SMTP_HOST=localhost SMTP_PORT=1025
.venv/bin/python -m app.main
```

## Features
| Page | What it does |
|---|---|
| **Dashboard** `/` | Total vulnerabilities, apps covered (registered), apps with findings, critical+high, past-SLO, breakdown by severity and environment, top 10 apps, owner coverage |
| **Applications** `/apps` | Every App ID from the registry *and* the vulnerability data, with counts by severity. Add / edit / delete apps, **Send notification** per app, or tick several and **Send to selected**. Unregistered App IDs get a "Register owner" button that pre-fills from the scan data |
| **App detail** `/apps/<id>` | Owner + recipients, the full vulnerability list, CSV export, notification history |
| **Upload Data** `/upload` | Accepts `.csv` and `.xlsx`/`.xlsm` (first worksheet; old `.xls` must be re-saved as `.xlsx`). **Merge** (upsert on `Alert ID`) or **Replace all**. Headers are matched case/space-insensitively and `Enviroment` is accepted. Bad rows are rejected and listed |
| **Notification log** `/notifications` | Every send attempt with recipients and status/error |

Recipients = owner email + "additional notification emails" (comma/semicolon/newline separated), de-duplicated.

## Code layout
- `app/models.py` – tables; `VULN_FIELDS` is the single list of CSV columns
- `app/importer.py` – CSV / Excel parsing and batched upsert
- `app/mailer.py` – SMTP send, HTML/text email, CSV attachment
- `app/main.py` – Flask routes
- `app/templates/` – Bootstrap pages and the email templates

## Prototype limitations
No login/authorisation, no CSRF protection, emails sent synchronously in the request, and tables
are created with `create_all` (no migrations). Add these before production use.
