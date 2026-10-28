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
| **Upload Data** `/upload` | Accepts `.csv` and `.xlsx`/`.xlsm` (first worksheet; old `.xls` must be re-saved as `.xlsx`). Files go into a draft **import**; see *Imports and remediation* below |
| **Import** `/runs/<id>` | Files in the import, a preview of what finalizing will change (new / updated / reopened / remediated / skipped, with the list), **Finalize** or **Discard** |
| **Notification log** `/notifications` | Every send attempt with recipients and status/error |

## Imports and remediation
1. Upload one or more files (a whole export split into batches is fine). They are staged in a **draft import**; live data does not change. Only one draft exists at a time and every page shows a reminder while it is waiting.
2. Open the import, check the preview, then **Finalize** (or **Discard**). Finalize only once *all* batches of an export are in.

Each vulnerability is **Open** or **Remediated**, matched by `Alert ID`. On finalize:

| Situation | Result |
|---|---|
| Alert not stored yet | **new**, open |
| Alert stored, the import's `Last Scan` is the same or newer | **updated** (still open) |
| Alert remediated, found again in a **newer** scan | **reopened** |
| Alert stored with a newer `Last Scan` than the import | **skipped** — re-uploading an old file changes nothing |
| Open alert missing from the import, and the import has a **newer scan of the same `Asset ID`** | **remediated** |
| Open alert whose asset is not in the import | untouched |

Open alerts whose asset has had no newer scan for `NOT_SEEN_DAYS` (default **90**) are flagged **Not seen** for review (e.g. image retired, scan failing). They stay open; they are not counted as fixed.

Counts, the dashboard and notification emails cover open vulnerabilities only. The app detail page has a Status filter (Open / Not rescanned 90+ days / Remediated / All); the Applications page shows a Remediated column and has *Not rescanned* and *All remediated* filters. The dashboard shows remediations in the last 30 days and average days to fix (from `Alert Opened`, else first import).

Recipients = owner email + "additional notification emails" (comma/semicolon/newline separated), de-duplicated.

## Code layout
- `app/models.py` – tables; `VULN_FIELDS` is the single list of CSV columns
- `app/importer.py` – CSV / Excel parsing, staging into import runs, preview and finalize
- `app/mailer.py` – SMTP send, HTML/text email, CSV attachment
- `app/main.py` – Flask routes
- `app/templates/` – Bootstrap pages and the email templates

## Prototype limitations
No login/authorisation, no CSRF protection, and emails are sent synchronously in the request. Schema
changes are applied by a small idempotent list in `app/models.py` (`_MIGRATIONS`) rather than a
migration tool. Add these before production use.
