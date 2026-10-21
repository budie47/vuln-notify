import csv
import io
import os
import smtplib
from datetime import date
from email.message import EmailMessage

from flask import render_template

from .models import VULN_FIELDS

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "1025"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "false").lower() == "true"
MAIL_FROM = os.environ.get("MAIL_FROM", "vuln-notify@example.com")

EMAIL_TABLE_LIMIT = 200


def vulns_to_csv(vulns):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([h for h, _, _ in VULN_FIELDS])
    for v in vulns:
        w.writerow(["" if getattr(v, n) is None else getattr(v, n) for _, n, _ in VULN_FIELDS])
    return buf.getvalue()


def send_app_notification(app, vulns, severity_counts):
    recipients = app.recipients()
    if not recipients:
        raise ValueError(f"App {app.app_id} has no owner email or notification list.")

    today = date.today()
    overdue = sum(1 for v in vulns if v.slo_date and v.slo_date < today)

    msg = EmailMessage()
    msg["Subject"] = f"[Action required] {len(vulns)} open vulnerabilities for {app.app_id}" + (
        f" ({app.app_name})" if app.app_name else ""
    )
    msg["From"] = MAIL_FROM
    msg["To"] = ", ".join(recipients)

    ctx = dict(
        app=app, vulns=vulns[:EMAIL_TABLE_LIMIT], total=len(vulns), truncated=len(vulns) > EMAIL_TABLE_LIMIT,
        severity_counts=severity_counts, overdue=overdue, today=today,
    )
    msg.set_content(render_template("email/notification.txt", **ctx))
    msg.add_alternative(render_template("email/notification.html", **ctx), subtype="html")
    msg.add_attachment(
        vulns_to_csv(vulns).encode("utf-8"), maintype="text", subtype="csv",
        filename=f"vulnerabilities_{app.app_id}_{today:%Y%m%d}.csv",
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)
    return recipients
