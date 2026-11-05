import base64
import csv
import hashlib
import io
import os
import smtplib
from datetime import date
from email.message import EmailMessage

from cryptography.fernet import Fernet, InvalidToken
from flask import render_template
from sqlalchemy import delete, select

from .models import VULN_FIELDS, Setting

# Environment defaults. Values saved on the Settings page (settings table) take precedence.
def _env_security():
    if os.environ.get("SMTP_SECURITY"):
        return os.environ["SMTP_SECURITY"].lower()
    return "starttls" if os.environ.get("SMTP_USE_TLS", "false").lower() == "true" else "none"


ENV_DEFAULTS = {
    "smtp_host": os.environ.get("SMTP_HOST", "localhost"),
    "smtp_port": os.environ.get("SMTP_PORT", "1025"),
    "smtp_security": _env_security(),  # none / starttls / ssl
    "smtp_user": os.environ.get("SMTP_USER", ""),
    "smtp_password": os.environ.get("SMTP_PASSWORD", ""),
    "mail_from": os.environ.get("MAIL_FROM", "vuln-notify@example.com"),
}
SMTP_KEYS = tuple(ENV_DEFAULTS)
SECURITY_CHOICES = ("none", "starttls", "ssl")


def _fernet():
    # Key derived from the app's SECRET_KEY: the SMTP password is unreadable without it.
    key = base64.urlsafe_b64encode(hashlib.sha256(os.environ.get("SECRET_KEY", "dev-secret").encode()).digest())
    return Fernet(key)


def smtp_config(session):
    """Effective SMTP settings: saved settings over environment defaults.

    Adds "source" (per key: "saved" or "default") and "password_error" when a saved password can't
    be decrypted (SECRET_KEY changed since it was saved).
    """
    saved = {s.key: s.value for s in session.scalars(select(Setting).where(Setting.key.in_(SMTP_KEYS)))}
    cfg = dict(ENV_DEFAULTS)
    cfg["source"] = {k: ("saved" if k in saved else "default") for k in SMTP_KEYS}
    cfg["password_error"] = False
    for k, v in saved.items():
        if k == "smtp_password":
            try:
                v = _fernet().decrypt(v.encode()).decode() if v else ""
            except InvalidToken:
                v, cfg["password_error"] = "", True
        cfg[k] = v
    cfg["smtp_port"] = int(cfg["smtp_port"] or 0)
    return cfg


def save_smtp_config(session, values, user=None, keep_password=True):
    """Saves the given SMTP settings. An empty password keeps the saved one when keep_password."""
    for k in SMTP_KEYS:
        if k not in values:
            continue
        v = (values[k] or "").strip()
        if k == "smtp_password":
            if not v and keep_password:
                continue
            v = _fernet().encrypt(v.encode()).decode() if v else ""
        row = session.get(Setting, k) or Setting(key=k)
        row.value, row.updated_by = v, user
        session.add(row)
    session.commit()


def reset_smtp_config(session):
    session.execute(delete(Setting).where(Setting.key.in_(SMTP_KEYS)))
    session.commit()


def _send(cfg, msg):
    if cfg["smtp_security"] == "ssl":
        conn = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=30)
    else:
        conn = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=30)
    with conn as smtp:
        if cfg["smtp_security"] == "starttls":
            smtp.starttls()
        if cfg["smtp_user"]:
            smtp.login(cfg["smtp_user"], cfg["smtp_password"])
        smtp.send_message(msg)


def send_test_email(session, to):
    cfg = smtp_config(session)
    msg = EmailMessage()
    msg["Subject"] = "Vuln Notify test email"
    msg["From"] = cfg["mail_from"]
    msg["To"] = to
    msg.set_content(
        f"This is a test email from Vuln Notify.\n\nServer: {cfg['smtp_host']}:{cfg['smtp_port']} "
        f"({cfg['smtp_security']})\nSender: {cfg['mail_from']}\n"
    )
    _send(cfg, msg)


EMAIL_TABLE_LIMIT = 200


def vulns_to_csv(vulns):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([h for h, _, _ in VULN_FIELDS])
    for v in vulns:
        w.writerow(["" if getattr(v, n) is None else getattr(v, n) for _, n, _ in VULN_FIELDS])
    return buf.getvalue()


def send_app_notification(session, app, vulns, severity_counts):
    cfg = smtp_config(session)
    recipients = app.recipients()
    if not recipients:
        raise ValueError(f"App {app.app_id} has no owner email or notification list.")

    today = date.today()
    overdue = sum(1 for v in vulns if v.slo_date and v.slo_date < today)

    msg = EmailMessage()
    msg["Subject"] = f"[Action required] {len(vulns)} open vulnerabilities for {app.app_id}" + (
        f" ({app.app_name})" if app.app_name else ""
    )
    msg["From"] = cfg["mail_from"]
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

    _send(cfg, msg)
    return recipients
