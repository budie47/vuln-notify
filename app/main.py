import io
import os
from datetime import date

from flask import Flask, Response, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from . import importer, mailer
from .models import (
    VULN_FIELDS, Application, NotificationLog, SessionLocal, UploadLog, Vulnerability, init_db,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB uploads

SEVERITIES = ["critical", "high", "medium", "low"]
APP_FORM_FIELDS = [
    "app_id", "app_name", "owner_name", "owner_email", "notification_emails",
    "business_service", "department", "description",
]

init_db()


@app.teardown_appcontext
def remove_session(exc=None):
    SessionLocal.remove()


@app.template_filter("fmt_dt")
def fmt_dt(value, fmt="%Y-%m-%d %H:%M"):
    return value.strftime(fmt) if value else ""


# ---------------------------------------------------------------- queries

def severity_summary(where=None):
    """Per-App-ID counts: total, per severity, overdue (past SLO) and last scan."""
    sev = func.lower(Vulnerability.severity)
    cols = [
        Vulnerability.app_id,
        func.count().label("total"),
        *[func.count().filter(sev == s).label(s) for s in SEVERITIES],
        func.count().filter(Vulnerability.slo_date < date.today()).label("overdue"),
        func.max(Vulnerability.last_scan).label("last_scan"),
    ]
    q = select(*cols).group_by(Vulnerability.app_id)
    if where is not None:
        q = q.where(where)
    return {r.app_id: r._asdict() for r in SessionLocal.execute(q)}


def get_app_or_404(app_id):
    a = SessionLocal.scalar(select(Application).where(Application.app_id == app_id))
    if not a:
        abort(404)
    return a


def vulns_for(app_id):
    sev_rank = func.array_position(SEVERITIES, func.lower(Vulnerability.severity))
    return SessionLocal.scalars(
        select(Vulnerability).where(Vulnerability.app_id == app_id)
        .order_by(sev_rank.nulls_last(), Vulnerability.slo_date.nulls_last(), Vulnerability.cve_id)
    ).all()


# ---------------------------------------------------------------- dashboard

@app.route("/")
def dashboard():
    s = SessionLocal
    today = date.today()
    total_vulns = s.scalar(select(func.count()).select_from(Vulnerability)) or 0
    registered = set(s.scalars(select(Application.app_id)).all())
    summary = severity_summary()
    vuln_apps = {k for k in summary if k}

    sev_label = func.coalesce(func.initcap(Vulnerability.severity), "Unknown")
    sev_rows = s.execute(select(sev_label, func.count()).group_by(sev_label)).all()
    order = {name.title(): i for i, name in enumerate(SEVERITIES)}
    sev_rows = sorted(sev_rows, key=lambda r: order.get(r[0], 99))

    env_label = func.coalesce(Vulnerability.environment, "Unknown")
    env_rows = s.execute(
        select(env_label, func.count()).group_by(env_label).order_by(func.count().desc()).limit(8)
    ).all()

    top_apps = sorted(summary.values(), key=lambda r: r["total"], reverse=True)[:10]

    stats = dict(
        total_vulns=total_vulns,
        registered_apps=len(registered),
        apps_with_vulns=len(vuln_apps),
        covered_apps=len(vuln_apps & registered),
        unregistered_apps=len(vuln_apps - registered),
        critical_high=sum((r["critical"] + r["high"]) for r in summary.values()),
        overdue=sum(r["overdue"] for r in summary.values()),
        exceptions=s.scalar(
            select(func.count()).select_from(Vulnerability)
            .where(func.coalesce(Vulnerability.exception, "").notin_(["", "No", "no", "N", "False", "false"]))
        ) or 0,
        notifications_sent=s.scalar(
            select(func.count()).select_from(NotificationLog).where(NotificationLog.status == "sent")
        ) or 0,
    )
    last_upload = s.scalar(select(UploadLog).order_by(UploadLog.id.desc()).limit(1))
    return render_template(
        "dashboard.html", stats=stats, sev_rows=sev_rows, env_rows=env_rows,
        top_apps=top_apps, registered=registered, last_upload=last_upload, today=today,
    )


# ---------------------------------------------------------------- applications

@app.route("/apps")
def apps_list():
    q = (request.args.get("q") or "").strip().lower()
    show = request.args.get("show", "all")  # all / registered / unregistered / with_vulns
    summary = severity_summary()
    apps = {a.app_id: a for a in SessionLocal.scalars(select(Application)).all()}
    last_notified = dict(SessionLocal.execute(
        select(NotificationLog.app_id, func.max(NotificationLog.sent_at))
        .where(NotificationLog.status == "sent").group_by(NotificationLog.app_id)
    ).all())

    rows = []
    for app_id in sorted(set(apps) | {k for k in summary if k}, key=str.lower):
        a = apps.get(app_id)
        counts = summary.get(app_id) or {"total": 0, "overdue": 0, **{x: 0 for x in SEVERITIES}}
        if show == "registered" and not a:
            continue
        if show == "unregistered" and a:
            continue
        if show == "with_vulns" and not counts["total"]:
            continue
        if q and q not in app_id.lower() and not (a and q in " ".join(
            filter(None, [a.app_name, a.owner_name, a.owner_email, a.notification_emails])).lower()):
            continue
        rows.append(dict(app_id=app_id, app=a, counts=counts, last_notified=last_notified.get(app_id)))
    unassigned = (summary.get(None) or {}).get("total", 0)
    return render_template("apps_list.html", rows=rows, q=q, show=show, severities=SEVERITIES,
                           unassigned=unassigned)


def _app_from_form(a):
    for f in APP_FORM_FIELDS:
        val = (request.form.get(f) or "").strip() or None
        setattr(a, f, val)
    if not a.app_id:
        raise ValueError("App ID is required.")
    if not a.recipients():
        flash("No owner email / notification list set — notifications can't be sent until you add one.", "warning")


@app.route("/apps/new", methods=["GET", "POST"])
def app_new():
    a = Application(app_id=request.args.get("app_id"))
    if request.method == "POST":
        try:
            _app_from_form(a)
            SessionLocal.add(a)
            SessionLocal.commit()
            flash(f"App {a.app_id} created.", "success")
            return redirect(url_for("app_detail", app_id=a.app_id))
        except IntegrityError:
            SessionLocal.rollback()
            flash(f"App ID {a.app_id} already exists.", "danger")
        except ValueError as e:
            flash(str(e), "danger")
    if a.app_id and not request.method == "POST":
        # Pre-fill from vulnerability data for an unregistered App ID.
        v = SessionLocal.scalar(select(Vulnerability).where(Vulnerability.app_id == a.app_id).limit(1))
        if v:
            a.business_service, a.department = v.business_service, v.department
            a.app_name = v.app_service
    return render_template("app_form.html", a=a, is_new=True)


@app.route("/apps/<app_id>/edit", methods=["GET", "POST"])
def app_edit(app_id):
    a = get_app_or_404(app_id)
    if request.method == "POST":
        try:
            _app_from_form(a)
            SessionLocal.commit()
            flash(f"App {a.app_id} updated.", "success")
            return redirect(url_for("app_detail", app_id=a.app_id))
        except IntegrityError:
            SessionLocal.rollback()
            flash("That App ID is already used by another application.", "danger")
        except ValueError as e:
            flash(str(e), "danger")
    return render_template("app_form.html", a=a, is_new=False)


@app.route("/apps/<app_id>/delete", methods=["POST"])
def app_delete(app_id):
    a = get_app_or_404(app_id)
    SessionLocal.delete(a)
    SessionLocal.commit()
    flash(f"App {app_id} deleted. Its vulnerability records are kept.", "success")
    return redirect(url_for("apps_list"))


@app.route("/apps/<app_id>")
def app_detail(app_id):
    a = SessionLocal.scalar(select(Application).where(Application.app_id == app_id))
    vulns = vulns_for(app_id)
    if not a and not vulns:
        abort(404)
    counts = severity_summary(Vulnerability.app_id == app_id).get(app_id)
    logs = SessionLocal.scalars(
        select(NotificationLog).where(NotificationLog.app_id == app_id)
        .order_by(NotificationLog.sent_at.desc()).limit(10)
    ).all()
    return render_template("app_detail.html", a=a, app_id=app_id, vulns=vulns, counts=counts,
                           logs=logs, severities=SEVERITIES, today=date.today())


@app.route("/apps/<app_id>/export.csv")
def app_export(app_id):
    data = mailer.vulns_to_csv(vulns_for(app_id))
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=vulnerabilities_{app_id}.csv"})


# ---------------------------------------------------------------- notifications

def notify_app(app_id):
    """Send one notification. Returns (ok, message)."""
    a = SessionLocal.scalar(select(Application).where(Application.app_id == app_id))
    if not a:
        return False, f"{app_id}: not registered — add the app and its owner email first."
    vulns = vulns_for(app_id)
    if not vulns:
        return False, f"{app_id}: no vulnerabilities to report."
    counts = severity_summary(Vulnerability.app_id == app_id).get(app_id)
    log = NotificationLog(app_id=app_id, vuln_count=len(vulns), recipients=", ".join(a.recipients()))
    try:
        mailer.send_app_notification(a, vulns, counts)
        log.status = "sent"
        msg = f"{app_id}: email sent to {log.recipients} ({len(vulns)} vulnerabilities)."
    except Exception as e:  # noqa: BLE001 — record any SMTP/config failure in the log
        log.status, log.error = "failed", str(e)
        msg = f"{app_id}: sending failed — {e}"
    SessionLocal.add(log)
    SessionLocal.commit()
    return log.status == "sent", msg


@app.route("/apps/<app_id>/notify", methods=["POST"])
def app_notify(app_id):
    ok, msg = notify_app(app_id)
    flash(msg, "success" if ok else "danger")
    return redirect(request.form.get("next") or url_for("apps_list"))


@app.route("/apps/notify-bulk", methods=["POST"])
def apps_notify_bulk():
    app_ids = request.form.getlist("app_ids")
    if not app_ids:
        flash("Select at least one application.", "warning")
        return redirect(url_for("apps_list"))
    results = [notify_app(x) for x in app_ids]
    sent = sum(ok for ok, _ in results)
    flash(f"Sent {sent} of {len(results)} notifications.", "success" if sent == len(results) else "warning")
    for ok, msg in results:
        if not ok:
            flash(msg, "danger")
    return redirect(url_for("apps_list"))


@app.route("/notifications")
def notifications():
    logs = SessionLocal.scalars(select(NotificationLog).order_by(NotificationLog.sent_at.desc()).limit(500)).all()
    return render_template("notifications.html", logs=logs)


# ---------------------------------------------------------------- upload

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Choose a CSV or Excel file to upload.", "warning")
        else:
            try:
                log = importer.load_file(SessionLocal, f.read(), f.filename,
                                        replace=request.form.get("mode") == "replace")
                flash(f"Loaded {log.rows_loaded} of {log.rows_read} rows from {f.filename}"
                      + (f" — {log.rows_rejected} rejected." if log.rows_rejected else "."),
                      "success" if not log.rows_rejected else "warning")
            except Exception as e:  # noqa: BLE001
                SessionLocal.rollback()
                flash(f"Upload failed: {e}", "danger")
        return redirect(url_for("upload"))
    logs = SessionLocal.scalars(select(UploadLog).order_by(UploadLog.id.desc()).limit(20)).all()
    return render_template("upload.html", logs=logs, headers=[h for h, _, _ in VULN_FIELDS],
                           accept=",".join(importer.SUPPORTED_EXTENSIONS))


@app.route("/upload/template.csv")
def upload_template():
    return Response(",".join(h for h, _, _ in VULN_FIELDS) + "\n", mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=vulnerability_template.csv"})


@app.route("/upload/template.xlsx")
def upload_template_xlsx():
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"
    ws.append([h for h, _, _ in VULN_FIELDS])
    for cell in ws[1]:
        cell.font = Font(bold=True)
    ws.freeze_panes = "A2"
    buf = io.BytesIO()
    wb.save(buf)
    return Response(buf.getvalue(),
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment; filename=vulnerability_template.xlsx"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
