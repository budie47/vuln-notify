import io
import os
from datetime import date, datetime, timedelta

from flask import Flask, Response, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError

from . import importer, mailer
from .models import (
    NOT_SEEN_DAYS, VULN_FIELDS, Application, ImportRun, NotificationLog, SessionLocal,
    StagedVulnerability, UploadLog, Vulnerability, engine, init_db,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB uploads

SEVERITIES = ["critical", "high", "medium", "low"]
PAGE_SIZES = ["10", "25", "50", "100", "all"]
DEFAULT_PAGE_SIZE = "25"
VULN_FILTER_ARGS = ("q", "status", "severity", "env", "slo", "exception")
APP_FILTER_ARGS = ("q", "show", "severity", "env", "slo", "exception", "notified")
APP_FORM_FIELDS = [
    "app_id", "app_name", "owner_name", "owner_email", "notification_emails",
    "business_service", "department", "description",
]

init_db()
# gunicorn --preload imports this module once and then forks workers; drop the connection used by
# init_db so workers never share a database socket.
engine.dispose()


@app.teardown_appcontext
def remove_session(exc=None):
    SessionLocal.remove()


@app.template_filter("fmt_dt")
def fmt_dt(value, fmt="%Y-%m-%d %H:%M"):
    return value.strftime(fmt) if value else ""


# ---------------------------------------------------------------- queries

IS_OPEN = Vulnerability.status == "open"
IS_REMEDIATED = Vulnerability.status == "remediated"


def not_seen_cutoff():
    return datetime.utcnow() - timedelta(days=NOT_SEEN_DAYS)


def not_seen_cond():
    """Open, but its asset has had no newer scan for NOT_SEEN_DAYS (image retired, scan failing...)."""
    return and_(IS_OPEN, func.coalesce(Vulnerability.last_scan, Vulnerability.last_seen_at) < not_seen_cutoff())


@app.context_processor
def inject_globals():
    draft = SessionLocal.scalar(select(ImportRun).where(ImportRun.status == "draft"))
    return {"draft_run": draft, "not_seen_days": NOT_SEEN_DAYS}


def severity_summary(where=None):
    """Per-App-ID counts of OPEN vulnerabilities: total, per severity, overdue (past SLO),
    not seen recently, last scan."""
    sev = func.lower(Vulnerability.severity)
    cols = [
        Vulnerability.app_id,
        func.count().label("total"),
        *[func.count().filter(sev == s).label(s) for s in SEVERITIES],
        func.count().filter(Vulnerability.slo_date < date.today()).label("overdue"),
        func.count().filter(not_seen_cond()).label("not_seen"),
        func.max(Vulnerability.last_scan).label("last_scan"),
    ]
    q = select(*cols).where(IS_OPEN).group_by(Vulnerability.app_id)
    if where is not None:
        q = q.where(where)
    return {r.app_id: r._asdict() for r in SessionLocal.execute(q)}


def paginate(total):
    """Reads per_page/page from the request and returns paging info for `total` rows."""
    per_page = request.args.get("per_page", DEFAULT_PAGE_SIZE)
    if per_page not in PAGE_SIZES:
        per_page = DEFAULT_PAGE_SIZE
    size = total if per_page == "all" else int(per_page)
    pages = max(1, -(-total // size)) if size else 1
    page = min(max(request.args.get("page", 1, type=int), 1), pages)
    offset = (page - 1) * size
    return dict(per_page=per_page, page=page, pages=pages, offset=offset, limit=size, total=total,
                first=offset + 1 if total else 0, last=min(offset + size, total), sizes=PAGE_SIZES)


def remediated_counts(where=None):
    """Per-App-ID number of remediated vulnerabilities."""
    q = select(Vulnerability.app_id, func.count()).where(IS_REMEDIATED).group_by(Vulnerability.app_id)
    if where is not None:
        q = q.where(where)
    return dict(SessionLocal.execute(q).all())


EMPTY_COUNTS = {"total": 0, "overdue": 0, "not_seen": 0, **{x: 0 for x in SEVERITIES}}


def get_app_or_404(app_id):
    a = SessionLocal.scalar(select(Application).where(Application.app_id == app_id))
    if not a:
        abort(404)
    return a


# A vulnerability counts as excepted unless its Exception value is blank or a "no".
HAS_EXCEPTION = func.lower(func.trim(func.coalesce(Vulnerability.exception, ""))).notin_(
    ["", "no", "n", "false", "0"])


def vuln_query(app_id, filters=None):
    """Select for one App ID's vulnerabilities, sorted by severity then SLO date.

    `filters` is a dict using the VULN_FILTER_ARGS keys (typically request.args). Only open
    vulnerabilities are returned unless filters["status"] asks for others.
    """
    f = filters or {}
    sev_rank = func.array_position(SEVERITIES, func.lower(Vulnerability.severity))
    q = select(Vulnerability).where(Vulnerability.app_id == app_id)
    status = f.get("status") or "open"
    if status == "remediated":
        q = q.where(IS_REMEDIATED)
    elif status == "not_seen":
        q = q.where(not_seen_cond())
    elif status != "all":
        q = q.where(IS_OPEN)

    term = (f.get("q") or "").strip()
    if term:
        like = f"%{term}%"
        q = q.where(or_(*[col.ilike(like) for col in (
            Vulnerability.cve_id, Vulnerability.cve_description, Vulnerability.package,
            Vulnerability.current_version, Vulnerability.recommended_version, Vulnerability.image,
            Vulnerability.image_tag, Vulnerability.asset_id, Vulnerability.alert_id,
            Vulnerability.cluster, Vulnerability.namespace, Vulnerability.exception_ritm,
        )]))
    if f.get("severity"):
        if f["severity"] == "unknown":
            q = q.where(or_(Vulnerability.severity.is_(None),
                            func.lower(Vulnerability.severity).notin_(SEVERITIES)))
        else:
            q = q.where(func.lower(Vulnerability.severity) == f["severity"].lower())
    if f.get("env"):
        q = q.where(Vulnerability.environment.is_(None) if f["env"] == "(none)"
                    else Vulnerability.environment == f["env"])
    if f.get("slo") == "overdue":
        q = q.where(Vulnerability.slo_date < date.today())
    elif f.get("slo") == "within":
        q = q.where(or_(Vulnerability.slo_date.is_(None), Vulnerability.slo_date >= date.today()))
    if f.get("exception") == "yes":
        q = q.where(HAS_EXCEPTION)
    elif f.get("exception") == "no":
        q = q.where(~HAS_EXCEPTION)
    if status == "remediated":
        return q.order_by(Vulnerability.remediated_at.desc(), sev_rank.nulls_last(), Vulnerability.cve_id)
    return q.order_by(sev_rank.nulls_last(), Vulnerability.slo_date.nulls_last(), Vulnerability.cve_id)


def vulns_for(app_id, filters=None):
    return SessionLocal.scalars(vuln_query(app_id, filters)).all()


# ---------------------------------------------------------------- dashboard

@app.route("/")
def dashboard():
    s = SessionLocal
    today = date.today()
    total_vulns = s.scalar(select(func.count()).select_from(Vulnerability).where(IS_OPEN)) or 0
    registered = set(s.scalars(select(Application.app_id)).all())
    summary = severity_summary()
    vuln_apps = {k for k in summary if k}

    sev_label = func.coalesce(func.initcap(Vulnerability.severity), "Unknown")
    sev_rows = s.execute(select(sev_label, func.count()).where(IS_OPEN).group_by(sev_label)).all()
    order = {name.title(): i for i, name in enumerate(SEVERITIES)}
    sev_rows = sorted(sev_rows, key=lambda r: order.get(r[0], 99))

    env_label = func.coalesce(Vulnerability.environment, "Unknown")
    env_rows = s.execute(
        select(env_label, func.count()).where(IS_OPEN).group_by(env_label)
        .order_by(func.count().desc()).limit(8)
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
            select(func.count()).select_from(Vulnerability).where(IS_OPEN, HAS_EXCEPTION)
        ) or 0,
        not_seen=sum(r["not_seen"] for r in summary.values()),
        notifications_sent=s.scalar(
            select(func.count()).select_from(NotificationLog).where(NotificationLog.status == "sent")
        ) or 0,
    )
    # Remediation: days from opened (scanner's Alert Opened, else first upload) to remediated.
    since = datetime.utcnow() - timedelta(days=30)
    opened = func.coalesce(Vulnerability.alert_opened, Vulnerability.first_seen_at)
    days_to_fix = func.extract("epoch", Vulnerability.remediated_at - opened) / 86400
    rem = s.execute(
        select(func.count(), func.count().filter(Vulnerability.remediated_at >= since), func.avg(days_to_fix))
        .where(IS_REMEDIATED)
    ).one()
    stats.update(remediated_total=rem[0], remediated_30d=rem[1],
                 avg_days_to_fix=round(rem[2]) if rem[2] is not None else None)
    rem_sev = dict(s.execute(
        select(sev_label, func.count()).where(IS_REMEDIATED, Vulnerability.remediated_at >= since)
        .group_by(sev_label)
    ).all())

    last_run = s.scalar(select(ImportRun).where(ImportRun.status == "finalized")
                        .order_by(ImportRun.finalized_at.desc()).limit(1))
    last_upload = None if last_run else s.scalar(select(UploadLog).order_by(UploadLog.id.desc()).limit(1))
    return render_template(
        "dashboard.html", stats=stats, rem_sev=rem_sev, last_run=last_run, sev_rows=sev_rows, env_rows=env_rows,
        top_apps=top_apps, registered=registered, last_upload=last_upload, today=today,
    )


# ---------------------------------------------------------------- applications

@app.route("/apps")
def apps_list():
    s = SessionLocal
    f = {k: request.args.get(k, "").strip() for k in APP_FILTER_ARGS}
    if f["show"] == "all":  # old links used show=all
        f["show"] = ""

    # Environment and exception narrow which vulnerabilities are counted for each app.
    scope = []
    if f["env"]:
        scope.append(Vulnerability.environment.is_(None) if f["env"] == "(none)"
                     else Vulnerability.environment == f["env"])
    if f["exception"] == "yes":
        scope.append(HAS_EXCEPTION)
    elif f["exception"] == "no":
        scope.append(~HAS_EXCEPTION)
    summary = severity_summary(and_(*scope) if scope else None)
    all_totals = {k: v["total"] for k, v in severity_summary().items()} if scope else None
    remediated = remediated_counts(and_(*scope) if scope else None)

    apps = {a.app_id: a for a in s.scalars(select(Application)).all()}
    last_notified = dict(s.execute(
        select(NotificationLog.app_id, func.max(NotificationLog.sent_at))
        .where(NotificationLog.status == "sent").group_by(NotificationLog.app_id)
    ).all())
    env_label = func.coalesce(Vulnerability.environment, "(none)")
    environments = s.scalars(select(env_label).distinct().order_by(env_label)).all()

    q = f["q"].lower()
    empty = EMPTY_COUNTS
    # Apps whose findings are all remediated stay listed (with 0 open).
    candidates = set(apps) | {k for k in (all_totals if scope else summary) if k} \
        | {k for k in remediated_counts() if k}
    rows = []
    for app_id in sorted(candidates, key=str.lower):
        a = apps.get(app_id)
        counts = summary.get(app_id) or empty
        if scope and not counts["total"] and not remediated.get(app_id):
            continue
        if f["show"] == "registered" and not a:
            continue
        if f["show"] == "unregistered" and a:
            continue
        if f["show"] == "with_vulns" and not counts["total"]:
            continue
        if f["show"] == "all_fixed" and (counts["total"] or not remediated.get(app_id)):
            continue
        if f["show"] == "not_seen" and not counts["not_seen"]:
            continue
        if f["show"] == "no_email" and (not a or a.recipients()):
            continue
        if f["severity"] in SEVERITIES and not counts[f["severity"]]:
            continue
        if f["slo"] == "overdue" and not counts["overdue"]:
            continue
        if f["slo"] == "within" and counts["overdue"]:
            continue
        if f["notified"] == "yes" and app_id not in last_notified:
            continue
        if f["notified"] == "no" and app_id in last_notified:
            continue
        if q:
            haystack = [app_id] + ([a.app_name, a.owner_name, a.owner_email, a.notification_emails,
                                    a.business_service, a.department] if a else [])
            if q not in " ".join(filter(None, haystack)).lower():
                continue
        rows.append(dict(app_id=app_id, app=a, counts=counts, last_notified=last_notified.get(app_id),
                         remediated=remediated.get(app_id, 0),
                         all_total=all_totals.get(app_id, 0) if scope else None))

    pg = paginate(len(rows))
    active = {k: v for k, v in f.items() if v}
    unassigned = (summary.get(None) or {}).get("total", 0)
    return render_template(
        "apps_list.html", rows=rows[pg["offset"]:pg["offset"] + pg["limit"]], filters=f, active=active,
        severities=SEVERITIES, environments=environments, unassigned=unassigned, pg=pg,
        unfiltered=len(candidates), scoped=bool(scope),
    )


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
    s = SessionLocal
    a = s.scalar(select(Application).where(Application.app_id == app_id))
    counts = severity_summary(Vulnerability.app_id == app_id).get(app_id)
    remediated = remediated_counts(Vulnerability.app_id == app_id).get(app_id, 0)
    if not a and not counts and not remediated:
        abort(404)
    open_total = counts["total"] if counts else 0

    filters = {k: request.args.get(k, "").strip() for k in VULN_FILTER_ARGS}
    q = vuln_query(app_id, filters)
    pg = paginate(s.scalar(select(func.count()).select_from(q.order_by(None).subquery())) or 0)
    vulns = s.scalars(q.offset(pg["offset"]).limit(pg["limit"])).all() if pg["total"] else []

    env_label = func.coalesce(Vulnerability.environment, "(none)")
    environments = s.scalars(
        select(env_label).where(Vulnerability.app_id == app_id).distinct().order_by(env_label)
    ).all()
    logs = s.scalars(
        select(NotificationLog).where(NotificationLog.app_id == app_id)
        .order_by(NotificationLog.sent_at.desc()).limit(10)
    ).all()
    active = {k: v for k, v in filters.items() if v}
    return render_template(
        "app_detail.html", a=a, app_id=app_id, vulns=vulns, counts=counts, logs=logs,
        severities=SEVERITIES, today=date.today(), filters=filters, active=active,
        environments=environments, pg=pg, per_page=pg["per_page"], remediated=remediated,
        unfiltered={"all": open_total + remediated, "remediated": remediated,
                    "not_seen": counts["not_seen"] if counts else 0}.get(filters["status"], open_total),
    )


@app.route("/apps/<app_id>/export.csv")
def app_export(app_id):
    data = mailer.vulns_to_csv(vulns_for(app_id, request.args))
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
    """Files are added to the draft import run; nothing goes live until the run is finalized."""
    s = SessionLocal
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Choose a CSV or Excel file to upload.", "warning")
            return redirect(url_for("upload"))
        try:
            run = importer.get_or_create_draft(s)
            log = importer.stage_file(s, run, f.read(), f.filename)
            flash(f"{f.filename}: {log.rows_loaded} of {log.rows_read} rows added to import #{run.id}"
                  + (f" — {log.rows_rejected} rejected." if log.rows_rejected else ".")
                  + " Add more files, or review and finalize when all batches are in.",
                  "success" if not log.rows_rejected else "warning")
            return redirect(url_for("run_detail", run_id=run.id))
        except Exception as e:  # noqa: BLE001
            s.rollback()
            flash(f"Upload failed: {e}", "danger")
            return redirect(url_for("upload"))
    runs = s.scalars(select(ImportRun).where(ImportRun.status != "draft")
                     .order_by(ImportRun.id.desc()).limit(20)).all()
    file_counts = dict(s.execute(select(UploadLog.run_id, func.count()).group_by(UploadLog.run_id)).all())
    legacy = s.scalars(select(UploadLog).where(UploadLog.run_id.is_(None))
                       .order_by(UploadLog.id.desc()).limit(20)).all()
    return render_template("upload.html", runs=runs, file_counts=file_counts, legacy=legacy,
                           headers=[h for h, _, _ in VULN_FIELDS],
                           accept=",".join(importer.SUPPORTED_EXTENSIONS))


@app.route("/runs/<int:run_id>")
def run_detail(run_id):
    s = SessionLocal
    run = s.get(ImportRun, run_id) or abort(404)
    files = s.scalars(select(UploadLog).where(UploadLog.run_id == run_id).order_by(UploadLog.id)).all()
    staged_by_file = dict(s.execute(
        select(StagedVulnerability.upload_id, func.count()).where(StagedVulnerability.run_id == run_id)
        .group_by(StagedVulnerability.upload_id)
    ).all())
    preview = importer.preview_run(s, run) if run.status == "draft" else None
    remediated = s.scalars(
        select(Vulnerability).where(Vulnerability.remediated_run_id == run_id)
        .order_by(Vulnerability.app_id, Vulnerability.asset_id, Vulnerability.cve_id).limit(200)
    ).all() if run.status == "finalized" else []
    return render_template("run_detail.html", run=run, files=files, staged_by_file=staged_by_file,
                           preview=preview, remediated=remediated,
                           accept=",".join(importer.SUPPORTED_EXTENSIONS))


@app.route("/runs/<int:run_id>/finalize", methods=["POST"])
def run_finalize(run_id):
    s = SessionLocal
    run = s.get(ImportRun, run_id) or abort(404)
    try:
        importer.finalize_run(s, run)
        flash(f"Import #{run.id} finalized: {run.rows_new} new, {run.rows_updated} updated, "
              f"{run.rows_reopened} reopened, {run.rows_remediated} marked remediated"
              + (f", {run.rows_skipped} older rows skipped." if run.rows_skipped else "."), "success")
    except Exception as e:  # noqa: BLE001
        s.rollback()
        flash(f"Finalize failed: {e}", "danger")
    return redirect(url_for("run_detail", run_id=run_id))


@app.route("/runs/<int:run_id>/discard", methods=["POST"])
def run_discard(run_id):
    s = SessionLocal
    run = s.get(ImportRun, run_id) or abort(404)
    try:
        importer.discard_run(s, run)
        flash(f"Import #{run.id} discarded. No data was changed.", "success")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("upload"))


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
