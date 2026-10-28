import os
from datetime import datetime

from sqlalchemy import (
    Column, Date, DateTime, Integer, String, Text, create_engine, Index, UniqueConstraint, text,
)
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

# An open vulnerability whose asset has had no new scan for this many days is "not seen recently".
NOT_SEEN_DAYS = int(os.environ.get("NOT_SEEN_DAYS", "90"))

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg2://vulnnotify:vulnnotify@localhost:5432/vulnnotify"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, future=True))
Base = declarative_base()

# (CSV header, column name, type). Order here is the order used for CSV export and email attachments.
VULN_FIELDS = [
    ("CSB ID", "csb_id", "str"),
    ("Alert ID", "alert_id", "str"),
    ("Last Scan", "last_scan", "datetime"),
    ("Severity", "severity", "str"),
    ("Alert Opened", "alert_opened", "datetime"),
    ("Days Open", "days_open", "int"),
    ("SLO Date", "slo_date", "date"),
    ("Exception", "exception", "str"),
    ("Exception RITM", "exception_ritm", "str"),
    ("Account ID", "account_id", "str"),
    ("Account Name", "account_name", "str"),
    ("Provider", "provider", "str"),
    ("Environment", "environment", "str"),
    ("Asset ID", "asset_id", "str"),
    ("Asset Type", "asset_type", "str"),
    ("CVE ID", "cve_id", "str"),
    ("CVE Description", "cve_description", "text"),
    ("CVE Link", "cve_link", "text"),
    ("Cluster", "cluster", "str"),
    ("Namespace", "namespace", "str"),
    ("Instance", "instance", "str"),
    ("Repository", "repository", "str"),
    ("Registry", "registry", "str"),
    ("Image", "image", "text"),
    ("Image Tag", "image_tag", "str"),
    ("Image Created", "image_created", "datetime"),
    ("Package", "package", "str"),
    ("Current Version", "current_version", "str"),
    ("Recommended Version", "recommended_version", "str"),
    ("Package Path", "package_path", "text"),
    ("Layer ID", "layer_id", "str"),
    ("Layer Instruction", "layer_instruction", "text"),
    ("OS", "os", "str"),
    ("OS Version", "os_version", "str"),
    ("OS End of Life", "os_end_of_life", "str"),
    ("Participating Firm", "participating_firm", "str"),
    ("Country", "country", "str"),
    ("CMS", "cms", "str"),
    ("Function", "function", "str"),
    ("App ID", "app_id", "str"),
    ("App Service", "app_service", "str"),
    ("Business Service", "business_service", "str"),
    ("Department", "department", "str"),
    ("Service Line", "service_line", "str"),
    ("Data Classification", "data_classification", "str"),
    ("Data Qualification", "data_qualification", "str"),
]

_SQL_TYPES = {
    "str": lambda: String(512),
    "text": lambda: Text(),
    "int": lambda: Integer(),
    "date": lambda: Date(),
    "datetime": lambda: DateTime(),
}

_vuln_attrs = {
    "__tablename__": "vulnerabilities",
    "id": Column(Integer, primary_key=True),
    "uploaded_at": Column(DateTime, default=datetime.utcnow, nullable=False),
    # Upload (file) and import run that last supplied this alert.
    "upload_id": Column(Integer, index=True),
    "run_id": Column(Integer),
    # Lifecycle. "open" until a finalized import run shows the same asset scanned more recently
    # without this alert; then "remediated". Found again in a newer scan -> open, reopened_at set.
    "status": Column(String(16), nullable=False, default="open", server_default="open"),
    "first_seen_at": Column(DateTime, default=datetime.utcnow),
    "last_seen_at": Column(DateTime, default=datetime.utcnow),
    "remediated_at": Column(DateTime),
    "remediated_run_id": Column(Integer),
    "reopened_at": Column(DateTime),
}
for _header, _name, _kind in VULN_FIELDS:
    _vuln_attrs[_name] = Column(_SQL_TYPES[_kind]())
_vuln_attrs["alert_id"] = Column(String(512), unique=True, nullable=False)
_vuln_attrs["__table_args__"] = (
    Index("ix_vuln_app_id", "app_id"),
    Index("ix_vuln_severity", "severity"),
    Index("ix_vuln_status", "status"),
    Index("ix_vuln_asset_id", "asset_id"),
)

Vulnerability = type("Vulnerability", (Base,), _vuln_attrs)

# Rows of a draft import run, held here until the run is finalized (or discarded).
_staged_attrs = {
    "__tablename__": "staged_vulnerabilities",
    "id": Column(Integer, primary_key=True),
    "run_id": Column(Integer, nullable=False),
    "upload_id": Column(Integer, nullable=False),
    "line_no": Column(Integer),
}
for _header, _name, _kind in VULN_FIELDS:
    _staged_attrs[_name] = Column(_SQL_TYPES[_kind]())
_staged_attrs["alert_id"] = Column(String(512), nullable=False)
_staged_attrs["__table_args__"] = (
    UniqueConstraint("run_id", "alert_id", name="uq_staged_run_alert"),
    Index("ix_staged_run_asset", "run_id", "asset_id"),
)
StagedVulnerability = type("StagedVulnerability", (Base,), _staged_attrs)


class ImportRun(Base):
    """A set of uploaded files applied together. status: draft -> finalized | discarded."""
    __tablename__ = "import_runs"

    id = Column(Integer, primary_key=True)
    status = Column(String(16), nullable=False, default="draft")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    finalized_at = Column(DateTime)
    rows_new = Column(Integer, default=0)
    rows_updated = Column(Integer, default=0)
    rows_reopened = Column(Integer, default=0)
    rows_skipped = Column(Integer, default=0)   # older than what is already stored
    rows_remediated = Column(Integer, default=0)
    assets_scanned = Column(Integer, default=0)

    __table_args__ = (
        # At most one draft at a time.
        Index("uq_one_draft_run", "status", unique=True, postgresql_where=text("status = 'draft'")),
    )


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True)
    app_id = Column(String(128), unique=True, nullable=False)
    app_name = Column(String(256))
    owner_name = Column(String(256))
    owner_email = Column(String(256))
    # Additional recipients, separated by commas / semicolons / newlines.
    notification_emails = Column(Text)
    business_service = Column(String(256))
    department = Column(String(256))
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def recipients(self):
        import re
        emails = [self.owner_email or ""] + re.split(r"[,;\s]+", self.notification_emails or "")
        seen, out = set(), []
        for e in (x.strip() for x in emails):
            if e and e.lower() not in seen:
                seen.add(e.lower())
                out.append(e)
        return out


class UploadLog(Base):
    __tablename__ = "upload_logs"

    id = Column(Integer, primary_key=True)
    filename = Column(String(512))
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    mode = Column(String(32))
    run_id = Column(Integer, index=True)
    rows_read = Column(Integer, default=0)
    rows_loaded = Column(Integer, default=0)
    rows_rejected = Column(Integer, default=0)
    errors = Column(Text)


class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id = Column(Integer, primary_key=True)
    app_id = Column(String(128), index=True)
    recipients = Column(Text)
    vuln_count = Column(Integer)
    status = Column(String(32))  # sent / failed
    error = Column(Text)
    sent_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# create_all only creates missing tables; columns added to existing tables are added here.
# Every statement is idempotent and runs on each start.
_MIGRATIONS = [
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS run_id integer",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS status varchar(16) NOT NULL DEFAULT 'open'",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS first_seen_at timestamp",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS last_seen_at timestamp",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediated_at timestamp",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediated_run_id integer",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS reopened_at timestamp",
    "UPDATE vulnerabilities SET first_seen_at = uploaded_at WHERE first_seen_at IS NULL",
    "UPDATE vulnerabilities SET last_seen_at = uploaded_at WHERE last_seen_at IS NULL",
    "CREATE INDEX IF NOT EXISTS ix_vuln_status ON vulnerabilities (status)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_asset_id ON vulnerabilities (asset_id)",
    "ALTER TABLE upload_logs ADD COLUMN IF NOT EXISTS run_id integer",
    "CREATE INDEX IF NOT EXISTS ix_upload_logs_run_id ON upload_logs (run_id)",
]


def init_db():
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        # Serialise concurrent starts (several workers / containers) on the same database.
        conn.execute(text("SELECT pg_advisory_xact_lock(724001)"))
        for stmt in _MIGRATIONS:
            conn.execute(text(stmt))
