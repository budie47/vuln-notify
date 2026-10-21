import os
from datetime import datetime

from sqlalchemy import (
    Column, Date, DateTime, Integer, String, Text, create_engine, Index,
)
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

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
    "upload_id": Column(Integer, index=True),
}
for _header, _name, _kind in VULN_FIELDS:
    _vuln_attrs[_name] = Column(_SQL_TYPES[_kind]())
_vuln_attrs["alert_id"] = Column(String(512), unique=True, nullable=False)
_vuln_attrs["__table_args__"] = (
    Index("ix_vuln_app_id", "app_id"),
    Index("ix_vuln_severity", "severity"),
)

Vulnerability = type("Vulnerability", (Base,), _vuln_attrs)


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


def init_db():
    Base.metadata.create_all(engine)
