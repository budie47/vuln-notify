"""Register a few demo applications: docker compose exec app python -m app.seed"""
from sqlalchemy import select

from .models import Application, SessionLocal, init_db

DEMO = [
    ("APP-1001", "Payments API", "Alice Tan", "alice.tan@example.com", "payments-dl@example.com"),
    ("APP-1002", "Customer Portal", "Ben Lee", "ben.lee@example.com", "portal-team@example.com; secops@example.com"),
    ("APP-1003", "HR Self Service", "Chitra Rao", "chitra.rao@example.com", ""),
    ("APP-1004", "Data Lake Ingest", "Dan Ong", "dan.ong@example.com", "data-eng@example.com"),
    ("APP-1005", "Audit Workpapers", "Eva Lim", "eva.lim@example.com", ""),
]

if __name__ == "__main__":
    init_db()
    s = SessionLocal()
    for app_id, name, owner, email, extra in DEMO:
        if not s.scalar(select(Application).where(Application.app_id == app_id)):
            s.add(Application(app_id=app_id, app_name=name, owner_name=owner, owner_email=email, notification_emails=extra))
    s.commit()
    print("seeded demo applications")
