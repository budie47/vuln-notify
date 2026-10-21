"""CSV -> vulnerabilities table loader."""
import csv
import io
import re

from dateutil import parser as dateparser
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert

from .models import VULN_FIELDS, UploadLog, Vulnerability

BATCH_SIZE = 1000


def _norm(header):
    return re.sub(r"[^a-z0-9]", "", (header or "").lower())


# Normalised header -> (column, kind). Also accepts the "Enviroment" spelling.
HEADER_MAP = {_norm(h): (name, kind) for h, name, kind in VULN_FIELDS}
HEADER_MAP["enviroment"] = ("environment", "str")


def _convert(value, kind):
    value = (value or "").strip()
    if value == "" or value.lower() in ("null", "none", "n/a", "-"):
        return None
    if kind == "int":
        return int(float(value.replace(",", "")))
    if kind == "date":
        return dateparser.parse(value).date()
    if kind == "datetime":
        return dateparser.parse(value).replace(tzinfo=None)
    if kind == "str":
        return value[:512]
    return value


def load_csv(session, file_bytes, filename, replace=False):
    text = file_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV file has no header row.")

    mapping = {h: HEADER_MAP[_norm(h)] for h in reader.fieldnames if _norm(h) in HEADER_MAP}
    if not any(col == "alert_id" for col, _ in mapping.values()):
        raise ValueError("CSV must contain an 'Alert ID' column.")
    if not any(col == "app_id" for col, _ in mapping.values()):
        raise ValueError("CSV must contain an 'App ID' column.")

    log = UploadLog(filename=filename, mode="replace" if replace else "upsert")
    session.add(log)
    session.flush()

    if replace:
        session.execute(delete(Vulnerability))

    errors, batch, seen = [], {}, 0
    loaded = rejected = 0

    def flush_batch():
        nonlocal loaded
        if not batch:
            return
        rows = list(batch.values())
        stmt = insert(Vulnerability.__table__).values(rows)
        update_cols = {c: stmt.excluded[c] for c in rows[0] if c != "alert_id"}
        session.execute(stmt.on_conflict_do_update(index_elements=["alert_id"], set_=update_cols))
        loaded += len(rows)
        batch.clear()

    all_cols = {name for _, name, _ in VULN_FIELDS}
    for line_no, raw in enumerate(reader, start=2):
        seen += 1
        row, row_err = {c: None for c in all_cols}, None
        for header, (col, kind) in mapping.items():
            try:
                row[col] = _convert(raw.get(header), kind)
            except (ValueError, OverflowError):
                row_err = f"line {line_no}: bad value for '{header}': {raw.get(header)!r}"
                break
        if not row_err and not row["alert_id"]:
            row_err = f"line {line_no}: missing Alert ID"
        if row_err:
            rejected += 1
            if len(errors) < 50:
                errors.append(row_err)
            continue
        row["upload_id"] = log.id
        # Last occurrence wins when the same Alert ID appears twice in one batch.
        batch[row["alert_id"]] = row
        if len(batch) >= BATCH_SIZE:
            flush_batch()
    flush_batch()

    log.rows_read = seen
    log.rows_loaded = loaded
    log.rows_rejected = rejected
    log.errors = "\n".join(errors) or None
    session.commit()
    return log
