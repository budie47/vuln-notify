"""CSV / Excel -> vulnerabilities table loader."""
import csv
import io
import re
from datetime import date, datetime

from openpyxl import load_workbook

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


EXCEL_EXTENSIONS = (".xlsx", ".xlsm")
SUPPORTED_EXTENSIONS = (".csv",) + EXCEL_EXTENSIONS


def _convert(value, kind):
    # Excel cells arrive already typed (datetime, int, float); CSV cells are strings.
    if isinstance(value, datetime):
        return value.date() if kind == "date" else value.replace(tzinfo=None) if kind == "datetime" else value.isoformat(" ")
    if isinstance(value, date):
        return value if kind in ("date", "datetime") else value.isoformat()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if kind == "int":
            return int(value)
        value = str(int(value)) if float(value).is_integer() else str(value)
    value = ("" if value is None else str(value)).strip()
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


def _read_csv(file_bytes):
    """Returns (headers, iterator of (line number, row dict))."""
    reader = csv.DictReader(io.StringIO(file_bytes.decode("utf-8-sig", errors="replace")))
    return reader.fieldnames, enumerate(reader, start=2)


def _read_excel(file_bytes):
    """Reads the first worksheet; the first non-empty row is the header row."""
    wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
    rows = wb.worksheets[0].iter_rows(values_only=True)
    headers, header_line = None, 0
    for header_line, values in enumerate(rows, start=1):
        if any(v not in (None, "") for v in values):
            headers = [str(v).strip() if v is not None else "" for v in values]
            break

    def body():
        for line_no, values in enumerate(rows, start=header_line + 1):
            if any(v not in (None, "") for v in values):
                yield line_no, dict(zip(headers, values))
        wb.close()

    return headers, body()


def load_file(session, file_bytes, filename, replace=False):
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == ".csv":
        headers, rows = _read_csv(file_bytes)
    elif ext in EXCEL_EXTENSIONS:
        try:
            headers, rows = _read_excel(file_bytes)
        except Exception as e:  # noqa: BLE001 — corrupt / password-protected workbooks
            raise ValueError(f"Could not read Excel file: {e}") from e
    elif ext == ".xls":
        raise ValueError("Old .xls files are not supported — save the file as .xlsx and upload again.")
    else:
        raise ValueError(f"Unsupported file type '{ext or filename}'. Upload a .csv or .xlsx file.")
    if not headers:
        raise ValueError("File has no header row.")

    mapping = {h: HEADER_MAP[_norm(h)] for h in headers if h and _norm(h) in HEADER_MAP}
    if not any(col == "alert_id" for col, _ in mapping.values()):
        raise ValueError("File must contain an 'Alert ID' column.")
    if not any(col == "app_id" for col, _ in mapping.values()):
        raise ValueError("File must contain an 'App ID' column.")

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
    for line_no, raw in rows:
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
