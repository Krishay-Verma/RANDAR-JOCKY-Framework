"""
SQLite persistence for JOCKY investigations.

One row per investigation. The full report is stored as an immutable JSON
document (evidence integrity: it is never rewritten after creation). Case
metadata an analyst may change - display name, status, notes - lives in
separate columns, so editing a case never alters collected evidence.

Schema migrations are additive and idempotent (`ALTER TABLE ADD COLUMN`),
so databases created by earlier versions upgrade in place.
"""

import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jocky.analysis.finding import SEVERITY_ORDER

# Anchored to the project root (or JOCKY_DB_PATH) - not the working
# directory - so the same database is used wherever the server is started.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DB_PATH = Path(os.environ.get("JOCKY_DB_PATH") or (_PROJECT_ROOT / "jocky.db"))

VALID_STATUSES = ("open", "in_review", "closed")
MAX_NAME_LEN = 200
MAX_NOTES_LEN = 10_000

_COLUMNS = (
    "id, investigation_name, endpoint_hostname, started_at, finished_at, "
    "findings_count, status, notes, severity_counts, updated_at"
)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def _severity_counts(report: dict) -> dict:
    c = Counter(f.get("severity", "informational") for f in report.get("findings", []))
    return {s: c.get(s, 0) for s in SEVERITY_ORDER}


def init_db() -> None:
    conn = get_connection()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_name TEXT NOT NULL,
                endpoint_hostname TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(investigations)")}
        migrations = {
            "status": "TEXT NOT NULL DEFAULT 'open'",
            "notes": "TEXT NOT NULL DEFAULT ''",
            "severity_counts": "TEXT NOT NULL DEFAULT '{}'",
            "updated_at": "TEXT",
        }
        added = False
        for col, ddl in migrations.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE investigations ADD COLUMN {col} {ddl}")
                added = True
        if added:  # backfill severity counts for pre-existing rows
            for row in conn.execute("SELECT id, report_json FROM investigations").fetchall():
                try:
                    counts = _severity_counts(json.loads(row["report_json"]))
                except (ValueError, TypeError):
                    continue
                conn.execute(
                    "UPDATE investigations SET severity_counts = ? WHERE id = ?",
                    (json.dumps(counts), row["id"]),
                )
        conn.commit()
    finally:
        conn.close()


def _row_to_summary(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["severity_counts"] = json.loads(d.get("severity_counts") or "{}")
    except ValueError:
        d["severity_counts"] = {}
    return d


def save_investigation(
    investigation_name: str,
    endpoint_hostname: str,
    started_at: str,
    finished_at: str,
    findings_count: int,
    report: dict,
) -> int:
    conn = get_connection()
    try:
        cur = conn.execute(
            """
            INSERT INTO investigations
                (investigation_name, endpoint_hostname, started_at, finished_at,
                 findings_count, report_json, severity_counts, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_name, endpoint_hostname, started_at, finished_at,
                findings_count, json.dumps(report),
                json.dumps(_severity_counts(report)),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_investigations() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM investigations ORDER BY id DESC"
        ).fetchall()
        return [_row_to_summary(r) for r in rows]
    finally:
        conn.close()


def get_investigation(investigation_id: int) -> Optional[dict]:
    conn = get_connection()
    try:
        row = conn.execute(
            f"SELECT {_COLUMNS}, report_json FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if row is None:
            return None
        record = _row_to_summary(row)
        record["report_json"] = json.loads(record["report_json"])
        return record
    finally:
        conn.close()


def update_investigation(
    investigation_id: int,
    name: Optional[str] = None,
    status: Optional[str] = None,
    notes: Optional[str] = None,
) -> bool:
    """Update case metadata only. Returns False if the row does not exist."""
    sets, params = [], []
    if name is not None:
        name = name.strip()
        if not name or len(name) > MAX_NAME_LEN:
            raise ValueError(f"Name must be 1-{MAX_NAME_LEN} characters.")
        sets.append("investigation_name = ?"); params.append(name)
    if status is not None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(VALID_STATUSES)}.")
        sets.append("status = ?"); params.append(status)
    if notes is not None:
        if len(notes) > MAX_NOTES_LEN:
            raise ValueError(f"Notes are limited to {MAX_NOTES_LEN} characters.")
        sets.append("notes = ?"); params.append(notes)
    if not sets:
        raise ValueError("Nothing to update.")
    sets.append("updated_at = ?"); params.append(datetime.now(timezone.utc).isoformat())
    params.append(investigation_id)

    conn = get_connection()
    try:
        cur = conn.execute(
            f"UPDATE investigations SET {', '.join(sets)} WHERE id = ?", params
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_investigation(investigation_id: int) -> bool:
    conn = get_connection()
    try:
        cur = conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_stats() -> dict:
    """Aggregate figures for the dashboard, computed from summary columns
    plus finding rule names from stored reports."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, investigation_name, endpoint_hostname, started_at, status, "
            "findings_count, severity_counts, report_json FROM investigations "
            "ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()

    sev, rules, hosts, status = Counter(), Counter(), Counter(), Counter()
    timeline = []
    for r in rows:
        try:
            counts = json.loads(r["severity_counts"] or "{}")
        except ValueError:
            counts = {}
        for k, v in counts.items():
            sev[k] += v
        hosts[r["endpoint_hostname"]] += 1
        status[r["status"]] += 1
        try:
            for f in json.loads(r["report_json"]).get("findings", []):
                if f.get("severity") not in ("informational",):
                    rules[f.get("rule_name", "unknown")] += 1
        except ValueError:
            pass
        if len(timeline) < 20:
            timeline.append({
                "id": r["id"], "name": r["investigation_name"],
                "started_at": r["started_at"], "findings": r["findings_count"],
                "critical": counts.get("critical", 0), "high": counts.get("high", 0),
            })
    return {
        "total_investigations": len(rows),
        "total_findings": sum(sev.values()),
        "severity_totals": {s: sev.get(s, 0) for s in SEVERITY_ORDER},
        "status_totals": {s: status.get(s, 0) for s in VALID_STATUSES},
        "top_rules": [{"rule": k, "count": v} for k, v in rules.most_common(6)],
        "hosts": [{"host": k, "count": v} for k, v in hosts.most_common(6)],
        "recent": list(reversed(timeline)),
    }
