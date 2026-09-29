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
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
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


def get_investigation(investigation_id: int, include_large_evidence: bool = True) -> Optional[dict]:
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
        if not include_large_evidence:
            report = record["report_json"]
            for collector in report.get("collector_results", []):
                data = collector.get("data")
                if not isinstance(data, dict):
                    continue
                for key, value in list(data.items()):
                    if isinstance(value, list) and len(value) > 200:
                        collector["data"] = {
                            k: v for k, v in data.items() if not isinstance(v, list)
                        }
                        collector["data"]["_lazy_evidence"] = {
                            "list_key": key, "total": len(value),
                            "message": "Large evidence is loaded on demand.",
                        }
                        break
            if len(report.get("timeline", [])) > 500:
                report["timeline"] = report["timeline"][:500]
                report["timeline_truncated"] = True
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


def search_investigations(query: str, limit: int = 50) -> list[dict]:
    """Search stored investigation metadata, findings and collected evidence.

    Search is deliberately bounded and read-only. It never alters the stored
    forensic report and returns concise contextual matches rather than dumping
    complete evidence documents into the global search response.
    """
    term = (query or "").strip().casefold()
    if not term:
        return []
    limit = min(max(int(limit), 1), 100)

    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, investigation_name, endpoint_hostname, started_at, findings_count, status, report_json "
            "FROM investigations ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()

    results: list[dict] = []

    def add(item: dict) -> bool:
        if len(results) >= limit:
            return False
        results.append(item)
        return True

    def scalar_matches(value) -> bool:
        if value is None or isinstance(value, (dict, list)):
            return False
        return term in str(value).casefold()

    def walk(value, path: str, out: list[tuple[str, str]]):
        if len(out) >= 12:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if isinstance(child, (dict, list)):
                    walk(child, child_path, out)
                elif scalar_matches(child):
                    out.append((child_path, str(child)))
        elif isinstance(value, list):
            for index, child in enumerate(value[:500]):
                child_path = f"{path}[{index}]"
                if isinstance(child, (dict, list)):
                    walk(child, child_path, out)
                elif scalar_matches(child):
                    out.append((child_path, str(child)))

    for row in rows:
        if len(results) >= limit:
            break
        base = {
            "investigation_id": row["id"],
            "investigation_name": row["investigation_name"],
            "endpoint_hostname": row["endpoint_hostname"],
            "started_at": row["started_at"],
            "status": row["status"],
        }
        summary_fields = (row["investigation_name"], row["endpoint_hostname"], row["status"], row["id"])
        if any(scalar_matches(v) for v in summary_fields):
            if not add({**base, "kind": "investigation", "title": row["investigation_name"], "matched_field": "case metadata", "matched_value": term}):
                break

        try:
            report = json.loads(row["report_json"])
        except (TypeError, ValueError):
            continue

        for finding in report.get("findings", []):
            haystack = (finding.get("rule_name"), finding.get("summary"), finding.get("reason"), finding.get("finding_id"))
            if any(scalar_matches(v) for v in haystack):
                if not add({**base, "kind": "finding", "title": finding.get("summary") or finding.get("rule_name"), "finding_id": finding.get("finding_id"), "rule_name": finding.get("rule_name"), "severity": finding.get("severity"), "reason": finding.get("reason"), "matched_field": "finding", "matched_value": term}):
                    break
                continue
            evidence_hits: list[tuple[str, str]] = []
            walk(finding.get("related_evidence") or {}, "related_evidence", evidence_hits)
            for path, value in evidence_hits[:3]:
                if not add({**base, "kind": "evidence", "title": finding.get("summary") or finding.get("rule_name"), "finding_id": finding.get("finding_id"), "rule_name": finding.get("rule_name"), "severity": finding.get("severity"), "collector": None, "path": path, "matched_value": value}):
                    break
            if len(results) >= limit:
                break

        if len(results) >= limit:
            break

        for collector in report.get("collector_results", []):
            if collector.get("status") != "success" or not collector.get("data"):
                continue
            if scalar_matches(collector.get("target")):
                if not add({**base, "kind": "evidence", "title": collector.get("target", "Evidence"), "collector": collector.get("target"), "path": "collector", "matched_value": collector.get("target")}):
                    break
            hits: list[tuple[str, str]] = []
            walk(collector.get("data"), "data", hits)
            for path, value in hits[:4]:
                if not add({**base, "kind": "evidence", "title": collector.get("target", "Evidence"), "collector": collector.get("target"), "path": path, "matched_value": value}):
                    break
            if len(results) >= limit:
                break

    return results



def list_investigations_page(page: int = 1, limit: int = 25, query: str = "", status_filter: str = "all", sort: str = "newest") -> dict:
    """Return a bounded page of case summaries without loading report bodies."""
    page = max(1, int(page))
    limit = min(max(int(limit), 1), 100)
    query = (query or "").strip()
    params = []
    where = []
    if query:
        like = f"%{query}%"
        where.append("(investigation_name LIKE ? OR endpoint_hostname LIKE ? OR CAST(id AS TEXT) LIKE ?)")
        params.extend([like, like, like])
    if status_filter != "all":
        if status_filter not in VALID_STATUSES:
            raise ValueError(f"Status must be one of: all, {', '.join(VALID_STATUSES)}")
        where.append("status = ?")
        params.append(status_filter)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    order = "id DESC"
    if sort == "oldest":
        order = "id ASC"
    elif sort == "severity":
        order = "json_extract(severity_counts, '$.critical') DESC, json_extract(severity_counts, '$.high') DESC, json_extract(severity_counts, '$.medium') DESC, id DESC"
    elif sort != "newest":
        raise ValueError("Sort must be newest, oldest, or severity.")
    offset = (page - 1) * limit
    conn = get_connection()
    try:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM investigations{clause}", params).fetchone()["n"]
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM investigations{clause} ORDER BY {order} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    finally:
        conn.close()
    return {
        "items": [_row_to_summary(r) for r in rows],
        "page": page, "limit": limit, "total": total,
        "has_next": offset + len(rows) < total,
        "has_previous": page > 1,
    }


def get_investigation_evidence_page(investigation_id: int, collector: str, page: int = 1, limit: int = 100, query: str = "") -> dict | None:
    """Return one bounded page from a collector's first evidence list."""
    record = get_investigation(investigation_id)
    if record is None:
        return None
    page = max(1, int(page)); limit = min(max(int(limit), 1), 250)
    collector_row = next((c for c in record["report_json"].get("collector_results", []) if c.get("target") == collector), None)
    if collector_row is None:
        raise ValueError("Collector not found in this investigation.")
    data = collector_row.get("data") or {}
    list_key = next((k for k, v in data.items() if isinstance(v, list)), None)
    if not list_key:
        return {"collector": collector, "list_key": None, "rows": [], "page": page, "limit": limit, "total": 0, "has_next": False, "scalars": data}
    rows = data.get(list_key) or []
    query = (query or "").strip().casefold()
    if query:
        rows = [r for r in rows if query in json.dumps(r, ensure_ascii=False, default=str).casefold()]
    offset = (page - 1) * limit
    chunk = rows[offset:offset + limit]
    scalars = {k: v for k, v in data.items() if k != list_key}
    return {
        "collector": collector, "list_key": list_key, "rows": chunk,
        "page": page, "limit": limit, "total": len(rows),
        "has_next": offset + len(chunk) < len(rows), "has_previous": page > 1,
        "scalars": scalars, "truncated": bool(collector_row.get("truncated", False)),
        "resource_bytes": collector_row.get("resource_bytes", 0),
        "record_count": collector_row.get("record_count", len(rows)),
    }

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
