"""Append-only audit log for RANDAR investigations."""
from __future__ import annotations
import json, os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_DB = Path(os.environ.get("JOCKY_DB_PATH") or (_ROOT / "jocky.db"))

def _conn():
    c=sqlite3.connect(_DB, timeout=15); c.row_factory=sqlite3.Row; return c

def init_audit():
    c=_conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, user_name TEXT NOT NULL, action TEXT NOT NULL, investigation_id INTEGER, investigation_name TEXT, script_hash TEXT, result_hash TEXT, details TEXT NOT NULL DEFAULT '{}')""")
        c.commit()
    finally: c.close()

def audit_event(action: str, report=None, details=None, investigation_id=None):
    c=_conn()
    try:
        source = getattr(report, 'source', {}) or {}
        inv_id = investigation_id or (details or {}).get('investigation_id')
        c.execute("INSERT INTO audit_log(timestamp,user_name,action,investigation_id,investigation_name,script_hash,result_hash,details) VALUES(?,?,?,?,?,?,?,?)", (datetime.now(timezone.utc).isoformat(), os.environ.get("RANDAR_OPERATOR_NAME", os.environ.get("JOCKY_OPERATOR_NAME", "admin")), action, inv_id, getattr(report,'investigation_name',None), getattr(report,'script_hash',None), getattr(report,'report_hash',None), json.dumps(details or {}, sort_keys=True)))
        c.commit()
    finally: c.close()

def list_audit_events(investigation_id=None, limit=200):
    c=_conn()
    try:
        if investigation_id is None:
            rows=c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows=c.execute("SELECT * FROM audit_log WHERE investigation_id=? ORDER BY id DESC LIMIT ?", (investigation_id,limit)).fetchall()
        out=[]
        for r in rows:
            d=dict(r)
            try:d['details']=json.loads(d['details'] or '{}')
            except Exception:d['details']={}
            out.append(d)
        return out
    finally:c.close()
