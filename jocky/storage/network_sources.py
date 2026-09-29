"""Persistent registry for bounded V1.1 network evidence sources."""
from __future__ import annotations
import hashlib, json, os, secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import sqlite3

_PROJECT_ROOT=Path(__file__).resolve().parents[2]
_DB_PATH=Path(os.environ.get("JOCKY_DB_PATH") or (_PROJECT_ROOT/"jocky.db"))
_EVIDENCE_ROOT=Path(os.environ.get("JOCKY_NETWORK_EVIDENCE_DIR") or (_PROJECT_ROOT/"network_evidence")).resolve()
_MAX_FILE_BYTES=20*1024*1024


def _conn():
    conn=sqlite3.connect(_DB_PATH,timeout=15); conn.row_factory=sqlite3.Row; return conn

def init_network_sources():
    _EVIDENCE_ROOT.mkdir(parents=True,exist_ok=True)
    c=_conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS network_sources (
            id TEXT PRIMARY KEY, filename TEXT NOT NULL, format TEXT NOT NULL,
            sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, path TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        c.commit()
    finally:c.close()

def detect_format(filename:str, content:bytes)->str:
    lower=filename.lower()
    if lower.endswith(".pcapng") or content[:4]==b"\x0a\x0d\x0d\x0a": return "pcapng"
    if lower.endswith(".pcap") or content[:4] in (b"\xd4\xc3\xb2\xa1",b"\xa1\xb2\xc3\xd4",b"M<\xb2\xa1",b"\xa1\xb2<M"): return "pcap"
    text=content[:8192].decode("utf-8","replace")
    if any(line.startswith("#path dns") for line in text.splitlines()): return "zeek_dns"
    if any(line.startswith("#path conn") for line in text.splitlines()): return "zeek_conn"
    if filename.lower().endswith((".jsonl",".json")):
        return "zeek_jsonl"
    fields=next((l for l in text.splitlines() if l.startswith("#fields")),"")
    if "query" in fields: return "zeek_dns"
    if "id.orig_h" in fields: return "zeek_conn"
    raise ValueError("Unable to identify the network evidence format. Use Zeek conn.log/dns.log, JSON-lines, PCAP, or PCAPNG.")

def save_network_source(filename:str, content:bytes)->dict:
    if not filename.strip(): raise ValueError("filename is required")
    if len(content)>_MAX_FILE_BYTES: raise ValueError("Network evidence is limited to 20 MiB.")
    fmt=detect_format(filename,content)
    digest=hashlib.sha256(content).hexdigest()
    sid=secrets.token_urlsafe(12)
    safe=Path(filename).name
    dest=_EVIDENCE_ROOT/f"{sid}_{safe}"
    dest.write_bytes(content)
    now=datetime.now(timezone.utc).isoformat()
    c=_conn()
    try:
        c.execute("INSERT INTO network_sources VALUES (?,?,?,?,?,?,?)",(sid,safe,fmt,digest,len(content),str(dest),now)); c.commit()
    finally:c.close()
    return {"id":sid,"filename":safe,"format":fmt,"sha256":digest,"size_bytes":len(content),"created_at":now}

def list_network_sources()->list[dict]:
    c=_conn()
    try:return [dict(r) for r in c.execute("SELECT id,filename,format,sha256,size_bytes,created_at FROM network_sources ORDER BY created_at DESC")]
    finally:c.close()

def get_network_source(source_id:str)->Optional[dict]:
    c=_conn()
    try:
        r=c.execute("SELECT * FROM network_sources WHERE id=?",(source_id,)).fetchone(); return dict(r) if r else None
    finally:c.close()

def delete_network_source(source_id:str)->bool:
    c=_conn()
    try:
        r=c.execute("SELECT path FROM network_sources WHERE id=?",(source_id,)).fetchone()
        if not r:return False
        c.execute("DELETE FROM network_sources WHERE id=?",(source_id,)); c.commit()
        try:Path(r["path"]).unlink(missing_ok=True)
        except OSError: pass
        return True
    finally:c.close()
