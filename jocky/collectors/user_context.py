"""Privacy-bounded user-context collectors.

Clipboard collection never returns clipboard contents. Browser collection never
returns URLs, cookie values, tokens, or decrypted cookie material. It records
bounded metadata suitable for forensic triage.
"""
from __future__ import annotations
import hashlib, json, os, platform, sqlite3, tempfile, shutil
from pathlib import Path
from typing import Any

_MAX_ROWS = 500


def _unsupported(name: str) -> dict[str, Any]:
    return {"supported": False, "status": "not_supported", "records": [], "count": 0, "surface": name}


def collect_clipboard_metadata() -> dict[str, Any]:
    if os.name != "nt":
        return _unsupported("clipboard_metadata")
    # We intentionally inspect only format/length metadata. Clipboard text is
    # never returned, logged, hashed, or persisted by RANDAR.
    ps = r'''$e=@(Get-Clipboard -Format Text -ErrorAction SilentlyContinue); if($e.Count -gt 0){ $t=($e -join "`n"); [pscustomobject]@{available=$true; format="text"; length=$t.Length} } else { [pscustomobject]@{available=$false; format=$null; length=0} } | ConvertTo-Json -Compress'''
    try:
        import subprocess
        p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if p.returncode != 0:
            return {"supported": True, "status": "error", "error": (p.stderr or p.stdout)[:500], "records": [], "count": 0}
        data = json.loads(p.stdout) if p.stdout.strip() else {"available": False, "length": 0}
        return {"supported": True, "status": "success", "records": [data], "count": 1}
    except Exception as exc:
        return {"supported": True, "status": "error", "error": str(exc), "records": [], "count": 0}


def _browser_roots() -> dict[str, Path]:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    return {
        "chrome": local / "Google/Chrome/User Data",
        "edge": local / "Microsoft/Edge/User Data",
        "brave": local / "BraveSoftware/Brave-Browser/User Data",
        "vivaldi": local / "Vivaldi/User Data",
    }


def _profiles(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    try:
        return [p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))][:50]
    except OSError:
        return []


def _query_copy(db: Path, query: str, limit: int = _MAX_ROWS) -> list[tuple]:
    """Read a SQLite database through a temporary copy to avoid browser locks."""
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        shutil.copy2(db, tmp)
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            cur = con.execute(query, (limit,))
            return cur.fetchmany(limit)
        finally:
            con.close()
    except (OSError, sqlite3.Error):
        return []
    finally:
        try: os.unlink(tmp)
        except OSError: pass


def _hash_host(host: str) -> str:
    return hashlib.sha256(host.casefold().encode("utf-8", "replace")).hexdigest()


def collect_browser_history_metadata() -> dict[str, Any]:
    if os.name != "nt":
        return _unsupported("browser_history_metadata")
    records = []
    for browser, root in _browser_roots().items():
        for profile in _profiles(root):
            db = profile / "History"
            if not db.is_file():
                continue
            rows = _query_copy(db, "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?")
            # Do not expose URLs/titles. Only retain a stable domain hash and
            # timestamp/count metadata.
            domains: dict[str, int] = {}
            for url, _title, last_visit in rows:
                try:
                    from urllib.parse import urlparse
                    host = (urlparse(str(url)).hostname or "").strip()
                except Exception:
                    host = ""
                if host:
                    h = _hash_host(host)
                    domains[h] = domains.get(h, 0) + 1
                records.append({"browser": browser, "profile": profile.name, "domain_hash": _hash_host(host) if host else None, "last_visit_time": last_visit})
                if len(records) >= _MAX_ROWS:
                    break
            if len(records) >= _MAX_ROWS:
                break
    return {"supported": True, "status": "success", "records": records[:_MAX_ROWS], "count": min(len(records), _MAX_ROWS), "privacy": "metadata_only; urls_and_titles_redacted"}


def collect_browser_cookie_metadata() -> dict[str, Any]:
    if os.name != "nt":
        return _unsupported("browser_cookie_metadata")
    records = []
    for browser, root in _browser_roots().items():
        for profile in _profiles(root):
            db = profile / "Network/Cookies"
            if not db.is_file():
                continue
            rows = _query_copy(db, "SELECT host_key, expires_utc, is_secure, is_httponly FROM cookies LIMIT ?")
            for host, expires, secure, httponly in rows:
                host = str(host or "")
                records.append({
                    "browser": browser, "profile": profile.name,
                    "host_hash": _hash_host(host) if host else None,
                    "expires_utc": expires,
                    "secure": bool(secure), "httponly": bool(httponly),
                })
                if len(records) >= _MAX_ROWS:
                    break
            if len(records) >= _MAX_ROWS:
                break
    return {"supported": True, "status": "success", "records": records[:_MAX_ROWS], "count": min(len(records), _MAX_ROWS), "privacy": "metadata_only; cookie_values_and_decryption_disabled"}
