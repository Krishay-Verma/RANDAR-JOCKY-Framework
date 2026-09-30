"""Read-only executable enrichment for persistence findings."""
from __future__ import annotations
import hashlib, json, os, re, subprocess, sys
from functools import lru_cache
from pathlib import Path
from typing import Any

TRUSTED_PUBLISHERS = {
    "microsoft corporation", "microsoft windows", "google llc", "google inc.",
    "nvidia corporation", "nvidia", "hewlett-packard", "hp inc.",
    "intel corporation", "intel", "amd", "advanced micro devices, inc.",
    "adobe inc.", "zoom video communications, inc.", "riot games, inc.",
    "epic games, inc.", "valve corp.", "oracle corporation", "vmware, inc.",
}
_RISK_PATHS = ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\desktop\\", "\\public\\", "\\recycle.bin\\")
_EXEC_EXTS = {".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".msi"}

def expand_windows_vars(path: str) -> str:
    if not path:
        return ""
    text = os.path.expandvars(str(path))
    env = {k.casefold(): v for k, v in os.environ.items()}
    text = re.sub(r"%([^%]+)%", lambda m: env.get(m.group(1).casefold(), m.group(0)), text)
    # Common Windows variables are useful in fixture-based analysis even when
    # the test host is not Windows.
    replacements = {
        "%windir%": os.environ.get("WINDIR", r"C:\Windows"),
        "%systemroot%": os.environ.get("SystemRoot", os.environ.get("WINDIR", r"C:\Windows")),
    }
    for k, v in replacements.items():
        text = re.sub(re.escape(k), lambda _m, value=v: value, text, flags=re.I)
    return text

def normalize_windows_path(path: str) -> str:
    text = expand_windows_vars(str(path or "")).strip().strip('"')
    if not text:
        return ""
    text = text.replace("/", "\\")
    # ntpath is available on every platform and gives Windows semantics.
    import ntpath
    return ntpath.normcase(ntpath.normpath(text))

def is_executable_path(path: str) -> bool:
    return Path(str(path).split("?")[0]).suffix.casefold() in _EXEC_EXTS

def path_risk_score(path: str) -> int:
    p = normalize_windows_path(path)
    return 2 if any(marker in p for marker in _RISK_PATHS) else 0

def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

@lru_cache(maxsize=2048)
def verify_file(path: str) -> dict[str, Any]:
    p = expand_windows_vars(path).strip().strip('"')
    result: dict[str, Any] = {
        "path": p, "exists": False, "sha256": None,
        "signature_status": "unknown", "publisher": None,
        "version": None, "created_at": None, "modified_at": None,
        "trusted_publisher": False, "verification_error": None,
    }
    try:
        st = os.stat(p)
        result.update({
            "exists": True,
            "created_at": st.st_ctime,
            "modified_at": st.st_mtime,
            "sha256": _sha256(p),
        })
    except OSError as exc:
        result["verification_error"] = str(exc)
        return result
    if os.name == "nt":
        ps = r"$s=Get-AuthenticodeSignature -LiteralPath $args[0]; $v=(Get-Item -LiteralPath $args[0]).VersionInfo; [pscustomobject]@{status=$s.Status.ToString();publisher=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null};version=$v.FileVersion} | ConvertTo-Json -Compress"
        try:
            proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps, p], capture_output=True, text=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                result["signature_status"] = str(data.get("status") or "unknown").casefold()
                subject = str(data.get("publisher") or "")
                match = re.search(r"CN=([^,]+)", subject, flags=re.I)
                result["publisher"] = (match.group(1) if match else subject) or None
                result["version"] = data.get("version")
            elif proc.stderr:
                result["verification_error"] = proc.stderr.strip()[:500]
        except Exception as exc:
            result["verification_error"] = str(exc)
    pub = str(result.get("publisher") or "").casefold()
    result["trusted_publisher"] = any(t in pub for t in TRUSTED_PUBLISHERS)
    if os.environ.get("RANDAR_VT_API_KEY") and result.get("sha256"):
        result["virustotal"] = lookup_virustotal_hash(result.get("sha256"))
    return result


def lookup_virustotal_hash(sha256: str | None) -> dict[str, Any] | None:
    """Optional hash-only VirusTotal lookup. Disabled unless API key is set."""
    api_key = os.environ.get("RANDAR_VT_API_KEY", "").strip()
    if not api_key or not sha256:
        return None
    try:
        import requests
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": api_key}, timeout=8)
        if response.status_code == 404:
            return {"status": "not_found"}
        response.raise_for_status()
        attrs = response.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        return {"status": "found", "reputation": attrs.get("reputation"), "analysis_stats": stats, "meaningful_name": attrs.get("meaningful_name")}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def parent_folder_context(path: str, limit: int = 50) -> dict[str, Any]:
    """Read-only bounded listing of the target's parent directory."""
    target = expand_windows_vars(str(path or "")).strip().strip('"')
    if not target:
        return {"status": "unknown", "entries": []}
    try:
        parent = Path(target).parent
        entries = []
        for item in sorted(parent.iterdir(), key=lambda x: x.name.casefold())[:limit]:
            try:
                st = item.stat()
                entries.append({"name": item.name, "is_dir": item.is_dir(), "size": st.st_size, "modified_at": st.st_mtime})
            except OSError:
                entries.append({"name": item.name, "metadata": "unavailable"})
        return {"status": "success", "path": str(parent), "entries": entries, "truncated": len(entries) >= limit}
    except OSError as exc:
        return {"status": "error", "error": str(exc), "entries": []}

def enrich_record(record: dict[str, Any], path: str | None = None) -> dict[str, Any]:
    row = dict(record)
    candidate = path or row.get("resolved_target") or row.get("executable") or row.get("task_to_run") or row.get("command")
    if candidate:
        row["path_normalized"] = normalize_windows_path(str(candidate))
        row["path_risk_score"] = path_risk_score(str(candidate))
        if is_executable_path(str(candidate)) and not row.get("verification"):
            row["verification"] = verify_file(str(candidate))
    return row
