"""Read-only Windows driver inventory for BYOVD *detection* research.

This module never loads, unloads, opens, exploits, or modifies a driver.  It
collects service/driver metadata and optionally correlates it with an
operator-supplied JSON vulnerability catalog.
"""

from __future__ import annotations

import hashlib
import json
import csv
import io
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_MAX_DRIVERS = 800
_DEFAULT_DB_ENV = "RANDAR_VULNERABLE_DRIVER_DB"
_SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\\Windows")
_DRIVER_ROOT = Path(_SYSTEM_ROOT) / "System32" / "drivers"
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _load_vulnerability_db() -> dict[str, Any]:
    path = os.environ.get(_DEFAULT_DB_ENV)
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _file_hash(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None



def _loaded_driver_map() -> dict[str, dict[str, Any]]:
    """Return read-only loaded-driver state using the fixed driverquery utility."""
    try:
        result = subprocess.run(
            ["driverquery.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=30, creationflags=_WIN_FLAGS,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode != 0:
        return {}
    rows: dict[str, dict[str, Any]] = {}
    try:
        for row in csv.reader(io.StringIO(result.stdout)):
            if not row or not row[0].strip():
                continue
            # driverquery's first columns are stable across supported Windows versions:
            # module name, display name, driver type, link date, path.
            name = row[0].strip().lower()
            if not name:
                continue
            rows[name] = {
                "loaded": True,
                "driverquery_display_name": row[1].strip() if len(row) > 1 else None,
                "driverquery_type": row[2].strip() if len(row) > 2 else None,
                "driverquery_link_date": row[3].strip() if len(row) > 3 else None,
                "driverquery_path": row[4].strip() if len(row) > 4 else None,
            }
    except csv.Error:
        return {}
    return rows


def _powershell_file_metadata(path: str) -> dict[str, Any]:
    """Best-effort signer/version metadata using a fixed PowerShell query."""
    if not path:
        return {}
    command = (
        "$p=$args[0]; $s=Get-AuthenticodeSignature -LiteralPath $p; "
        "$i=Get-Item -LiteralPath $p -ErrorAction Stop; "
        "[pscustomobject]@{status=[string]$s.Status; publisher=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{$null}; "
        "version=[string]$i.VersionInfo.FileVersion} | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command, path],
            capture_output=True, text=True, timeout=6, creationflags=_WIN_FLAGS,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        data = json.loads(result.stdout)
        status = str(data.get("status") or "").lower()
        if status == "valid":
            signature = "signed"
        elif status in {"notsigned", "nottrusted", "hashmismatch", "invalid"}:
            signature = "unsigned" if status == "notsigned" else status
        else:
            signature = "unknown"
        return {"signature_status": signature, "publisher": data.get("publisher"), "version": data.get("version")}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return {}

def collect_driver_inventory() -> dict[str, Any]:
    """Collect driver-service metadata without changing kernel state."""
    if os.name != "nt":
        return {
            "supported": False,
            "platform": os.name,
            "drivers": [],
            "count": 0,
            "error": "The Windows driver inventory is only available on Windows.",
        }

    import winreg

    vuln_db = _load_vulnerability_db()
    loaded_map = _loaded_driver_map()
    drivers: list[dict[str, Any]] = []
    errors = 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as root:
            index = 0
            while index < _MAX_DRIVERS:
                try:
                    service_name = winreg.EnumKey(root, index)
                    index += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(root, service_name) as key:
                        kind = winreg.QueryValueEx(key, "Type")[0]
                        # SERVICE_KERNEL_DRIVER=1, SERVICE_FILE_SYSTEM_DRIVER=2
                        if kind not in (1, 2):
                            continue
                        image_path = ""
                        start_type = None
                        display_name = service_name
                        for name, default in (("ImagePath", ""), ("Start", None), ("DisplayName", service_name)):
                            try:
                                value = winreg.QueryValueEx(key, name)[0]
                            except OSError:
                                value = default
                            if name == "ImagePath": image_path = str(value or "")
                            elif name == "Start": start_type = value
                            elif name == "DisplayName": display_name = str(value or service_name)

                        normalized = image_path.strip().strip('"').replace("/", "\\")
                        if normalized.lower().startswith("\\systemroot\\"):
                            normalized = os.path.join(_SYSTEM_ROOT, normalized[len("\\systemroot\\"):].lstrip("\\"))
                        elif normalized.lower().startswith("system32\\"):
                            normalized = os.path.join(_SYSTEM_ROOT, normalized)
                        elif not os.path.isabs(normalized) and normalized:
                            normalized = str(_DRIVER_ROOT / normalized)
                        path = Path(normalized) if normalized else None
                        filename = path.name.lower() if path else ""
                        record = {
                            "service_name": service_name,
                            "display_name": display_name,
                            "image_path": str(path) if path else image_path,
                            "start_type": start_type,
                            "file_exists": bool(path and path.is_file()),
                            "sha256": _file_hash(path) if path else None,
                            "is_user_writable_path": bool(path and _looks_user_writable(str(path))),
                            "is_system_path": bool(path and _is_system_path(str(path))),
                            "signature_status": "not_collected",
                            "publisher": None,
                            "version": None,
                            "loaded": False,
                            "known_vulnerable": False,
                            "vulnerability_ids": [],
                        }
                        loaded_info = loaded_map.get(service_name.lower()) or loaded_map.get(filename) or {}
                        record.update({k: v for k, v in loaded_info.items() if v is not None})
                        if record.get("file_exists") and (record.get("loaded") or record.get("known_vulnerable")):
                            record.update(_powershell_file_metadata(record.get("image_path") or ""))
                        match = vuln_db.get(filename) or vuln_db.get(service_name.lower())
                        if isinstance(match, dict):
                            record["known_vulnerable"] = bool(match.get("known_vulnerable", True))
                            record["vulnerability_ids"] = list(match.get("ids", []))[:20]
                            record["catalog_source"] = match.get("source")
                        drivers.append(record)
                except OSError:
                    errors += 1
    except OSError as exc:
        return {
            "supported": True,
            "drivers": [],
            "count": 0,
            "errors": 1,
            "error": f"Driver service inventory unavailable: {exc}",
        }

    return {
        "supported": True,
        "drivers": drivers[:_MAX_DRIVERS],
        "count": len(drivers),
        "errors": errors,
        "vulnerability_catalog": os.environ.get(_DEFAULT_DB_ENV) or None,
    }


def _looks_user_writable(path: str) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in ("\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\"))


def _is_system_path(path: str) -> bool:
    lower = os.path.normpath(path).lower()
    root = os.path.normpath(_SYSTEM_ROOT).lower()
    return lower.startswith(root + os.sep.lower()) or lower == root
