"""Read-only Windows service inventory for V1.3."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from jocky.collectors.win_acl import assess_service_path
from jocky.analysis.persistence_enrichment import enrich_record, expand_windows_vars

_MAX_SERVICES = 500
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0



def collect_services() -> dict[str, Any]:
    if os.name != "nt":
        return {
            "supported": False, "platform": sys.platform, "services": [], "count": 0,
            "error": "Windows service collection is only available on Windows.",
        }
    try:
        result = subprocess.run(
            ["sc.exe", "queryex", "type=", "service", "state=", "all"],
            capture_output=True, text=True, timeout=45, creationflags=_WIN_FLAGS,
        )
    except Exception as exc:
        return {"supported": True, "platform": "Windows", "services": [], "count": 0, "error": str(exc)}
    if result.returncode != 0:
        return {"supported": True, "platform": "Windows", "services": [], "count": 0,
                "error": (result.stderr or result.stdout or "sc.exe query failed")[:500]}

    names = re.findall(r"^\s*SERVICE_NAME:\s*(.+?)\s*$", result.stdout, flags=re.MULTILINE)
    state_map: dict[str, str] = {}
    pid_map: dict[str, int] = {}
    blocks = re.split(r"(?=^\s*SERVICE_NAME:)", result.stdout, flags=re.MULTILINE)
    for block in blocks:
        match = re.search(r"^\s*SERVICE_NAME:\s*(.+?)\s*$", block, flags=re.MULTILINE)
        state = re.search(r"^\s*STATE\s*:\s*\d+\s+(\w+)", block, flags=re.MULTILINE)
        pid = re.search(r"^\s*PID\s*:\s*(\d+)", block, flags=re.MULTILINE)
        if match and state:
            key = match.group(1).strip()
            state_map[key] = state.group(1).strip().lower()
            if pid:
                pid_map[key] = int(pid.group(1))
    services: list[dict[str, Any]] = []
    errors = 0
    for name in names[:_MAX_SERVICES]:
        try:
            service = _query_service(name.strip())
            service["state"] = state_map.get(name.strip(), "unknown")
            service["pid"] = pid_map.get(name.strip())
            services.append(service)
        except Exception:
            errors += 1
    return {
        "supported": True, "platform": "Windows", "services": services,
        "count": len(services), "query_errors": errors, "truncated": len(names) > _MAX_SERVICES,
    }


def _query_service(name: str) -> dict[str, Any]:
    result = subprocess.run(
        ["sc.exe", "qc", name], capture_output=True, text=True, timeout=8, creationflags=_WIN_FLAGS
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "sc.exe qc failed")
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip().upper()] = value.strip()
    raw_path = expand_windows_vars(values.get("BINARY_PATH_NAME", ""))
    executable = _extract_executable(raw_path)
    service_dll = None
    if os.name == "nt":
        try:
            import winreg
            base = rf"SYSTEM\CurrentControlSet\Services\{name}\Parameters"
            service_dll = _registry_value(winreg.HKEY_LOCAL_MACHINE, base, "ServiceDll")
        except Exception:
            service_dll = None
    acl = assess_service_path(executable)
    enriched = enrich_record({"service_name": name, "display_name": values.get("DISPLAY_NAME") or name, "executable": executable or raw_path, "command_line": raw_path, "account": values.get("SERVICE_START_NAME"), "state": "unknown", "start_mode": _start_mode(values.get("START_TYPE", "")), "path_exists": bool(executable and os.path.isfile(executable)), "writable_path": acl.get("writable", "unknown"), "writable_path_details": acl}, executable)
    if executable and os.path.isfile(executable):
        try:
            import datetime as _dt
            st = os.stat(executable)
            enriched["file_created_at"] = _dt.datetime.fromtimestamp(st.st_ctime, _dt.timezone.utc).isoformat()
            enriched["file_modified_at"] = _dt.datetime.fromtimestamp(st.st_mtime, _dt.timezone.utc).isoformat()
        except OSError:
            pass
    enriched["unquoted_path"] = _has_unquoted_service_path(raw_path)
    enriched["service_dll"] = service_dll
    if service_dll:
        enriched["service_dll_verification"] = enrich_record({}, service_dll).get("verification")
    return enriched

def _registry_value(root, path: str, name: str):
    import winreg
    key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None
    finally:
        winreg.CloseKey(key)

def _has_unquoted_service_path(command: str) -> bool:
    text = str(command or "").strip()
    if text.startswith('"'):
        return False
    exe = _extract_executable(text)
    return bool(exe and " " in exe and os.path.splitext(exe)[1].casefold() in {".exe", ".sys", ".dll"})

def _extract_executable(command: str) -> str:
    text = command.strip()
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 1 else text.strip('"')
    # Fixed parsing only; do not execute or expand the returned command line.
    match = re.match(r"(?i)([A-Za-z]:\\.*?\.(?:exe|sys|dll))(?=\s|$)", text)
    if match:
        return match.group(1)
    match = re.match(r"(?i)([^\s]+\.(?:exe|sys|dll))(?=\s|$)", text)
    return match.group(1) if match else text.split()[0]


def _start_mode(value: str) -> str:
    upper = value.upper()
    if "AUTO_START" in upper:
        return "auto"
    if "DEMAND_START" in upper:
        return "demand"
    if "DISABLED" in upper:
        return "disabled"
    if "BOOT_START" in upper:
        return "boot"
    if "SYSTEM_START" in upper:
        return "system"
    return "unknown"

