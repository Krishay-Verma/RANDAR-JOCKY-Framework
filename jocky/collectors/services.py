"""Read-only Windows service inventory for V1.3."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

_MAX_SERVICES = 500
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

_USER_WRITABLE_MARKERS = (
    "\\users\\public\\", "\\appdata\\", "\\temp\\", "\\tmp\\",
    "\\downloads\\", "\\desktop\\", "/tmp/", "/var/tmp/", "/dev/shm/",
)


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
    blocks = re.split(r"(?=^\s*SERVICE_NAME:)", result.stdout, flags=re.MULTILINE)
    for block in blocks:
        match = re.search(r"^\s*SERVICE_NAME:\s*(.+?)\s*$", block, flags=re.MULTILINE)
        state = re.search(r"^\s*STATE\s*:\s*\d+\s+(\w+)", block, flags=re.MULTILINE)
        if match and state:
            state_map[match.group(1).strip()] = state.group(1).strip().lower()
    services: list[dict[str, Any]] = []
    errors = 0
    for name in names[:_MAX_SERVICES]:
        try:
            service = _query_service(name.strip())
            service["state"] = state_map.get(name.strip(), "unknown")
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
    raw_path = values.get("BINARY_PATH_NAME", "")
    executable = _extract_executable(raw_path)
    writable = _looks_user_writable(executable) or _is_writable(executable)
    return {
        "service_name": name,
        "display_name": values.get("DISPLAY_NAME") or name,
        "executable": executable or raw_path,
        "command_line": raw_path,
        "account": values.get("SERVICE_START_NAME"),
        "state": "unknown",
        "start_mode": _start_mode(values.get("START_TYPE", "")),
        "path_exists": bool(executable and os.path.isfile(executable)),
        "writable_path": writable,
    }


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


def _looks_user_writable(path: str) -> bool:
    lower = path.lower().replace("/", "\\")
    return any(marker.replace("/", "\\") in lower for marker in _USER_WRITABLE_MARKERS)


def _is_writable(path: str) -> bool:
    if not path:
        return False
    try:
        candidate = Path(path)
        if candidate.is_file():
            return os.access(candidate, os.W_OK)
        parent = candidate.parent
        return parent.exists() and os.access(parent, os.W_OK)
    except OSError:
        return False
