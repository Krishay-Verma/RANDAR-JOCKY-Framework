"""Windows loaded-module collector.

The collector is deliberately read-only.  It uses psutil's process memory-map
view to build a process -> module inventory without opening process memory for
writing or invoking injection primitives.
"""

import hashlib
import os
from pathlib import Path
from typing import Any

import psutil

_MAX_PROCESSES = 400
_MAX_MODULES = 5000
_MAX_HASH_BYTES = 16 * 1024 * 1024
_MAX_HASHED_MODULES = 250

_USER_WRITABLE_MARKERS = (
    "\\appdata\\",
    "\\users\\public\\",
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\desktop\\",
)
_SYSTEM_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)


def collect_modules() -> dict[str, Any]:
    """Collect loaded file-backed modules for Windows processes.

    On non-Windows hosts the collector returns an explicit unsupported status
    instead of attempting to emulate Windows semantics.
    """
    if os.name != "nt":
        return {
            "supported": False,
            "platform": os.name,
            "modules": [],
            "count": 0,
            "error": "The Windows module collector is only available on Windows.",
        }

    modules: list[dict[str, Any]] = []
    errors = 0
    hashed = 0
    seen_hashes: set[str] = set()

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        if len(modules) >= _MAX_MODULES or proc.pid is None:
            break
        try:
            exe = proc.info.get("exe")
            exe_real = _safe_realpath(exe)
            maps = proc.memory_maps(grouped=False)
            for mapping in maps:
                if len(modules) >= _MAX_MODULES:
                    break
                path = getattr(mapping, "path", "") or ""
                if not path or path.startswith("["):
                    continue
                path_real = _safe_realpath(path)
                lower = path_real.lower()
                if not lower.endswith((".dll", ".exe", ".sys")):
                    continue

                user_writable = _looks_user_writable(lower)
                is_system = lower.startswith(_SYSTEM_PREFIXES)
                entry = {
                    "pid": proc.pid,
                    "process_name": proc.info.get("name") or "unknown",
                    "process_exe": exe,
                    "module_name": Path(path_real).name,
                    "module_path": path_real,
                    "rss_bytes": getattr(mapping, "rss", None),
                    "vms_bytes": getattr(mapping, "vms", None),
                    "is_main_image": bool(exe_real and path_real == exe_real),
                    "is_system_path": is_system,
                    "is_user_writable": user_writable,
                    "hash_status": "not_collected",
                    "sha256": None,
                }

                # Hash only modules in paths that deserve closer inspection.
                # This keeps a normal Windows host fast while still providing
                # cryptographic evidence for the most relevant anomalies.
                if user_writable and hashed < _MAX_HASHED_MODULES and path_real not in seen_hashes:
                    digest = _safe_sha256(path_real)
                    if digest:
                        entry["sha256"] = digest
                        entry["hash_status"] = "sha256"
                        seen_hashes.add(path_real)
                        hashed += 1

                modules.append(entry)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            errors += 1
        except Exception:
            errors += 1

    return {
        "supported": True,
        "modules": modules,
        "count": len(modules),
        "process_errors": errors,
        "hashed_modules": hashed,
        "truncated": len(modules) >= _MAX_MODULES,
    }


def _safe_realpath(path: str | None) -> str:
    if not path:
        return ""
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def _looks_user_writable(path: str) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in _USER_WRITABLE_MARKERS)


def _safe_sha256(path: str) -> str | None:
    try:
        stat = os.stat(path)
        if not os.path.isfile(path) or stat.st_size > _MAX_HASH_BYTES:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            remaining = _MAX_HASH_BYTES
            while remaining:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None
