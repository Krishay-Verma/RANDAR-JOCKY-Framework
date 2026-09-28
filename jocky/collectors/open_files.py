"""
Open file handle collector.

Uses psutil to enumerate every open file handle per process.
Useful for detecting exfiltration staging, keyloggers writing to temp
files, and unexpected access to sensitive paths.

Security notes:
  - Per-process file list capped at _MAX_FILES_PER_PROCESS
  - AccessDenied is silently skipped — we collect what we can
  - NoSuchProcess is silently skipped (process exited mid-enumeration)
  - Total file limit prevents memory exhaustion
"""

from typing import Any

import psutil

_MAX_PROCESSES = 500
_MAX_FILES_PER_PROCESS = 50
_MAX_TOTAL_FILES = 2000


def collect_open_files() -> dict[str, Any]:
    open_files: list[dict] = []
    error_count = 0

    for proc in psutil.process_iter(["pid", "name", "username"]):
        if len(open_files) >= _MAX_TOTAL_FILES:
            break
        try:
            for f in proc.open_files()[:_MAX_FILES_PER_PROCESS]:
                open_files.append({
                    "pid": proc.pid,
                    "process_name": proc.info.get("name", "unknown"),
                    "username": proc.info.get("username") or "unknown",
                    "path": f.path,
                    "mode": getattr(f, "mode", None),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            error_count += 1

    return {
        "open_files": open_files,
        "count": len(open_files),
        "error_count": error_count,
    }