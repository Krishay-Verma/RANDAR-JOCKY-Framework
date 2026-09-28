"""
Scheduled task collector.

Windows: queries Task Scheduler via schtasks.exe
Linux:   reads /etc/crontab, /etc/cron.d/*, and current user crontab

Security notes:
  - subprocess called with explicit argument lists — no shell=True
  - CREATE_NO_WINDOW on Windows prevents console flicker and avoids
    spawning a visible window that could alert an attacker
  - Output is capped to prevent memory exhaustion from pathological
    task schedulers
"""

import csv
import io
import os
import platform
import subprocess
import sys
from typing import Any

_MAX_TASKS = 500
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def collect_scheduled_tasks() -> dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        return _windows_tasks()
    if system == "Linux":
        return _linux_cron()
    return {"tasks": [], "count": 0, "platform": system, "note": "Unsupported"}


# ── Windows ────────────────────────────────────────────────────────────────────

def _windows_tasks() -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=_WIN_FLAGS,
        )
    except Exception as exc:
        return {"tasks": [], "count": 0, "platform": "Windows", "error": str(exc)}

    tasks: list[dict] = []
    try:
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            name = row.get("TaskName", "").strip()
            if not name or name == "TaskName":
                continue
            tasks.append({
                "name": name,
                "status": row.get("Status", "").strip(),
                "run_as": row.get("Run As User", "").strip(),
                "task_to_run": row.get("Task To Run", "").strip(),
                "next_run": row.get("Next Run Time", "").strip(),
                "last_run": row.get("Last Run Time", "").strip(),
            })
            if len(tasks) >= _MAX_TASKS:
                break
    except Exception as exc:
        return {"tasks": [], "count": 0, "platform": "Windows", "error": str(exc)}

    return {"tasks": tasks, "count": len(tasks), "platform": "Windows"}


# ── Linux ──────────────────────────────────────────────────────────────────────

def _linux_cron() -> dict[str, Any]:
    tasks: list[dict] = []
    cron_paths: list[str] = ["/etc/crontab"]

    for cron_dir in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                     "/etc/cron.weekly", "/etc/cron.monthly"):
        if os.path.isdir(cron_dir):
            for fname in os.listdir(cron_dir):
                cron_paths.append(os.path.join(cron_dir, fname))

    for fpath in cron_paths:
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        tasks.append({"source": fpath, "entry": line})
                        if len(tasks) >= _MAX_TASKS:
                            break
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            pass

    try:
        proc = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True, timeout=5,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                tasks.append({"source": "user_crontab", "entry": line})
    except Exception:
        pass

    return {"tasks": tasks, "count": len(tasks), "platform": "Linux"}