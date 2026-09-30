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

from jocky.analysis.persistence_enrichment import enrich_record, expand_windows_vars, parent_folder_context

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
            task = {
                "name": name,
                "status": row.get("Status", "").strip(),
                "run_as": row.get("Run As User", "").strip(),
                "task_to_run": expand_windows_vars(row.get("Task To Run", "").strip()),
                "next_run": row.get("Next Run Time", "").strip(),
                "last_run": row.get("Last Run Time", "").strip(),
                "schedule_type": row.get("Schedule Type", "").strip(),
                "author": row.get("Author", "").strip(),
            }
            enriched = enrich_record(task, task.get("task_to_run"))
            # Expensive context is only gathered for paths that have an
            # explicit risk signal; the normal clean-task path stays cheap.
            if int(enriched.get("path_risk_score") or 0) > 0:
                enriched["parent_folder_context"] = parent_folder_context(enriched.get("path_normalized") or enriched.get("task_to_run"))
                enriched["registry_task_cache"] = _task_registry_context(name)
            tasks.append(enriched)
            if len(tasks) >= _MAX_TASKS:
                break
    except Exception as exc:
        return {"tasks": [], "count": 0, "platform": "Windows", "error": str(exc)}

    return {"tasks": tasks, "count": len(tasks), "platform": "Windows"}


def _task_registry_context(task_name: str) -> dict[str, Any]:
    if os.name != "nt" or not task_name:
        return {"status": "not_available"}
    try:
        import winreg
        base = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\"
        parts = [p for p in str(task_name).strip("\\").split("\\") if p]
        key_path = base + "\\".join(parts)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        values = {}
        try:
            idx = 0
            while True:
                try:
                    n, v, _ = winreg.EnumValue(key, idx); values[n] = v; idx += 1
                except OSError: break
        finally:
            winreg.CloseKey(key)
        return {"status": "success", "registry_path": key_path, "values": values}
    except Exception as exc:
        return {"status": "unavailable", "error": str(exc)[:300]}


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