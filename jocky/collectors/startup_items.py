"""
Startup item collector.

Windows: reads HKLM/HKCU Run and RunOnce registry keys, plus
         the common Startup folder paths.
Linux:   enumerates /etc/systemd/system, /lib/systemd/system,
         and /etc/init.d entries.

Security notes:
  - winreg access is read-only (KEY_READ flag only)
  - No registry writes occur at any point
  - Paths are capped to prevent enumeration abuse
"""

import os
import platform
import sys
from typing import Any

from jocky.analysis.persistence_enrichment import enrich_record, expand_windows_vars

_MAX_ITEMS = 300


def collect_startup_items() -> dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        return _windows_startup()
    if system == "Linux":
        return _linux_startup()
    return {"items": [], "count": 0, "platform": system}


# ── Windows ────────────────────────────────────────────────────────────────────

def _windows_startup() -> dict[str, Any]:
    items: list[dict] = []

    if sys.platform == "win32":
        try:
            import winreg
            _hive_name = {
                winreg.HKEY_LOCAL_MACHINE: "HKLM",
                winreg.HKEY_CURRENT_USER: "HKCU",
            }
            run_keys = [
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                # 32-bit view on 64-bit systems
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hive, key_path in run_keys:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    idx = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, idx)
                            row = {
                                "source": f"{_hive_name[hive]}\\{key_path}",
                                "name": name,
                                "command": expand_windows_vars(str(value)),
                                "type": "registry_run_key",
                            }
                            items.append(enrich_record(row, _resolve_executable(str(value))))
                            idx += 1
                            if len(items) >= _MAX_ITEMS:
                                break
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    pass
        except ImportError:
            pass

    # Startup folders
    for folder in (
        os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        ),
        os.path.expandvars(
            r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        ),
    ):
        if os.path.isdir(folder):
            for fname in os.listdir(folder):
                command = os.path.join(folder, fname)
                row = {"source": folder, "name": fname, "command": command, "type": "startup_folder"}
                target = _resolve_executable(command)
                if target:
                    row["resolved_target"] = target
                items.append(enrich_record(row, target or command))

    return {"items": items, "count": len(items), "platform": "Windows"}


def _resolve_executable(command: str) -> str | None:
    """Resolve a .lnk target without executing the target."""
    text = expand_windows_vars(str(command or "")).strip().strip('"')
    if not text.lower().endswith(".lnk"):
        return text if os.path.splitext(text)[1].casefold() in {".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh"} else None
    if os.name != "nt":
        return None
    ps = r'$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($args[0]); $s.TargetPath'
    try:
        proc = __import__("subprocess").run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps, text], capture_output=True, text=True, timeout=5, creationflags=getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0))
        target = proc.stdout.strip()
        return target or None
    except Exception:
        return None


# ── Linux ──────────────────────────────────────────────────────────────────────

def _linux_startup() -> dict[str, Any]:
    items: list[dict] = []

    for sdir in (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ):
        if os.path.isdir(sdir):
            for fname in os.listdir(sdir):
                if fname.endswith(".service"):
                    items.append({
                        "source": sdir,
                        "name": fname,
                        "type": "systemd_service",
                    })
                    if len(items) >= _MAX_ITEMS:
                        break

    if os.path.isdir("/etc/init.d"):
        for fname in os.listdir("/etc/init.d"):
            items.append({"source": "/etc/init.d", "name": fname, "type": "init_d"})

    return {"items": items, "count": len(items), "platform": "Linux"}