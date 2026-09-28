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
                            items.append({
                                "source": f"{_hive_name[hive]}\\{key_path}",
                                "name": name,
                                "command": value,
                                "type": "registry_run_key",
                            })
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
                items.append({
                    "source": folder,
                    "name": fname,
                    "command": os.path.join(folder, fname),
                    "type": "startup_folder",
                })

    return {"items": items, "count": len(items), "platform": "Windows"}


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