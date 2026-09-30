"""
System information collector.

Gathers safe, non-sensitive facts about the host machine: hostname, OS,
architecture, CPU/memory basics, and the current username. This function
only reads information — it never modifies the system.
"""

import platform
import socket
import getpass
from datetime import datetime, timezone

import psutil
import os


def collect_system_info() -> dict:
    """
    Return a dictionary of basic system information.

    Uses only standard library `platform`/`socket`/`getpass` plus `psutil`
    for CPU/memory details, since accurate cross-platform hardware info
    isn't reliably available from the standard library alone.
    """
    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = None

    elevation = _windows_elevation() if os.name == "nt" else {"is_admin": bool(getattr(os, "geteuid", lambda: 1)() == 0), "is_elevated": bool(getattr(os, "geteuid", lambda: 1)() == 0), "integrity_level": "root" if bool(getattr(os, "geteuid", lambda: 1)() == 0) else "user"}
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "cpu_count": psutil.cpu_count(logical=True),
        "total_memory_bytes": psutil.virtual_memory().total,
        "current_user": current_user,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        **elevation,
        "elevation_required_for": [
            "Security Windows Event Log", "protected process executable/username fields",
            "full service and driver ACL/registry metadata",
        ],
    }

def _windows_elevation() -> dict:
    try:
        import ctypes
        shell32 = ctypes.windll.shell32
        is_admin = bool(shell32.IsUserAnAdmin())
        # TokenElevation is a simple, stable way to distinguish an elevated
        # token from an unelevated admin token. If it cannot be read, report
        # unknown instead of guessing.
        token = ctypes.c_void_p()
        advapi = ctypes.windll.advapi32
        kernel = ctypes.windll.kernel32
        process = kernel.GetCurrentProcess()
        TOKEN_QUERY = 0x0008
        if not advapi.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            return {"is_admin": is_admin, "is_elevated": None, "integrity_level": "unknown"}
        elevation = ctypes.c_ulong(0); ret = ctypes.c_ulong(0)
        TokenElevation = 20
        ok = advapi.GetTokenInformation(token, TokenElevation, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(ret))
        kernel.CloseHandle(token)
        return {"is_admin": is_admin, "is_elevated": bool(elevation.value) if ok else None, "integrity_level": "high" if ok and elevation.value else "medium"}
    except Exception:
        return {"is_admin": None, "is_elevated": None, "integrity_level": "unknown"}
