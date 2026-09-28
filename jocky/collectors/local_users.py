"""
Local user account collector.

Windows: queries `net user` for account names, then `net user <name>`
         for account details per user.
Linux:   reads /etc/passwd — no shell execution required.

Security notes:
  - subprocess called with explicit arg list — no shell=True
  - /etc/shadow is not read — we collect only non-sensitive account
    metadata from /etc/passwd
  - User count capped at _MAX_USERS
"""

import platform
import subprocess
import sys
from typing import Any

_MAX_USERS = 200
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

# Shells that indicate an interactive login-capable account on Linux.
_INTERACTIVE_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish",
                       "/usr/bin/bash", "/usr/bin/zsh"}


def collect_local_users() -> dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        return _windows_users()
    if system == "Linux":
        return _linux_users()
    return {"users": [], "count": 0, "platform": system}


# ── Windows ────────────────────────────────────────────────────────────────────

def _windows_users() -> dict[str, Any]:
    users: list[dict] = []

    try:
        result = subprocess.run(
            ["net", "user"],
            capture_output=True, text=True, timeout=10,
            creationflags=_WIN_FLAGS,
        )
    except Exception as exc:
        return {"users": [], "count": 0, "platform": "Windows", "error": str(exc)}

    names: list[str] = []
    in_accounts = False
    for line in result.stdout.splitlines():
        if "User accounts for" in line:
            in_accounts = True
            continue
        if "The command completed" in line:
            break
        if in_accounts and line.strip() and not line.startswith("-"):
            names.extend(tok for tok in line.split() if tok.strip())

    for name in names[:_MAX_USERS]:
        entry: dict[str, Any] = {"username": name, "platform": "Windows"}
        try:
            detail = subprocess.run(
                ["net", "user", name],
                capture_output=True, text=True, timeout=5,
                creationflags=_WIN_FLAGS,
            )
            for dline in detail.stdout.splitlines():
                if "Account active" in dline:
                    entry["active"] = "Yes" in dline
                if "Password expires" in dline:
                    entry["password_expires"] = dline.split(None, 2)[-1].strip()
                if "Last logon" in dline:
                    entry["last_logon"] = dline.split(None, 2)[-1].strip()
                if "Local Group Memberships" in dline:
                    entry["groups"] = dline.split("*")[-1].strip()
        except Exception:
            pass
        users.append(entry)

    return {"users": users, "count": len(users), "platform": "Windows"}


# ── Linux ──────────────────────────────────────────────────────────────────────

def _linux_users() -> dict[str, Any]:
    users: list[dict] = []
    try:
        with open("/etc/passwd", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                uid = int(parts[2]) if (parts[2].isascii() and parts[2].isdigit()) else -1
                shell = parts[6]
                users.append({
                    "username": parts[0],
                    "uid": uid,
                    "gid": parts[3],
                    "home": parts[5],
                    "shell": shell,
                    "interactive": shell in _INTERACTIVE_SHELLS,
                    "is_system_account": uid < 1000 and uid != 0,
                    "is_root": uid == 0,
                })
                if len(users) >= _MAX_USERS:
                    break
    except (PermissionError, FileNotFoundError) as exc:
        return {"users": [], "count": 0, "platform": "Linux", "error": str(exc)}

    return {"users": users, "count": len(users), "platform": "Linux"}