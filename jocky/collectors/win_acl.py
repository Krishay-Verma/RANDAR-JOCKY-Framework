"""Windows DACL inspection for defensive write-access triage.

The decision is based on the actual DACL, not path-name heuristics or
``os.access``. The PowerShell command is fixed and receives only the path as
an argument; it never changes ACLs or executes the target file.
"""
from __future__ import annotations
import json, os, re, subprocess, sys
from pathlib import Path
from typing import Any

# Well-known non-admin principals. SID comparison avoids localization issues.
_TARGET_SIDS = {"S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4"}
_WRITE_RIGHTS = {"write", "modify", "fullcontrol", "writeattributes", "writeextendedattributes", "createfiles", "createfolders", "delete", "deletechildren"}


def _parse_icacls(output: str) -> dict[str, Any]:
    """Compatibility parser for fixture/unit-test ACL text."""
    grants: list[dict[str, Any]] = []
    denies: list[dict[str, Any]] = []
    for line in output.splitlines():
        if ":" not in line:
            continue
        principal, perms = line.strip().split(":", 1)
        principal = principal.strip().strip('"').casefold()
        if principal not in {"everyone", "builtin\\users", "users", "nt authority\\authenticated users", "authenticated users", "interactive"} and not principal.endswith("\\users"):
            continue
        for ace in re.findall(r"\(([^)]*)\)", perms):
            deny = "DENY" in ace.upper()
            codes = {x.strip().upper() for x in re.split(r"[, ]+", ace.replace("(OI)", "").replace("(CI)", "")) if x.strip()}
            item = {"principal": principal, "permissions": sorted(codes)}
            (denies if deny else grants).append(item)
    return {"grants": grants, "denies": denies}


def _powershell_acl(path: str) -> dict[str, Any]:
    script = r'''
$acl = Get-Acl -LiteralPath $args[0]
$rows = foreach ($a in $acl.Access) {
  try { $sid = $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $a.IdentityReference.Value }
  [pscustomobject]@{ Sid=$sid; Identity=$a.IdentityReference.Value; Type=$a.AccessControlType.ToString(); Rights=$a.FileSystemRights.ToString() }
}
$rows | ConvertTo-Json -Compress -Depth 4
'''
    proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, path], capture_output=True, text=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "ACL query failed").strip()[:500])
    raw = json.loads(proc.stdout) if proc.stdout.strip() else []
    rows = raw if isinstance(raw, list) else [raw]
    return {"rows": rows}


def inspect_write_access(path: str) -> dict[str, Any]:
    if os.name != "nt":
        return {"writable": "unknown", "source": "unsupported_platform", "principals": []}
    target = str(Path(path))
    if not target:
        return {"writable": "unknown", "source": "empty_path", "principals": []}
    try:
        parsed = _powershell_acl(target)
    except Exception as exc:
        return {"writable": "unknown", "source": "acl_query_error", "error": str(exc), "principals": []}
    denied_sids = {str(r.get("Sid") or "").upper() for r in parsed["rows"] if str(r.get("Type") or "").casefold() == "deny" and str(r.get("Sid") or "").upper() in _TARGET_SIDS and any(x in str(r.get("Rights") or "").casefold() for x in _WRITE_RIGHTS)}
    principals = []
    for row in parsed["rows"]:
        sid = str(row.get("Sid") or "").upper()
        if sid not in _TARGET_SIDS or str(row.get("Type") or "").casefold() == "deny" or sid in denied_sids:
            continue
        rights = str(row.get("Rights") or "")
        low = rights.casefold()
        if any(x in low for x in _WRITE_RIGHTS):
            principals.append({"sid": sid, "identity": row.get("Identity"), "rights": rights})
    return {"writable": bool(principals), "source": "dacl_powershell", "principals": principals, "denied_sids": sorted(denied_sids)}


def assess_service_path(executable: str) -> dict[str, Any]:
    if not executable:
        return {"writable": "unknown", "file": {}, "parent": {}}
    file_acl = inspect_write_access(executable)
    try:
        parent_acl = inspect_write_access(str(Path(executable).parent))
    except Exception:
        parent_acl = {"writable": "unknown", "source": "parent_error"}
    states = {file_acl.get("writable"), parent_acl.get("writable")}
    if True in states:
        writable: Any = True
    elif file_acl.get("writable") is False and parent_acl.get("writable") is False:
        writable = False
    else:
        writable = "unknown"
    return {"writable": writable, "file": file_acl, "parent": parent_acl}
