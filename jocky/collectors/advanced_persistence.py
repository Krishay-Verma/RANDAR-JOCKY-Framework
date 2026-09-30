"""Read-only Windows persistence surface collectors.

All collectors are defensive inventory only. They read registry/filesystem or
fixed PowerShell management APIs and never create, modify, enable, disable,
or execute persistence mechanisms.
"""
from __future__ import annotations
import json, os, platform, re, subprocess
from pathlib import Path
from typing import Any

_WIN_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)

def _unsupported(name: str) -> dict[str, Any]:
    return {"supported": False, "platform": platform.system(), "status": "not_supported", "records": [], "count": 0, "surface": name}

def _registry_values(root, path: str) -> dict[str, Any]:
    import winreg
    out = {}
    try:
        key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
    except OSError:
        return out
    try:
        idx = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, idx); out[name] = value; idx += 1
            except OSError: break
    finally:
        winreg.CloseKey(key)
    return out

def collect_wmi_event_subscriptions() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("wmi_event_subscriptions")
    ps = r'Get-CimInstance -Namespace root/subscription -ClassName __EventFilter,__EventConsumer,__FilterToConsumerBinding | Select-Object __CLASS,Name,Query,CommandLineTemplate,ExecutablePath,Filter,Consumer | ConvertTo-Json -Compress -Depth 4'
    try:
        p = subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",ps], capture_output=True, text=True, timeout=20, creationflags=_WIN_FLAGS)
        if p.returncode != 0: return {"supported": True, "status": "error", "error": (p.stderr or p.stdout)[:500], "records": [], "count": 0}
        raw = json.loads(p.stdout) if p.stdout.strip() else []
        records = raw if isinstance(raw, list) else [raw]
        return {"supported": True, "status": "success", "records": records[:300], "count": min(len(records),300)}
    except Exception as exc:
        return {"supported": True, "status": "error", "error": str(exc), "records": [], "count": 0}

def _enum_subkeys(root, base: str, max_items: int = 300) -> list[str]:
    import winreg
    out=[]
    try: key=winreg.OpenKey(root, base, 0, winreg.KEY_READ)
    except OSError: return out
    try:
        for i in range(max_items):
            try: out.append(winreg.EnumKey(key,i))
            except OSError: break
    finally: winreg.CloseKey(key)
    return out

def collect_ifeo_persistence() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("ifeo")
    import winreg
    base=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    records=[]
    for name in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
        vals=_registry_values(winreg.HKEY_LOCAL_MACHINE, base+"\\"+name)
        if vals.get("Debugger") or vals.get("GlobalFlag") or vals.get("VerifierDlls"):
            records.append({"image":name, **{k: vals.get(k) for k in ("Debugger","GlobalFlag","VerifierDlls") if vals.get(k) is not None}, "registry_path":base+"\\"+name})
    return {"supported":True,"status":"success","records":records,"count":len(records)}

def collect_winlogon_persistence() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("winlogon")
    import winreg
    base=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    vals=_registry_values(winreg.HKEY_LOCAL_MACHINE,base)
    keys=("Shell","Userinit","Notify","GinaDLL","VmApplet","Taskman")
    return {"supported":True,"status":"success","records":[{"name":k,"value":vals.get(k),"registry_path":base} for k in keys if vals.get(k) not in (None,"")],"count":sum(vals.get(k) not in (None,"") for k in keys)}

def collect_appinit_persistence() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("appinit_dlls")
    import winreg
    paths=[r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"]
    records=[]
    for path in paths:
        vals=_registry_values(winreg.HKEY_LOCAL_MACHINE,path)
        if vals.get("AppInit_DLLs") or vals.get("LoadAppInit_DLLs"):
            records.append({"registry_path":path,"AppInit_DLLs":vals.get("AppInit_DLLs",""),"LoadAppInit_DLLs":vals.get("LoadAppInit_DLLs",0)})
    return {"supported":True,"status":"success","records":records,"count":len(records)}

def collect_com_hijack_persistence() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("com_hijack")
    import winreg
    base=r"Software\Classes\CLSID"
    records=[]
    for clsid in _enum_subkeys(winreg.HKEY_CURRENT_USER,base,5000):
        for sub in ("InprocServer32","LocalServer32","TreatAs"):
            vals=_registry_values(winreg.HKEY_CURRENT_USER,base+"\\"+clsid+"\\"+sub)
            if vals:
                records.append({"clsid":clsid,"subkey":sub,"values":vals,"registry_path":base+"\\"+clsid+"\\"+sub})
    return {"supported":True,"status":"success","records":records[:1000],"count":min(len(records),1000)}

def collect_bits_persistence() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("bits_jobs")
    ps=r'Get-BitsTransfer -AllUsers | Select-Object DisplayName,JobId,OwnerAccountName,JobState,RemoteName,LocalName,CreationTime,ModificationTime | ConvertTo-Json -Compress -Depth 3'
    try:
        p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",ps],capture_output=True,text=True,timeout=15,creationflags=_WIN_FLAGS)
        if p.returncode!=0: return {"supported":True,"status":"error","error":(p.stderr or p.stdout)[:500],"records":[],"count":0}
        raw=json.loads(p.stdout) if p.stdout.strip() else []
        records=raw if isinstance(raw,list) else [raw]
        return {"supported":True,"status":"success","records":records[:500],"count":min(len(records),500)}
    except Exception as exc: return {"supported":True,"status":"error","error":str(exc),"records":[],"count":0}

def collect_all_users_startup() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("all_users_startup")
    root=Path(os.environ.get("SystemDrive", "C:")) / "Users"
    records=[]
    try:
        for profile in root.iterdir():
            folder=profile/"AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
            if not folder.is_dir(): continue
            for item in folder.iterdir():
                records.append({"user":profile.name,"name":item.name,"path":str(item),"type":"startup_folder"})
                if len(records)>=500: break
            if len(records)>=500: break
    except OSError: pass
    return {"supported":True,"status":"success","records":records,"count":len(records)}

def collect_browser_extensions() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("browser_extensions")
    local=Path(os.environ.get("LOCALAPPDATA", ""))
    roots={"chrome":local/"Google/Chrome/User Data","edge":local/"Microsoft/Edge/User Data","brave":local/"BraveSoftware/Brave-Browser/User Data"}
    records=[]
    for browser,root in roots.items():
        if not root.is_dir(): continue
        try: profiles=[p for p in root.iterdir() if p.is_dir() and (p.name=="Default" or p.name.startswith("Profile "))]
        except OSError: profiles=[]
        for profile in profiles:
            ext=profile/"Extensions"
            if not ext.is_dir(): continue
            try: ids=list(ext.iterdir())
            except OSError: ids=[]
            for extid in ids[:1000]:
                manifests=list(extid.glob("*/manifest.json"))[:1]
                for manifest in manifests:
                    try: meta=json.loads(manifest.read_text(encoding="utf-8",errors="replace"))
                    except Exception: meta={}
                    records.append({"browser":browser,"profile":profile.name,"extension_id":extid.name,"path":str(extid),"name":meta.get("name"),"version":meta.get("version"),"manifest":str(manifest)})
    return {"supported":True,"status":"success","records":records[:2000],"count":min(len(records),2000)}

def collect_office_addins() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("office_addins")
    import winreg
    roots=[r"Software\Microsoft\Office",r"Software\WOW6432Node\Microsoft\Office"]
    records=[]
    for base in roots:
        for ver in _enum_subkeys(winreg.HKEY_CURRENT_USER,base):
            for app in ("Word","Excel","PowerPoint","Outlook","Access"):
                path=f"{base}\\{ver}\\{app}\\Addins"
                for addin in _enum_subkeys(winreg.HKEY_CURRENT_USER,path):
                    vals=_registry_values(winreg.HKEY_CURRENT_USER,path+"\\"+addin)
                    records.append({"application":app,"version":ver,"addin":addin,"registry_path":path+"\\"+addin,"values":vals})
    return {"supported":True,"status":"success","records":records[:1000],"count":min(len(records),1000)}

def collect_lsa_auth_packages() -> dict[str, Any]:
    if os.name != "nt": return _unsupported("lsa_auth_packages")
    import winreg
    base=r"SYSTEM\CurrentControlSet\Control\Lsa"
    vals=_registry_values(winreg.HKEY_LOCAL_MACHINE,base)
    packages=vals.get("Authentication Packages", [])
    if isinstance(packages,str): packages=[packages]
    records=[{"package":str(x),"registry_path":base} for x in packages]
    return {"supported":True,"status":"success","records":records,"count":len(records)}

def collect_advanced_persistence() -> dict[str, Any]:
    funcs={
      "wmi_event_subscriptions":collect_wmi_event_subscriptions,"ifeo":collect_ifeo_persistence,"winlogon":collect_winlogon_persistence,"appinit_dlls":collect_appinit_persistence,"com_hijack":collect_com_hijack_persistence,"bits_jobs":collect_bits_persistence,"all_users_startup":collect_all_users_startup,"browser_extensions":collect_browser_extensions,"office_addins":collect_office_addins,"lsa_auth_packages":collect_lsa_auth_packages,
    }
    out={"supported":os.name=="nt","status":"success" if os.name=="nt" else "not_supported","surfaces":{}}
    for name,fn in funcs.items():
        try: out["surfaces"][name]=fn()
        except Exception as exc: out["surfaces"][name]={"supported":True,"status":"error","error":str(exc),"records":[],"count":0}
    out["count"]=sum(int(v.get("count",0)) for v in out["surfaces"].values())
    return out
