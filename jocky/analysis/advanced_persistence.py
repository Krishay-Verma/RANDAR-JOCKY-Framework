"""Rules for the additional Windows persistence surfaces."""
from __future__ import annotations
import re
from typing import Any
from jocky.analysis.finding import Finding
from jocky.analysis.persistence_enrichment import enrich_record

def _rows(evidence, surface):
    direct_key = {"wmi_event_subscriptions":"wmi_event_subscriptions","ifeo":"ifeo_persistence","winlogon":"winlogon_persistence","appinit_dlls":"appinit_persistence","com_hijack":"com_hijack_persistence","bits_jobs":"bits_persistence","all_users_startup":"all_users_startup","browser_extensions":"browser_extensions","office_addins":"office_addins","lsa_auth_packages":"lsa_auth_packages"}.get(surface, surface)
    direct = evidence.get(direct_key)
    if isinstance(direct, dict):
        return direct.get("records", []) or []
    adv=evidence.get("advanced_persistence") or {}
    data=(adv.get("surfaces") or {}).get(surface) or {}
    return data.get("records", []) if isinstance(data,dict) else []

def _path_signal(row):
    text=" ".join(str(v) for v in row.values())
    return bool(re.search(r"(?i)\\(?:temp|appdata|downloads|public)\\|%temp%|%appdata%",text))

def _rule(surface, name, default_severity="review_recommended"):
    def fn(evidence):
        out=[]
        for raw in _rows(evidence,surface):
            row=enrich_record(raw, raw.get("path") or raw.get("ExecutablePath") or raw.get("Debugger") or raw.get("AppInit_DLLs"))
            text=" ".join(str(v) for v in row.values())
            if surface=="winlogon" and str(row.get("name"))=="Shell" and str(row.get("value") or "").casefold()=="explorer.exe": continue
            if surface=="winlogon" and str(row.get("name"))=="Userinit" and "userinit.exe" in str(row.get("value") or "").casefold(): continue
            if surface=="lsa_auth_packages" and str(row.get("package") or "").casefold() in {"msv1_0","schannel","tspkg","wdigest","kerberos","cloudap"}: continue
            sev=default_severity
            if _path_signal(row): sev="medium"
            if row.get("verification",{}).get("signature_status") in {"invalid","nottrusted","notsigned","unsigned"}: sev="high"
            simple = {"surface": surface, "record": row}
            for k in ("path", "ExecutablePath", "Debugger", "AppInit_DLLs", "registry_path", "name", "image", "clsid", "package", "LocalName", "RemoteName"):
                if row.get(k) not in (None, ""):
                    simple[k] = row.get(k)
            out.append(Finding(name,sev,f"{name} persistence surface observed",f"The {surface} collector returned a persistence-related record. Review the configured value and its signer/hash before escalation.",simple))
        return out
    return fn

RULES={
 "wmi_event_subscription":_rule("wmi_event_subscriptions","wmi_event_subscription"),
 "ifeo_debugger":_rule("ifeo","ifeo_debugger","medium"),
 "winlogon_persistence":_rule("winlogon","winlogon_persistence","medium"),
 "appinit_dlls":_rule("appinit_dlls","appinit_dlls","medium"),
 "com_hijack":_rule("com_hijack","com_hijack"),
 "bits_persistence":_rule("bits_jobs","bits_persistence"),
 "all_users_startup":_rule("all_users_startup","all_users_startup"),
 "browser_extensions":_rule("browser_extensions","browser_extensions"),
 "office_addins":_rule("office_addins","office_addins"),
 "lsa_auth_packages":_rule("lsa_auth_packages","lsa_auth_packages","medium"),
}
