from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class SoftwareProfile:
    key: str
    label: str
    category: str
    executable_tokens: tuple[str, ...] = ()
    path_tokens: tuple[str, ...] = ()
    driver_tokens: tuple[str, ...] = ()
    documented_kernel_component: bool = False

PROFILES = (
    SoftwareProfile("microsoft_defender", "Microsoft Defender", "antivirus", ("msmpeng.exe","msmpengcp.exe","senseir.exe","mssense.exe","nissrv.exe","securityhealthservice.exe"), ("\\microsoft\\defender\\","\\windows defender\\"), ("wdboot.sys","wdfilter.sys","wdnisdrv.sys"), True),
    SoftwareProfile("kaspersky", "Kaspersky", "antivirus", ("avp.exe","klnagent.exe","kav.exe"), ("\\kaspersky lab\\","\\kaspersky\\"), ("klif.sys","klim6.sys","klbackupflt.sys")),
    SoftwareProfile("crowdstrike", "CrowdStrike Falcon", "edr", ("csfalconservice.exe","csagent.exe"), ("\\crowdstrike\\",), ("csagent.sys",), True),
    SoftwareProfile("sentinelone", "SentinelOne", "edr", ("sentinelagent.exe","sentinelservicehost.exe"), ("\\sentinelone\\",), ("sentinelmonitor.sys",), True),
    SoftwareProfile("bitdefender", "Bitdefender", "antivirus", ("vsserv.exe","bdagent.exe"), ("\\bitdefender\\",), ("bdfwfpf.sys","trufos.sys")),
    SoftwareProfile("eset", "ESET", "antivirus", ("ekrn.exe",), ("\\eset\\",), ("eamonm.sys","ehdrv.sys")),
    SoftwareProfile("sophos", "Sophos", "antivirus", ("sophoshealth.exe","sophosfs.exe","sophosfilescanner.exe"), ("\\sophos\\",), ("sophos*.sys",)),
    SoftwareProfile("malwarebytes", "Malwarebytes", "antivirus", ("mbamservice.exe","mbamtray.exe"), ("\\malwarebytes\\",), ("mbam*.sys",)),
    SoftwareProfile("avast", "Avast", "antivirus", ("avastsvc.exe","aswidsagent.exe"), ("\\avast software\\","\\avast\\"), ("asw*.sys",)),
    SoftwareProfile("mcafee", "McAfee", "antivirus", ("mfemms.exe","mfevtps.exe","mcshield.exe"), ("\\mcafee\\",), ("mfe*.sys",)),
    SoftwareProfile("norton", "Norton", "antivirus", ("ns.exe","nortonsecurity.exe"), ("\\norton\\","\\symantec\\"), ("sym*.sys",)),
    SoftwareProfile("trend_micro", "Trend Micro", "antivirus", ("ntrtscan.exe","tmlisten.exe","pccntmon.exe"), ("\\trend micro\\",), ("tm*.sys",)),
    SoftwareProfile("riot_vanguard", "Riot Vanguard", "anti_cheat", ("vgc.exe","vgtray.exe"), ("\\riot vanguard\\",), ("vgk.sys",), True),
    SoftwareProfile("easy_anticheat", "Easy Anti-Cheat", "anti_cheat", ("easyanticheat.exe","easyanticheat_eos.exe","easyanticheat_launcher.exe"), ("\\easyanticheat\\","\\easyanticheat_eos\\"), ("easyanticheat*.sys",), True),
    SoftwareProfile("battleye", "BattlEye", "anti_cheat", ("beservice.exe","beservice_x64.exe","belauncher.exe"), ("\\battleye\\",), ("bedaisy.sys",), True),
    SoftwareProfile("denuvo_anticheat", "Denuvo Anti-Cheat", "anti_cheat", ("denuvoanticheat.exe",), ("\\denuvo\\","\\denuvo anti-cheat\\"), ("denuvo*.sys",), True),
    SoftwareProfile("faceit_ac", "FACEIT Anti-Cheat", "anti_cheat", ("faceitclient.exe","faceitservice.exe"), ("\\faceit\\",), ("faceit*.sys",), True),
    SoftwareProfile("vpn", "VPN client", "network_security", ("openvpn.exe","wireguard.exe","tailscale.exe","zerotier-one.exe"), ("\\openvpn\\","\\wireguard\\","\\tailscale\\","\\zerotier\\")),
    SoftwareProfile("vmware", "VMware", "virtualization", ("vmware.exe","vmware-vmx.exe"), ("\\vmware\\",), ("vmci.sys","vmnet*.sys")),
    SoftwareProfile("virtualbox", "VirtualBox", "virtualization", ("virtualbox.exe","virtualboxvm.exe"), ("\\virtualbox\\",), ("vbox*.sys",)),
)

def _norm(value: Any) -> str:
    return str(value or "").replace("/", "\\").lower()

def _match(value: str, token: str) -> bool:
    token = token.lower()
    if "*" in token:
        prefix = token.rstrip("*")
        return value.startswith(prefix) or prefix in value
    return value == token or token in value

def classify(executable: str | None = None, path: str | None = None, name: str | None = None, driver: bool = False) -> list[dict[str, Any]]:
    exe, path_n, name_n = _norm(executable), _norm(path), _norm(name)
    out = []
    for profile in PROFILES:
        checks = (
            ("name", name_n, profile.executable_tokens),
            ("executable", exe, profile.executable_tokens),
            ("path", path_n, profile.path_tokens),
            ("driver", path_n, profile.driver_tokens if driver else ()),
            ("service", name_n, profile.driver_tokens if driver else ()),
        )
        basis = next((f"{kind}:{token}" for kind, value, tokens in checks for token in tokens if value and _match(value, token)), None)
        if basis:
            out.append({"key": profile.key, "label": profile.label, "category": profile.category, "match_basis": basis, "documented_kernel_component": profile.documented_kernel_component})
    return out

def annotate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    processes = (evidence.get("processes") or {}).get("processes", [])
    drivers = (evidence.get("driver_inventory") or {}).get("drivers", [])
    driver_matches: dict[str, set[str]] = {}
    for driver in drivers:
        flags = classify(path=driver.get("image_path"), name=driver.get("service_name") or driver.get("display_name"), driver=True)
        driver["program_flags"] = flags
        driver["kernel_component_observed"] = True
        for flag in flags:
            driver_matches.setdefault(flag["key"], set()).add(str(driver.get("service_name") or driver.get("image_path") or "unknown"))
    for process in processes:
        flags = classify(executable=process.get("exe_path"), path=process.get("exe_path"), name=process.get("name"))
        kernel_evidence = []
        for flag in flags:
            kernel_evidence.extend(sorted(driver_matches.get(flag["key"], set())))
        process["program_flags"] = flags
        process["kernel_component_observed"] = bool(kernel_evidence)
        process["kernel_evidence"] = kernel_evidence[:20]
    for module in (evidence.get("modules") or {}).get("modules", []):
        flags = classify(path=module.get("module_path"), name=module.get("module_name"))
        module["program_flags"] = flags
        module["kernel_component_observed"] = str(module.get("module_name") or "").lower().endswith(".sys")
    return evidence

def summarize(evidence: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    kernel = []
    for collection, key in (("processes","processes"),("modules","modules"),("driver_inventory","drivers")):
        for item in (evidence.get(collection) or {}).get(key, []) or []:
            for flag in item.get("program_flags", []) or []:
                counts[flag["key"]] = counts.get(flag["key"], 0) + 1
            if item.get("kernel_component_observed"):
                kernel.append({"name": item.get("name") or item.get("service_name") or item.get("module_name"), "path": item.get("exe_path") or item.get("image_path") or item.get("module_path")})
    return {"flagged_programs": counts, "kernel_components_observed": kernel[:100]}
