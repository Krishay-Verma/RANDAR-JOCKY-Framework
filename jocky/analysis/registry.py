"""
Analysis rule registry — the only allowed entry points for evidence analysis.

All rules are pure functions: evidence dict in, list[Finding] out.
Adding a rule requires an explicit entry here.
"""

from jocky.analysis.rules import (
    rule_missing_executable_path,
    rule_unusual_executable_directory,
    rule_process_network_correlation,
)
from jocky.analysis.injection_rules import (
    rule_dll_sideloading,
    rule_injection_correlation,
    rule_process_hollowing_indicators,
    rule_reflective_load_indicators,
    rule_suspicious_module_loads,
    rule_thread_hijacking_indicators,
)
from jocky.analysis.network_hunting import (
    rule_suspicious_dns_queries, rule_dns_entropy, rule_rare_domains,
    rule_suspicious_tld_patterns, rule_dns_bursts, rule_unusual_query_types,
    rule_long_random_labels, rule_dns_tunneling_indicators, rule_dns_beaconing,
    rule_network_beaconing, rule_port_scan, rule_horizontal_scan,
    rule_service_discovery, rule_udp_scan, rule_network_classification,
    rule_process_network_correlation as rule_network_process_correlation,
)
from jocky.analysis.pe_rules import (
    rule_unsigned_loaded_module, rule_suspicious_imports, rule_high_entropy_module,
    rule_module_disk_mismatch, rule_suspicious_writable_module,
)
from jocky.analysis.windows_telemetry import (
    rule_encoded_powershell, rule_suspicious_powershell_parent,
    rule_powershell_network_activity, rule_powershell_child_processes,
    rule_suspicious_services, rule_writable_service_paths,
    rule_persistence_correlation,
    rule_service_configuration_anomalies,
)
from jocky.analysis.research_rules import (
    rule_in_memory_execution_indicators,
    rule_byoVD_driver_indicators,
)
from jocky.analysis.driver_forensics import build_driver_forensics_findings
from jocky.analysis.memory_forensics import build_memory_forensics, build_memory_forensics_findings
from jocky.analysis.persistence_forensics import rule_persistence_cross_surface_correlation, rule_persistence_privilege_correlation
from jocky.analysis.advanced_persistence import RULES as ADVANCED_RULES
from jocky.analysis.rules_extended import (
    check_high_connection_processes,
    check_privileged_user_anomaly,
    check_suspicious_startup_items,
    check_unusual_scheduled_tasks,
)


def _memory_forensics_correlation_rule(evidence):
    report = build_memory_forensics(evidence)
    return build_memory_forensics_findings(report)

def _driver_forensics_exposure_rule(evidence):
    report = {"drivers": (evidence.get("driver_inventory") or {}).get("drivers", [])}
    return build_driver_forensics_findings(report)

_RULES: dict[str, object] = {
    # Original rules — mapped to their DSL-facing names
    "missing_paths":               rule_missing_executable_path,
    "suspicious_processes":        rule_unusual_executable_directory,
    "process_network_correlation": rule_network_process_correlation,
    # Extended rules
    "unusual_scheduled_tasks":     check_unusual_scheduled_tasks,
    "suspicious_startup_items":    check_suspicious_startup_items,
    "high_connection_processes":   check_high_connection_processes,
    "privileged_user_anomaly":     check_privileged_user_anomaly,
    "suspicious_module_loads":      rule_suspicious_module_loads,
    "dll_sideloading":              rule_dll_sideloading,
    "process_hollowing_indicators": rule_process_hollowing_indicators,
    "reflective_load_indicators":   rule_reflective_load_indicators,
    "thread_hijacking_indicators":  rule_thread_hijacking_indicators,
    "injection_correlation":        rule_injection_correlation,
    "in_memory_execution_indicators": rule_in_memory_execution_indicators,
    "byovd_driver_indicators":       rule_byoVD_driver_indicators,
    # V2.5 driver forensic correlation rule. The registry adapter accepts the
    # evidence dictionary used by the standalone driver scan.
    "memory_forensics_correlation":  _memory_forensics_correlation_rule,
    "driver_forensics_exposure":     _driver_forensics_exposure_rule,
    # V1.2 network threat hunting
    "suspicious_dns_queries":       rule_suspicious_dns_queries,
    "dns_entropy":                  rule_dns_entropy,
    "rare_domains":                rule_rare_domains,
    "suspicious_tld_patterns":     rule_suspicious_tld_patterns,
    "dns_bursts":                  rule_dns_bursts,
    "unusual_query_types":         rule_unusual_query_types,
    "long_random_labels":           rule_long_random_labels,
    "dns_tunneling_indicators":    rule_dns_tunneling_indicators,
    "dns_beaconing":               rule_dns_beaconing,
    "network_beaconing":            rule_network_beaconing,
    "port_scan":                   rule_port_scan,
    "horizontal_scan":             rule_horizontal_scan,
    "service_discovery":            rule_service_discovery,
    "udp_scan":                    rule_udp_scan,
    "network_classification":      rule_network_classification,
    # V1.3 Windows telemetry
    "encoded_powershell":             rule_encoded_powershell,
    "suspicious_powershell_parent":   rule_suspicious_powershell_parent,
    "powershell_network_activity":   rule_powershell_network_activity,
    "powershell_child_processes":     rule_powershell_child_processes,
    "suspicious_services":            rule_suspicious_services,
    "writable_service_paths":         rule_writable_service_paths,
    "persistence_correlation":        rule_persistence_correlation,
    "persistence_cross_surface_correlation": rule_persistence_cross_surface_correlation,
    "persistence_privilege_correlation": rule_persistence_privilege_correlation,
    "service_configuration_anomalies": rule_service_configuration_anomalies,
    # V1.4 PE / module correlation
    "unsigned_loaded_module":          rule_unsigned_loaded_module,
    "suspicious_imports":              rule_suspicious_imports,
    "high_entropy_module":             rule_high_entropy_module,
    "module_disk_mismatch":            rule_module_disk_mismatch,
    "suspicious_writable_module":      rule_suspicious_writable_module,
    "wmi_event_subscription": ADVANCED_RULES["wmi_event_subscription"],
    "ifeo_debugger": ADVANCED_RULES["ifeo_debugger"],
    "winlogon_persistence": ADVANCED_RULES["winlogon_persistence"],
    "appinit_dlls": ADVANCED_RULES["appinit_dlls"],
    "com_hijack": ADVANCED_RULES["com_hijack"],
    "bits_persistence": ADVANCED_RULES["bits_persistence"],
    "all_users_startup": ADVANCED_RULES["all_users_startup"],
    "browser_extensions": ADVANCED_RULES["browser_extensions"],
    "office_addins": ADVANCED_RULES["office_addins"],
    "lsa_auth_packages": ADVANCED_RULES["lsa_auth_packages"],
}


def get_rule(name: str):
    return _RULES[name]


def is_known_rule(name: str) -> bool:
    return name in _RULES


def list_rules() -> list[str]:
    return list(_RULES.keys())