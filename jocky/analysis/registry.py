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
)
from jocky.analysis.rules_extended import (
    check_high_connection_processes,
    check_privileged_user_anomaly,
    check_suspicious_startup_items,
    check_unusual_scheduled_tasks,
)

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
    # V1.4 PE / module correlation
    "unsigned_loaded_module":          rule_unsigned_loaded_module,
    "suspicious_imports":              rule_suspicious_imports,
    "high_entropy_module":             rule_high_entropy_module,
    "module_disk_mismatch":            rule_module_disk_mismatch,
    "suspicious_writable_module":      rule_suspicious_writable_module,
}


def get_rule(name: str):
    return _RULES[name]


def is_known_rule(name: str) -> bool:
    return name in _RULES


def list_rules() -> list[str]:
    return list(_RULES.keys())