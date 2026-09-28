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
    "process_network_correlation": rule_process_network_correlation,
    # Extended rules
    "unusual_scheduled_tasks":     check_unusual_scheduled_tasks,
    "suspicious_startup_items":    check_suspicious_startup_items,
    "high_connection_processes":   check_high_connection_processes,
    "privileged_user_anomaly":     check_privileged_user_anomaly,
}


def get_rule(name: str):
    return _RULES[name]


def is_known_rule(name: str) -> bool:
    return name in _RULES


def list_rules() -> list[str]:
    return list(_RULES.keys())