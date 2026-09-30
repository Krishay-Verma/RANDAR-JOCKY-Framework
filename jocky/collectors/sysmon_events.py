"""Bounded, read-only Sysmon Event Log collector for V1.3."""

from typing import Any

from jocky.collectors.windows_event_logs import collect_log_metadata

SYSMON_EVENT_IDS = {1, 3, 7, 8, 10, 11, 12, 13, 14, 22}


def collect_sysmon_events() -> dict[str, Any]:
    result = collect_log_metadata(
        "Microsoft-Windows-Sysmon/Operational",
        SYSMON_EVENT_IDS,
        "JOCKY_SYSMON_EVENT_LOG_FIXTURE",
    )
    if result.get("status") == "not_installed":
        result["error"] = None
    return result
