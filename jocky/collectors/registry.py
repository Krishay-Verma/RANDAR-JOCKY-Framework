"""
Collector registry — the only allowed entry points for data collection.

Adding a collector requires an explicit entry here.
The interpreter resolves collector names exclusively through this dict
and calls each entry with zero arguments, so any collector that needs
configuration must have it bound here.
"""

import os
from functools import partial
from pathlib import Path

from jocky.collectors.file_hash import collect_file_hashes
from jocky.collectors.drivers import collect_driver_inventory
from jocky.collectors.local_users import collect_local_users
from jocky.collectors.memory_regions import collect_memory_regions
from jocky.collectors.modules import collect_modules
from jocky.collectors.threads import collect_threads
from jocky.collectors.logged_in_users import collect_logged_in_users
from jocky.collectors.network_connections import collect_network_connections
from jocky.collectors.network_artifacts import collect_network_artifacts
from jocky.collectors.windows_event_logs import collect_windows_event_logs
from jocky.collectors.sysmon_events import collect_sysmon_events
from jocky.collectors.services import collect_services
from jocky.collectors.pe_metadata import collect_pe_metadata
from jocky.collectors.open_files import collect_open_files
from jocky.collectors.processes import collect_processes
from jocky.collectors.scheduled_tasks import collect_scheduled_tasks
from jocky.collectors.startup_items import collect_startup_items
from jocky.collectors.system_info import collect_system_info
from jocky.collectors.user_context import collect_clipboard_metadata, collect_browser_history_metadata, collect_browser_cookie_metadata
from jocky.collectors.advanced_persistence import (
    collect_wmi_event_subscriptions, collect_ifeo_persistence, collect_winlogon_persistence,
    collect_appinit_persistence, collect_com_hijack_persistence, collect_bits_persistence,
    collect_all_users_startup, collect_browser_extensions, collect_office_addins, collect_lsa_auth_packages,
    collect_advanced_persistence,
)

# The one directory file_hash is allowed to read. Anchored to the project
# root (three levels up from this file), NOT the current working directory,
# so the result does not change depending on where uvicorn was launched.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Override with JOCKY_EVIDENCE_DIR. The path is fixed by the operator's
# environment, never by a script, so a script cannot choose what is hashed.
_EVIDENCE_DIR = Path(
    os.environ.get("JOCKY_EVIDENCE_DIR") or (_PROJECT_ROOT / "sample_evidence")
).resolve()

_COLLECTORS: dict[str, object] = {
    "system_info":         collect_system_info,
    "processes":           collect_processes,
    "network_connections": collect_network_connections,
    "network_artifacts": collect_network_artifacts,
    "windows_event_logs":  collect_windows_event_logs,
    "sysmon_events":        collect_sysmon_events,
    "services":             collect_services,
    "pe_metadata":          collect_pe_metadata,
    "logged_in_users":     collect_logged_in_users,
    "file_hash":           partial(collect_file_hashes, str(_EVIDENCE_DIR)),
    "scheduled_tasks":     collect_scheduled_tasks,
    "startup_items":       collect_startup_items,
    "open_files":          collect_open_files,
    "local_users":         collect_local_users,
    "modules":             collect_modules,
    "threads":             collect_threads,
    "memory_regions":      collect_memory_regions,
    "driver_inventory":    collect_driver_inventory,
    "wmi_event_subscriptions": collect_wmi_event_subscriptions,
    "ifeo_persistence": collect_ifeo_persistence,
    "winlogon_persistence": collect_winlogon_persistence,
    "appinit_persistence": collect_appinit_persistence,
    "com_hijack_persistence": collect_com_hijack_persistence,
    "bits_persistence": collect_bits_persistence,
    "all_users_startup": collect_all_users_startup,
    "browser_extensions": collect_browser_extensions,
    "office_addins": collect_office_addins,
    "lsa_auth_packages": collect_lsa_auth_packages,
    "advanced_persistence": collect_advanced_persistence,
    "clipboard_metadata": collect_clipboard_metadata,
    "browser_history_metadata": collect_browser_history_metadata,
    "browser_cookie_metadata": collect_browser_cookie_metadata,
}


def get_collector(name: str):
    return _COLLECTORS[name]


def is_known_collector(name: str) -> bool:
    return name in _COLLECTORS


def list_collectors() -> list[str]:
    return list(_COLLECTORS.keys())