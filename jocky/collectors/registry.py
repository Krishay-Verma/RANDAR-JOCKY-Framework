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
from jocky.collectors.local_users import collect_local_users
from jocky.collectors.logged_in_users import collect_logged_in_users
from jocky.collectors.network_connections import collect_network_connections
from jocky.collectors.open_files import collect_open_files
from jocky.collectors.processes import collect_processes
from jocky.collectors.scheduled_tasks import collect_scheduled_tasks
from jocky.collectors.startup_items import collect_startup_items
from jocky.collectors.system_info import collect_system_info

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
    "logged_in_users":     collect_logged_in_users,
    "file_hash":           partial(collect_file_hashes, str(_EVIDENCE_DIR)),
    "scheduled_tasks":     collect_scheduled_tasks,
    "startup_items":       collect_startup_items,
    "open_files":          collect_open_files,
    "local_users":         collect_local_users,
}


def get_collector(name: str):
    return _COLLECTORS[name]


def is_known_collector(name: str) -> bool:
    return name in _COLLECTORS


def list_collectors() -> list[str]:
    return list(_COLLECTORS.keys())