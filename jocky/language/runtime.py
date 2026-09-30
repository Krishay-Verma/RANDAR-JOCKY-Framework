"""V2.0 runtime target compatibility checks.

JOCKY bytecode is platform-neutral, while collectors expose platform-specific
capabilities. The runtime therefore checks a requested target before running
an artifact instead of silently executing it against the wrong host.
"""

from __future__ import annotations

import os

from jocky.language.compiler import host_target


class RuntimeCompatibilityError(RuntimeError):
    """Raised when an artifact targets a different operating environment."""


def is_target_compatible(target: str) -> bool:
    target = target.lower()
    return target == "portable" or target == host_target()


def require_target_compatible(target: str) -> None:
    if not is_target_compatible(target):
        raise RuntimeCompatibilityError(
            f"Artifact targets {target!r}, but this host provides {host_target()!r}. "
            "Compile for the host target or use the portable target."
        )


def runtime_info() -> dict[str, str]:
    return {
        "host_target": host_target(),
        "os_name": os.name,
    }
