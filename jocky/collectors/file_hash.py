"""
File hashing collector.

Computes SHA-256 hashes for files within one explicitly approved
directory. This collector never scans the whole filesystem — the
directory it's allowed to touch is fixed by the investigator when the
investigation is configured, not by the JOCKY script itself.

For now (this milestone), the target directory is passed directly into
the function. Later, when we build the API, the investigator will pick
it via the dashboard.
"""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

# Hard safety ceiling: never hash more than this many files in one run,
# even if the approved directory turns out to be huge. Prevents an
# investigation from silently taking hours or filling the report with
# thousands of rows.
_MAX_FILES = 500

# Read files in chunks rather than loading a whole file into memory,
# so hashing a large file doesn't spike memory usage.
_CHUNK_SIZE = 65536


def collect_file_hashes(target_directory: str) -> dict:
    """
    Hash every file directly inside target_directory (non-recursive).

    Returns an error entry (not an exception) if the directory doesn't
    exist or isn't accessible, since a misconfigured investigation
    shouldn't crash the whole run.
    """
    directory = Path(target_directory)

    if not directory.exists() or not directory.is_dir():
        return {
            "target_directory": target_directory,
            "files": [],
            "count": 0,
            "error": f"Directory not found or not accessible: {target_directory}",
        }

    # Resolve once so every candidate can be checked against the real
    # location of the approved directory, not a path that merely looks
    # like it is inside.
    try:
        root = directory.resolve(strict=True)
    except OSError as exc:
        return {
            "target_directory": target_directory,
            "files": [],
            "count": 0,
            "error": f"Cannot resolve directory: {exc}",
        }

    files = []
    truncated = False

    for path in sorted(root.iterdir()):
        if len(files) >= _MAX_FILES:
            truncated = True
            break

        # Symlinks are refused outright: following one can leave the
        # approved directory and disclose files elsewhere on the host.
        if path.is_symlink():
            files.append({
                "path": str(path),
                "size_bytes": None,
                "sha256": None,
                "modified_at": None,
                "error": "Skipped: symbolic links are not followed.",
            })
            continue

        if not path.is_file():
            continue

        try:
            # Belt and braces: even a non-symlink entry must resolve to
            # somewhere inside the approved root.
            path.resolve(strict=True).relative_to(root)

            stat = path.stat()
            files.append({
                "path": str(path),
                "size_bytes": stat.st_size,
                "sha256": _hash_file(path),
                "modified_at": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat(),
            })
        except ValueError:
            files.append({
                "path": str(path),
                "size_bytes": None,
                "sha256": None,
                "modified_at": None,
                "error": "Skipped: resolves outside the approved directory.",
            })
        except (PermissionError, OSError) as exc:
            files.append({
                "path": str(path),
                "size_bytes": None,
                "sha256": None,
                "modified_at": None,
                "error": str(exc),
            })

    return {
        "target_directory": str(root),
        "files": files,
        "count": len(files),
        "truncated": truncated,
    }


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            hasher.update(chunk)
    return hasher.hexdigest()