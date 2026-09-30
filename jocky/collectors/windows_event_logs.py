"""Read-only Windows Event Log collector for the controlled V1.3 set.

The collector never accepts a log name or command from the JOCKY DSL.  On
Windows it queries a fixed allowlist of channels with ``wevtutil`` and parses
only event metadata.  For offline demos/tests an operator may point
``JOCKY_WINDOWS_EVENT_LOG_FIXTURE`` at a bounded XML export.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

_MAX_EVENTS_PER_LOG = 400
_MAX_TOTAL_EVENTS = 2000
_MAX_FIXTURE_BYTES = 20 * 1024 * 1024
_WIN_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

WINDOWS_LOGS = (
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
)

# Controlled V1.3 event families.
_EVENT_TYPES = {
    4688: "process_creation",
    4624: "logon",
    4625: "logon",
    4634: "logon",
    4647: "logon",
    4672: "privilege",
    7045: "service_change",
    4698: "scheduled_task_created",
    106: "scheduled_task_created",
    4699: "scheduled_task_deleted",
    4103: "powershell",
    4104: "powershell",
}


def collect_windows_event_logs() -> dict[str, Any]:
    fixture = os.environ.get("JOCKY_WINDOWS_EVENT_LOG_FIXTURE")
    # Fixture mode is deliberately operator-configured so offline CI/demo
    # runs can exercise the exact parser without pretending a non-Windows host
    # has a Windows Event Log service.
    if fixture:
        try:
            text = _read_fixture(fixture)
            events = _parse_events(text, source="fixture")
            events = [e for e in events if e["event_type"] in set(_EVENT_TYPES.values())]
            return _result(events, ["fixture"], truncated=len(events) >= _MAX_TOTAL_EVENTS)
        except Exception as exc:
            return {"supported": True, "platform": "Windows", "events": [], "count": 0, "sources": [], "error": str(exc)}

    if os.name != "nt":
        return {
            "supported": False,
            "platform": sys.platform,
            "events": [],
            "count": 0,
            "sources": [],
            "error": "Windows Event Log collection is only available on Windows.",
        }

    events: list[dict[str, Any]] = []
    sources: list[str] = []
    errors: list[str] = []
    truncated = False
    for log_name in WINDOWS_LOGS:
        if len(events) >= _MAX_TOTAL_EVENTS:
            truncated = True
            break
        try:
            output = _query_log(log_name, min(_MAX_EVENTS_PER_LOG, _MAX_TOTAL_EVENTS - len(events)))
            parsed = _parse_events(output, source=log_name)
            matched = [e for e in parsed if e["event_type"] in set(_EVENT_TYPES.values())]
            events.extend(matched)
            sources.append(log_name)
            # `truncated` means the matching event set hit the collection cap,
            # not merely that the raw channel returned the query count.
            if len(events) >= _MAX_TOTAL_EVENTS or len(matched) >= _MAX_EVENTS_PER_LOG:
                truncated = True
        except Exception as exc:
            errors.append(f"{log_name}: {exc}")

    result = _result(events[:_MAX_TOTAL_EVENTS], sources, truncated)
    if errors:
        result["errors"] = errors
    return result


def _query_log(log_name: str, count: int) -> str:
    proc = subprocess.run(
        ["wevtutil", "qe", log_name, "/f:xml", "/rd:true", "/c:" + str(count)],
        capture_output=True,
        text=True,
        timeout=45,
        creationflags=_WIN_FLAGS,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "query failed").strip()
        raise RuntimeError(detail[:500])
    return proc.stdout


def _read_fixture(path: str) -> str:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Event-log fixture not found: {resolved}")
    if resolved.stat().st_size > _MAX_FIXTURE_BYTES:
        raise ValueError("Event-log fixture exceeds the 20 MiB safety limit.")
    return resolved.read_text(encoding="utf-8", errors="replace")


def _parse_events(xml_text: str, source: str) -> list[dict[str, Any]]:
    # wevtutil may emit several standalone Event XML documents. Extract only
    # complete Event elements rather than attempting to wrap untrusted text.
    chunks = re.findall(r"<Event\b.*?</Event>", xml_text, flags=re.IGNORECASE | re.DOTALL)
    events: list[dict[str, Any]] = []
    for chunk in chunks[:_MAX_TOTAL_EVENTS]:
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError:
            continue
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        system = root.find("e:System", ns)
        if system is None:
            system = root.find("System")
        if system is None:
            continue
        def child(name: str):
            node = system.find(f"e:{name}", ns)
            return node if node is not None else system.find(name)
        provider = child("Provider")
        eid = child("EventID")
        channel = child("Channel")
        computer = child("Computer")
        record = child("EventRecordID")
        created = child("TimeCreated")
        event_id = _int(eid.text if eid is not None else None)
        if event_id is None:
            continue
        data: dict[str, Any] = {}
        nodes = root.findall("e:EventData/e:Data", ns)
        if not nodes:
            nodes = root.findall("EventData/Data")
        for node in nodes:
            name = node.attrib.get("Name") or f"field_{len(data)}"
            data[name] = node.text or ""
        # Some providers use UserData rather than EventData. Keep only direct
        # textual children so the result stays bounded and serializable.
        if not data:
            nodes = root.findall("e:UserData//*", ns)
            if not nodes:
                nodes = root.findall("UserData//*")
            for node in nodes[:50]:
                if node.text and node.text.strip():
                    data.setdefault(node.tag.rsplit("}", 1)[-1], node.text.strip())

        events.append({
            "source": source,
            "provider": provider.attrib.get("Name") if provider is not None else None,
            "event_id": event_id,
            "event_type": _EVENT_TYPES.get(event_id, "other"),
            "channel": channel.text if channel is not None else source,
            "computer": computer.text if computer is not None else None,
            "record_id": _int(record.text if record is not None else None),
            "timestamp": (created.attrib.get("SystemTime") if created is not None else None),
            "data": data,
        })
    return events


def _result(events: list[dict[str, Any]], sources: list[str], truncated: bool) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for event in events:
        kind = event["event_type"]
        counts[kind] = counts.get(kind, 0) + 1
    return {
        "supported": True,
        "platform": "Windows",
        "events": events,
        "count": len(events),
        "event_type_counts": counts,
        "sources": sources,
        "truncated": bool(truncated and events),
        "status": "success" if events or sources else "no_matching_events",
        "collection_note": "No matching events were returned; this is distinct from access failure or truncation.",
    }


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# Shared by the Sysmon collector; intentionally not part of the DSL surface.
def collect_log_metadata(log_name: str, event_ids: set[int], fixture_env: str) -> dict[str, Any]:
    """Query one fixed operator-selected channel for a bounded event-ID set."""
    fixture = os.environ.get(fixture_env)
    if os.name != "nt" and not fixture:
        return {"supported": False, "platform": sys.platform, "events": [], "count": 0,
                "error": "Sysmon collection is only available on Windows."}
    try:
        text = _read_fixture(fixture) if fixture else _query_log(log_name, _MAX_TOTAL_EVENTS)
        parsed = [e for e in _parse_events(text, source="fixture" if fixture else log_name)
                  if e["event_id"] in event_ids]
        parsed = parsed[:_MAX_TOTAL_EVENTS]
        counts: dict[str, int] = {}
        for event in parsed:
            key = str(event["event_id"])
            counts[key] = counts.get(key, 0) + 1
        return {
            "supported": True,
            "platform": "Windows",
            "source": "fixture" if fixture else log_name,
            "events": parsed,
            "count": len(parsed),
            "event_id_counts": counts,
            "truncated": len(parsed) >= _MAX_TOTAL_EVENTS,
        }
    except Exception as exc:
        detail = str(exc)
        lower = detail.casefold()
        if "not found" in lower or "cannot find" in lower or "could not be opened" in lower or "channel name" in lower:
            return {"supported": True, "platform": "Windows", "events": [], "count": 0,
                    "source": "fixture" if fixture else log_name, "status": "not_installed", "error": None, "message": "Channel is not installed or is unavailable on this host."}
        return {"supported": True, "platform": "Windows", "events": [], "count": 0,
                "source": "fixture" if fixture else log_name, "status": "error", "error": detail[:500]}
