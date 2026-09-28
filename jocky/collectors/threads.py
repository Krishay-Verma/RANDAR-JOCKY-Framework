"""Windows process-thread metadata collector.

This collector gathers thread inventory and timing metadata only.  It never
suspends, resumes, terminates, or modifies a thread.
"""

import os
from typing import Any

import psutil

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenThread.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _ntdll.NtQueryInformationThread.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
    ]
    _ntdll.NtQueryInformationThread.restype = wintypes.LONG

_MAX_PROCESSES = 400
_MAX_THREADS = 6000
_THREAD_QUERY_INFORMATION = 0x0040


def collect_threads() -> dict[str, Any]:
    """Collect observable thread metadata on Windows."""
    if os.name != "nt":
        return {
            "supported": False,
            "platform": os.name,
            "threads": [],
            "count": 0,
            "error": "The Windows thread collector is only available on Windows.",
        }

    threads: list[dict[str, Any]] = []
    errors = 0
    for proc in psutil.process_iter(["pid", "name"]):
        if len(threads) >= _MAX_THREADS:
            break
        try:
            for thread in proc.threads():
                if len(threads) >= _MAX_THREADS:
                    break
                start_address = _safe_thread_start_address(thread.id)
                threads.append({
                    "pid": proc.pid,
                    "process_name": proc.info.get("name") or "unknown",
                    "thread_id": thread.id,
                    "user_time": thread.user_time,
                    "system_time": thread.system_time,
                    "start_address": start_address,
                    "start_address_status": "collected" if start_address is not None else "unavailable",
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            errors += 1
        except Exception:
            errors += 1

    return {
        "supported": True,
        "threads": threads,
        "count": len(threads),
        "process_errors": errors,
        "truncated": len(threads) >= _MAX_THREADS,
    }


def _safe_thread_start_address(thread_id: int) -> int | None:
    """Read a thread start address without suspending or modifying the thread."""
    if os.name != "nt":
        return None
    handle = _kernel32.OpenThread(_THREAD_QUERY_INFORMATION, False, thread_id)
    if not handle:
        return None
    try:
        value = ctypes.c_void_p()
        returned = wintypes.ULONG()
        # ThreadQuerySetWin32StartAddress is information class 9.
        status = _ntdll.NtQueryInformationThread(
            handle, 9, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(returned)
        )
        if status != 0:
            return None
        return int(value.value) if value.value else None
    except (OSError, ValueError):
        return None
    finally:
        _kernel32.CloseHandle(handle)
