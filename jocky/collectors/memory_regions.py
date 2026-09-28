"""Windows virtual-memory-region metadata collector.

Only region metadata is queried.  JOCKY does not read or write process memory.
The collector is intentionally bounded because a full virtual address-space
walk across every process can be expensive on a busy endpoint.
"""

import ctypes
import os
from ctypes import wintypes
from typing import Any

import psutil

_MAX_PROCESSES = 120
_MAX_REGIONS_PER_PROCESS = 250
_MAX_TOTAL_REGIONS = 8000

_PROCESS_QUERY_INFORMATION = 0x0400
_MEM_COMMIT = 0x1000
_MEM_PRIVATE = 0x20000

_PAGE_EXECUTE = 0x10
_PAGE_EXECUTE_READ = 0x20
_PAGE_EXECUTE_READWRITE = 0x40
_PAGE_EXECUTE_WRITECOPY = 0x80

_PROTECT_NAMES = {
    0x01: "NOACCESS", 0x02: "READONLY", 0x04: "READWRITE",
    0x08: "WRITECOPY", 0x10: "EXECUTE", 0x20: "EXECUTE_READ",
    0x40: "EXECUTE_READWRITE", 0x80: "EXECUTE_WRITECOPY",
}


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", wintypes.LPVOID),
            ("AllocationBase", wintypes.LPVOID),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    _kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


def collect_memory_regions() -> dict[str, Any]:
    """Collect bounded Windows virtual-memory metadata."""
    if os.name != "nt":
        return {
            "supported": False,
            "platform": os.name,
            "regions": [],
            "count": 0,
            "error": "The Windows memory-region collector is only available on Windows.",
        }

    regions: list[dict[str, Any]] = []
    errors = 0
    process_count = 0

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        if process_count >= _MAX_PROCESSES or len(regions) >= _MAX_TOTAL_REGIONS:
            break
        try:
            collected = _query_process(proc.pid, proc.info.get("name") or "unknown")
            regions.extend(collected)
            process_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            errors += 1
        except Exception:
            errors += 1

    return {
        "supported": True,
        "regions": regions[:_MAX_TOTAL_REGIONS],
        "count": min(len(regions), _MAX_TOTAL_REGIONS),
        "process_count": process_count,
        "process_errors": errors,
        "truncated": len(regions) > _MAX_TOTAL_REGIONS,
    }


def _query_process(pid: int, process_name: str) -> list[dict[str, Any]]:
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return []

    results: list[dict[str, Any]] = []
    try:
        address = 0
        mbi = _MEMORY_BASIC_INFORMATION()
        pointer_bits = ctypes.sizeof(ctypes.c_void_p) * 8
        max_address = (1 << (pointer_bits - 1)) - 1

        while address < max_address and len(results) < _MAX_REGIONS_PER_PROCESS:
            size = _kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not size or not mbi.RegionSize:
                break

            state = int(mbi.State)
            protect = int(mbi.Protect)
            region_type = int(mbi.Type)
            if state == _MEM_COMMIT:
                results.append({
                    "pid": pid,
                    "process_name": process_name,
                    "base_address": int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0),
                    "region_size": int(mbi.RegionSize),
                    "protect": protect,
                    "protect_name": _PROTECT_NAMES.get(protect, hex(protect)),
                    "state": state,
                    "type": region_type,
                    "type_name": _memory_type_name(region_type),
                    "is_executable": protect in {
                        _PAGE_EXECUTE, _PAGE_EXECUTE_READ,
                        _PAGE_EXECUTE_READWRITE, _PAGE_EXECUTE_WRITECOPY,
                    },
                    "is_private": region_type == _MEM_PRIVATE,
                    "is_private_executable": (
                        region_type == _MEM_PRIVATE and protect in {
                            _PAGE_EXECUTE, _PAGE_EXECUTE_READ,
                            _PAGE_EXECUTE_READWRITE, _PAGE_EXECUTE_WRITECOPY,
                        }
                    ),
                })

            next_address = int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0) + int(mbi.RegionSize)
            if next_address <= address:
                break
            address = next_address
    finally:
        _kernel32.CloseHandle(handle)

    return results


def _memory_type_name(value: int) -> str:
    if value == _MEM_PRIVATE:
        return "PRIVATE"
    if value == 0x1000000:
        return "IMAGE"
    if value == 0x40000:
        return "MAPPED"
    return hex(value)
