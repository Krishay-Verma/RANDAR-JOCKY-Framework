"""Bounded, read-only PE metadata collector for V1.4.

The collector inspects executable files already visible through the Windows
process/module inventory. It never executes, modifies, maps, or writes a PE.
Metadata is parsed directly from the PE format to avoid introducing a large
third-party parser dependency.
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.serialization import pkcs7
except Exception:  # pragma: no cover - optional extraction path
    pkcs7 = None

_MAX_FILES = 300
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_IMPORTS = 500
_MAX_EXPORTS = 500
_MAX_SECTIONS = 96
_READ_CHUNK = 1024 * 1024

_MACHINE = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01C4: "ARM", 0x0200: "IA64"}


def collect_pe_metadata() -> dict[str, Any]:
    if os.name != "nt":
        return {
            "supported": False,
            "platform": os.name,
            "files": [],
            "count": 0,
            "error": "PE metadata collection is only available on Windows.",
        }

    paths: list[str] = []
    seen: set[str] = set()
    errors = 0

    # Process images are the primary bounded evidence surface.
    try:
        import psutil
        for proc in psutil.process_iter(["exe"]):
            try:
                path = proc.info.get("exe")
            except Exception:
                path = None
            _add_path(paths, seen, path)
            if len(paths) >= _MAX_FILES:
                break
    except Exception:
        errors += 1

    # Add loaded file-backed modules. This gives the collector a direct bridge
    # to the existing module/injection telemetry without scanning arbitrary disk.
    if len(paths) < _MAX_FILES:
        try:
            import psutil
            for proc in psutil.process_iter(["pid"]):
                if len(paths) >= _MAX_FILES:
                    break
                try:
                    for mapping in proc.memory_maps(grouped=False):
                        path = getattr(mapping, "path", "") or ""
                        if path and not path.startswith("["):
                            _add_path(paths, seen, path)
                            if len(paths) >= _MAX_FILES:
                                break
                except Exception:
                    errors += 1
        except Exception:
            errors += 1

    files: list[dict[str, Any]] = []
    for path in paths:
        try:
            metadata = _parse_pe(path)
            if metadata:
                files.append(metadata)
        except (OSError, PermissionError):
            errors += 1
        except Exception:
            errors += 1

    return {
        "supported": True,
        "platform": "Windows",
        "files": files,
        "count": len(files),
        "candidate_paths": len(paths),
        "parse_errors": errors,
        "truncated": len(paths) >= _MAX_FILES,
    }


def _add_path(paths: list[str], seen: set[str], path: str | None) -> None:
    if not path:
        return
    try:
        real = os.path.realpath(path)
    except OSError:
        real = path
    lower = real.lower()
    if not lower.endswith((".exe", ".dll", ".sys", ".ocx", ".scr")):
        return
    if lower in seen:
        return
    try:
        if not os.path.isfile(real):
            return
    except OSError:
        return
    seen.add(lower)
    paths.append(real)


def _parse_pe(path: str) -> dict[str, Any] | None:
    stat = os.stat(path)
    if stat.st_size < 64 or stat.st_size > _MAX_FILE_BYTES:
        return None
    with open(path, "rb") as handle:
        data = handle.read(min(stat.st_size, 2 * 1024 * 1024))
        if len(data) < 64 or data[:2] != b"MZ":
            return None
        pe_offset = _u32(data, 0x3C)
        if pe_offset is None or pe_offset + 24 > len(data):
            return None
        if data[pe_offset:pe_offset + 4] != b"PE\0\0":
            return None
        coff = pe_offset + 4
        machine = _u16(data, coff)
        sections_count = _u16(data, coff + 2) or 0
        timestamp = _u32(data, coff + 4) or 0
        optional_size = _u16(data, coff + 16) or 0
        characteristics = _u16(data, coff + 18) or 0
        optional = coff + 20
        if optional + optional_size > len(data) or optional_size < 72:
            return None
        magic = _u16(data, optional)
        if magic not in (0x10B, 0x20B):
            return None
        is_pe32_plus = magic == 0x20B
        image_base = _u64(data, optional + 24) if is_pe32_plus else _u32(data, optional + 28)
        section_alignment = _u32(data, optional + 32) or 0
        size_of_image = _u32(data, optional + 56) or 0
        subsystem = _u16(data, optional + 68) or 0
        dll_chars = _u16(data, optional + 70) or 0
        number_rva_sizes_off = optional + (108 if is_pe32_plus else 92)
        number_rva_sizes = _u32(data, number_rva_sizes_off) or 0
        data_dir = number_rva_sizes_off + 4

        sections_offset = optional + optional_size
        sections = []
        for index in range(min(sections_count, _MAX_SECTIONS)):
            off = sections_offset + index * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size = _u32(data, off + 8) or 0
            virtual_address = _u32(data, off + 12) or 0
            raw_size = _u32(data, off + 16) or 0
            raw_offset = _u32(data, off + 20) or 0
            characteristics_section = _u32(data, off + 36) or 0
            entropy = _section_entropy(handle, stat.st_size, raw_offset, raw_size)
            sections.append({
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "entropy": round(entropy, 4) if entropy is not None else None,
                "executable": bool(characteristics_section & 0x20000000),
                "writable": bool(characteristics_section & 0x80000000),
                "readable": bool(characteristics_section & 0x40000000),
            })

        dirs = []
        for i in range(min(number_rva_sizes, 16)):
            off = data_dir + i * 8
            if off + 8 > len(data):
                break
            dirs.append((_u32(data, off) or 0, _u32(data, off + 4) or 0))
        while len(dirs) < 16:
            dirs.append((0, 0))

        imports = _parse_imports(handle, stat.st_size, dirs[1], sections)
        exports = _parse_exports(handle, stat.st_size, dirs[0], sections)
        cert = _parse_certificate(handle, stat.st_size, dirs[4])
        file_sha256 = _sha256_file(handle)

        total_entropy = _file_entropy(handle, stat.st_size)
        return {
            "path": os.path.realpath(path),
            "filename": Path(path).name,
            "size": stat.st_size,
            "sha256": file_sha256,
            "architecture": _MACHINE.get(machine or 0, f"0x{machine or 0:04x}"),
            "machine": machine,
            "pe_type": "PE32+" if is_pe32_plus else "PE32",
            "timestamp": timestamp,
            "section_alignment": section_alignment,
            "size_of_image": size_of_image,
            "image_base": image_base,
            "subsystem": subsystem,
            "characteristics": characteristics,
            "dll_characteristics": dll_chars,
            "section_count": len(sections),
            "sections": sections,
            "imports": imports,
            "import_count": len(imports),
            "exports": exports,
            "export_count": len(exports),
            "entropy": round(total_entropy, 4) if total_entropy is not None else None,
            "signature_status": cert["status"],
            "signer": cert.get("signer"),
            "signature_certificate_count": cert.get("certificate_count", 0),
        }


def _parse_imports(handle, file_size: int, directory, sections) -> list[str]:
    rva, size = directory
    if not rva or not size:
        return []
    offset = _rva_to_offset(rva, sections, file_size)
    if offset is None:
        return []
    result: list[str] = []
    try:
        for _ in range(_MAX_IMPORTS):
            raw = _read_at(handle, offset, 20)
            if len(raw) < 20:
                break
            original_thunk, _, _, name_rva, first_thunk = struct.unpack("<IIIII", raw)
            if not any((original_thunk, name_rva, first_thunk)):
                break
            name_off = _rva_to_offset(name_rva, sections, file_size)
            if name_off is not None:
                name = _read_c_string(handle, name_off, 260)
                if name:
                    result.append(name)
            offset += 20
    except OSError:
        return result
    return result


def _parse_exports(handle, file_size: int, directory, sections) -> list[str]:
    rva, size = directory
    if not rva or not size:
        return []
    offset = _rva_to_offset(rva, sections, file_size)
    if offset is None:
        return []
    raw = _read_at(handle, offset, 40)
    if len(raw) < 40:
        return []
    _, _, _, _, _, _, number_of_names, _, _, address_names, _ = struct.unpack("<IIHHIIIIIII", raw)
    if number_of_names > _MAX_EXPORTS:
        number_of_names = _MAX_EXPORTS
    names_offset = _rva_to_offset(address_names, sections, file_size)
    if names_offset is None:
        return []
    exports: list[str] = []
    for i in range(number_of_names):
        entry = _read_at(handle, names_offset + i * 4, 4)
        if len(entry) < 4:
            break
        name_rva = struct.unpack("<I", entry)[0]
        name_off = _rva_to_offset(name_rva, sections, file_size)
        if name_off is None:
            continue
        name = _read_c_string(handle, name_off, 260)
        if name:
            exports.append(name)
    return exports


def _parse_certificate(handle, file_size: int, directory) -> dict[str, Any]:
    cert_file_offset, cert_size = directory
    if not cert_file_offset or cert_size < 8 or cert_file_offset + cert_size > file_size:
        return {"status": "unsigned", "certificate_count": 0, "signer": None}
    blob = _read_at(handle, cert_file_offset, min(cert_size, 4 * 1024 * 1024))
    if len(blob) < 8:
        return {"status": "embedded_signature", "certificate_count": 0, "signer": None}
    length, revision, cert_type = struct.unpack("<IHH", blob[:8])
    if cert_type != 0x0002 or length < 8 or length > len(blob):
        return {"status": "embedded_signature", "certificate_count": 0, "signer": None}
    payload = blob[8:length]
    signer = None
    certificate_count = 0
    if pkcs7 is not None:
        try:
            certs = pkcs7.load_der_pkcs7_certificates(payload)
            certificate_count = len(certs)
            if certs:
                signer = certs[0].subject.rfc4514_string()
        except Exception:
            pass
    return {"status": "embedded_signature", "certificate_count": certificate_count, "signer": signer}


def _rva_to_offset(rva: int, sections: list[dict[str, Any]], file_size: int) -> int | None:
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            delta = rva - start
            if delta >= section["raw_size"]:
                return None
            offset = section["raw_offset"] + delta
            return offset if 0 <= offset < file_size else None
    return rva if 0 <= rva < file_size else None


def _section_entropy(handle, file_size: int, offset: int, size: int) -> float | None:
    if not size or offset < 0 or offset >= file_size:
        return None
    size = min(size, file_size - offset, _MAX_FILE_BYTES)
    handle.seek(offset)
    data = handle.read(size)
    return _entropy(data)


def _file_entropy(handle, file_size: int) -> float | None:
    handle.seek(0)
    remaining = min(file_size, _MAX_FILE_BYTES)
    counts = [0] * 256
    total = 0
    while remaining:
        chunk = handle.read(min(_READ_CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        total += len(chunk)
        for value in chunk:
            counts[value] += 1
    if not total:
        return None
    return -sum((n / total) * math.log2(n / total) for n in counts if n)


def _sha256_file(handle) -> str:
    handle.seek(0)
    digest = hashlib.sha256()
    remaining = _MAX_FILE_BYTES
    while remaining:
        chunk = handle.read(min(_READ_CHUNK, remaining))
        if not chunk:
            break
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _read_at(handle, offset: int, size: int) -> bytes:
    if offset < 0:
        return b""
    handle.seek(offset)
    return handle.read(size)


def _read_c_string(handle, offset: int, max_len: int) -> str:
    raw = _read_at(handle, offset, max_len)
    raw = raw.split(b"\0", 1)[0]
    return raw.decode("ascii", "replace") if raw else ""


def _u16(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int | None:
    if offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts if n)
