"""
JOCKY Bytecode — serialisable, tamper-evident IR format.

A compiled investigation is a self-contained bytecode blob:

  Header (JSON, length-prefixed):
    - magic:      "JOCKY"
    - version:    int
    - name:       investigation name
    - compiled_at: ISO timestamp
    - command_count: int

  Body (JSON, length-prefixed):
    - list of opcode dicts

  Signature (32 bytes HMAC-SHA256):
    - signs header_bytes + body_bytes
    - key is the JOCKY_BYTECODE_KEY env var (or a dev default)

Wire format (all big-endian):
  [4 bytes header length]
  [N bytes header JSON]
  [4 bytes body length]
  [M bytes body JSON]
  [32 bytes HMAC-SHA256 signature]

Opcodes:
  COLLECT   target: str
  ANALYZE   rule: str
  REPORT    name: str
  LET       name: str, value_type: str, value: any
  IF        condition: dict, then_count: int, else_count: int
  (IF is followed by then_count + else_count opcodes in the body)

Threat surface closed:
  - Signature prevents tampered bytecode from executing silently
  - Version field enables future format changes with clear rejection
  - Magic bytes prevent accidental execution of arbitrary files
  - HMAC key never embedded in bytecode — must be present at runtime
"""

import hashlib
import hmac
import json
import os
import struct
from datetime import datetime, timezone
from typing import Any

from jocky.language.ir import (
    AnalyzeCommand, CollectCommand, IfCommand,
    Investigation, LetCommand, LiteralExpr,
    PropertyExpr, ReportCommand, VarExpr,
)

# ── Constants ──────────────────────────────────────────────────────────────────

MAGIC        = "JOCKY"
VERSION      = 1
_HEADER_FMT  = ">I"   # 4-byte big-endian unsigned int (length prefix)
_SIG_BYTES   = 32     # HMAC-SHA256 output length

_ENV_KEY     = "JOCKY_BYTECODE_KEY"

# A key shorter than this is too easy to guess or brute-force.
_MIN_KEY_LENGTH = 32


def _get_signing_key() -> bytes:
    raw = os.environ.get(_ENV_KEY, "").strip()
    if not raw:
        raise RuntimeError(
            f"{_ENV_KEY} is not set. Bytecode signing is disabled until "
            "a key is configured. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    if len(raw) < _MIN_KEY_LENGTH:
        raise RuntimeError(
            f"{_ENV_KEY} is too short (minimum {_MIN_KEY_LENGTH} characters)."
        )
    return raw.encode("utf-8")


# ── Compilation ────────────────────────────────────────────────────────────────

def compile_investigation(investigation: Investigation) -> bytes:
    """
    Compile an Investigation IR into signed bytecode.
    Returns the raw bytecode blob.
    """
    opcodes = _flatten_commands(investigation.commands)

    header = {
        "magic":         MAGIC,
        "version":       VERSION,
        "name":          investigation.name,
        "compiled_at":   datetime.now(timezone.utc).isoformat(),
        "command_count": len(opcodes),
    }

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    body_bytes   = json.dumps(opcodes, separators=(",", ":")).encode("utf-8")

    header_len = struct.pack(_HEADER_FMT, len(header_bytes))
    body_len   = struct.pack(_HEADER_FMT, len(body_bytes))

    payload = header_len + header_bytes + body_len + body_bytes
    sig     = _sign(payload)

    return payload + sig


def _flatten_commands(commands: list, depth: int = 0) -> list[dict]:
    """
    Recursively flatten the IR command tree into a linear opcode list.
    IfCommand emits an IF opcode followed by then-block and else-block
    opcodes, with counts in the IF opcode so the VM knows how many
    opcodes belong to each branch.
    """
    opcodes: list[dict] = []
    for cmd in commands:
        if isinstance(cmd, CollectCommand):
            opcodes.append({"op": "COLLECT", "target": cmd.target, "line": cmd.line})

        elif isinstance(cmd, AnalyzeCommand):
            opcodes.append({"op": "ANALYZE", "rule": cmd.rule, "line": cmd.line})

        elif isinstance(cmd, ReportCommand):
            opcodes.append({"op": "REPORT", "name": cmd.name, "line": cmd.line})

        elif isinstance(cmd, LetCommand):
            opcodes.append({
                "op":         "LET",
                "name":       cmd.name,
                "value":      _serialise_expr(cmd.value),
                "line":       cmd.line,
            })

        elif isinstance(cmd, IfCommand):
            then_ops = _flatten_commands(cmd.then_commands, depth + 1)
            else_ops = _flatten_commands(cmd.else_commands, depth + 1)
            opcodes.append({
                "op":         "IF",
                "condition":  _serialise_condition(cmd.condition),
                "then_count": len(then_ops),
                "else_count": len(else_ops),
                "line":       cmd.line,
            })
            opcodes.extend(then_ops)
            opcodes.extend(else_ops)

    return opcodes


def _serialise_expr(expr) -> dict:
    if isinstance(expr, LiteralExpr):
        return {"kind": "literal", "value": expr.value,
                "vtype": type(expr.value).__name__}
    if isinstance(expr, VarExpr):
        return {"kind": "var", "name": expr.name}
    if isinstance(expr, PropertyExpr):
        return {"kind": "property",
                "collector": expr.collector, "property": expr.property}
    raise ValueError(f"Unknown expr type: {type(expr).__name__}")


def _serialise_condition(cond) -> dict:
    return {
        "left":     _serialise_expr(cond.left),
        "operator": cond.operator,
        "right":    _serialise_expr(cond.right),
    }


# ── Verification and loading ───────────────────────────────────────────────────

class BytecodeError(Exception):
    """Raised when bytecode is malformed, wrong version, or tampered."""
    pass


def verify_and_load(blob: bytes) -> tuple[dict, list[dict]]:
    """
    Verify the HMAC signature and parse bytecode.

    Returns (header_dict, opcodes_list).
    Raises BytecodeError on any failure — all failure modes collapsed
    into one type to prevent oracle attacks.
    """
    try:
        if len(blob) < 8 + _SIG_BYTES:
            raise BytecodeError("Bytecode too short to be valid.")

        payload = blob[:-_SIG_BYTES]
        sig     = blob[-_SIG_BYTES:]

        # Constant-time signature check.
        expected_sig = _sign(payload)
        if not hmac.compare_digest(sig, expected_sig):
            raise BytecodeError(
                "Bytecode signature verification failed. "
                "The blob may have been tampered with."
            )

        offset = 0

        # Parse header.
        (header_len,) = struct.unpack_from(_HEADER_FMT, payload, offset)
        offset += 4
        header = json.loads(payload[offset: offset + header_len])
        offset += header_len

        # Validate header fields.
        if header.get("magic") != MAGIC:
            raise BytecodeError(
                f"Invalid magic bytes: {header.get('magic')!r}. "
                f"Expected {MAGIC!r}."
            )
        if header.get("version") != VERSION:
            raise BytecodeError(
                f"Unsupported bytecode version: {header.get('version')}. "
                f"Expected {VERSION}."
            )

        # Parse body.
        (body_len,) = struct.unpack_from(_HEADER_FMT, payload, offset)
        offset += 4
        opcodes = json.loads(payload[offset: offset + body_len])

        return header, opcodes

    except BytecodeError:
        raise
    except Exception as exc:
        raise BytecodeError(f"Bytecode parse failed: {exc}") from exc


# ── Signing ────────────────────────────────────────────────────────────────────

def _sign(payload: bytes) -> bytes:
    return hmac.new(_get_signing_key(), payload, hashlib.sha256).digest()


# ── Disassembly ────────────────────────────────────────────────────────────────

def disassemble(blob: bytes) -> str:
    """
    Human-readable disassembly of a bytecode blob.
    Useful for debugging and audit logging.
    """
    header, opcodes = verify_and_load(blob)

    lines = [
        f"JOCKY Bytecode v{header['version']}",
        f"Investigation : {header['name']}",
        f"Compiled at   : {header['compiled_at']}",
        f"Opcodes       : {header['command_count']}",
        f"Signature     : OK",
        "",
        "── Opcodes ──────────────────────────────────────",
    ]

    for i, op in enumerate(opcodes):
        op_name = op.get("op", "?")
        if op_name == "COLLECT":
            lines.append(f"  {i:04d}  COLLECT   {op['target']}")
        elif op_name == "ANALYZE":
            lines.append(f"  {i:04d}  ANALYZE   {op['rule']}")
        elif op_name == "REPORT":
            lines.append(f"  {i:04d}  REPORT    \"{op['name']}\"")
        elif op_name == "LET":
            v = op["value"]
            lines.append(
                f"  {i:04d}  LET       {op['name']} = "
                f"{v.get('value', v.get('name', v.get('collector','?')))}"
            )
        elif op_name == "IF":
            cond = op["condition"]
            left  = _fmt_expr(cond["left"])
            right = _fmt_expr(cond["right"])
            lines.append(
                f"  {i:04d}  IF        {left} {cond['operator']} {right} "
                f"[then:{op['then_count']} else:{op['else_count']}]"
            )
        else:
            lines.append(f"  {i:04d}  {op_name}")

    return "\n".join(lines)


def _fmt_expr(expr: dict) -> str:
    kind = expr.get("kind")
    if kind == "literal":
        return repr(expr["value"])
    if kind == "var":
        return expr["name"]
    if kind == "property":
        return f"{expr['collector']}.{expr['property']}"
    return "?"