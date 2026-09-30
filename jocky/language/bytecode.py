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
    PropertyExpr, ReportCommand, VarExpr, UserRuleCommand,
)

# ── Constants ──────────────────────────────────────────────────────────────────

MAGIC        = "JOCKY"
VERSION      = 1
_HEADER_FMT  = ">I"   # 4-byte big-endian unsigned int (length prefix)
_SIG_BYTES   = 32     # HMAC-SHA256 output length

_ENV_KEY     = "JOCKY_BYTECODE_KEY"

# A key shorter than this is too easy to guess or brute-force.
_MIN_KEY_LENGTH = 32
_MAX_OPCODES = 2000
_MAX_NAME_LENGTH = 200
_VALID_OPERATORS = {">", "<", ">=", "<=", "==", "!="}


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

def compile_investigation(
    investigation: Investigation,
    *,
    toolchain_version: str = "1.x",
    ir_version: str = "1.0",
    target: str = "portable",
    deterministic: bool = False,
    source_hash: str | None = None,
    ir_hash: str | None = None,
    opcodes: list[dict] | None = None,
    transformation_profile: str = "none",
    transformation_seed: str | None = None,
    transformation_id: str | None = None,
    transformation_input_hash: str | None = None,
    transformation_output_hash: str | None = None,
    transformation_changes: list[str] | None = None,
    build_id: str | None = None,
) -> bytes:
    """
    Compile an Investigation IR into signed bytecode.
    Returns the raw bytecode blob.
    """
    opcodes = list(opcodes) if opcodes is not None else _flatten_commands(investigation.commands)
    if len(opcodes) > _MAX_OPCODES:
        raise BytecodeError(
            f"Investigation produces too many bytecode operations (max {_MAX_OPCODES})."
        )

    header = {
        "magic":            MAGIC,
        "version":          VERSION,
        "name":             investigation.name,
        "compiled_at":      None if deterministic else datetime.now(timezone.utc).isoformat(),
        "command_count":    len(opcodes),
        "toolchain_version": toolchain_version,
        "ir_version":       ir_version,
        "target":            target,
        "deterministic":    bool(deterministic),
        "transformation_profile": transformation_profile,
    }
    if source_hash is not None:
        header["source_hash"] = source_hash
    if ir_hash is not None:
        header["ir_hash"] = ir_hash
    if transformation_seed is not None:
        header["transformation_seed"] = transformation_seed
    if transformation_id is not None:
        header["transformation_id"] = transformation_id
    if transformation_input_hash is not None:
        header["transformation_input_hash"] = transformation_input_hash
    if transformation_output_hash is not None:
        header["transformation_output_hash"] = transformation_output_hash
    if transformation_changes is not None:
        header["transformation_changes"] = list(transformation_changes)
    if build_id is not None:
        header["build_id"] = build_id

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
            opcodes.append({"op": "ANALYZE", "rule": cmd.rule, "where": _serialise_condition(cmd.where) if cmd.where else None, "line": cmd.line})

        elif isinstance(cmd, UserRuleCommand):
            opcodes.append({"op": "USER_RULE", "name": cmd.name, "condition": _serialise_condition(cmd.condition), "severity": cmd.severity, "line": cmd.line})

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
    if cond.kind != "comparison":
        return {"kind": cond.kind, "children": [_serialise_condition(c) for c in cond.children]}
    return {"kind": "comparison", "left": _serialise_expr(cond.left), "operator": cond.operator, "right": _serialise_expr(cond.right)}


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

        # Parse header with strict length bounds before slicing.
        if len(payload) < offset + 4:
            raise BytecodeError("Missing bytecode header length.")
        (header_len,) = struct.unpack_from(_HEADER_FMT, payload, offset)
        offset += 4
        if header_len <= 0 or header_len > len(payload) - offset:
            raise BytecodeError("Invalid bytecode header length.")
        header = json.loads(payload[offset: offset + header_len])
        offset += header_len
        if not isinstance(header, dict):
            raise BytecodeError("Bytecode header must be an object.")
        if not isinstance(header.get("name"), str) or not header["name"].strip():
            raise BytecodeError("Bytecode investigation name is invalid.")
        if not isinstance(header.get("command_count"), int) or header["command_count"] < 0:
            raise BytecodeError("Bytecode command count is invalid.")
        if "toolchain_version" in header and (
            not isinstance(header["toolchain_version"], str)
            or len(header["toolchain_version"]) > 50
        ):
            raise BytecodeError("Bytecode toolchain version is invalid.")
        if "ir_version" in header and (
            not isinstance(header["ir_version"], str) or len(header["ir_version"]) > 30
        ):
            raise BytecodeError("Bytecode IR version is invalid.")
        if "target" in header and header["target"] not in {"portable", "windows", "ubuntu"}:
            raise BytecodeError("Bytecode target is invalid.")
        if "deterministic" in header and not isinstance(header["deterministic"], bool):
            raise BytecodeError("Bytecode deterministic flag is invalid.")
        if "transformation_profile" in header:
            if not isinstance(header["transformation_profile"], str) or len(header["transformation_profile"]) > 50:
                raise BytecodeError("Bytecode transformation profile is invalid.")
        for value_name in ("transformation_id", "transformation_input_hash", "transformation_output_hash"):
            if value_name in header:
                value = header[value_name]
                if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                    raise BytecodeError(f"Bytecode {value_name} is invalid.")
        if "transformation_seed" in header and (not isinstance(header["transformation_seed"], str) or len(header["transformation_seed"]) > 256):
            raise BytecodeError("Bytecode transformation seed is invalid.")
        if "build_id" in header:
            value = header["build_id"]
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise BytecodeError("Bytecode build_id is invalid.")
        for hash_name in ("source_hash", "ir_hash"):
            if hash_name in header:
                value = header[hash_name]
                if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                    raise BytecodeError(f"Bytecode {hash_name} is invalid.")

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

        # Parse body with strict length bounds.
        if len(payload) < offset + 4:
            raise BytecodeError("Missing bytecode body length.")
        (body_len,) = struct.unpack_from(_HEADER_FMT, payload, offset)
        offset += 4
        if body_len <= 0 and header["command_count"] != 0:
            raise BytecodeError("Bytecode body length is inconsistent.")
        if body_len > len(payload) - offset:
            raise BytecodeError("Invalid bytecode body length.")
        body_end = offset + body_len
        opcodes = json.loads(payload[offset:body_end])
        if not isinstance(opcodes, list):
            raise BytecodeError("Bytecode body must be an opcode list.")
        if len(opcodes) != header["command_count"]:
            raise BytecodeError("Bytecode command count does not match body.")
        if body_end != len(payload):
            raise BytecodeError("Unexpected trailing data in bytecode payload.")

        _validate_opcodes(opcodes)
        return header, opcodes

    except BytecodeError:
        raise
    except Exception as exc:
        raise BytecodeError(f"Bytecode parse failed: {exc}") from exc




def _validate_opcodes(opcodes: list[dict]) -> None:
    """Validate signed opcode structure and JOCKY capability boundaries."""
    if len(opcodes) > _MAX_OPCODES:
        raise BytecodeError(f"Bytecode contains too many operations (max {_MAX_OPCODES}).")

    from jocky.collectors.registry import is_known_collector
    from jocky.analysis.registry import is_known_rule
    from jocky.language.interpreter import list_evidence_properties

    valid_ops = {"COLLECT", "ANALYZE", "REPORT", "LET", "IF", "USER_RULE"}
    allowed_properties = set(list_evidence_properties())
    valid_operators = _VALID_OPERATORS
    variable_names = set()

    for index, op in enumerate(opcodes):
        if not isinstance(op, dict):
            raise BytecodeError(f"Opcode {index} is not an object.")
        kind = op.get("op")
        if kind not in valid_ops:
            raise BytecodeError(f"Opcode {index} has unknown operation {kind!r}.")
        if not isinstance(op.get("line", 0), int) or op.get("line", 0) < 0:
            raise BytecodeError(f"Opcode {index} has an invalid source line.")
        if kind in {"COLLECT", "ANALYZE", "REPORT"}:
            field = {"COLLECT": "target", "ANALYZE": "rule", "REPORT": "name"}[kind]
            value = op.get(field)
            if not isinstance(value, str) or not value or len(value) > _MAX_NAME_LENGTH:
                raise BytecodeError(f"Opcode {index} has an invalid {field}.")
            if kind == "COLLECT" and not is_known_collector(value):
                raise BytecodeError(f"Opcode {index} references an unknown collector.")
            if kind == "ANALYZE" and not is_known_rule(value):
                raise BytecodeError(f"Opcode {index} references an unknown analysis rule.")
            if kind == "ANALYZE" and op.get("where") is not None:
                _validate_condition(op["where"], index, allowed_properties, variable_names, finding_mode=True)
        elif kind == "LET":
            name = op.get("name")
            if not isinstance(name, str) or not name or len(name) > 100:
                raise BytecodeError(f"Opcode {index} has an invalid variable name.")
            import re
            if not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
                raise BytecodeError(f"Opcode {index} has an invalid variable name.")
            variable_names.add(name)
            _validate_expr(op.get("value"), index, allowed_properties, variable_names)
        elif kind == "USER_RULE":
            name = op.get("name"); severity = op.get("severity")
            if not isinstance(name, str) or not name or len(name) > _MAX_NAME_LENGTH:
                raise BytecodeError(f"Opcode {index} has an invalid user-rule name.")
            if severity not in {"informational", "review_recommended", "medium", "high", "critical"}:
                raise BytecodeError(f"Opcode {index} has an invalid user-rule severity.")
            _validate_condition(op.get("condition"), index, allowed_properties, variable_names, finding_mode=True)
        elif kind == "IF":
            condition = op.get("condition")
            if not isinstance(condition, dict):
                raise BytecodeError(f"Opcode {index} has an invalid condition.")
            _validate_condition(condition, index, allowed_properties, variable_names)
            tc, ec = condition.get("then_count"), condition.get("else_count")
            # branch counts are stored on the opcode, not condition; retain below
            tc, ec = op.get("then_count"), op.get("else_count")
            if not isinstance(tc, int) or not isinstance(ec, int) or tc < 0 or ec < 0:
                raise BytecodeError(f"Opcode {index} has invalid branch counts.")
            if tc + ec > len(opcodes) - index - 1:
                raise BytecodeError(f"IF opcode {index} exceeds opcode body.")

    for index, op in enumerate(opcodes):
        if op.get("op") == "IF":
            end = index + 1 + op["then_count"] + op["else_count"]
            if end > len(opcodes):
                raise BytecodeError(f"IF opcode {index} exceeds opcode body.")


def _validate_condition(condition: object, index: int, allowed_properties: set[str], variable_names: set[str], finding_mode: bool = False) -> None:
    if not isinstance(condition, dict): raise BytecodeError(f"Opcode {index} has an invalid condition.")
    kind = condition.get("kind", "comparison")
    if kind in {"and", "or", "not"}:
        children = condition.get("children")
        if not isinstance(children, list) or not children or len(children) > 20:
            raise BytecodeError(f"Opcode {index} has invalid boolean condition children.")
        for child in children: _validate_condition(child, index, allowed_properties, variable_names, finding_mode)
        return
    if kind != "comparison": raise BytecodeError(f"Opcode {index} has unknown condition kind.")
    operator = condition.get("operator")
    if operator not in _VALID_OPERATORS: raise BytecodeError(f"Opcode {index} has an invalid comparison operator.")
    _validate_expr(condition.get("left"), index, allowed_properties, variable_names, finding_mode)
    _validate_expr(condition.get("right"), index, allowed_properties, variable_names, finding_mode)

def _validate_expr(expr: object, index: int, allowed_properties: set[str], variable_names: set[str], finding_mode: bool = False) -> None:
    if not isinstance(expr, dict):
        raise BytecodeError(f"Opcode {index} has an invalid expression.")
    kind = expr.get("kind")
    if kind == "literal":
        value = expr.get("value")
        if not isinstance(value, (str, int, bool)) or isinstance(value, float):
            raise BytecodeError(f"Opcode {index} has an invalid literal.")
        return
    if kind == "var":
        name = expr.get("name")
        if not isinstance(name, str) or name not in variable_names:
            raise BytecodeError(f"Opcode {index} references an undefined variable.")
        return
    if kind == "property":
        collector = expr.get("collector")
        prop = expr.get("property")
        if not isinstance(collector, str) or not isinstance(prop, str):
            raise BytecodeError(f"Opcode {index} has an invalid evidence property.")
        allowed_finding = {"process.name", "process.pid", "destination.address", "destination.ip", "destination.port", "destination.is_external", "source.address", "source.ip", "source.port", "module.name", "module.path", "evidence.source_rule"}
        if finding_mode:
            if f"{collector}.{prop}" not in allowed_finding: raise BytecodeError(f"Opcode {index} references an unapproved finding property.")
        elif f"{collector}.{prop}" not in allowed_properties:
            raise BytecodeError(f"Opcode {index} references an unapproved evidence property.")
        return
    raise BytecodeError(f"Opcode {index} has an unknown expression kind.")

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
        f"Toolchain     : {header.get('toolchain_version', 'legacy')}",
        f"IR version    : {header.get('ir_version', 'legacy')}",
        f"Target        : {header.get('target', 'legacy')}",
        f"Deterministic : {header.get('deterministic', False)}",
        f"Source hash   : {header.get('source_hash', 'n/a')}",
        f"IR hash       : {header.get('ir_hash', 'n/a')}",
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