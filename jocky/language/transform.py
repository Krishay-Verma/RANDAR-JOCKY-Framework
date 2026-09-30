"""JOCKY V2.2 representation transformation and research pipeline.

V2.2 extends the signed JOCKY representation without changing the
investigation semantics.  The pipeline is deliberately limited to the JOCKY
IR/bytecode representation; it does not generate native binaries, alter
security controls, or implement process/kernel evasion techniques.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
from typing import Any

from jocky.language.bytecode import _flatten_commands
from jocky.language.ir import Investigation

TRANSFORM_VERSION = "2.2.0"
TRANSFORMATION_PROFILES = frozenset({
    "none",
    "deterministic",
    "randomized",
    "reproducible-randomized",
    "compatibility-preserving",
    "automated-obfuscation",
})


class TransformationError(ValueError):
    """Raised when a requested representation transformation is invalid."""


@dataclass(frozen=True)
class TransformationResult:
    opcodes: list[dict]
    profile: str
    seed: str | None
    transformation_id: str
    input_hash: str
    output_hash: str
    changes: tuple[str, ...]


def validate_profile(profile: str) -> str:
    value = str(profile).strip().lower()
    if value not in TRANSFORMATION_PROFILES:
        raise TransformationError(
            f"Unsupported transformation profile {profile!r}. "
            f"Expected one of: {', '.join(sorted(TRANSFORMATION_PROFILES))}."
        )
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _rename_expr(expr: dict, mapping: dict[str, str]) -> dict:
    result = dict(expr)
    if result.get("kind") == "var" and result.get("name") in mapping:
        result["name"] = mapping[result["name"]]
    return result


def _rename_condition(condition: dict | None, mapping: dict[str, str]) -> dict | None:
    if condition is None:
        return None
    result = dict(condition)
    kind = result.get("kind", "comparison")
    if kind == "comparison":
        result["left"] = _rename_expr(result["left"], mapping)
        result["right"] = _rename_expr(result["right"], mapping)
    else:
        result["children"] = [
            _rename_condition(child, mapping) for child in result.get("children", [])
        ]
    return result


def _rename_variables(opcodes: list[dict], token: str) -> list[dict]:
    """Rename LET bindings and all corresponding variable references."""
    mapping: dict[str, str] = {}
    counter = 0
    for opcode in opcodes:
        if opcode.get("op") == "LET":
            old = opcode.get("name")
            if isinstance(old, str) and old not in mapping:
                mapping[old] = f"v{token[:8]}_{counter}"
                counter += 1

    if not mapping:
        return [dict(op) for op in opcodes]

    output: list[dict] = []
    for opcode in opcodes:
        result = dict(opcode)
        if result.get("op") == "LET":
            result["name"] = mapping.get(result.get("name"), result.get("name"))
            result["value"] = _rename_expr(result["value"], mapping)
        elif result.get("op") == "ANALYZE":
            result["where"] = _rename_condition(result.get("where"), mapping)
        elif result.get("op") == "IF":
            result["condition"] = _rename_condition(result.get("condition"), mapping)
        elif result.get("op") == "USER_RULE":
            result["condition"] = _rename_condition(result.get("condition"), mapping)
        output.append(result)
    return output


def _stable_token(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _canonical_semantic(opcodes: list[dict]) -> bytes:
    """Canonicalize executable semantics for equivalence checks.

    V2.2 deliberately ignores source-line metadata and representation-only
    fields. Variable identifiers are normalized by first binding order.
    """
    mapping: dict[str, str] = {}
    counter = 0

    def expr(e):
        nonlocal counter
        if not isinstance(e, dict):
            return e
        kind = e.get("kind")
        if kind == "var":
            name = e.get("name")
            if name not in mapping:
                mapping[name] = f"$v{counter}"
                counter += 1
            return {"kind": "var", "name": mapping[name]}
        if kind == "literal":
            return {"kind": "literal", "value": e.get("value")}
        if kind == "property":
            return {"kind": "property", "collector": e.get("collector"), "property": e.get("property")}
        return {k: v for k, v in e.items() if k not in {"line", "representation_tag"}}

    def cond(c):
        if not c:
            return None
        if c.get("kind", "comparison") != "comparison":
            return {"kind": c.get("kind"), "children": [cond(x) for x in c.get("children", [])]}
        return {"kind": "comparison", "left": expr(c.get("left")), "operator": c.get("operator"), "right": expr(c.get("right"))}

    result=[]
    for op in opcodes:
        name=op.get("op")
        if name == "LET":
            old=op.get("name")
            if old not in mapping:
                mapping[old]=f"$v{counter}"; counter+=1
            result.append({"op":"LET","name":mapping[old],"value":expr(op.get("value"))})
        elif name == "ANALYZE":
            result.append({"op":"ANALYZE","rule":op.get("rule"),"where":cond(op.get("where"))})
        elif name == "USER_RULE":
            result.append({"op":"USER_RULE","name":op.get("name"),"condition":cond(op.get("condition")),"severity":op.get("severity")})
        elif name == "IF":
            result.append({"op":"IF","condition":cond(op.get("condition")),"then_count":op.get("then_count"),"else_count":op.get("else_count")})
        elif name == "COLLECT":
            result.append({"op":"COLLECT","target":op.get("target")})
        elif name == "REPORT":
            result.append({"op":"REPORT","name":op.get("name")})
        else:
            result.append({k:v for k,v in op.items() if k not in {"line","representation_tag"}})
    return _canonical(result)


def _representation_tag(token: str, index: int) -> str:
    return hashlib.sha256(f"{token}:{index}".encode("utf-8")).hexdigest()[:12]


def _reorder_layout(opcode: dict, token: str, index: int) -> dict:
    """Change serialized JSON key layout only; never changes opcode semantics."""
    tag = _representation_tag(token, index)
    ordered = {"op": opcode.get("op")}
    for key in sorted((k for k in opcode if k not in {"op", "line", "representation_tag"}), reverse=(int(tag[0], 16) % 2 == 1)):
        ordered[key] = opcode[key]
    if "line" in opcode:
        ordered["line"] = opcode["line"]
    ordered["representation_tag"] = tag
    return ordered


def transform_investigation(
    investigation: Investigation,
    *,
    profile: str = "none",
    seed: str | None = None,
) -> TransformationResult:
    """Apply safe, semantics-preserving JOCKY representation transformations.

    V2.2 adds an automated research profile composed only of JOCKY-level
    representation changes: identifier renaming, serialized layout diversity,
    and provenance metadata. It does not transform native binaries, perform
    process manipulation, or alter security controls.
    """
    profile = validate_profile(profile)
    original = _flatten_commands(investigation.commands)
    input_hash = hashlib.sha256(_canonical(original)).hexdigest()

    if profile == "none":
        effective_seed = None
        transformed = [dict(op) for op in original]
        changes: tuple[str, ...] = ()
    else:
        if profile in {"deterministic", "compatibility-preserving"}:
            effective_seed = _stable_token(input_hash + ":" + TRANSFORM_VERSION)
        elif profile == "reproducible-randomized":
            if not seed:
                raise TransformationError("reproducible-randomized profile requires an explicit seed.")
            effective_seed = _stable_token(str(seed))
        else:
            effective_seed = secrets.token_hex(16) if not seed else str(seed)

        token = _stable_token(effective_seed)
        transformed = _rename_variables(original, token)
        changes_list = ["variable_identifier_representation"]
        if profile == "automated-obfuscation":
            transformed = [_reorder_layout(op, token, i) for i, op in enumerate(transformed)]
            changes_list.extend(["serialized_layout_diversification", "representation_metadata"])
        changes = tuple(changes_list)

    output_hash = hashlib.sha256(_canonical(transformed)).hexdigest()
    transformation_id = hashlib.sha256(_canonical({
        "version": TRANSFORM_VERSION, "profile": profile, "seed": effective_seed,
        "input_hash": input_hash, "output_hash": output_hash,
    })).hexdigest()
    return TransformationResult(
        opcodes=transformed, profile=profile, seed=effective_seed,
        transformation_id=transformation_id, input_hash=input_hash,
        output_hash=output_hash, changes=changes,
    )


def validate_semantic_equivalence(original: list[dict], transformed: list[dict]) -> bool:
    """Return whether two JOCKY opcode streams have the same semantics."""
    return _canonical_semantic(original) == _canonical_semantic(transformed)
