"""JOCKY V2.0 source compiler and validation facade.

This module is deliberately thin: lexing, parsing and bytecode validation
remain implemented by their existing modules.  The V2.0 compiler adds the
missing toolchain-level contract around them: target metadata, reproducible
build metadata, source/IR hashes and a stable artifact object.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import platform

from jocky.language.bytecode import compile_investigation, verify_and_load
from jocky.language.ir import Investigation
from jocky.language.lexer import tokenize
from jocky.language.parser import parse
from jocky.language.transform import TransformationResult, transform_investigation

TOOLCHAIN_VERSION = "2.4.0"
IR_VERSION = "1.0"
SUPPORTED_TARGETS = frozenset({"portable", "windows", "ubuntu"})


class CompilerError(ValueError):
    """Raised for source/toolchain validation failures."""


@dataclass(frozen=True)
class CompilationArtifact:
    """A complete V2.0 compilation result."""

    source_hash: str
    ir_hash: str
    target: str
    deterministic: bool
    bytecode: bytes
    header: dict
    opcodes: list[dict]
    build_id: str
    artifact_hash: str
    transformation_profile: str
    transformation_id: str
    transformation_changes: tuple[str, ...] = ()


def validate_target(target: str) -> str:
    target = target.strip().lower()
    if target not in SUPPORTED_TARGETS:
        raise CompilerError(
            f"Unsupported target {target!r}. "
            f"Expected one of: {', '.join(sorted(SUPPORTED_TARGETS))}."
        )
    return target


def parse_source(source: str) -> Investigation:
    if not isinstance(source, str) or not source.strip():
        raise CompilerError("JOCKY source must be a non-empty string.")
    try:
        return parse(tokenize(source))
    except Exception as exc:
        # Keep lexer/parser details intact while exposing one compiler-level
        # exception to CLI and future integrations.
        raise CompilerError(str(exc)) from exc


def canonical_ir(investigation: Investigation) -> bytes:
    """Return a stable JSON representation of the parsed IR.

    The representation intentionally excludes timestamps and other build
    metadata so the same source produces the same IR hash.
    """
    from jocky.language.bytecode import _flatten_commands

    payload = {
        "ir_version": IR_VERSION,
        "name": investigation.name,
        "opcodes": _flatten_commands(investigation.commands),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compile_source(
    source: str,
    *,
    target: str = "portable",
    deterministic: bool = False,
    transformation_profile: str = "none",
    transformation_seed: str | None = None,
) -> CompilationArtifact:
    """Compile JOCKY source into a signed V2.2 artifact."""
    target = validate_target(target)
    investigation = parse_source(source)

    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    ir_hash = hashlib.sha256(canonical_ir(investigation)).hexdigest()
    transformed: TransformationResult = transform_investigation(
        investigation, profile=transformation_profile, seed=transformation_seed
    )

    build_id = hashlib.sha256(
        (source_hash + ir_hash + transformed.transformation_id + target + TOOLCHAIN_VERSION).encode()
    ).hexdigest()
    bytecode = compile_investigation(
        investigation,
        toolchain_version=TOOLCHAIN_VERSION,
        ir_version=IR_VERSION,
        target=target,
        deterministic=deterministic,
        source_hash=source_hash,
        ir_hash=ir_hash,
        opcodes=transformed.opcodes,
        transformation_profile=transformed.profile,
        transformation_seed=transformed.seed,
        transformation_id=transformed.transformation_id,
        transformation_input_hash=transformed.input_hash,
        transformation_output_hash=transformed.output_hash,
        transformation_changes=list(transformed.changes),
        build_id=build_id,
    )
    header, opcodes = verify_and_load(bytecode)
    artifact_hash = hashlib.sha256(bytecode).hexdigest()

    # Build identity is signed into the artifact; artifact_hash identifies the
    # complete wire blob without creating a circular header dependency.
    header["build_id"] = build_id

    return CompilationArtifact(
        source_hash=source_hash,
        ir_hash=ir_hash,
        target=target,
        deterministic=deterministic,
        bytecode=bytecode,
        header=header,
        opcodes=opcodes,
        build_id=build_id,
        artifact_hash=artifact_hash,
        transformation_profile=transformed.profile,
        transformation_id=transformed.transformation_id,
        transformation_changes=transformed.changes,
    )


def host_target() -> str:
    """Return the normalized JOCKY target represented by the current host."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "ubuntu"
    return "portable"
