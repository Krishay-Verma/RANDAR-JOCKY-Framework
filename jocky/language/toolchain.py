"""Public V2.0 JOCKY toolchain API."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from jocky.language.bytecode import BytecodeError, disassemble, verify_and_load
from jocky.language.compiler import (
    CompilationArtifact,
    TOOLCHAIN_VERSION,
    compile_source,
    parse_source,
)


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    investigation_name: str
    source_hash: str
    ir_hash: str
    target: str
    command_count: int
    build_id: str
    artifact_hash: str
    transformation_profile: str
    transformation_id: str


def validate_source(source: str, *, target: str = "portable") -> ValidationResult:
    artifact = compile_source(source, target=target, deterministic=True)
    return ValidationResult(
        valid=True,
        investigation_name=artifact.header["name"],
        source_hash=artifact.source_hash,
        ir_hash=artifact.ir_hash,
        target=artifact.target,
        command_count=len(artifact.opcodes),
        build_id=artifact.build_id,
        artifact_hash=artifact.artifact_hash,
        transformation_profile=artifact.transformation_profile,
        transformation_id=artifact.transformation_id,
    )


def compile_file(
    source_path: str | Path,
    output_path: str | Path,
    *,
    target: str = "portable",
    deterministic: bool = False,
    transformation_profile: str = "none",
    transformation_seed: str | None = None,
) -> CompilationArtifact:
    source = Path(source_path).read_text(encoding="utf-8")
    artifact = compile_source(
        source, target=target, deterministic=deterministic,
        transformation_profile=transformation_profile,
        transformation_seed=transformation_seed,
    )
    Path(output_path).write_bytes(artifact.bytecode)
    return artifact


def verify_file(path: str | Path) -> dict:
    header, opcodes = verify_and_load(Path(path).read_bytes())
    return {"header": header, "opcode_count": len(opcodes)}


def inspect_file(path: str | Path) -> str:
    return disassemble(Path(path).read_bytes())


__all__ = [
    "TOOLCHAIN_VERSION",
    "CompilationArtifact",
    "ValidationResult",
    "compile_source",
    "compile_file",
    "validate_source",
    "verify_file",
    "inspect_file",
    "parse_source",
    "BytecodeError",
]
