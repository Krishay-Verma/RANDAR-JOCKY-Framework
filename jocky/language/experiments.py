"""V2.2 transformation experiment orchestration and provenance."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json

from jocky.language.compiler import compile_source, canonical_ir, parse_source
from jocky.language.bytecode import _flatten_commands
from jocky.language.transform import validate_semantic_equivalence, validate_profile

EXPERIMENT_VERSION = "2.2.0"

@dataclass(frozen=True)
class TransformationExperiment:
    experiment_id: str
    experiment_version: str
    source_hash: str
    ir_hash: str
    transformation_profile: str
    transformation_seed: str | None
    compiler_version: str
    input_artifact_hash: str
    output_artifact_hash: str
    transformation_id: str
    validation: str
    semantic_equivalent: bool
    output_size_bytes: int
    created_at: str


def run_transformation_experiment(
    source: str,
    *,
    target: str = "portable",
    profile: str = "automated-obfuscation",
    seed: str | None = None,
    deterministic: bool = True,
) -> TransformationExperiment:
    profile = validate_profile(profile)
    investigation = parse_source(source)
    original = _flatten_commands(investigation.commands)
    ir_hash = hashlib.sha256(canonical_ir(investigation)).hexdigest()
    baseline = compile_source(source, target=target, deterministic=deterministic, transformation_profile="none")
    output = compile_source(source, target=target, deterministic=deterministic, transformation_profile=profile, transformation_seed=seed)
    equivalent = validate_semantic_equivalence(baseline.opcodes, output.opcodes)
    validation = "passed" if equivalent else "failed"
    created = datetime.now(timezone.utc).isoformat()
    experiment_id = hashlib.sha256(json.dumps({
        "version": EXPERIMENT_VERSION, "source_hash": baseline.source_hash,
        "ir_hash": ir_hash, "profile": profile, "seed": output.header.get("transformation_seed"),
        "compiler": output.header.get("toolchain_version"),
        "input": baseline.artifact_hash, "output": output.artifact_hash,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return TransformationExperiment(
        experiment_id=experiment_id,
        experiment_version=EXPERIMENT_VERSION,
        source_hash=baseline.source_hash,
        ir_hash=ir_hash,
        transformation_profile=profile,
        transformation_seed=output.header.get("transformation_seed"),
        compiler_version=output.header.get("toolchain_version", ""),
        input_artifact_hash=baseline.artifact_hash,
        output_artifact_hash=output.artifact_hash,
        transformation_id=output.transformation_id,
        validation=validation,
        semantic_equivalent=equivalent,
        output_size_bytes=len(output.bytecode),
        created_at=created,
    )


def experiment_dict(experiment: TransformationExperiment) -> dict:
    return asdict(experiment)
