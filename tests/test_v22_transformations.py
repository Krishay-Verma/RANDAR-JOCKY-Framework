import hashlib
import os
os.environ.setdefault("JOCKY_BYTECODE_KEY", "k" * 40)
from jocky.language.compiler import compile_source
from jocky.language.transform import validate_semantic_equivalence
from jocky.language.experiments import run_transformation_experiment


def test_v22_automated_obfuscation_changes_representation_and_preserves_semantics():
    source = 'investigation "v22" { let hostname = 1; if hostname == 1 { report "ok"; } }'
    baseline = compile_source(source, deterministic=True, transformation_profile="none")
    transformed = compile_source(source, deterministic=True, transformation_profile="automated-obfuscation")
    assert transformed.bytecode != baseline.bytecode
    assert transformed.transformation_profile == "automated-obfuscation"
    assert "serialized_layout_diversification" in transformed.transformation_changes
    assert validate_semantic_equivalence(baseline.opcodes, transformed.opcodes)
    assert len(transformed.artifact_hash) == 64


def test_v22_reproducible_automated_obfuscation_is_stable():
    source = 'investigation "v22" { let x = 1; report "ok"; }'
    first = compile_source(source, deterministic=True, transformation_profile="automated-obfuscation", transformation_seed="lab")
    second = compile_source(source, deterministic=True, transformation_profile="automated-obfuscation", transformation_seed="lab")
    other = compile_source(source, deterministic=True, transformation_profile="automated-obfuscation", transformation_seed="other")
    assert first.bytecode == second.bytecode
    assert first.bytecode != other.bytecode


def test_v22_experiment_registry_record_is_complete():
    source = 'investigation "experiment" { let x = 1; if x == 1 { report "ok"; } }'
    record = run_transformation_experiment(source, profile="automated-obfuscation", seed="s")
    assert len(record.experiment_id) == 64
    assert record.validation == "passed"
    assert record.semantic_equivalent is True
    assert record.input_artifact_hash != record.output_artifact_hash
    assert record.experiment_version == "2.2.0"
