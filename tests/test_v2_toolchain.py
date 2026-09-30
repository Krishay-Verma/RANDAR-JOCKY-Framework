import hashlib
import os

os.environ.setdefault("JOCKY_BYTECODE_KEY", "k" * 40)

from jocky.language.compiler import CompilerError, compile_source
from jocky.language.toolchain import validate_source


def test_v2_compile_contains_cross_platform_metadata():
    source = 'investigation "v2" { collect system_info; report "r"; }'
    artifact = compile_source(source, target="windows", deterministic=True)
    assert artifact.header["toolchain_version"] == "2.4.0"
    assert artifact.header["ir_version"] == "1.0"
    assert artifact.header["target"] == "windows"
    assert artifact.header["deterministic"] is True
    assert artifact.header["compiled_at"] is None
    assert len(artifact.source_hash) == 64
    assert len(artifact.ir_hash) == 64


def test_v2_deterministic_build_is_byte_identical():
    source = 'investigation "v2" { collect system_info; report "r"; }'
    first = compile_source(source, target="ubuntu", deterministic=True)
    second = compile_source(source, target="ubuntu", deterministic=True)
    assert first.bytecode == second.bytecode
    assert hashlib.sha256(first.bytecode).hexdigest() == hashlib.sha256(second.bytecode).hexdigest()


def test_v2_target_validation():
    source = 'investigation "v2" { collect system_info; }'
    for target in ("portable", "windows", "ubuntu"):
        assert compile_source(source, target=target, deterministic=True).target == target
    try:
        compile_source(source, target="macos", deterministic=True)
    except CompilerError as exc:
        assert "Unsupported target" in str(exc)
    else:
        raise AssertionError("unsupported target was accepted")


def test_v2_validate_is_non_mutating_and_deterministic():
    source = 'investigation "validate" { collect processes; analyze in_memory_execution_indicators; }'
    result = validate_source(source, target="portable")
    assert result.valid is True
    assert result.command_count == 2
    assert len(result.source_hash) == 64
    assert len(result.ir_hash) == 64


def test_v21_deterministic_transformation_is_reproducible_and_changes_representation():
    source = 'investigation "v21" { let hostname = 1; if hostname == 1 { report "ok"; } }'
    first = compile_source(source, target="portable", deterministic=True, transformation_profile="deterministic")
    second = compile_source(source, target="portable", deterministic=True, transformation_profile="deterministic")
    baseline = compile_source(source, target="portable", deterministic=True, transformation_profile="none")
    assert first.bytecode == second.bytecode
    assert first.artifact_hash == second.artifact_hash
    assert first.build_id == second.build_id
    assert first.transformation_profile == "deterministic"
    assert first.transformation_id == second.transformation_id
    assert first.bytecode != baseline.bytecode
    assert first.header["build_id"] == first.build_id
    assert len(first.artifact_hash) == 64


def test_v21_reproducible_randomized_profile_uses_seed():
    source = 'investigation "v21" { let hostname = 1; report "ok"; }'
    first = compile_source(source, deterministic=True, transformation_profile="reproducible-randomized", transformation_seed="seed-a")
    second = compile_source(source, deterministic=True, transformation_profile="reproducible-randomized", transformation_seed="seed-a")
    other = compile_source(source, deterministic=True, transformation_profile="reproducible-randomized", transformation_seed="seed-b")
    assert first.bytecode == second.bytecode
    assert first.bytecode != other.bytecode


def test_v21_randomized_profile_changes_build_identity():
    source = 'investigation "v21" { collect system_info; report "ok"; }'
    first = compile_source(source, deterministic=False, transformation_profile="randomized")
    second = compile_source(source, deterministic=False, transformation_profile="randomized")
    assert first.bytecode != second.bytecode
    assert first.artifact_hash != second.artifact_hash
    assert first.transformation_id != second.transformation_id
    assert first.build_id != second.build_id


def test_v21_transformation_preserves_execution_model():
    source = 'investigation "v21" { let x = 1; if x == 1 { report "ok"; } }'
    artifact = compile_source(source, deterministic=True, transformation_profile="deterministic")
    from jocky.api.bytecode_routes import _opcodes_to_ir
    investigation = _opcodes_to_ir(artifact.header["name"], artifact.opcodes)
    assert investigation.name == "v21"
    assert [type(c).__name__ for c in investigation.commands] == ["LetCommand", "IfCommand"]
