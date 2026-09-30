import pytest

from jocky.language.compiler import compile_source
from jocky.language.execution import ExecutionAdapterError, execute_investigation
from jocky.api.bytecode_routes import _opcodes_to_ir
from jocky.language.bytecode import verify_and_load

SCRIPT = '''investigation "runtime-test" { collect system_info; }'''


def test_execution_adapter_records_telemetry():
    artifact = compile_source(SCRIPT, deterministic=True)
    header, opcodes = verify_and_load(artifact.bytecode)
    investigation = _opcodes_to_ir(header["name"], opcodes)
    result, telemetry = execute_investigation(investigation, target="portable")

    assert result.execution_status in {"complete", "partial"}
    assert telemetry.runtime_version == "2.4.0"
    assert telemetry.status == result.execution_status
    assert telemetry.events[0].event == "runtime.started"
    assert telemetry.events[-1].event in {"runtime.completed", "runtime.failed"}
    assert telemetry.resource_usage["collector_count"] == 1
    assert "collector:system_info" in telemetry.forensic_artifacts


def test_unknown_execution_adapter_is_rejected():
    artifact = compile_source(SCRIPT, deterministic=True)
    header, opcodes = verify_and_load(artifact.bytecode)
    investigation = _opcodes_to_ir(header["name"], opcodes)
    with pytest.raises(ExecutionAdapterError):
        execute_investigation(investigation, adapter="arbitrary-os-command")
