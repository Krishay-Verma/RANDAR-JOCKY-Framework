"""
Bytecode compilation and execution routes.

Protected endpoints — investigator token required.

  POST /api/bytecode/compile   compile a script to bytecode
  POST /api/bytecode/execute   execute bytecode directly
  POST /api/bytecode/disasm    disassemble bytecode (audit/debug)
"""

import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from jocky.api.auth import verify_token
from jocky.reports.forensic_scan import persist_forensic_scan
from jocky.language.bytecode import BytecodeError, compile_investigation, disassemble, verify_and_load
from jocky.language.compiler import CompilerError, compile_source
from jocky.language.interpreter import InterpreterError, run_investigation
from jocky.language.execution import ExecutionAdapterError, execute_investigation

bytecode_router = APIRouter(
    dependencies=[Depends(verify_token)],
    tags=["bytecode"],
)


class ScriptRequest(BaseModel):
    script: str = Field(min_length=1, max_length=20_000)
    target: str = Field(default="portable", pattern=r"^(portable|windows|ubuntu)$")
    deterministic: bool = False
    transformation_profile: str = Field(default="none", pattern=r"^(none|deterministic|randomized|reproducible-randomized|compatibility-preserving|automated-obfuscation)$")
    transformation_seed: str | None = Field(default=None, max_length=256)


class BytecodeRequest(BaseModel):
    bytecode_b64: str = Field(min_length=1, max_length=400_000)


class RuntimeExecutionRequest(BaseModel):
    script: str = Field(min_length=1, max_length=20_000)
    target: str = Field(default="portable", pattern=r"^(portable|windows|ubuntu)$")
    adapter: str = Field(default="jocky-interpreter", pattern=r"^jocky-interpreter$")
    transformation_profile: str = Field(default="none", pattern=r"^(none|deterministic|randomized|reproducible-randomized|compatibility-preserving|automated-obfuscation)$")
    transformation_seed: str | None = Field(default=None, max_length=256)


# ── Compile ────────────────────────────────────────────────────────────────────

@bytecode_router.post("/api/bytecode/compile")
def compile_script_to_bytecode(request: ScriptRequest) -> dict:
    """
    Compile a JOCKY script to signed bytecode.

    Returns base64-encoded bytecode and metadata.
    The bytecode blob is HMAC-signed — any modification will be
    detected and rejected at execution time.
    """
    try:
        artifact = compile_source(
            request.script,
            target=request.target,
            deterministic=request.deterministic,
            transformation_profile=request.transformation_profile,
            transformation_seed=request.transformation_seed,
        )
        blob = artifact.bytecode
        header, opcodes = artifact.header, artifact.opcodes
    except (CompilerError, BytecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    b64 = base64.b64encode(blob).decode("ascii")

    return {
        "investigation_name": header["name"],
        "bytecode_b64":       b64,
        "bytecode_size_bytes": len(blob),
        "opcode_count":       len(opcodes),
        "compiled_at":        header["compiled_at"],
        "signature":          "HMAC-SHA256",
        "version":            header["version"],
        "toolchain_version":  header.get("toolchain_version"),
        "ir_version":         header.get("ir_version"),
        "target":             header.get("target"),
        "deterministic":      header.get("deterministic", False),
        "source_hash":        header.get("source_hash"),
        "ir_hash":            header.get("ir_hash"),
        "build_id":           artifact.build_id,
        "artifact_hash":      artifact.artifact_hash,
        "transformation_profile": artifact.transformation_profile,
        "transformation_id":  artifact.transformation_id,
        "transformation_seed": header.get("transformation_seed"),
        "transformation_changes": list(artifact.transformation_changes),
    }


# ── Controlled runtime ────────────────────────────────────────────────────────

@bytecode_router.post("/api/runtime/execute")
def execute_runtime(request: RuntimeExecutionRequest) -> dict:
    """Compile and execute through the V2.3 controlled runtime abstraction."""
    try:
        artifact = compile_source(
            request.script, target=request.target, deterministic=True,
            transformation_profile=request.transformation_profile,
            transformation_seed=request.transformation_seed,
        )
        investigation = _opcodes_to_ir(artifact.header["name"], artifact.opcodes)
        result, telemetry = execute_investigation(
            investigation, adapter=request.adapter, target=request.target
        )
    except (CompilerError, BytecodeError, ExecutionAdapterError, InterpreterError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "investigation_name": artifact.header["name"],
        "build_id": artifact.build_id,
        "artifact_hash": artifact.artifact_hash,
        "transformation_profile": artifact.transformation_profile,
        "execution_status": result.execution_status,
        "elapsed_ms": result.elapsed_ms,
        "collector_count": len(result.collector_results),
        "findings_count": len(result.findings),
        "runtime": telemetry.to_dict(),
        "collectors": [
            {"target": c.target, "status": c.status, "duration_ms": c.duration_ms, "record_count": c.record_count}
            for c in result.collector_results
        ],
        "findings": [
            {"rule_name": f.rule_name, "severity": f.severity, "summary": f.summary}
            for f in result.findings
        ],
    }


# ── Memory forensics ───────────────────────────────────────────────────────────

@bytecode_router.post("/api/memory-forensics/scan")
def memory_forensics_scan() -> dict:
    """Run a bounded memory scan and persist it as a first-class investigation."""
    import time
    from jocky.collectors.registry import get_collector
    from jocky.analysis.memory_forensics import build_memory_forensics, build_memory_forensics_findings
    from jocky.analysis.registry import get_rule
    from jocky.analysis.software_catalog import annotate_evidence, summarize as summarize_software

    started_mono = time.monotonic()
    started_at = datetime.now(timezone.utc)
    evidence = {}
    errors = []
    for target in ("processes", "modules", "threads", "memory_regions"):
        try:
            evidence[target] = get_collector(target)()
        except Exception as exc:
            evidence[target] = {"error": str(exc), "supported": False}
            errors.append({"collector": target, "error": str(exc)})

    annotate_evidence(evidence)
    report = build_memory_forensics(evidence)
    report["software_summary"] = summarize_software(evidence)
    findings = build_memory_forensics_findings(report)
    analysis_results = [{"target": "memory_forensics_correlation", "status": "success", "finding_count": len(findings)}]
    for rule_name in (
        "in_memory_execution_indicators",
        "process_hollowing_indicators",
        "reflective_load_indicators",
        "thread_hijacking_indicators",
    ):
        try:
            rule_findings = get_rule(rule_name)(evidence)
            findings.extend(rule_findings)
            analysis_results.append({"target": rule_name, "status": "success", "finding_count": len(rule_findings)})
        except Exception as exc:
            errors.append({"rule": rule_name, "error": str(exc)})
            analysis_results.append({"target": rule_name, "status": "error", "finding_count": 0, "error": str(exc)})

    finished_at = datetime.now(timezone.utc)
    elapsed_ms = int((time.monotonic() - started_mono) * 1000)
    finding_dicts = [_finding_to_dict(f) for f in findings]
    investigation_id, stored_report = persist_forensic_scan(
        investigation_name="Memory Forensics Scan",
        scan_type="memory",
        evidence=evidence,
        findings=finding_dicts,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=elapsed_ms,
        collector_errors=errors,
        analysis_results=analysis_results,
        snapshot_hash=report.get("snapshot_hash"),
    )
    report["findings"] = finding_dicts
    report["finding_count"] = len(findings)
    report["collector_errors"] = errors
    report["elapsed_ms"] = elapsed_ms
    report["investigation_id"] = investigation_id
    report["persisted"] = True
    return report


def _finding_to_dict(finding):
    return {
        "rule_name": finding.rule_name, "severity": finding.severity,
        "summary": finding.summary, "reason": finding.reason,
        "related_evidence": finding.related_evidence,
        "limitations": finding.limitations, "next_check": finding.next_check,
        "evidence_refs": finding.evidence_refs,
    }


# ── Disassemble ────────────────────────────────────────────────────────────────

@bytecode_router.post("/api/bytecode/disasm")
def disassemble_bytecode(request: BytecodeRequest) -> dict:
    """
    Disassemble bytecode into human-readable opcode listing.
    Verifies the signature before disassembly.
    """
    try:
        blob = base64.b64decode(request.bytecode_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding.")

    try:
        listing = disassemble(blob)
    except BytecodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"disassembly": listing}


# ── Execute ────────────────────────────────────────────────────────────────────

@bytecode_router.post("/api/bytecode/execute")
def execute_bytecode(request: BytecodeRequest) -> dict:
    """
    Verify and execute a bytecode blob locally.

    The blob is signature-verified before any execution occurs.
    Opcodes are re-interpreted through the same allowlist pipeline
    as source-level scripts — bytecode is not a bypass.
    """
    try:
        blob = base64.b64decode(request.bytecode_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding.")

    try:
        header, opcodes = verify_and_load(blob)
    except BytecodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Reconstruct IR from opcodes and execute through normal pipeline.
    try:
        investigation = _opcodes_to_ir(header["name"], opcodes)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Bytecode reconstruction failed: {exc}",
        )

    try:
        result, telemetry = execute_investigation(
            investigation, target=header.get("target", "portable")
        )
    except (InterpreterError, ExecutionAdapterError) as exc:
        raise HTTPException(status_code=400, detail=f"Execution error: {exc}")

    return {
        "investigation_name": header["name"],
        "collector_count":    len(result.collector_results),
        "findings_count":     len(result.findings),
        "execution_status":   result.execution_status,
        "elapsed_ms":         result.elapsed_ms,
        "collectors": [
            {"target": cr.target, "status": cr.status, "duration_ms": cr.duration_ms}
            for cr in result.collector_results
        ],
        "findings": [
            {
                "rule_name": f.rule_name,
                "severity":  f.severity,
                "summary":   f.summary,
            }
            for f in result.findings
        ],
        "runtime": telemetry.to_dict(),
    }


# ── IR reconstruction ──────────────────────────────────────────────────────────

def _opcodes_to_ir(name: str, opcodes: list[dict]):
    """Reconstruct an Investigation IR from a flat opcode list."""
    from jocky.language.ir import (
        Investigation, CollectCommand, AnalyzeCommand,
        ReportCommand, LetCommand, IfCommand, UserRuleCommand,
        LiteralExpr, VarExpr, PropertyExpr, Condition,
    )

    def build_expr(e: dict):
        kind = e["kind"]
        if kind == "literal":
            return LiteralExpr(value=e["value"])
        if kind == "var":
            return VarExpr(name=e["name"])
        if kind == "property":
            return PropertyExpr(
                collector=e["collector"], property=e["property"]
            )
        raise ValueError(f"Unknown expr kind: {kind!r}")

    def build_condition(c: dict):
        kind = c.get("kind", "comparison")
        if kind in {"and", "or", "not"}:
            return Condition(kind=kind, children=[build_condition(x) for x in c.get("children", [])])
        return Condition(left=build_expr(c["left"]), operator=c["operator"], right=build_expr(c["right"]), kind="comparison")

    def consume(ops: list[dict], count: int, offset: int):
        return ops[offset: offset + count], offset + count

    def build_commands(ops: list[dict], start: int, end: int):
        commands = []
        i = start
        while i < end:
            op = ops[i]
            name_ = op["op"]
            line  = op.get("line", 0)

            if name_ == "COLLECT":
                commands.append(CollectCommand(target=op["target"], line=line))
                i += 1
            elif name_ == "ANALYZE":
                commands.append(AnalyzeCommand(rule=op["rule"], line=line, where=build_condition(op["where"]) if op.get("where") else None))
            elif name_ == "USER_RULE":
                commands.append(UserRuleCommand(name=op["name"], condition=build_condition(op["condition"]), severity=op["severity"], line=line))
                i += 1
            elif name_ == "REPORT":
                commands.append(ReportCommand(name=op["name"], line=line))
                i += 1
            elif name_ == "LET":
                commands.append(LetCommand(
                    name=op["name"],
                    value=build_expr(op["value"]),
                    line=line,
                ))
                i += 1
            elif name_ == "IF":
                tc = op["then_count"]
                ec = op["else_count"]
                then_cmds = build_commands(ops, i + 1, i + 1 + tc)
                else_cmds = build_commands(ops, i + 1 + tc, i + 1 + tc + ec)
                commands.append(IfCommand(
                    condition=build_condition(op["condition"]),
                    then_commands=then_cmds,
                    else_commands=else_cmds,
                    line=line,
                ))
                i += 1 + tc + ec
            else:
                raise ValueError(f"Unknown opcode: {name_!r}")

        return commands

    commands = build_commands(opcodes, 0, len(opcodes))
    return Investigation(name=name, commands=commands)

class TransformationExperimentRequest(BaseModel):
    script: str = Field(min_length=1, max_length=20_000)
    target: str = Field(default="portable", pattern=r"^(portable|windows|ubuntu)$")
    profile: str = Field(default="automated-obfuscation", pattern=r"^(deterministic|randomized|reproducible-randomized|compatibility-preserving|automated-obfuscation)$")
    seed: str | None = Field(default=None, max_length=256)
    deterministic: bool = True


@bytecode_router.post("/api/transformations/experiments")
def run_transformation_experiment_route(request: TransformationExperimentRequest) -> dict:
    """Compile baseline + transformed artifacts and record equivalence evidence."""
    from jocky.language.experiments import experiment_dict, run_transformation_experiment
    from jocky.storage.database import save_transformation_experiment
    try:
        record = run_transformation_experiment(
            request.script, target=request.target, profile=request.profile,
            seed=request.seed, deterministic=request.deterministic,
        )
    except (CompilerError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    payload = experiment_dict(record)
    save_transformation_experiment(payload)
    return payload


@bytecode_router.get("/api/transformations/experiments")
def list_transformation_experiments_route(limit: int = 100) -> list[dict]:
    from jocky.storage.database import list_transformation_experiments
    return list_transformation_experiments(limit)


@bytecode_router.get("/api/transformations/experiments/summary")
def transformation_experiment_summary_route() -> dict:
    from jocky.storage.database import transformation_experiment_summary
    return transformation_experiment_summary()
