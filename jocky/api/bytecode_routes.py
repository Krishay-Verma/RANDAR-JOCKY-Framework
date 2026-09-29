"""
Bytecode compilation and execution routes.

Protected endpoints — investigator token required.

  POST /api/bytecode/compile   compile a script to bytecode
  POST /api/bytecode/execute   execute bytecode directly
  POST /api/bytecode/disasm    disassemble bytecode (audit/debug)
"""

import base64

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from jocky.api.auth import verify_token
from jocky.language.bytecode import BytecodeError, compile_investigation, disassemble, verify_and_load
from jocky.language.interpreter import InterpreterError, run_investigation
from jocky.language.lexer import LexError, tokenize
from jocky.language.parser import ParseError, parse

bytecode_router = APIRouter(
    dependencies=[Depends(verify_token)],
    tags=["bytecode"],
)


class ScriptRequest(BaseModel):
    script: str = Field(min_length=1, max_length=20_000)


class BytecodeRequest(BaseModel):
    bytecode_b64: str = Field(min_length=1, max_length=400_000)


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
        tokens = tokenize(request.script)
        investigation = parse(tokens)
    except LexError as exc:
        raise HTTPException(status_code=400, detail=f"Lexer error: {exc}")
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Parser error: {exc}")

    try:
        blob = compile_investigation(investigation)
        header, opcodes = verify_and_load(blob)  # round-trip integrity check
    except BytecodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    b64 = base64.b64encode(blob).decode("ascii")

    return {
        "investigation_name": investigation.name,
        "bytecode_b64":       b64,
        "bytecode_size_bytes": len(blob),
        "opcode_count":       len(opcodes),
        "compiled_at":        header["compiled_at"],
        "signature":          "HMAC-SHA256",
        "version":            header["version"],
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
        result = run_investigation(investigation)
    except InterpreterError as exc:
        raise HTTPException(status_code=400, detail=f"Execution error: {exc}")

    return {
        "investigation_name": header["name"],
        "collector_count":    len(result.collector_results),
        "findings_count":     len(result.findings),
        "collectors": [
            {"target": cr.target, "status": cr.status}
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