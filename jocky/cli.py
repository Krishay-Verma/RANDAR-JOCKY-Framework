"""Command-line interface for the JOCKY V2.0 toolchain."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from jocky.language.compiler import CompilerError, compile_source
from jocky.language.spec import as_dict
from jocky.language.toolchain import inspect_file, validate_source, verify_file
from jocky.language.runtime import require_target_compatible


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jocky", description="JOCKY V2.7 compiler/toolchain")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("compile", help="compile JOCKY source to signed bytecode")
    c.add_argument("source", type=Path)
    c.add_argument("-o", "--output", type=Path, required=True)
    c.add_argument("--target", choices=("portable", "windows", "ubuntu"), default="portable")
    c.add_argument("--deterministic", action="store_true")
    c.add_argument("--transformation-profile", choices=("none", "deterministic", "randomized", "reproducible-randomized", "compatibility-preserving", "automated-obfuscation"), default="none")
    c.add_argument("--transformation-seed")

    v = sub.add_parser("verify", help="verify a signed bytecode artifact")
    v.add_argument("bytecode", type=Path)

    i = sub.add_parser("inspect", help="verify and disassemble bytecode")
    i.add_argument("bytecode", type=Path)

    va = sub.add_parser("validate", help="validate JOCKY source")
    va.add_argument("source", type=Path)
    va.add_argument("--target", choices=("portable", "windows", "ubuntu"), default="portable")

    s = sub.add_parser("sign", help="compile and sign JOCKY source")
    s.add_argument("source", type=Path)
    s.add_argument("-o", "--output", type=Path, required=True)
    s.add_argument("--target", choices=("portable", "windows", "ubuntu"), default="portable")
    s.add_argument("--deterministic", action="store_true")
    s.add_argument("--transformation-profile", choices=("none", "deterministic", "randomized", "reproducible-randomized", "compatibility-preserving", "automated-obfuscation"), default="none")
    s.add_argument("--transformation-seed")


    e = sub.add_parser("experiment", help="run a controlled V2.2 transformation experiment")
    e.add_argument("source", type=Path)
    e.add_argument("--target", choices=("portable", "windows", "ubuntu"), default="portable")
    e.add_argument("--profile", choices=("deterministic", "randomized", "reproducible-randomized", "compatibility-preserving", "automated-obfuscation"), default="automated-obfuscation")
    e.add_argument("--seed")
    e.add_argument("--output", type=Path)

    r = sub.add_parser("run", help="compile and execute a JOCKY investigation locally")
    r.add_argument("source", type=Path)
    r.add_argument("--target", choices=("portable", "windows", "ubuntu"), default="portable")

    mf = sub.add_parser("memory-scan", help="run the read-only memory-forensics metadata correlation pass")
    df = sub.add_parser("driver-scan", help="run the read-only Windows driver/kernel observation pass")
    pf = sub.add_parser("persistence-scan", help="run the read-only persistence and privilege correlation pass")

    sp = sub.add_parser("spec", help="print the V2.0 language specification")
    sp.add_argument("--json", action="store_true")
    return p


def _run_source(source: str, target: str) -> int:
    require_target_compatible(target)
    artifact = compile_source(source, target=target)
    from jocky.api.bytecode_routes import _opcodes_to_ir
    from jocky.language.interpreter import run_investigation
    investigation = _opcodes_to_ir(artifact.header["name"], artifact.opcodes)
    result = run_investigation(investigation)
    print(json.dumps({
        "toolchain_version": artifact.header.get("toolchain_version"),
        "target": artifact.target,
        "investigation_name": artifact.header["name"],
        "collectors": [{"target": x.target, "status": x.status} for x in result.collector_results],
        "findings": [{"rule_name": x.rule_name, "severity": x.severity, "summary": x.summary} for x in result.findings],
    }, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command in {"compile", "sign"}:
            source = args.source.read_text(encoding="utf-8")
            artifact = compile_source(
                source, target=args.target, deterministic=args.deterministic,
                transformation_profile=args.transformation_profile,
                transformation_seed=args.transformation_seed,
            )
            args.output.write_bytes(artifact.bytecode)
            print(json.dumps({
                "output": str(args.output),
                "toolchain_version": artifact.header.get("toolchain_version"),
                "bytecode_version": artifact.header.get("version"),
                "target": artifact.target,
                "deterministic": artifact.deterministic,
                "source_hash": artifact.source_hash,
                "ir_hash": artifact.ir_hash,
                "opcode_count": len(artifact.opcodes),
                "size_bytes": len(artifact.bytecode),
                "build_id": artifact.build_id,
                "artifact_hash": artifact.artifact_hash,
                "transformation_profile": artifact.transformation_profile,
                "transformation_id": artifact.transformation_id,
            }, indent=2))
            return 0
        if args.command == "verify":
            print(json.dumps(verify_file(args.bytecode), indent=2))
            return 0
        if args.command == "inspect":
            print(inspect_file(args.bytecode))
            return 0
        if args.command == "validate":
            source = args.source.read_text(encoding="utf-8")
            print(json.dumps(validate_source(source, target=args.target).__dict__, indent=2))
            return 0
        if args.command == "experiment":
            from jocky.language.experiments import experiment_dict, run_transformation_experiment
            record = run_transformation_experiment(
                args.source.read_text(encoding="utf-8"), target=args.target,
                profile=args.profile, seed=args.seed, deterministic=True,
            )
            payload = experiment_dict(record)
            text = json.dumps(payload, indent=2)
            if args.output:
                args.output.write_text(text + "\n", encoding="utf-8")
            print(text)
            return 0
        if args.command == "run":
            return _run_source(args.source.read_text(encoding="utf-8"), args.target)
        if args.command == "memory-scan":
            from jocky.collectors.registry import get_collector
            from jocky.analysis.memory_forensics import build_memory_forensics
            evidence = {name: get_collector(name)() for name in ("processes", "modules", "threads", "memory_regions")}
            print(json.dumps(build_memory_forensics(evidence), indent=2, default=str))
            return 0
        if args.command == "driver-scan":
            from jocky.api.driver_routes import driver_forensics_scan
            print(json.dumps(driver_forensics_scan(), indent=2, default=str))
            return 0
        if args.command == "persistence-scan":
            from jocky.api.persistence_routes import persistence_forensics_scan
            print(json.dumps(persistence_forensics_scan(), indent=2, default=str))
            return 0
        if args.command == "spec":
            print(json.dumps(as_dict(), indent=2) if args.json else as_dict()["ebnf"])
            return 0
    except (CompilerError, OSError, ValueError) as exc:
        print(f"jocky: error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"jocky: execution error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
