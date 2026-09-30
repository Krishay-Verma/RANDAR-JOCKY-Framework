"""Authorized laboratory scenario generator for RANDAR V2.0.

This module generates *synthetic forensic observations* for research and
regression testing. It never opens another process, allocates remote memory,
loads a driver, changes kernel state, or injects code.
"""
from __future__ import annotations

import argparse
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jocky.analysis.research_rules import (
    rule_byoVD_driver_indicators,
    rule_in_memory_execution_indicators,
)
from jocky.analysis.injection_rules import (
    rule_injection_correlation,
    rule_process_hollowing_indicators,
    rule_reflective_load_indicators,
    rule_thread_hijacking_indicators,
)


def build_scenario(name: str = "in-memory-byoVD-lab") -> dict[str, Any]:
    """Return deterministic synthetic evidence for an authorized lab case."""
    if name not in {"in-memory-byoVD-lab", "clean"}:
        raise ValueError(f"Unknown lab scenario: {name}")
    if name == "clean":
        return {
            "scenario": name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "processes": {"processes": [{"pid": 4242, "name": "lab-clean.exe"}]},
            "memory_regions": {"regions": []},
            "threads": {"threads": []},
            "modules": {"modules": []},
            "driver_inventory": {"drivers": []},
        }

    evidence = {
        "scenario": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lab_only": True,
        "processes": {"processes": [{"pid": 4242, "name": "lab-target.exe"}]},
        "memory_regions": {"regions": [{
            "pid": 4242, "process_name": "lab-target.exe",
            "base_address": 0x10000000, "region_size": 0x4000,
            "protect": 0x40, "protect_name": "EXECUTE_READWRITE",
            "state": 0x1000, "type": 0x20000, "type_name": "PRIVATE",
            "is_executable": True, "is_private": True,
            "is_private_executable": True,
        }]},
        "threads": {"threads": [{
            "pid": 4242, "process_name": "lab-target.exe",
            "thread_id": 7, "start_address": 0x10001200,
        }]},
        "modules": {"modules": [{
            "pid": 4242, "process_name": "lab-target.exe",
            "path": r"C:\Users\Lab\AppData\Local\lab\observer.dll",
            "is_user_writable": True,
        }]},
        "driver_inventory": {"drivers": [{
            "service_name": "LabVulnerableDriver",
            "display_name": "RANDAR Lab Vulnerable Driver Fixture",
            "image_path": r"C:\Windows\System32\drivers\labvuln.sys",
            "file_exists": True,
            "is_user_writable_path": False,
            "sha256": hashlib.sha256(b"RANDAR-LAB-DRIVER-FIXTURE").hexdigest(),
            "known_vulnerable": True,
            "vulnerability_ids": ["RANDAR-LAB-BYOVD-001"],
            "catalog_source": "RANDAR synthetic laboratory catalog",
        }]},
    }
    return evidence


def analyze(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    rules = [
        rule_in_memory_execution_indicators,
        rule_byoVD_driver_indicators,
        rule_process_hollowing_indicators,
        rule_reflective_load_indicators,
        rule_thread_hijacking_indicators,
        rule_injection_correlation,
    ]
    findings = []
    for rule in rules:
        findings.extend(rule(evidence))
    return [f.to_dict() if hasattr(f, "to_dict") else f.__dict__ for f in findings]


def run(scenario: str, output: Path | None = None) -> dict[str, Any]:
    evidence = build_scenario(scenario)
    result = {
        "schema_version": "2.0",
        "scenario": scenario,
        "safety_boundary": "synthetic-observation-only",
        "evidence": evidence,
        "findings": analyze(evidence),
    }
    encoded = json.dumps(result, sort_keys=True, indent=2).encode("utf-8")
    result["result_sha256"] = hashlib.sha256(encoded).hexdigest()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="RANDAR V2.0 authorized research-lab simulator")
    parser.add_argument("--scenario", default="in-memory-byoVD-lab", choices=["in-memory-byoVD-lab", "clean"])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.scenario, args.output)
    print(json.dumps({
        "scenario": result["scenario"],
        "finding_count": len(result["findings"]),
        "result_sha256": result["result_sha256"],
        "output": str(args.output) if args.output else None,
        "safety_boundary": result["safety_boundary"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
