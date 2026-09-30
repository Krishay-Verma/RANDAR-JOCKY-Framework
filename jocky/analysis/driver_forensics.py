"""Read-only driver and kernel-observation correlation for RANDAR V2.5.

This module consumes driver/service metadata plus optional Windows security
telemetry. It never loads, unloads, opens, exploits, or modifies a driver or
kernel object.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from jocky.analysis.finding import Finding, SEVERITY_HIGH, SEVERITY_REVIEW


def build_driver_forensics(evidence: dict[str, Any]) -> dict[str, Any]:
    inventory = evidence.get("driver_inventory", {}) or {}
    drivers = inventory.get("drivers", []) or []
    event_logs = evidence.get("windows_event_logs", {}) or {}
    sysmon = evidence.get("sysmon_events", {}) or {}

    loaded = [d for d in drivers if d.get("loaded") is True]
    vulnerable = [d for d in drivers if d.get("known_vulnerable")]
    writable = [d for d in drivers if d.get("is_user_writable_path")]
    missing = [d for d in drivers if d.get("file_exists") is False]
    unsigned = [d for d in drivers if d.get("signature_status") == "unsigned"]
    unknown_signature = [d for d in drivers if d.get("signature_status") in {None, "unknown", "not_collected"}]

    telemetry = {
        "windows_event_logs": {
            "supported": bool(event_logs.get("supported")),
            "count": int(event_logs.get("count") or 0),
            "error": event_logs.get("error"),
        },
        "sysmon_events": {
            "supported": bool(sysmon.get("supported")),
            "count": int(sysmon.get("count") or 0),
            "error": sysmon.get("error"),
        },
    }

    normalized = {
        "drivers": drivers,
        "telemetry": telemetry,
    }
    snapshot_hash = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()

    return {
        "version": "3.0.0",
        "mode": "read-only-driver-observation",
        "supported": bool(inventory.get("supported")),
        "snapshot_hash": snapshot_hash,
        "catalog_source": inventory.get("vulnerability_catalog"),
        "summary": {
            "drivers": len(drivers),
            "loaded_drivers": len(loaded),
            "known_vulnerable_drivers": len(vulnerable),
            "user_writable_driver_paths": len(writable),
            "missing_driver_images": len(missing),
            "unsigned_drivers": len(unsigned),
            "unknown_signature_drivers": len(unknown_signature),
        },
        "drivers": drivers,
        "kernel_observation": {
            "driver_inventory": "available" if inventory.get("supported") else "unavailable",
            "security_telemetry": telemetry,
            "kernel_state_modified": False,
            "kernel_objects_read": False,
            "limitations": [
                "RANDAR observes driver/service metadata and available security telemetry only.",
                "No kernel object memory is read or modified.",
                "Vulnerable-driver matching depends on the configured operator-supplied catalog.",
            ],
        },
    }


def build_driver_forensics_findings(report: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for driver in report.get("drivers", []) or []:
        reasons: list[str] = []
        if driver.get("known_vulnerable"):
            reasons.append("matched the configured vulnerable-driver catalog")
        if driver.get("is_user_writable_path"):
            reasons.append("driver image path is user-writable")
        if driver.get("file_exists") is False:
            reasons.append("registered driver image is missing")
        if driver.get("signature_status") == "unsigned":
            reasons.append("driver image is unsigned")
        if not reasons:
            continue

        high = bool(driver.get("known_vulnerable"))
        findings.append(Finding(
            rule_name="driver_forensics_exposure",
            severity=SEVERITY_HIGH if high else SEVERITY_REVIEW,
            summary=f"Driver '{driver.get('service_name')}' requires kernel-driver review",
            reason=(
                "; ".join(reasons) + ". These are exposure indicators, not proof of driver abuse. "
                "RANDAR does not load, exploit, disable, or modify the driver."
            ),
            related_evidence={
                "service_name": driver.get("service_name"),
                "display_name": driver.get("display_name"),
                "image_path": driver.get("image_path"),
                "sha256": driver.get("sha256"),
                "version": driver.get("version"),
                "publisher": driver.get("publisher"),
                "signature_status": driver.get("signature_status"),
                "loaded": driver.get("loaded"),
                "known_vulnerable": driver.get("known_vulnerable"),
                "vulnerability_ids": driver.get("vulnerability_ids", []),
                "catalog_source": driver.get("catalog_source"),
                "snapshot_hash": report.get("snapshot_hash"),
            },
            limitations="Catalog freshness and signature availability depend on endpoint and operator configuration.",
            next_check="Verify publisher, signer, version, vulnerability status, load state, and whether the driver is required.",
        ))
    return findings
