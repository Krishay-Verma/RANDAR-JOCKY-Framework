"""
API routes for the JOCKY investigation service.

Security posture:
  - `protected_router` carries verify_token as a router-level dependency.
    Every route added here is authenticated automatically. No per-route
    decoration to forget.
  - `public_router` is intentionally minimal — only /api/health, which
    exposes no sensitive data.
  - New routes must be added to protected_router unless explicitly
    justified as public.
"""

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response

from jocky.api.catalog import build_catalog
from jocky.api.key_store import clear_key, get_active_key, has_active_key, register_key
from jocky.reports.encryptor import encrypt_report_for_key
from cryptography.hazmat.primitives import hashes, serialization

from jocky.api.auth import verify_token
from jocky.analysis.finding import Finding
from jocky.language.interpreter import CollectorResult, InterpreterError, run_investigation
from jocky.collectors.network_artifacts import set_network_source, reset_network_source
from jocky.storage.network_sources import list_network_sources, save_network_source, delete_network_source, get_network_source
from jocky.language.ir import AnalyzeCommand, CollectCommand, ReportCommand
from jocky.language.lexer import LexError, tokenize
from jocky.language.parser import ParseError, parse
from jocky.reports.builder import build_report
from jocky.reports.html_writer import build_html_string
from jocky.reports.report import Report, CollectorResult as ReportCollectorResult, AnalysisResult, compute_report_hash, verify_report_integrity
from jocky.api.investigation_jobs import submit as submit_investigation_job, get as get_investigation_job, cancel as cancel_investigation_job
from jocky.api.schemas import (
    InvestigationResponse, RegisterKeyRequest, RunInvestigationRequest,
    UpdateInvestigationRequest, NetworkSourceUploadRequest,
)
from jocky.storage.audit import audit_event, list_audit_events
from jocky.storage.database import (
    delete_investigation,
    get_investigation,
    get_stats,
    list_investigations,
    save_investigation,
    update_investigation,
    search_investigations,
    list_investigations_page,
    get_investigation_evidence_page,
)

# ── Public router ──────────────────────────────────────────────────────────────
# Only routes with zero sensitive surface area belong here.
public_router = APIRouter()


@public_router.get("/api/health", tags=["public"])
def health_check() -> dict:
    """Liveness probe. Returns no system information."""
    return {"status": "ok"}


# ── Protected router ───────────────────────────────────────────────────────────
# Router-level dependency: every route below requires a valid bearer token.
# Adding a new route to this router is sufficient — no per-route decoration.
protected_router = APIRouter(dependencies=[Depends(verify_token)])


@protected_router.post(
    "/api/investigations",
    response_model=InvestigationResponse,
    tags=["investigations"],
)
def create_investigation(request: RunInvestigationRequest) -> InvestigationResponse:
    """Validate, run, persist, and return a RANDAR investigation."""
    try:
        tokens = tokenize(request.script)
        investigation = parse(tokens)
    except LexError as exc:
        raise HTTPException(status_code=400, detail=f"Lexer error: {exc}")
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Parser error: {exc}")

    script_hash = hashlib.sha256(request.script.encode("utf-8")).hexdigest()
    started_at = datetime.now(timezone.utc)

    network_token = set_network_source(request.network_source_id)
    try:
        result = run_investigation(investigation)
    except InterpreterError as exc:
        raise HTTPException(status_code=400, detail=f"Interpreter error: {exc}")
    finally:
        reset_network_source(network_token)

    finished_at = datetime.now(timezone.utc)

    bytecode_hash = _compile_hash(investigation)
    report = build_report(result, started_at, finished_at, script_hash=script_hash, bytecode_hash=bytecode_hash)
    report_dict = asdict(report)

    new_id = save_investigation(
        investigation_name=report.investigation_name,
        endpoint_hostname=report.endpoint_hostname,
        started_at=report.started_at,
        finished_at=report.finished_at,
        findings_count=len(report.findings),
        report=report_dict,
    )

    audit_event("investigation_completed", report=report, investigation_id=new_id, details={"mode": "synchronous"})
    return InvestigationResponse(
        id=new_id,
        investigation_name=report.investigation_name,
        endpoint_hostname=report.endpoint_hostname,
        started_at=report.started_at,
        finished_at=report.finished_at,
        findings_count=len(report.findings),
        report_json=report_dict,
    )


@protected_router.post("/api/investigations/jobs", tags=["investigations"])
def create_investigation_job(request: RunInvestigationRequest) -> dict:
    """Queue a long-running investigation and return immediately."""
    try:
        tokens = tokenize(request.script)
        investigation = parse(tokens)
    except LexError as exc:
        raise HTTPException(status_code=400, detail=f"Lexer error: {exc}")
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Parser error: {exc}")
    job_id = submit_investigation_job(investigation, request.script, request.network_source_id)
    return {"job_id": job_id, "status": "queued", "message": "Investigation queued."}


@protected_router.get("/api/investigations/jobs/{job_id}", tags=["investigations"])
def get_investigation_job_status(job_id: str) -> dict:
    job = get_investigation_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Investigation job not found.")
    return job


@protected_router.post("/api/investigations/jobs/{job_id}/cancel", tags=["investigations"])
def cancel_investigation_job_route(job_id: str) -> dict:
    job = cancel_investigation_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Investigation job not found.")
    return job

@protected_router.post("/api/keys/register", tags=["keys"])
def register_investigator_key(payload: RegisterKeyRequest) -> dict:
    """
    Register an RSA public key for this session.

    Body: { "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n..." }

    The key is held in memory only — never written to disk or the
    database. It is used to wrap the AES key in encrypted report
    downloads.
    """
    if not payload.public_key_pem.strip():
        raise HTTPException(
            status_code=400,
            detail="public_key_pem is required.",
        )
    try:
        register_key(payload.public_key_pem.encode("utf-8"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"registered": True, "message": "Public key registered for this session."}


@protected_router.get("/api/keys/status", tags=["keys"])
def key_status() -> dict:
    """Whether a public key is registered, with its SHA-256 fingerprint."""
    key = get_active_key()
    if key is None:
        return {"registered": False}
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    fp = digest.finalize().hex()
    return {
        "registered": True,
        "key_bits": key.key_size,
        "fingerprint_sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
    }


@protected_router.post("/api/network-sources", tags=["network-evidence"])
def upload_network_source(payload: NetworkSourceUploadRequest) -> dict:
    """Register bounded Zeek/PCAP evidence supplied as base64 text."""
    import base64, binascii
    filename = payload.filename.strip()
    encoded = payload.content_base64
    if not filename or not isinstance(encoded, str):
        raise HTTPException(status_code=400, detail="filename and content_base64 are required.")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise HTTPException(status_code=400, detail="content_base64 is invalid.")
    try:
        return save_network_source(filename, content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@protected_router.get("/api/network-sources", tags=["network-evidence"])
def get_network_sources() -> list[dict]:
    return list_network_sources()


@protected_router.get("/api/network-sources/{source_id}", tags=["network-evidence"])
def get_network_source_details(source_id: str) -> dict:
    source = get_network_source(source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Network evidence source not found.")
    source.pop("path", None)
    return source


@protected_router.delete("/api/network-sources/{source_id}", tags=["network-evidence"])
def remove_network_source(source_id: str) -> dict:
    if not delete_network_source(source_id):
        raise HTTPException(status_code=404, detail="Network evidence source not found.")
    return {"deleted": True}


@protected_router.get("/api/catalog", tags=["investigations"])
def catalog() -> dict:
    """Collectors, rules and evidence properties this engine supports."""
    return build_catalog()


@protected_router.get("/api/stats", tags=["investigations"])
def stats() -> dict:
    """Aggregated dashboard figures."""
    return get_stats()


@protected_router.delete("/api/keys/register", tags=["keys"])
def deregister_investigator_key() -> dict:
    """Deregister the current session public key."""
    clear_key()
    return {"cleared": True}


@protected_router.post("/api/validate", tags=["investigations"])
def validate_script(request: RunInvestigationRequest) -> dict:
    """
    Lex and parse a script without executing it.
    No collectors are invoked and nothing is written to the database.
    """
    try:
        tokens = tokenize(request.script)
        investigation = parse(tokens)
    except LexError as exc:
        raise HTTPException(status_code=400, detail=f"Lexer error: {exc}")
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Parser error: {exc}")

    collect_count = sum(
        1 for c in investigation.commands if isinstance(c, CollectCommand)
    )
    analyze_count = sum(
        1 for c in investigation.commands if isinstance(c, AnalyzeCommand)
    )
    has_report = any(isinstance(c, ReportCommand) for c in investigation.commands)

    return {
        "valid": True,
        "investigation_name": investigation.name,
        "total_commands": len(investigation.commands),
        "collect_count": collect_count,
        "analyze_count": analyze_count,
        "has_report": has_report,
    }


@protected_router.post("/api/compile", tags=["investigations"])
def compile_script(request: RunInvestigationRequest) -> dict:
    """
    Return the IR for a script without executing it.
    Useful for debugging and demonstrating the DSL pipeline.
    """
    import base64

    try:
        tokens = tokenize(request.script)
        investigation = parse(tokens)
    except LexError as exc:
        raise HTTPException(status_code=400, detail=f"Lexer error: {exc}")
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Parser error: {exc}")

    commands = [
        {
            "type": type(cmd).__name__,
            "target": getattr(cmd, "target", None) or getattr(cmd, "name", None),
        }
        for cmd in investigation.commands
    ]

    ir_bytes = json.dumps(commands).encode("utf-8")
    ir_b64 = base64.b64encode(ir_bytes).decode("ascii")

    return {
        "investigation_name": investigation.name,
        "token_count": len(tokens),
        "command_count": len(commands),
        "commands": commands,
        "ir_base64": ir_b64,
    }


@protected_router.get("/api/search", tags=["search"])
def global_search(q: str = "", limit: int = 50) -> dict:
    """Search stored case metadata, findings and evidence for an analyst query."""
    query = q.strip()
    if len(query) > 120:
        raise HTTPException(status_code=400, detail="Search query is limited to 120 characters.")
    return {"query": query, "results": search_investigations(query, limit)}


@protected_router.get("/api/investigations", tags=["investigations"])
def get_investigations(page: int | None = None, limit: int = 25, q: str = "", status: str = "all", sort: str = "newest") -> list[dict] | dict:
    """Return legacy list output by default; V1.9 pagination when page is supplied."""
    if page is None:
        return list_investigations()
    try:
        return list_investigations_page(page=page, limit=limit, query=q, status_filter=status, sort=sort)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@protected_router.get("/api/investigations/{investigation_id}/evidence", tags=["investigations"])
def get_evidence_page(investigation_id: int, collector: str, page: int = 1, limit: int = 100, q: str = "") -> dict:
    """Lazy-load one bounded page of a collector's evidence."""
    if not collector or len(collector) > 100:
        raise HTTPException(status_code=400, detail="collector is required and must be at most 100 characters.")
    try:
        payload = get_investigation_evidence_page(investigation_id, collector, page, limit, q)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if payload is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return payload


@protected_router.get(
    "/api/investigations/{investigation_id}", tags=["investigations"]
)
def get_investigation_by_id(investigation_id: int, include_evidence: bool = True) -> dict:
    """Return a stored case; V1.9 can omit large evidence arrays for lazy loading."""
    record = get_investigation(investigation_id, include_large_evidence=include_evidence)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return record


@protected_router.patch("/api/investigations/{investigation_id}", tags=["investigations"])
def edit_investigation(investigation_id: int, payload: UpdateInvestigationRequest) -> dict:
    """Edit case metadata (name, status, notes). Evidence is never modified."""
    try:
        found = update_investigation(
            investigation_id,
            name=payload.investigation_name,
            status=payload.status,
            notes=payload.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return get_investigation(investigation_id)


@protected_router.delete("/api/investigations/{investigation_id}", tags=["investigations"])
def remove_investigation(investigation_id: int) -> dict:
    record = get_investigation(investigation_id)
    if not delete_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="Investigation not found.")
    if record:
        audit_event("investigation_deleted", report=_report_from_dict(record["report_json"]), details={"investigation_id": investigation_id})
    return {"deleted": True}


@protected_router.get(
    "/api/investigations/{investigation_id}/report.json",
    tags=["investigations"],
)
def download_json_report(investigation_id: int) -> Response:
    """Return the stored forensic report as a canonical JSON download."""
    record = get_investigation(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    report = _report_from_dict(record["report_json"])
    if not verify_report_integrity(report):
        raise HTTPException(
            status_code=409,
            detail="Stored report integrity verification failed; export refused.",
        )

    payload = json.dumps(
        record["report_json"],
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")
    audit_event("json_report_exported", report=report, investigation_id=investigation_id)
    return Response(
        content=payload,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="randar_report_{investigation_id}.json"',
            "X-Report-SHA256": report.report_hash or compute_report_hash(report),
        },
    )


@protected_router.get(
    "/api/investigations/{investigation_id}/integrity",
    tags=["investigations"],
)
def verify_stored_report(investigation_id: int) -> dict:
    """Verify the stored report digest without modifying the evidence."""
    record = get_investigation(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    report = _report_from_dict(record["report_json"])
    computed = compute_report_hash(report)
    audit_event("integrity_verified", report=report, investigation_id=investigation_id, details={"valid": computed == report.report_hash})
    return {
        "valid": computed == report.report_hash,
        "stored_hash": report.report_hash,
        "computed_hash": computed,
        "algorithm": "SHA-256",
    }


@protected_router.get(
    "/api/investigations/{investigation_id}/report.html",
    tags=["investigations"],
    response_class=HTMLResponse,
)
def download_html_report(investigation_id: int) -> HTMLResponse:
    """Reconstruct and return the HTML report for a stored investigation."""
    record = get_investigation(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    rj = record["report_json"]
    report = _report_from_dict(rj)
    if not verify_report_integrity(report):
        raise HTTPException(status_code=409, detail="Stored report integrity verification failed; export refused.")
    html = build_html_string(report)
    audit_event("html_report_exported", report=report, investigation_id=investigation_id)

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": (
                f'attachment; filename="randar_report_{investigation_id}.html"'
            ),
            # The report is static; forbid script execution if it is opened inline.
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        },
    )


@protected_router.get(
    "/api/investigations/{investigation_id}/report.encrypted",
    tags=["investigations"],
)
def download_encrypted_report(investigation_id: int) -> Response:
    """
    Return the JSON report encrypted with hybrid encryption.

    Requires a public key to be registered via POST /api/keys/register
    before calling this endpoint. The AES session key is wrapped with
    the investigator's RSA public key — the server never sees the
    unwrapped key and cannot decrypt the report itself.

    Wire format: nonce || GCM tag || wrapped_key_len || wrapped_key || ciphertext
    Decrypt with: python -m jocky.api.decrypt_report
    """
    if not has_active_key():
        raise HTTPException(
            status_code=409,
            detail=(
                "No investigator public key registered. "
                "POST your public key to /api/keys/register first."
            ),
        )

    record = get_investigation(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    public_key = get_active_key()
    report = _report_from_dict(record["report_json"])
    if not verify_report_integrity(report):
        raise HTTPException(status_code=409, detail="Stored report integrity verification failed; export refused.")
    plaintext = json.dumps(record["report_json"], indent=2, ensure_ascii=False).encode("utf-8")

    try:
        blob = encrypt_report_for_key(plaintext, public_key)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Encryption failed. Check server logs.",
        )

    audit_event("encrypted_report_exported", report=report, investigation_id=investigation_id)
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="randar_report_{investigation_id}.enc"'
            ),
            "X-Encryption": "AES-256-GCM+RSA-OAEP",
        },
    )


@protected_router.get("/api/investigations/{investigation_id}/audit", tags=["integrity"])
def investigation_audit(investigation_id: int) -> list[dict]:
    record = get_investigation(investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return list_audit_events(investigation_id)


@protected_router.get("/api/audit", tags=["integrity"])
def audit_log(limit: int = 200) -> list[dict]:
    return list_audit_events(None, min(max(limit, 1), 500))


# ── Internal helpers ───────────────────────────────────────────────────────────

def _compile_hash(investigation):
    """Compile+verify a signed JOCKY bytecode artifact for provenance when configured."""
    try:
        from jocky.language.bytecode import compile_investigation, verify_and_load
        blob = compile_investigation(investigation)
        verify_and_load(blob)
        return hashlib.sha256(blob).hexdigest()
    except Exception:
        return None


def _report_from_dict(rj: dict) -> Report:
    """Reconstruct a Report dataclass from stored JSON."""
    return Report(
        investigation_name=rj["investigation_name"],
        endpoint_hostname=rj["endpoint_hostname"],
        started_at=rj["started_at"],
        finished_at=rj["finished_at"],
        report_name=rj.get("report_name"),
        script_hash=rj.get("script_hash"),
        report_hash=rj.get("report_hash"),
        collector_results=[
            ReportCollectorResult(
                target=cr["target"],
                status=cr["status"],
                data=cr.get("data"),
                error=cr.get("error"),
                evidence_hash=cr.get("evidence_hash"),
                duration_ms=cr.get("duration_ms", 0),
                record_count=cr.get("record_count", 0),
                truncated=cr.get("truncated", False),
                resource_bytes=cr.get("resource_bytes", 0),
            )
            for cr in rj.get("collector_results", [])
        ],
        analysis_results=[
            AnalysisResult(
                target=ar["target"],
                status=ar.get("status", "success"),
                finding_count=ar.get("finding_count", 0),
                error=ar.get("error"),
            )
            for ar in rj.get("analysis_results", [])
        ],
        findings=[
            Finding(
                rule_name=f["rule_name"],
                severity=f["severity"],
                summary=f["summary"],
                reason=f["reason"],
                related_evidence=f.get("related_evidence", {}),
                finding_id=f.get("finding_id"),
                evidence_refs=f.get("evidence_refs", []),
                limitations=f.get("limitations"),
                next_check=f.get("next_check"),
            )
            for f in rj.get("findings", [])
        ],
        collector_errors=rj.get("collector_errors", [
            {"target": cr["target"], "error": cr.get("error")}
            for cr in rj.get("collector_results", [])
            if cr.get("status") == "error"
        ]),
        source=rj.get("source", {}),
        product_name=rj.get("product_name", "RANDAR"),
        product_version=rj.get("product_version", "2.0.0"),
        dsl_name=rj.get("dsl_name", "JOCKY"),
        dsl_version=rj.get("dsl_version", "1.5"),
        bytecode_hash=rj.get("bytecode_hash"),
        timeline=rj.get("timeline", []),
        execution_status=rj.get("execution_status", "complete"),
        termination_reason=rj.get("termination_reason"),
        elapsed_ms=rj.get("elapsed_ms", 0),
        resource_usage=rj.get("resource_usage", {}),
        software_summary=rj.get("software_summary", {}),
        elevation=rj.get("elevation", {}),
        coverage=rj.get("coverage", {}),
        summary=rj.get("summary", {}),
        integrity_version=rj.get("integrity_version", 1),
    )