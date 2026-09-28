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
from jocky.language.ir import AnalyzeCommand, CollectCommand, ReportCommand
from jocky.language.lexer import LexError, tokenize
from jocky.language.parser import ParseError, parse
from jocky.reports.builder import build_report
from jocky.reports.html_writer import build_html_string
from jocky.reports.report import Report
from jocky.api.schemas import (
    InvestigationResponse, RegisterKeyRequest, RunInvestigationRequest,
    UpdateInvestigationRequest,
)
from jocky.storage.database import (
    delete_investigation,
    get_investigation,
    get_stats,
    list_investigations,
    save_investigation,
    update_investigation,
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
    """Validate, run, persist, and return a JOCKY investigation."""
    try:
        tokens = tokenize(request.script)
        investigation = parse(tokens)
    except LexError as exc:
        raise HTTPException(status_code=400, detail=f"Lexer error: {exc}")
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Parser error: {exc}")

    script_hash = hashlib.sha256(request.script.encode("utf-8")).hexdigest()
    started_at = datetime.now(timezone.utc)

    try:
        result = run_investigation(investigation)
    except InterpreterError as exc:
        raise HTTPException(status_code=400, detail=f"Interpreter error: {exc}")

    finished_at = datetime.now(timezone.utc)

    report = build_report(result, started_at, finished_at, script_hash=script_hash)
    report_dict = asdict(report)

    new_id = save_investigation(
        investigation_name=report.investigation_name,
        endpoint_hostname=report.endpoint_hostname,
        started_at=report.started_at,
        finished_at=report.finished_at,
        findings_count=len(report.findings),
        report=report_dict,
    )

    return InvestigationResponse(
        id=new_id,
        investigation_name=report.investigation_name,
        endpoint_hostname=report.endpoint_hostname,
        started_at=report.started_at,
        finished_at=report.finished_at,
        findings_count=len(report.findings),
        report_json=report_dict,
    )

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


@protected_router.get("/api/investigations", tags=["investigations"])
def get_investigations() -> list[dict]:
    """Return summary rows for all investigations, newest first."""
    return list_investigations()


@protected_router.get(
    "/api/investigations/{investigation_id}", tags=["investigations"]
)
def get_investigation_by_id(investigation_id: int) -> dict:
    """Return the full stored record for one investigation."""
    record = get_investigation(investigation_id)
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
    if not delete_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"deleted": True}


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
    html = build_html_string(report)

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": (
                f'attachment; filename="jocky_report_{investigation_id}.html"'
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
    plaintext = json.dumps(record["report_json"], indent=2).encode("utf-8")

    try:
        blob = encrypt_report_for_key(plaintext, public_key)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Encryption failed. Check server logs.",
        )

    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="jocky_report_{investigation_id}.enc"'
            ),
            "X-Encryption": "AES-256-GCM+RSA-OAEP",
        },
    )


# ── Internal helpers ───────────────────────────────────────────────────────────

def _report_from_dict(rj: dict) -> Report:
    """Reconstruct a Report dataclass from stored JSON."""
    return Report(
        investigation_name=rj["investigation_name"],
        endpoint_hostname=rj["endpoint_hostname"],
        started_at=rj["started_at"],
        finished_at=rj["finished_at"],
        report_name=rj.get("report_name"),
        script_hash=rj.get("script_hash"),
        collector_results=[
            CollectorResult(
                target=cr["target"],
                status=cr["status"],
                data=cr.get("data"),
                error=cr.get("error"),
            )
            for cr in rj.get("collector_results", [])
        ],
        findings=[
            Finding(
                rule_name=f["rule_name"],
                severity=f["severity"],
                summary=f["summary"],
                reason=f["reason"],
                related_evidence=f.get("related_evidence", {}),
            )
            for f in rj.get("findings", [])
        ],
        collector_errors=[],
    )