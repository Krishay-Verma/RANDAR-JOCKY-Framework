"""
JOCKY FastAPI application entry point.

Startup: load .env -> assert auth configured -> init SQLite -> mount routers.
If `frontend/dist` exists (after `npm run build`) it is served from the same
origin, so the whole product runs on a single port.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from jocky.api.agent_routes import agent_router, management_router
from jocky.api.auth import assert_auth_configured
from jocky.api.bytecode_routes import bytecode_router
from jocky.api.driver_routes import driver_router
from jocky.api.persistence_routes import persistence_router
from jocky.api.forensic_job_routes import router as forensic_job_router
from jocky.api.routes import protected_router, public_router
from jocky.storage.database import init_db, init_transformation_experiments
from jocky.storage.audit import init_audit
from jocky.api.agent_store import init_persistence as init_agent_persistence
from jocky.storage.network_sources import init_network_sources

try:
    assert_auth_configured()
except RuntimeError as _auth_err:
    raise SystemExit(
        f"\n[RANDAR] Startup aborted - authentication not configured:\n  {_auth_err}\n"
    ) from _auth_err

_MAX_BODY_BYTES = 28 * 1024 * 1024  # accommodates base64-wrapped 20 MiB evidence uploads
_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _install_windows_disconnect_handler() -> None:
    """Keep normal Windows client disconnects out of the console log.

    Python's Proactor event loop can report WinError 10054 when a browser
    closes/reloads a local HTTP connection while the socket is being torn
    down. The request has already ended; there is no application failure to
    recover from. Other loop exceptions still use asyncio's normal handler.
    """
    if os.name != "nt":
        return

    loop = asyncio.get_running_loop()

    def handler(current_loop, context):
        exc = context.get("exception")
        message = context.get("message", "")
        winerror = getattr(exc, "winerror", None)
        if (isinstance(exc, ConnectionResetError) and winerror == 10054) or (
            message == "Exception in callback _ProactorBasePipeTransport._call_connection_lost()"
            and isinstance(exc, ConnectionResetError)
        ):
            return
        current_loop.default_exception_handler(context)

    loop.set_exception_handler(handler)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    init_network_sources()
    init_transformation_experiments()
    init_audit()
    init_agent_persistence()
    _install_windows_disconnect_handler()
    yield


app = FastAPI(
    title="RANDAR Investigation API",
    description="Host triage and forensic investigation service. "
                "All investigation endpoints require a bearer token.",
    version="3.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.environ.get("RANDAR_DOCS", os.environ.get("JOCKY_DOCS", "true")).lower() != "false" else None,
    redoc_url=None,
)

_origins = [
    o.strip()
    for o in os.environ.get(
        "RANDAR_CORS_ORIGINS", os.environ.get("JOCKY_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    )).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def hardening(request, call_next):
    """Reject oversized bodies and attach baseline security headers."""
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > _MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request body too large."}, status_code=413)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


app.include_router(public_router)
app.include_router(protected_router)
app.include_router(management_router)
app.include_router(agent_router)
app.include_router(bytecode_router)
app.include_router(driver_router)
app.include_router(persistence_router)
app.include_router(forensic_job_router)

if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not found."}, status_code=404)
        target = (_DIST / path).resolve()
        if path and target.is_file() and _DIST.resolve() in target.parents:
            return FileResponse(target)
        return FileResponse(_DIST / "index.html")
