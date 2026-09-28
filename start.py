"""
JOCKY launcher - installs, configures and starts the whole stack.

    python start.py              first run: set up everything, then start
    python start.py --dev        Vite dev server (hot reload) + API auto-reload
    python start.py --new-token  issue a new API token (invalidates the old one)
    python start.py --rebuild    force a frontend rebuild
    python start.py --no-browser --host 127.0.0.1 --port 8000

Uses only the standard library so it can run before any dependency exists.
"""

import argparse
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
VENV = ROOT / "venv"
FRONTEND = ROOT / "frontend"
PY = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

if os.name == "nt":
    os.system("")  # enable ANSI escapes in the Windows console


def _c(code: str, msg: str) -> str:
    return f"\033[{code}m{msg}\033[0m" if sys.stdout.isatty() else msg


def ok(m): print(f"  {_c('92', '[ok]')}   {m}")
def note(m): print(f"  {_c('96', '[..]')}   {m}")
def warn(m): print(f"  {_c('93', '[warn]')} {m}")
def fail(m): print(f"  {_c('91', '[fail]')} {m}"); sys.exit(1)


def run(cmd, cwd=ROOT, quiet=False):
    r = subprocess.run(cmd, cwd=str(cwd), capture_output=quiet, text=True)
    return r.returncode == 0


# ── .env handling ─────────────────────────────────────────────────────────────

def read_env() -> dict:
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def write_env(updates: dict) -> None:
    lines, seen = [], set()
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            k = line.split("=", 1)[0].strip()
            if k in updates and "=" in line:
                lines.append(f"{k}={updates[k]}"); seen.add(k)
            else:
                lines.append(line)
    lines += [f"{k}={v}" for k, v in updates.items() if k not in seen]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(ENV_FILE, 0o600)


def issue_token() -> None:
    token = secrets.token_urlsafe(32)
    write_env({"JOCKY_API_TOKEN_HASH": hashlib.sha256(token.encode()).hexdigest()})
    bar = "-" * 60
    print(f"\n  {bar}\n  YOUR API TOKEN (shown once - store it in a password manager)\n\n"
          f"    {_c('1', token)}\n\n  It is required to sign in to the console.\n  {bar}\n")


def ensure_config() -> None:
    env = read_env()
    h = env.get("JOCKY_API_TOKEN_HASH", "")
    if len(h) != 64 or any(c not in "0123456789abcdefABCDEF" for c in h):
        note("No valid API token configured - generating one.")
        issue_token()
    else:
        ok("API token configured.")
    if len(env.get("JOCKY_BYTECODE_KEY", "")) < 32:
        write_env({"JOCKY_BYTECODE_KEY": secrets.token_urlsafe(48)})
        ok("Bytecode signing key generated.")


# ── Setup steps ───────────────────────────────────────────────────────────────

def ensure_python_env() -> None:
    if sys.version_info < (3, 10):
        fail(f"Python 3.10+ is required (found {sys.version_info.major}.{sys.version_info.minor}).")
    if not PY.exists():
        note("Creating virtual environment ...")
        if not run([sys.executable, "-m", "venv", str(VENV)], quiet=True):
            fail("Could not create the virtual environment (on Debian/Ubuntu: apt install python3-venv).")
    stamp = VENV / ".req-hash"
    digest = hashlib.sha256((ROOT / "requirements.txt").read_bytes()).hexdigest()
    if stamp.exists() and stamp.read_text() == digest:
        ok("Python dependencies up to date.")
        return
    note("Installing Python dependencies ...")
    if not run([str(PY), "-m", "pip", "install", "-q", "--disable-pip-version-check",
                "-r", str(ROOT / "requirements.txt")]):
        fail("pip install failed. Check your network connection and requirements.txt.")
    stamp.write_text(digest)
    ok("Python dependencies installed.")


def frontend_stale() -> bool:
    index = FRONTEND / "dist" / "index.html"
    if not index.exists():
        return True
    built = index.stat().st_mtime
    watch = [FRONTEND / "index.html", FRONTEND / "package.json"] + list((FRONTEND / "src").rglob("*"))
    return any(p.is_file() and p.stat().st_mtime > built for p in watch)


def ensure_frontend(dev: bool, rebuild: bool) -> bool:
    """Return True if a UI is available (built or dev)."""
    npm = shutil.which("npm")
    if not (FRONTEND / "package.json").exists():
        warn("frontend/ not found - API only.")
        return False
    if npm is None:
        if (FRONTEND / "dist" / "index.html").exists() and not dev:
            warn("Node.js not found - serving the existing UI build.")
            return True
        warn("Node.js is not installed - starting the API only. Install Node 20.19+ or 22.12+ for the UI.")
        return False

    if not _node_supported():
        if (FRONTEND / "dist" / "index.html").exists() and not dev:
            warn("Node.js is too old for the current Vite toolchain - serving the existing UI build.")
            return True
        warn("Node.js 20.19+ or 22.12+ is required by the current Vite toolchain.")
        return False

    if not _frontend_tool_ready():
        if (FRONTEND / "node_modules").exists():
            note("Frontend dependencies look incomplete - repairing node_modules ...")
            shutil.rmtree(FRONTEND / "node_modules", ignore_errors=True)
        else:
            note("Installing frontend dependencies (first run only) ...")
        if not _install_frontend(npm):
            warn("npm dependency installation failed - starting the API only.")
            return False
        if not _frontend_tool_ready():
            warn("Vite is still unavailable after dependency installation - starting the API only.")
            return False

    if dev:
        return True
    if rebuild or frontend_stale():
        note("Building the frontend ...")
        if not run([npm, "run", "build"], FRONTEND):
            warn("Frontend build failed - starting the API only. Try 'cd frontend; npm ci; npm run build'.")
            return False
    ok("Frontend ready.")
    return True


def _node_supported() -> bool:
    """Vite 8 requires Node 20.19+ or 22.12+."""
    node = shutil.which("node")
    if node is None:
        return False
    try:
        out = subprocess.check_output([node, "--version"], text=True, stderr=subprocess.DEVNULL).strip()
        major, minor = (int(x) for x in out.lstrip("v").split(".")[:2])
        return (major == 20 and minor >= 19) or major >= 22
    except (OSError, ValueError):
        return False


def _frontend_tool_ready() -> bool:
    """Verify that the actual Vite package and executable are present."""
    package = FRONTEND / "node_modules" / "vite" / "package.json"
    bin_dir = FRONTEND / "node_modules" / ".bin"
    executable = bin_dir / ("vite.cmd" if os.name == "nt" else "vite")
    return package.is_file() and executable.is_file()


def _install_frontend(npm: str) -> bool:
    """Install from the lockfile when available for deterministic setup."""
    lockfile = FRONTEND / "package-lock.json"
    command = "ci" if lockfile.exists() else "install"
    return run([npm, command, "--no-audit", "--no-fund"], FRONTEND)


# ── Run ───────────────────────────────────────────────────────────────────────

def wait_healthy(url: str, secs: int = 25) -> bool:
    end = time.time() + secs
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"{url}/api/health", timeout=2):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="JOCKY launcher")
    ap.add_argument("--dev", action="store_true", help="hot-reload frontend and API")
    ap.add_argument("--new-token", action="store_true", help="issue a new API token and exit")
    ap.add_argument("--rebuild", action="store_true", help="force a frontend rebuild")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()

    print(f"\n  {_c('1', 'JOCKY')}  forensic triage platform\n")
    if a.new_token:
        issue_token()
        return

    ensure_python_env()
    ensure_config()
    have_ui = ensure_frontend(a.dev, a.rebuild)

    if a.host not in ("127.0.0.1", "localhost", "::1"):
        warn(f"Binding to {a.host} exposes the API to the network. Put it behind TLS.")

    api_url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '::') else a.host}:{a.port}"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    if a.dev:
        env["JOCKY_CORS_ORIGINS"] = "http://localhost:5173,http://127.0.0.1:5173"
    cmd = [str(PY), "-m", "uvicorn", "jocky.api.main:app", "--host", a.host, "--port", str(a.port)]
    if a.dev:
        cmd.append("--reload")

    procs = [subprocess.Popen(cmd, cwd=str(ROOT), env=env)]
    open_url = api_url
    if a.dev and have_ui:
        procs.append(subprocess.Popen([shutil.which("npm"), "run", "dev", "--", "--host", "127.0.0.1"], cwd=str(FRONTEND)))
        open_url = "http://localhost:5173"

    if not wait_healthy(api_url):
        for p in procs:
            p.terminate()
        fail("The API did not start. Scroll up for the error.")

    print(f"\n  {_c('92', 'JOCKY is running')}\n    Console   {open_url if have_ui else '(UI unavailable)'}\n"
          f"    API docs  {api_url}/docs\n\n  Press Ctrl+C to stop.\n")
    if have_ui and not a.no_browser:
        webbrowser.open(open_url)

    try:
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        warn("A service exited unexpectedly.")
    except KeyboardInterrupt:
        pass
    finally:
        for p in reversed(procs):
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
        print("\n  Stopped.\n")


if __name__ == "__main__":
    main()
