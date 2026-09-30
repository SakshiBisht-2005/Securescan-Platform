#!/usr/bin/env python
"""One-command local launcher for SecureScan.

Starts everything you need in a single terminal:
  1. Redis (reuse if already up; otherwise start via Docker when available)
  2. Celery worker (--pool=solo on all platforms so Windows works)
  3. Frontend static server (http://127.0.0.1:5500 by default)
  4. Django API (http://127.0.0.1:8000) in the foreground

Usage:
    python start.py                  # from the repo root
    python run_dev.py                # from backend/ with the venv
    .\\start.ps1                     # Windows helper (uses backend\\venv)

Ctrl+C stops the API, Celery, and the frontend together. A Redis container
started by this script is left running for the next time.
"""
import atexit
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
FRONTEND_DIR = REPO_ROOT / "frontend"

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    pass

_broker_url = (
    os.environ.get("CELERY_BROKER_URL")
    or os.environ.get("REDIS_URL")
    or "redis://localhost:6379/0"
)
_parsed = urlparse(_broker_url)
REDIS_HOST = _parsed.hostname or "127.0.0.1"
REDIS_PORT = _parsed.port or 6379
REDIS_CONTAINER_NAME = "securescan-redis"

API_HOST = os.environ.get("DEV_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("DEV_API_PORT", "8000"))

_frontend_url = os.environ.get("FRONTEND_BASE_URL", "http://127.0.0.1:5500")
_frontend_parsed = urlparse(_frontend_url)
FRONTEND_HOST = os.environ.get("DEV_FRONTEND_HOST", _frontend_parsed.hostname or "127.0.0.1")
FRONTEND_PORT = int(os.environ.get("DEV_FRONTEND_PORT", str(_frontend_parsed.port or 5500)))

_child_processes = []  # list[tuple[str, subprocess.Popen]]


def _log(msg):
    print(f"[run_dev] {msg}", flush=True)


def _venv_python():
    if os.name == "nt":
        candidate = BASE_DIR / "venv" / "Scripts" / "python.exe"
    else:
        candidate = BASE_DIR / "venv" / "bin" / "python"
    return candidate if candidate.is_file() else None


def _reexec_with_venv():
    """Plain `python start.py` often hits system Python, which has no Celery."""
    desired = _venv_python()
    if desired is None:
        _log(
            "WARNING: backend/venv not found. Install dependencies with:\n"
            "  cd backend && python -m venv venv && venv\\Scripts\\activate && pip install -r requirements.txt"
        )
        return
    current = Path(sys.executable).resolve()
    if current == desired.resolve():
        return
    _log(f"Switching to project venv: {desired}")
    os.execv(str(desired), [str(desired), str(Path(__file__).resolve()), *sys.argv[1:]])


def PYTHON():
    venv = _venv_python()
    return str(venv) if venv else sys.executable


def _port_open(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _stop_proc(name, proc):
    if proc.poll() is not None:
        return
    _log(f"Stopping {name} (pid {proc.pid})...")
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            text=True,
        )
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError, AttributeError):
            proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


def _popen(name, args, cwd):
    kwargs = {"cwd": str(cwd)}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(args, **kwargs)
    _child_processes.append((name, proc))
    return proc


def _cleanup():
    # Stop in reverse start order; Django is usually already exiting.
    for name, proc in reversed(_child_processes):
        _stop_proc(name, proc)
    _child_processes.clear()


def ensure_redis():
    if _port_open(REDIS_HOST, REDIS_PORT):
        _log(f"Redis already reachable on {REDIS_HOST}:{REDIS_PORT}.")
        return

    docker = shutil.which("docker")
    if not docker:
        _log(
            f"WARNING: Redis isn't reachable on {REDIS_HOST}:{REDIS_PORT} and "
            "Docker isn't on PATH, so it can't be started automatically. "
            "The UI and API will still run, but scans will fail to queue "
            "until Redis is running (Memurai, WSL, or Docker Desktop)."
        )
        return

    existing = subprocess.run(
        [docker, "ps", "-aq", "-f", f"name=^{REDIS_CONTAINER_NAME}$"],
        capture_output=True, text=True,
    )
    if existing.stdout.strip():
        _log(f"Starting existing Docker container '{REDIS_CONTAINER_NAME}'...")
        subprocess.run([docker, "start", REDIS_CONTAINER_NAME])
    else:
        _log(f"Creating Redis container '{REDIS_CONTAINER_NAME}' via Docker...")
        subprocess.run([
            docker, "run", "-d", "--name", REDIS_CONTAINER_NAME,
            "-p", f"{REDIS_PORT}:6379", "redis:7-alpine",
        ])

    for _ in range(20):
        if _port_open(REDIS_HOST, REDIS_PORT):
            _log("Redis is up.")
            return
        time.sleep(0.5)
    _log("WARNING: Redis container started but the port isn't reachable yet — scans may fail to queue at first.")


def start_celery_worker():
    _log("Starting Celery worker (--pool=solo)...")
    return _popen(
        "Celery",
        [PYTHON(), "-m", "celery", "-A", "config", "worker", "--pool=solo", "-l", "info"],
        BASE_DIR,
    )


def start_celery_beat():
    logs = BASE_DIR / "logs"
    logs.mkdir(exist_ok=True)
    _log("Starting Celery beat (weekly scheduled scans)...")
    return _popen(
        "Celery beat",
        [
            PYTHON(), "-m", "celery", "-A", "config", "beat", "-l", "info",
            f"--pidfile={logs / 'celerybeat.pid'}",
            f"--schedule={logs / 'celerybeat-schedule'}",
        ],
        BASE_DIR,
    )


def start_frontend():
    if not FRONTEND_DIR.is_dir():
        _log(f"WARNING: Frontend folder not found at {FRONTEND_DIR} — skipping UI server.")
        return None

    if _port_open(FRONTEND_HOST, FRONTEND_PORT):
        _log(f"Frontend already running on http://{FRONTEND_HOST}:{FRONTEND_PORT} — reusing it.")
        return None

    _log(f"Starting frontend at http://{FRONTEND_HOST}:{FRONTEND_PORT} ...")
    return _popen(
        "Frontend",
        [PYTHON(), "-m", "http.server", str(FRONTEND_PORT), "--bind", FRONTEND_HOST],
        FRONTEND_DIR,
    )


def start_api():
    """Run Django in the foreground. Returns True if this process started it."""
    if _port_open(API_HOST, API_PORT):
        _log(
            f"API already running on http://{API_HOST}:{API_PORT} — reusing it. "
            "Press Ctrl+C to stop Celery and the frontend started by this command."
        )
        return False

    _log(f"Starting Django API at http://{API_HOST}:{API_PORT} ...")
    subprocess.run(
        [PYTHON(), "manage.py", "runserver", f"{API_HOST}:{API_PORT}"],
        cwd=str(BASE_DIR),
    )
    return True


def _print_banner():
    ui = f"http://{FRONTEND_HOST}:{FRONTEND_PORT}"
    api = f"http://{API_HOST}:{API_PORT}"
    _log("")
    _log("SecureScan is starting:")
    _log(f"  UI   {ui}")
    _log(f"  API  {api}")
    _log("  Ctrl+C stops the API, Celery, and the frontend.")
    host = (os.environ.get("EMAIL_HOST") or "").strip()
    user = (os.environ.get("EMAIL_HOST_USER") or "").strip()
    password = (os.environ.get("EMAIL_HOST_PASSWORD") or "").strip()
    if host and user and password:
        _log(f"  SMTP  {host} as {user}")
    else:
        _log("  SMTP  not configured — verification mail will not leave this machine.")
        _log("        Set EMAIL_HOST, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD in backend/.env")
        _log("        (Gmail: App Password). See docs/EMAIL.md")
    _log("")


def main():
    _reexec_with_venv()
    atexit.register(_cleanup)
    ensure_redis()
    start_celery_worker()
    start_celery_beat()
    start_frontend()
    _print_banner()
    try:
        started = start_api()
        if not started:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        _log("Shutting down...")


if __name__ == "__main__":
    main()
