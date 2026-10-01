#!/usr/bin/env python
"""One-command local launcher for SecureScan.

Starts everything you need in a single terminal:
  1. Redis (reuse if already up; otherwise start via Docker when available)
  2. Celery worker (--pool=solo on all platforms so Windows works)
  3. Frontend on :5500 (static files + /api proxied to Django)
  4. Django API (http://127.0.0.1:8000)
  5. Optional one Cloudflare tunnel for :5500 when cloudflared is installed

Usage:
    python start.py                  # from the repo root
    python run_dev.py                # from backend/ with the venv
    .\\start.ps1                     # Windows helper (uses backend\\venv)

Ctrl+C stops the API, Celery, and the frontend together. A Redis container
started by this script is left running for the next time.
"""
import atexit
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
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
# Never use hostname localhost — Windows resolves it to IPv6 [::1] and cloudflared 502s.
if FRONTEND_HOST in ("localhost", "::1", "[::1]"):
    FRONTEND_HOST = "127.0.0.1"
if API_HOST in ("localhost", "::1", "[::1]"):
    API_HOST = "127.0.0.1"

_child_processes = []  # list[tuple[str, subprocess.Popen]]
_TUNNEL_URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com", re.I)
_public_ui_url = None
_frontend_httpds = []
_PROXY_PREFIXES = ("/api", "/django-admin", "/media", "/static")
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


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


def _wait_port(host, port, timeout=45, label=""):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.25)
    if label:
        _log(f"WARNING: {label} did not open {host}:{port} within {timeout}s.")
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


def _csv_add(env_name, values):
    current = [item.strip() for item in os.environ.get(env_name, "").split(",") if item.strip()]
    for value in values:
        value = (value or "").strip()
        if value and value not in current:
            current.append(value)
    if current:
        os.environ[env_name] = ",".join(current)


def _write_api_config(api_public_url=""):
    path = FRONTEND_DIR / "assets" / "js" / "api-config.js"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "window.SECURESCAN_API_BASE = %s;\n" % json.dumps((api_public_url or "").rstrip("/")),
        encoding="utf-8",
    )


def _cloudflare_wanted():
    flag = (os.environ.get("CLOUDFLARE_TUNNEL") or "auto").strip().lower()
    if flag in ("0", "false", "off", "no"):
        return False
    if flag in ("1", "true", "on", "yes"):
        return True
    return shutil.which("cloudflared") is not None


def _cloudflared_command_lines():
    """Return (pid, commandline) for running cloudflared processes."""
    rows = []
    if os.name != "nt":
        return rows
    try:
        out = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process -Filter \"Name='cloudflared.exe'\" | "
                "ForEach-Object { '{0}|{1}' -f $_.ProcessId, $_.CommandLine }",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return rows
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        pid_s, cmd = line.split("|", 1)
        try:
            rows.append((int(pid_s), cmd or ""))
        except ValueError:
            continue
    return rows


def _stop_wrong_port_tunnels():
    """Stop leftover quick tunnels aimed at :8080 (Cloudflare's default example port)."""
    for pid, cmd in _cloudflared_command_lines():
        lower = cmd.lower()
        if "8080" not in lower:
            continue
        if f":{FRONTEND_PORT}" in lower or f"127.0.0.1:{FRONTEND_PORT}" in lower:
            continue
        _log(
            f"Stopping leftover cloudflared (pid {pid}) that points at port 8080. "
            "SecureScan is on port %s, not 8080." % FRONTEND_PORT
        )
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
        )


def _write_tunnel_config(local_url):
    cfg_dir = BASE_DIR / ".cache"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / "cloudflared-quick.yml"
    path.write_text(
        "# Generated by run_dev.py. Origin must be IPv4 127.0.0.1, never localhost:8080.\n"
        "url: %s\n" % local_url,
        encoding="utf-8",
    )
    return path


def _start_quick_tunnel(name, local_url, timeout=45):
    exe = shutil.which("cloudflared")
    if not exe:
        return None, None
    cfg = _write_tunnel_config(local_url)
    _log(f"Opening Cloudflare tunnel for {name} ({local_url})...")
    env = os.environ.copy()
    env.pop("TUNNEL_ORIGIN_CERT", None)
    kwargs = {
        "cwd": str(cfg.parent),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text": True,
        "bufsize": 1,
        "env": env,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        kwargs["encoding"] = "utf-8"
        kwargs["errors"] = "replace"
    else:
        kwargs["start_new_session"] = True
    # --url plus isolated --config so a user config.yml cannot switch origin to localhost:8080.
    proc = subprocess.Popen(
        [
            exe,
            "tunnel",
            "--config",
            str(cfg),
            "--no-autoupdate",
            "--url",
            local_url,
        ],
        **kwargs,
    )
    _child_processes.append((f"Cloudflare {name}", proc))
    found = []

    def _read():
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    print(f"[cloudflared {name}] {line}", flush=True)
                match = _TUNNEL_URL_RE.search(line)
                if match:
                    found.append(match.group(0).rstrip("/"))
        except Exception:
            return

    thread = threading.Thread(target=_read, daemon=True)
    thread.start()
    deadline = time.time() + timeout
    while time.time() < deadline:
        if found:
            return proc, found[0]
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    _log(f"WARNING: Cloudflare did not publish a URL for {name} in time.")
    return proc, None


def start_cloudflare_tunnels():
    """One public URL for port 5500 (HTML + /api). Django stays local on 8000."""
    global _public_ui_url
    _write_api_config("")
    if not _cloudflare_wanted():
        return
    if not shutil.which("cloudflared"):
        _log(
            "CLOUDFLARE_TUNNEL is on, but cloudflared is not installed. "
            "Install it with: winget install --id Cloudflare.cloudflared -e"
        )
        return

    if not _port_open("127.0.0.1", FRONTEND_PORT) and not _port_open(FRONTEND_HOST, FRONTEND_PORT):
        _log("Frontend is not listening — skipping Cloudflare until port 5500 is up.")
        return

    _stop_wrong_port_tunnels()

    ui_local = f"http://127.0.0.1:{FRONTEND_PORT}"
    _, ui_url = _start_quick_tunnel("site", ui_local)
    _public_ui_url = ui_url
    if ui_url:
        parsed = urlparse(ui_url)
        _csv_add("ALLOWED_HOSTS", [parsed.hostname, ".trycloudflare.com"])
        _csv_add("CORS_ALLOWED_ORIGINS", [ui_url])
        _csv_add("CSRF_TRUSTED_ORIGINS", [ui_url])
        os.environ["FRONTEND_BASE_URL"] = ui_url
        _log(f"Public site (share this): {ui_url}")
        _log("Keep this window open. Closing it, or using an old trycloudflare URL, causes 502.")
    else:
        _log("Cloudflare did not return a URL. Use http://127.0.0.1:%s locally." % FRONTEND_PORT)


def _cleanup():
    global _frontend_httpds
    for httpd in _frontend_httpds:
        try:
            httpd.shutdown()
        except Exception:
            pass
    _frontend_httpds = []
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


class DualStackHTTPServer(ThreadingHTTPServer):
    """Listen on IPv6 and IPv4 so Windows `localhost` ([::1]) does not 502."""

    address_family = socket.AF_INET6
    allow_reuse_address = True

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        return ThreadingHTTPServer.server_bind(self)


def _listen_frontend(handler, port):
    """Bind dual-stack :: then fall back to 127.0.0.1."""
    try:
        httpd = DualStackHTTPServer(("::", port), handler)
        return httpd, f"[::]:{port} (IPv4+IPv6)"
    except OSError:
        pass

    class IPv4HTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True

    httpd = IPv4HTTPServer(("127.0.0.1", port), handler)
    return httpd, f"127.0.0.1:{port}"


def start_frontend():
    global _frontend_httpds
    if not FRONTEND_DIR.is_dir():
        _log(f"WARNING: Frontend folder not found at {FRONTEND_DIR} — skipping UI server.")
        return None

    if _port_open(FRONTEND_HOST, FRONTEND_PORT) or _port_open("127.0.0.1", FRONTEND_PORT):
        _log(
            f"Port {FRONTEND_PORT} is already in use. Stop the other program "
            "(old http.server / Live Server) so start.py can proxy /api. "
            "A leftover process here is a common cause of Cloudflare 502."
        )
        return None

    class SecureScanHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

        def log_message(self, fmt, *args):
            sys.stderr.write("[frontend] " + (fmt % args) + "\n")

        def _should_proxy(self):
            path = urlparse(self.path).path
            return any(path == p or path.startswith(p + "/") for p in _PROXY_PREFIXES)

        def _proxy(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            headers = {}
            for key, val in self.headers.items():
                if key.lower() in _HOP_BY_HOP:
                    continue
                headers[key] = val
            headers["Host"] = "127.0.0.1:%s" % API_PORT
            incoming_host = self.headers.get("Host") or ""
            headers["X-Forwarded-Host"] = incoming_host
            headers["X-Forwarded-Proto"] = (
                "https" if "trycloudflare.com" in incoming_host.lower() else "http"
            )
            headers["X-Forwarded-For"] = self.client_address[0]
            conn = http.client.HTTPConnection("127.0.0.1", API_PORT, timeout=300)
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
            except OSError:
                self.send_error(
                    502,
                    "Django is not running on port %s. Wait for start.py to finish starting."
                    % API_PORT,
                )
                return
            finally:
                conn.close()
            self.send_response(resp.status, resp.reason)
            for key, val in resp.getheaders():
                if key.lower() in _HOP_BY_HOP or key.lower() == "content-length":
                    continue
                self.send_header(key, val)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            if self._should_proxy():
                return self._proxy()
            return super().do_GET()

        def do_HEAD(self):
            if self._should_proxy():
                return self._proxy()
            return super().do_HEAD()

        def do_POST(self):
            if self._should_proxy():
                return self._proxy()
            self.send_error(501, "Unsupported method")

        def do_PUT(self):
            return self._proxy() if self._should_proxy() else self.send_error(501)

        def do_PATCH(self):
            return self._proxy() if self._should_proxy() else self.send_error(501)

        def do_DELETE(self):
            return self._proxy() if self._should_proxy() else self.send_error(501)

        def do_OPTIONS(self):
            if self._should_proxy():
                return self._proxy()
            self.send_response(204)
            self.send_header("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
            self.end_headers()

    ports = [FRONTEND_PORT]
    if 8080 not in ports:
        ports.append(8080)

    for port in ports:
        if port != FRONTEND_PORT and (
            _port_open("127.0.0.1", port) or _port_open("::1", port)
        ):
            _log(f"Port {port} is busy — not mirroring the site there.")
            continue
        try:
            httpd, where = _listen_frontend(SecureScanHandler, port)
        except OSError as exc:
            _log(f"Could not listen on port {port}: {exc}")
            continue
        _frontend_httpds.append(httpd)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        _log(f"Frontend listening on {where} (UI + /api proxy)")

    if not _frontend_httpds:
        _log("Frontend did not bind any port.")
        return None
    if not _wait_port("127.0.0.1", FRONTEND_PORT, timeout=10, label="Frontend"):
        _log("Frontend server started but 127.0.0.1:%s is not reachable yet." % FRONTEND_PORT)
    return _frontend_httpds


def start_api():
    """Run Django in the foreground. Returns True if this process started it."""
    if _port_open(API_HOST, API_PORT):
        _log(
            f"API already running on http://{API_HOST}:{API_PORT} — reusing it. "
            "Press Ctrl+C to stop Celery, the frontend, and Cloudflare."
        )
        return False

    _log(f"Starting Django API at http://{API_HOST}:{API_PORT} ...")
    proc = _popen(
        "Django",
        [PYTHON(), "manage.py", "runserver", f"{API_HOST}:{API_PORT}"],
        BASE_DIR,
    )
    if not _wait_port(API_HOST, API_PORT, timeout=60, label="Django"):
        _log("Django did not open port %s. Login over Cloudflare will 502 until it does." % API_PORT)
    return proc


def _print_banner():
    ui = _public_ui_url or f"http://{FRONTEND_HOST}:{FRONTEND_PORT}"
    _log("")
    _log("SecureScan is starting:")
    _log(f"  Site  {ui}")
    _log(f"  API   proxied at {ui.rstrip('/')}/api/  (local Django http://{API_HOST}:{API_PORT})")
    if _public_ui_url:
        _log("  Share the Site URL only. Do not reuse an old trycloudflare link after restart.")
        _log("  Do not run: cloudflared tunnel --url http://localhost:8080")
        _log("  That command caused your 502 (Cloudflare up, nothing on [::1]:8080).")
    _log("  Ctrl+C stops Django, Celery, the frontend, and Cloudflare.")
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
    if _cloudflare_wanted():
        _csv_add("ALLOWED_HOSTS", [".trycloudflare.com"])
    ensure_redis()
    start_celery_worker()
    start_celery_beat()
    start_frontend()
    started = start_api()
    start_cloudflare_tunnels()
    _print_banner()
    try:
        if started:
            started.wait()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        _log("Shutting down...")


if __name__ == "__main__":
    main()
