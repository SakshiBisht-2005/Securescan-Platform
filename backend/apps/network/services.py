"""Defensive network helpers for hosts you operate.

Active TCP checks only target this machine (127.0.0.1). HTTP fetches refuse
private, loopback, link-local, and metadata destinations.
"""
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

from common.exceptions import ValidationAppError

LOCAL_PORTS = [
    22, 53, 80, 443, 3306, 3389, 5432, 5500, 6379, 8000, 8080, 8443, 27017,
]
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
INTERESTING_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "server",
    "x-powered-by",
]


def client_identity(request):
    forwarded = (request.META.get("HTTP_X_FORWARDED_FOR") or "").split(",")[0].strip()
    ip = forwarded or request.META.get("REMOTE_ADDR") or ""
    identity = {
        "client_ip": ip,
        "classification": None,
        "user_agent": request.META.get("HTTP_USER_AGENT", "")[:300],
        "note": "This is the address your browser used to reach SecureScan, not a scan of other networks.",
    }
    if ip:
        try:
            identity["classification"] = classify_ip(ip)
        except ValidationAppError:
            identity["classification"] = {"ip": ip, "kind": "unknown"}
    return identity


def classify_ip(raw: str):
    text = (raw or "").strip()
    if not text:
        raise ValidationAppError("Enter an IPv4 or IPv6 address.")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValidationAppError("That is not a valid IP address.") from exc
    return {
        "ip": str(addr),
        "version": addr.version,
        "is_private": addr.is_private,
        "is_loopback": addr.is_loopback,
        "is_link_local": addr.is_link_local,
        "is_multicast": addr.is_multicast,
        "is_reserved": addr.is_reserved,
        "is_global": addr.is_global,
        "kind": _kind(addr),
    }


def _kind(addr):
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "private"
    if addr.is_global:
        return "public"
    return "special"


def dns_lookup(host: str):
    host = (host or "").strip().rstrip(".")
    if not host or not HOST_RE.match(host):
        raise ValidationAppError("Enter a hostname such as example.com.")
    records = {"a": [], "aaaa": [], "ptr": []}
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        detail = exc.args[-1] if exc.args else "lookup failed"
        raise ValidationAppError(f"Could not resolve that name ({detail}).") from exc
    seen = set()
    for info in infos:
        ip = info[4][0]
        if ip in seen:
            continue
        seen.add(ip)
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.version == 4:
            records["a"].append(ip)
        else:
            records["aaaa"].append(ip)
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            if name:
                records["ptr"].append(name)
        except (socket.herror, socket.gaierror, OSError):
            pass
    records["ptr"] = sorted(set(records["ptr"]))
    return {"host": host, "records": records}


def localhost_ports():
    results = []
    for port in LOCAL_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            open_now = sock.connect_ex(("127.0.0.1", port)) == 0
        except OSError:
            open_now = False
        finally:
            sock.close()
        results.append({"port": port, "open": open_now})
    return {
        "target": "127.0.0.1",
        "scope": "This SecureScan machine only.",
        "ports": results,
        "open_count": sum(1 for row in results if row["open"]),
    }


def _blocked_ip(addr) -> bool:
    return any(
        (
            addr.is_private,
            addr.is_loopback,
            addr.is_link_local,
            addr.is_multicast,
            addr.is_reserved,
            addr.is_unspecified,
        )
    )


def _assert_public_http_url(raw: str):
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValidationAppError("Use an http:// or https:// URL you operate.")
    if parsed.username or parsed.password:
        raise ValidationAppError("URLs with credentials are not allowed.")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationAppError("That hostname could not be resolved.") from exc
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _blocked_ip(addr):
            raise ValidationAppError("That URL points at a private or local address and is blocked.")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _assert_public_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_security_headers(url: str):
    raw = (url or "").strip()
    _assert_public_http_url(raw)
    parsed = urlparse(raw)
    req = urllib.request.Request(raw, method="GET", headers={"User-Agent": "SecureScan-HeaderCheck/1.0"})
    handlers = [_SafeRedirect()]
    if parsed.scheme == "https":
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=8) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            status_code = getattr(resp, "status", None) or resp.getcode()
            final_url = resp.geturl()
            resp.read(64)
    except urllib.error.HTTPError as exc:
        headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        status_code = exc.code
        final_url = getattr(exc, "url", None) or raw
    except urllib.error.URLError as exc:
        raise ValidationAppError("Could not fetch that URL.") from exc
    except ValidationAppError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ValidationAppError(f"Could not fetch that URL ({exc.__class__.__name__}).") from exc

    lowered = {k.lower(): v for k, v in headers.items()}
    security = []
    for name in INTERESTING_HEADERS:
        present = name in lowered
        security.append({"header": name, "present": present, "value": lowered.get(name, "")[:300]})
    skip_missing = {"server", "x-powered-by", "access-control-allow-origin"}
    missing = [row["header"] for row in security if not row["present"] and row["header"] not in skip_missing]
    return {
        "url": raw,
        "final_url": final_url,
        "status_code": status_code,
        "security_headers": security,
        "missing": missing,
    }
