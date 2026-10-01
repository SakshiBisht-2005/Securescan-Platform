"""Defensive analyzers. No exploit payloads, no remote port scans of other hosts."""
import io
import json
import re
import ssl
import urllib.error
import urllib.request
import zipfile

from apps.network import services as net
from common.exceptions import ValidationAppError

MAX_TEXT = 180_000
MAX_ZIP = 12 * 1024 * 1024

SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|aws_secret|private_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    r"|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"
)
EVAL_RE = re.compile(r"\b(eval|exec|pickle\.loads|innerHTML|dangerouslySetInnerHTML)\s*[\(=]")
USER_DOCKER = re.compile(r"(?im)^USER\s+")
ENV_SECRET = re.compile(r"(?im)^(?:ENV|ARG)\s+\w*(PASS|SECRET|TOKEN|KEY)\w*")


def _find(fid, title, severity, detail, evidence=""):
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "detail": detail,
        "evidence": (evidence or "")[:400],
    }


def _need_owned(confirm):
    if not confirm:
        raise ValidationAppError("Confirm you own or are authorized to test this target.")


def _clip(text):
    text = text or ""
    if len(text) > MAX_TEXT:
        raise ValidationAppError("Paste is too large. Keep it under 180 KB.")
    return text


def _tls_info(hostname: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(net.socket.socket(), server_hostname=hostname) as sock:
            sock.settimeout(8)
            sock.connect((hostname, 443))
            cert = sock.getpeercert()
    except Exception:  # noqa: BLE001
        return None
    not_after = cert.get("notAfter") if cert else None
    subject = {}
    for part in cert.get("subject") or ():
        for key, val in part:
            subject[key] = val
    return {"not_after": not_after, "subject_cn": subject.get("commonName", "")}


def _web_surface(url: str):
    findings = []
    headers = net.http_security_headers(url)
    for name in headers.get("missing") or []:
        findings.append(
            _find(
                f"hdr-{name}",
                f"Missing {name}",
                "medium",
                "Browsers and APIs are safer when this header is set on responses you control.",
            )
        )
    lowered = {row["header"]: row for row in headers.get("security_headers") or []}
    server = lowered.get("server") or {}
    if server.get("present") and server.get("value"):
        findings.append(
            _find(
                "banner-server",
                "Server banner exposed",
                "low",
                "Response includes a Server header. Trim version details in production.",
                server.get("value"),
            )
        )
    if (url or "").startswith("http://"):
        findings.append(
            _find("http-plain", "URL uses HTTP", "high", "Use HTTPS for the public site and APIs."),
        )
    host = net.urlparse(url).hostname
    if host and (url or "").startswith("https://"):
        tls = _tls_info(host)
        if tls and tls.get("not_after"):
            findings.append(
                _find("tls-expiry", "TLS certificate seen", "info", "Certificate notAfter date.", tls["not_after"])
            )
    return findings, headers


def run_black_box(data, confirm):
    _need_owned(confirm)
    url = (data.get("url") or "").strip()
    net._assert_public_http_url(url)
    host = net.urlparse(url).hostname
    dns = net.dns_lookup(host)
    findings, headers = _web_surface(url)
    return {
        "summary": "Passive black-box look at DNS and HTTP security posture of the URL you named.",
        "target": {"url": url, "dns": dns},
        "headers": headers,
        "findings": findings,
    }


def run_gray_box(data, confirm):
    _need_owned(confirm)
    url = (data.get("url") or "").strip()
    net._assert_public_http_url(url)
    token = (data.get("bearer_token") or "").strip()
    findings, headers = _web_surface(url)
    status_code = headers.get("status_code")
    if token:
        findings.append(
            _find(
                "token-supplied",
                "Credential provided for gray-box",
                "info",
                "The token was used only to attach Authorization on one GET. It is not stored.",
            )
        )
        import ssl as sslmod

        parsed = net.urlparse(url)
        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "SecureScan-GrayBox/1.0",
                "Authorization": "Bearer " + token,
            },
        )
        handlers = [net._SafeRedirect()]
        if parsed.scheme == "https":
            handlers.append(urllib.request.HTTPSHandler(context=sslmod.create_default_context()))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=8) as resp:
                auth_status = getattr(resp, "status", None) or resp.getcode()
                resp.read(64)
        except urllib.error.HTTPError as exc:
            auth_status = exc.code
        except Exception as exc:  # noqa: BLE001
            raise ValidationAppError(f"Authenticated request failed ({exc.__class__.__name__}).") from exc
        if auth_status in (401, 403):
            findings.append(
                _find(
                    "auth-rejected",
                    "Token was not accepted",
                    "medium",
                    f"GET with Authorization returned HTTP {auth_status}. Check audience, expiry, and path.",
                )
            )
        elif auth_status and auth_status < 400:
            findings.append(
                _find(
                    "auth-accepted",
                    "Authenticated GET succeeded",
                    "info",
                    f"HTTP {auth_status}. Next: confirm object-level authorization on other resources.",
                )
            )
    elif status_code and status_code < 400:
        findings.append(
            _find(
                "anon-ok",
                "Endpoint answered without a token",
                "medium",
                "If this route should be private, require authentication.",
            )
        )
    return {
        "summary": "Gray-box: public headers plus one optional authenticated GET you authorized.",
        "target": {"url": url, "token_provided": bool(token)},
        "headers": headers,
        "findings": findings,
    }


def _source_findings(source: str):
    source = _clip(source)
    if not source.strip():
        raise ValidationAppError("Paste source or configuration to review.")
    findings = []
    for match in SECRET_RE.finditer(source):
        findings.append(
            _find(
                "secret-%s" % match.start(),
                "Possible secret in source",
                "high",
                "Rotate the credential and move it to a secret store. Do not commit it.",
                match.group(0)[:80],
            )
        )
        if len(findings) >= 25:
            break
    if EVAL_RE.search(source):
        findings.append(
            _find(
                "dangerous-api",
                "Risky dynamic execution or HTML sink",
                "medium",
                "eval/exec/pickle/innerHTML-style APIs need strict review.",
            )
        )
    if re.search(r"(?i)latest", source) and re.search(r"(?i)(FROM |image:)", source):
        findings.append(
            _find("float-tag", "Floating image tag", "low", "Pin image digests or versions for IaC/containers.")
        )
    if not findings:
        findings.append(
            _find(
                "source-clean",
                "No quick-pattern hits",
                "info",
                "Run a full project scan in Code mode for Semgrep, Bandit, SCA, and Gitleaks.",
            )
        )
    return findings


def run_white_box(data, confirm):
    findings = _source_findings(data.get("source") or "")
    return {
        "summary": "White-box pattern review of pasted source. Use Projects for repository SAST/SCA.",
        "findings": findings,
    }


def run_code_security(data, confirm):
    out = run_white_box(data, confirm)
    out["summary"] = (
        "Code security: secrets and unsafe APIs in the paste, plus IaC/container hints. "
        "Full SAST/SCA stays on the Projects scanner."
    )
    out["next"] = "projects.html"
    return out


def run_penetration_testing(data, confirm):
    _need_owned(confirm)
    notes = (data.get("scope_notes") or "").strip()
    url = (data.get("url") or "").strip()
    findings = [
        _find(
            "roe",
            "Rules of engagement recorded",
            "info",
            "Validation is limited to the URL and notes you provided. No exploit development is performed.",
            notes[:300] or "(no extra notes)",
        )
    ]
    headers = None
    if url:
        extra, headers = _web_surface(url)
        findings.extend(extra)
    return {
        "summary": "Authorized validation: scope note plus optional passive web checks. Not an attack simulation.",
        "engagement": {
            "in_scope": url or notes or "(describe the asset)",
            "out_of_scope": "Third-party systems, denial of service, exploit payloads, and credentials you do not own.",
        },
        "headers": headers,
        "findings": findings,
    }


def run_web(data, confirm):
    _need_owned(confirm)
    url = (data.get("url") or "").strip()
    findings, headers = _web_surface(url)
    if "http://" in (headers.get("final_url") or url or ""):
        findings.append(_find("no-https-final", "Final URL is not HTTPS", "high", "Redirect users to HTTPS."))
    return {
        "summary": "OWASP-style baseline on a site you operate: transport and security headers.",
        "headers": headers,
        "findings": findings,
    }


def run_network(data, confirm):
    host = (data.get("host") or "").strip()
    result = {"summary": "Local listening ports on this SecureScan host, plus optional DNS.", "findings": []}
    result["local_ports"] = net.localhost_ports()
    open_count = result["local_ports"].get("open_count") or 0
    result["findings"].append(
        _find(
            "local-open",
            "Listening ports on 127.0.0.1",
            "info" if open_count else "info",
            f"{open_count} of the common ports are open on this machine only.",
        )
    )
    if host:
        try:
            result["dns"] = net.dns_lookup(host)
        except ValidationAppError as exc:
            result["findings"].append(_find("dns-fail", "DNS lookup failed", "low", str(exc)))
        try:
            result["ip"] = net.classify_ip(host)
        except ValidationAppError:
            pass
    return result


def run_cloud(data, confirm):
    text = _clip(data.get("config_text") or "")
    if not text.strip():
        raise ValidationAppError("Paste IAM, bucket, or security-group JSON you are authorized to review.")
    findings = []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        blob = text
        if re.search(r'"Principal"\s*:\s*"\*"', blob) or re.search(r'"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"', blob):
            findings.append(_find("principal-star", "Principal * in policy text", "high", "Avoid anonymous principals."))
        if re.search(r'"Action"\s*:\s*"\*"', blob):
            findings.append(_find("action-star", "Action * in policy text", "high", "Scope actions to what the role needs."))
        if not findings:
            findings.append(_find("not-json", "Could not parse JSON", "low", "Paste a JSON policy document."))
        return {"summary": "Cloud configuration review from pasted text.", "findings": findings}

    blob = json.dumps(doc)
    if '"Principal": "*"' in blob or '"AWS": "*"' in blob:
        findings.append(_find("principal-star", "Wildcard principal", "high", "This allows any AWS principal or anonymous access."))
    if re.search(r'"Action":\s*"\*"', blob):
        findings.append(_find("action-star", "Wildcard action", "high", "Limit Action to required APIs."))
    if re.search(r'(?i)"PublicAccessBlockConfiguration"', blob) and "false" in blob.lower():
        findings.append(_find("public-block", "Public access block may be off", "high", "Keep S3 public access blocks enabled unless the bucket is meant to be public."))
    if re.search(r'(?i)0\.0\.0\.0/0', blob):
        findings.append(_find("world-cidr", "0.0.0.0/0 in configuration", "high", "World-open network rules need a documented exception."))
    if not findings:
        findings.append(_find("cloud-ok", "No high-risk IAM/network patterns", "info", "Still review least privilege in the cloud console."))
    return {"summary": "Static cloud JSON review (IAM, storage, network).", "findings": findings}


def run_container(data, confirm):
    text = _clip(data.get("config_text") or "")
    if not text.strip():
        raise ValidationAppError("Paste a Dockerfile, Compose, or Kubernetes snippet.")
    findings = []
    if re.search(r"(?im)^FROM\s+\S+:latest\b", text) or re.search(r"(?im)^\s+image:\s+\S+:latest\b", text):
        findings.append(_find("latest-tag", "Image tag :latest", "medium", "Pin versions or digests so builds are repeatable."))
    if re.search(r"(?im)^FROM\s+", text) and not USER_DOCKER.search(text):
        findings.append(_find("no-user", "Dockerfile has no USER", "medium", "Run the process as a non-root user."))
    if ENV_SECRET.search(text):
        findings.append(_find("env-secret", "Secret-like build ARG/ENV", "high", "Use runtime secrets, not image ENV."))
    if re.search(r"(?im)privileged:\s*true", text):
        findings.append(_find("privileged", "privileged: true", "high", "Avoid privileged containers in production."))
    if re.search(r"(?i)hostNetwork:\s*true", text):
        findings.append(_find("host-net", "hostNetwork: true", "medium", "Host networking widens blast radius."))
    if not findings:
        findings.append(_find("container-ok", "No quick container misconfig hits", "info", "Still scan the image with your registry scanner."))
    return {"summary": "Static container/Kubernetes configuration review.", "findings": findings}


def run_api(data, confirm):
    text = _clip(data.get("spec_text") or "")
    if not text.strip():
        raise ValidationAppError("Paste an OpenAPI JSON document (YAML is not parsed yet).")
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationAppError("OpenAPI must be JSON for this check.") from exc
    findings = []
    if not isinstance(spec, dict):
        raise ValidationAppError("OpenAPI root must be an object.")
    servers = spec.get("servers") or []
    for srv in servers:
        url = (srv.get("url") or "") if isinstance(srv, dict) else ""
        if url.startswith("http://"):
            findings.append(_find("api-http", "Server URL is HTTP", "high", url[:200]))
    schemes = spec.get("components", {}).get("securitySchemes") if isinstance(spec.get("components"), dict) else None
    if spec.get("swagger") == "2.0":
        schemes = spec.get("securityDefinitions")
    if not schemes:
        findings.append(_find("no-schemes", "No securitySchemes defined", "high", "Declare how clients authenticate."))
    paths = spec.get("paths") or {}
    public = 0
    for path, ops in paths.items() if isinstance(paths, dict) else []:
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.startswith("x-") or method == "parameters":
                continue
            if not isinstance(op, dict):
                continue
            sec = op.get("security", spec.get("security"))
            if sec == [] or sec is None:
                public += 1
                if public <= 8:
                    findings.append(
                        _find(
                            "anon-%s-%s" % (method, path),
                            "Operation may be anonymous",
                            "medium",
                            f"{method.upper()} {path} has empty or missing security. Confirm it is meant to be public.",
                        )
                    )
    if not findings:
        findings.append(_find("api-ok", "Spec has schemes and no obvious anonymous flood", "info", "Still test object-level authorization."))
    return {
        "summary": "OpenAPI review: transport, security schemes, anonymous operations.",
        "findings": findings,
        "path_count": len(paths) if isinstance(paths, dict) else 0,
    }


def run_mobile(data, confirm, package_bytes=None, filename=""):
    if not package_bytes:
        raise ValidationAppError("Upload an APK, IPA, or zip of the app you are authorized to test.")
    if len(package_bytes) > MAX_ZIP:
        raise ValidationAppError("Package is larger than 12 MB for this static check.")
    findings = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(package_bytes))
    except zipfile.BadZipFile as exc:
        raise ValidationAppError("That file is not a readable zip/APK/IPA.") from exc
    names = zf.namelist()[:400]
    joined = "\n".join(names)
    if "AndroidManifest.xml" in names or any(n.endswith("AndroidManifest.xml") for n in names):
        findings.append(_find("android", "Android package structure", "info", "AndroidManifest.xml is present."))
    if any("Info.plist" in n for n in names):
        findings.append(_find("ios", "iOS package structure", "info", "Info.plist is present."))
    if any(n.startswith("META-INF/") for n in names):
        findings.append(_find("signed", "META-INF present", "info", "Java/Android signing metadata found."))
    text_blobs = [filename, joined]
    for name in names:
        if name.endswith("/") or name.endswith(".so") or name.endswith(".dex"):
            continue
        if zf.getinfo(name).file_size > 80_000:
            continue
        if not re.search(r"\.(xml|plist|json|txt|properties|js|html)$", name, re.I):
            continue
        try:
            raw = zf.read(name)
        except Exception:  # noqa: BLE001
            continue
        try:
            text_blobs.append(raw.decode("utf-8", errors="ignore"))
        except Exception:  # noqa: BLE001
            continue
    blob = "\n".join(text_blobs)[:MAX_TEXT]
    for match in SECRET_RE.finditer(blob):
        findings.append(
            _find("mob-secret", "Secret-like string in package", "high", "Remove hardcoded keys from the client.", match.group(0)[:80])
        )
        if len(findings) > 20:
            break
    urls = re.findall(r"https?://[^\s\"']{8,120}", blob)
    for url in sorted(set(urls))[:8]:
        findings.append(_find("mob-url", "Embedded URL", "info", "Review pinning and environments.", url))
    if not findings:
        findings.append(_find("mob-empty", "Little readable metadata", "info", "DEX/native code needs a dedicated mobile lab."))
    return {
        "summary": "Static mobile package review (no dynamic instrumentation).",
        "file": filename or "upload",
        "entries": names[:40],
        "findings": findings,
    }


RUNNERS = {
    "black_box": run_black_box,
    "gray_box": run_gray_box,
    "white_box": run_white_box,
    "penetration_testing": run_penetration_testing,
    "web": run_web,
    "network": run_network,
    "cloud": run_cloud,
    "container": run_container,
    "api": run_api,
    "code_security": run_code_security,
    "mobile": run_mobile,
}
