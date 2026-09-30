"""Built-in rule sets used as a dependable fallback when the corresponding
external tool (gitleaks, checkov, trivy) is not installed, and to give the
secret-detection adapter a curated, low-noise pattern set even when
gitleaks IS present (both are merged and deduplicated).

These are intentionally simple, well-known detection patterns for
DEFENSIVE purposes only (recognizing exposed secrets/misconfigurations in
the user's own code so they can fix them) - nothing here performs any
offensive action against a detected credential.
"""

# (secret_type, compiled-at-use regex pattern, confidence)
SECRET_PATTERNS = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "HIGH"),
    ("AWS Secret Access Key", r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "HIGH"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    ("GitHub Personal Access Token", r"gh[pousr]_[A-Za-z0-9]{36,255}", "HIGH"),
    ("GitLab Personal Access Token", r"glpat-[0-9a-zA-Z\-_]{20}", "HIGH"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,48}", "HIGH"),
    ("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "HIGH"),
    ("Stripe Live Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", "MEDIUM"),
    ("Generic Private Key", r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", "HIGH"),
    ("JWT-like Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "MEDIUM"),
    ("Generic API Key Assignment", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "MEDIUM"),
    ("Hardcoded Password Assignment", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"](?!.*\{\{)[^'\"\s]{6,}['\"]", "MEDIUM"),
    ("Database Connection String With Credentials", r"(?i)(postgres|mysql|mongodb)(\+\w+)?://[^:\s]+:[^@\s]+@[^\s'\"]+", "HIGH"),
    ("Generic Bearer Token", r"(?i)authorization\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9\-_.]{20,}", "MEDIUM"),
]

# Files that must never be treated as source code for secret-scanning purposes
# even if extension-based filtering misses them (kept intentionally short -
# broad exclusion belongs to upload_service's exclusion patterns instead).
SECRET_SCAN_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".zip", ".pdf",
}

# ---------------------------------------------------------------------------
# IaC fallback rules: (rule_id, title, severity, matcher_fn(text) -> list[line_no])
# Deliberately simple substring/regex checks - not a full policy engine -
# used only when Checkov is unavailable.
# ---------------------------------------------------------------------------
import re  # noqa: E402


def _lines_matching(text, pattern):
    matches = []
    for i, line in enumerate(text.splitlines(), start=1):
        if re.search(pattern, line):
            matches.append(i)
    return matches


IAC_RULES = [
    {
        "id": "IAC-TF-001",
        "title": "Terraform resource with unrestricted ingress (0.0.0.0/0)",
        "severity": "HIGH",
        "category": "infrastructure_as_code",
        "applies_to": (".tf",),
        "pattern": r'cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"',
        "remediation": "Restrict ingress cidr_blocks to known, minimal IP ranges instead of 0.0.0.0/0.",
    },
    {
        "id": "IAC-TF-002",
        "title": "S3 bucket ACL set to public-read or public-read-write",
        "severity": "CRITICAL",
        "category": "infrastructure_as_code",
        "applies_to": (".tf",),
        "pattern": r'acl\s*=\s*"public-read(-write)?"',
        "remediation": "Set the bucket ACL to 'private' and use bucket policies / access points for controlled sharing.",
    },
    {
        "id": "IAC-TF-003",
        "title": "Storage/database resource without encryption enabled",
        "severity": "MEDIUM",
        "category": "infrastructure_as_code",
        "applies_to": (".tf",),
        "pattern": r"(storage_encrypted|encrypted)\s*=\s*false",
        "remediation": "Enable encryption at rest for this resource.",
    },
    {
        "id": "IAC-K8S-001",
        "title": "Kubernetes container running as privileged",
        "severity": "CRITICAL",
        "category": "infrastructure_as_code",
        "applies_to": (".yml", ".yaml"),
        "pattern": r"privileged:\s*true",
        "remediation": "Remove `privileged: true` and grant only the specific Linux capabilities the container needs.",
    },
    {
        "id": "IAC-K8S-002",
        "title": "Kubernetes container missing resource limits",
        "severity": "LOW",
        "category": "infrastructure_as_code",
        "applies_to": (".yml", ".yaml"),
        "pattern": r"kind:\s*Pod|kind:\s*Deployment",
        "invert_requires": r"resources:\s*\n\s*limits:",
        "remediation": "Set CPU/memory `resources.limits` to prevent resource exhaustion.",
    },
    {
        "id": "IAC-CI-001",
        "title": "CI workflow uses an unpinned third-party action (@main/@master/latest tag)",
        "severity": "MEDIUM",
        "category": "infrastructure_as_code",
        "applies_to": (".yml", ".yaml"),
        "pattern": r"uses:\s*[\w-]+/[\w-]+@(main|master|latest)\b",
        "remediation": "Pin third-party GitHub Actions to a specific commit SHA or release tag.",
    },
    {
        "id": "IAC-CI-002",
        "title": "CI workflow runs on pull_request_target with checkout of untrusted code",
        "severity": "HIGH",
        "category": "infrastructure_as_code",
        "applies_to": (".yml", ".yaml"),
        "pattern": r"pull_request_target",
        "remediation": "Avoid combining `pull_request_target` with checking out and executing the PR head; use `pull_request` or explicitly checkout a trusted ref.",
    },
    {
        "id": "IAC-CFN-001",
        "title": "CloudFormation security group allows ingress from 0.0.0.0/0",
        "severity": "HIGH",
        "category": "infrastructure_as_code",
        "applies_to": (".yml", ".yaml", ".json"),
        "pattern": r"CidrIp:\s*0\.0\.0\.0/0",
        "remediation": "Restrict CidrIp to known ranges instead of 0.0.0.0/0.",
    },
]


DOCKERFILE_RULES = [
    {
        "id": "DOCKER-001",
        "title": "Container runs as root (no USER instruction)",
        "severity": "MEDIUM",
        "check": lambda lines: not any(l.strip().upper().startswith("USER ") for l in lines),
        "remediation": "Add a non-root `USER` instruction before the container's entrypoint/cmd.",
    },
    {
        "id": "DOCKER-002",
        "title": "Dockerfile uses ADD with a remote URL (prefer COPY / verified download)",
        "severity": "LOW",
        "check": lambda lines: any(re.match(r"^\s*ADD\s+https?://", l, re.I) for l in lines),
        "remediation": "Use `COPY` for local files, or download with checksum verification instead of `ADD <url>`.",
    },
    {
        "id": "DOCKER-003",
        "title": "Dockerfile hardcodes a secret-like build ARG/ENV",
        "severity": "HIGH",
        "check": lambda lines: any(re.search(r"(?i)^(ENV|ARG)\s+\w*(SECRET|PASSWORD|TOKEN|API_KEY)\w*\s*=", l) for l in lines),
        "remediation": "Pass secrets via a secrets manager or build-time secret mounts, not ENV/ARG baked into the image.",
    },
    {
        "id": "DOCKER-004",
        "title": "Base image uses the 'latest' tag (non-reproducible builds)",
        "severity": "LOW",
        "check": lambda lines: any(re.match(r"^\s*FROM\s+\S+(:latest)?\s*$", l, re.I) and ":" not in l.split()[1] for l in lines if l.strip().upper().startswith("FROM")),
        "remediation": "Pin the base image to a specific version tag or digest.",
    },
    {
        "id": "DOCKER-005",
        "title": "Dockerfile exposes a common database/admin port",
        "severity": "INFO",
        "check": lambda lines: any(re.match(r"^\s*EXPOSE\s+(22|3306|5432|6379|27017)\b", l, re.I) for l in lines),
        "remediation": "Avoid exposing administrative/database ports directly; use an internal network or bastion instead.",
    },
]


COMPOSE_RULES = [
    {
        "id": "COMPOSE-001",
        "title": "docker-compose service runs in privileged mode",
        "severity": "CRITICAL",
        "pattern": r"privileged:\s*true",
        "remediation": "Remove `privileged: true`; grant only specific `cap_add` capabilities if required.",
    },
    {
        "id": "COMPOSE-002",
        "title": "docker-compose service mounts the Docker socket",
        "severity": "HIGH",
        "pattern": r"/var/run/docker\.sock",
        "remediation": "Avoid mounting the Docker socket into containers; it grants effective host root access.",
    },
    {
        "id": "COMPOSE-003",
        "title": "docker-compose service has a hardcoded credential in environment",
        "severity": "MEDIUM",
        "pattern": r"(?i)(PASSWORD|SECRET|TOKEN)\s*[:=]\s*['\"]?[^\s'\"$][^\s'\"]{3,}",
        "remediation": "Use an `.env` file (excluded from version control) or a secrets manager instead of inline credentials.",
    },
]
