"""Project CI token hashing and request authentication.

Plaintext is shown once on rotate. SHA-256 is stored for Bearer checks.
The same value is encrypted at rest so GitHub webhook HMAC can be verified.
"""
import hashlib
import hmac
import secrets

from django.core import signing
from django.shortcuts import get_object_or_404

from apps.projects.models import Project
from common.exceptions import PermissionDeniedAppError

_SIGNER_SALT = "projects.ci_token"


def hash_ci_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_ci_token():
    raw = "ssci_" + secrets.token_urlsafe(32)
    encrypted = signing.dumps(raw, salt=_SIGNER_SALT)
    return raw, hash_ci_token(raw), raw[:12], encrypted


def decrypt_ci_token(encrypted: str) -> str:
    return signing.loads(encrypted, salt=_SIGNER_SALT)


def extract_bearer(request) -> str:
    header = request.META.get("HTTP_AUTHORIZATION") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return (request.META.get("HTTP_X_SECURESCAN_TOKEN") or "").strip()


def token_matches_project(project, raw: str) -> bool:
    if not raw or not project.ci_token_hash:
        return False
    return hmac.compare_digest(project.ci_token_hash, hash_ci_token(raw))


def verify_github_signature(body: bytes, signature_header: str, raw_token: str) -> bool:
    if not raw_token or not signature_header:
        return False
    expected = "sha256=" + hmac.new(raw_token.encode("utf-8"), body, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected, signature_header.strip())
    except Exception:  # noqa: BLE001
        return False


def authenticate_ci_project(request, project_id, *, allow_hmac=False) -> Project:
    project = get_object_or_404(Project, pk=project_id)
    bearer = extract_bearer(request)
    if token_matches_project(project, bearer):
        return project
    if allow_hmac and project.ci_token_encrypted:
        sig = request.META.get("HTTP_X_HUB_SIGNATURE_256") or ""
        try:
            raw = decrypt_ci_token(project.ci_token_encrypted)
        except Exception:  # noqa: BLE001
            raw = ""
        if verify_github_signature(request.body, sig, raw):
            return project
    raise PermissionDeniedAppError("Invalid or missing CI token.")
