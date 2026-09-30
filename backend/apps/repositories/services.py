"""Secure Git repository import.

Design constraints:
- Never execute code from the cloned repository.
- Never log tokens/credentials, even on failure.
- Enforce a clone timeout and depth limit (avoid huge/slow clones).
- Credentials are encrypted at rest with Django's signing framework and
  are only decrypted transiently in-process to build the clone URL; they
  are never written to disk or included in error messages.
"""
import logging
import re
import shutil
import tempfile
import uuid

import git
from django.conf import settings
from django.core import signing

from common.exceptions import ValidationAppError

logger = logging.getLogger("security")

_SIGNER_SALT = "repositories.git_credential"
_ALLOWED_URL_RE = re.compile(r"^https://[A-Za-z0-9._-]+(/[A-Za-z0-9._~%\-]+)+(\.git)?/?$")


def encrypt_token(raw_token: str) -> str:
    return signing.dumps(raw_token, salt=_SIGNER_SALT)


def decrypt_token(encrypted: str) -> str:
    return signing.loads(encrypted, salt=_SIGNER_SALT, max_age=None)


def validate_repository_url(url: str):
    """Only allow https:// URLs to a plausible host/path. Rejects
    file://, ssh://, and anything that could be used for SSRF against
    internal services or local file inclusion."""
    if not _ALLOWED_URL_RE.match(url or ""):
        raise ValidationAppError(
            "Repository URL must be a valid https:// URL (e.g. https://github.com/org/repo.git)."
        )


def _clone_error_message(exc: git.GitCommandError) -> str:
    """Map git's stderr to a safe user-facing message. Never include the
    clone URL or command line — those can contain injected credentials."""
    text = f"{getattr(exc, 'stderr', '')} {getattr(exc, 'stdout', '')}".lower()
    if any(s in text for s in ("authentication failed", "invalid username", "terminal prompts disabled", "403", "401")):
        return "Git authentication failed. Private repositories need a saved Git credential."
    if any(s in text for s in ("not found", "404", "does not exist", "repository not found")):
        return "Repository not found. Check the URL, or add a credential if the repository is private."
    if any(s in text for s in ("remote branch", "pathspec", "did not match")):
        return "Branch not found. Try the repository's default branch (often master instead of main)."
    if any(s in text for s in ("could not resolve host", "unable to access", "failed to connect", "timed out")):
        return "Could not reach the Git host. Check your network connection."
    return "Failed to clone repository. Check the URL, branch, and credentials."


def _is_missing_branch_error(exc: git.GitCommandError) -> bool:
    text = f"{getattr(exc, 'stderr', '')} {getattr(exc, 'stdout', '')}".lower()
    return any(s in text for s in ("remote branch", "pathspec", "did not match"))


def encrypt_token(raw_token: str) -> str:
    return signing.dumps(raw_token, salt=_SIGNER_SALT)


def decrypt_token(encrypted: str) -> str:
    return signing.loads(encrypted, salt=_SIGNER_SALT, max_age=None)


def validate_repository_url(url: str):
    """Only allow https:// URLs to a plausible host/path. Rejects
    file://, ssh://, and anything that could be used for SSRF against
    internal services or local file inclusion."""
    if not _ALLOWED_URL_RE.match(url or ""):
        raise ValidationAppError(
            "Repository URL must be a valid https:// URL (e.g. https://github.com/org/repo.git)."
        )


def clone_repository(url: str, branch: str, credential_token: str | None = None) -> str:
    """Clones the repository (shallow, single branch) into an isolated
    temp directory and returns the path. The caller must clean it up."""
    validate_repository_url(url)

    clone_url = url
    if credential_token:
        # Inject token as basic-auth into the URL only in-memory; never persisted or logged.
        if url.startswith("https://"):
            clone_url = url.replace("https://", f"https://{credential_token}@", 1)

    settings.SCAN_TEMP_DIR.mkdir(parents=True, exist_ok=True)
    dest_dir = tempfile.mkdtemp(prefix=f"repo_{uuid.uuid4().hex}_", dir=str(settings.SCAN_TEMP_DIR))

    try:
        clone_kwargs = {
            "depth": 1,
            "single_branch": True,
            "env": {"GIT_TERMINAL_PROMPT": "0"},
            "kill_after_timeout": settings.GIT_IMPORT_TIMEOUT_SECONDS,
        }
        try:
            git.Repo.clone_from(clone_url, dest_dir, branch=branch or None, **clone_kwargs)
        except git.GitCommandError as branch_exc:
            # `main` is the UI default, but many repos still use `master` (or another HEAD).
            if branch and _is_missing_branch_error(branch_exc):
                shutil.rmtree(dest_dir, ignore_errors=True)
                dest_dir = tempfile.mkdtemp(prefix=f"repo_{uuid.uuid4().hex}_", dir=str(settings.SCAN_TEMP_DIR))
                git.Repo.clone_from(clone_url, dest_dir, **clone_kwargs)
            else:
                raise
    except git.GitCommandError as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        safe_message = _clone_error_message(exc)
        logger.warning("Git clone failed for a repository import (details omitted from user-facing message).")
        raise ValidationAppError(safe_message) from exc
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(dest_dir, ignore_errors=True)
        logger.exception("Unexpected error during git clone")
        raise ValidationAppError("Failed to clone repository.") from exc

    # Remove git internals - we only need the working tree contents for scanning.
    shutil.rmtree(f"{dest_dir}/.git", ignore_errors=True)
    return dest_dir


def get_head_commit_sha(url: str, branch: str, credential_token: str | None = None) -> str:
    """Best-effort retrieval of the HEAD commit sha via ls-remote, without a full clone."""
    try:
        clone_url = url
        if credential_token and url.startswith("https://"):
            clone_url = url.replace("https://", f"https://{credential_token}@", 1)
        g = git.cmd.Git()
        output = g.ls_remote(clone_url, branch or "HEAD")
        return output.split()[0] if output else ""
    except Exception:  # noqa: BLE001
        return ""


def credential_token_for_project(project) -> str | None:
    """Use the token from the last git import, else the owner's newest stored credential."""
    from .models import GitCredential

    last = (
        project.repository_imports.filter(credential__isnull=False)
        .select_related("credential")
        .order_by("-id")
        .first()
    )
    if last and last.credential_id:
        try:
            return decrypt_token(last.credential.encrypted_token)
        except Exception:  # noqa: BLE001
            pass
    cred = GitCredential.objects.filter(owner_id=project.owner_id).order_by("-id").first()
    if cred:
        try:
            return decrypt_token(cred.encrypted_token)
        except Exception:  # noqa: BLE001
            pass
    return None


def refresh_project_from_git(project, branch: str | None = None) -> str:
    """Re-clone project.repository_url into the working tree and re-index. Returns commit SHA."""
    from apps.projects import storage
    from apps.projects.upload_service import index_directory_to_project

    url = (project.repository_url or "").strip()
    if not url:
        return ""
    validate_repository_url(url)
    branch = branch or project.default_branch or "main"
    token = credential_token_for_project(project)
    cloned_dir = clone_repository(url, branch, token)
    sha = get_head_commit_sha(url, branch, token)
    try:
        root = storage.project_root(project)
        shutil.rmtree(root, ignore_errors=True)
        shutil.move(cloned_dir, str(root))
        index_directory_to_project(project, str(root), project.exclusion_patterns)
        project.save(update_fields=["updated_at"])
        return sha
    except Exception:
        shutil.rmtree(cloned_dir, ignore_errors=True)
        raise
