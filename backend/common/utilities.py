import hashlib
import re
import unicodedata


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_of_file(path, chunk_size=1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_filename(name: str) -> str:
    """Normalize and strip a filename of any path components / control
    characters so it is safe to join onto a directory path."""
    name = unicodedata.normalize("NFKD", name)
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    name = name.lstrip(".")  # avoid hidden files / relative traversal remnants
    return name or "file"


def mask_secret(value: str, keep_prefix: int = 6, keep_suffix: int = 0) -> str:
    """Mask a secret value for display, e.g. sk_live_ab************1234."""
    if not value:
        return ""
    if len(value) <= keep_prefix + keep_suffix:
        return "*" * len(value)
    prefix = value[:keep_prefix]
    suffix = value[-keep_suffix:] if keep_suffix else ""
    stars = "*" * max(8, len(value) - keep_prefix - keep_suffix)
    return f"{prefix}{stars}{suffix}"


def compute_fingerprint(*parts) -> str:
    """Stable fingerprint used to deduplicate findings across scans:
    same rule + same file + same line + same normalized snippet ==
    same finding, even if line numbers shift slightly is handled at a
    higher level (see scanner_engine/deduplicator.py)."""
    joined = "||".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", errors="ignore")).hexdigest()
