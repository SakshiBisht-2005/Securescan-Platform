"""Small shared parsing helpers used by multiple adapters (kept separate
from any single adapter so they can be reused/tested independently)."""
import re


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def truncate(text: str, limit: int = 2000) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "... [truncated]"


def safe_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
