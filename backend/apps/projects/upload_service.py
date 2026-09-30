"""Secure handling of uploaded project source-code archives.

Threat model: the uploaded ZIP is fully untrusted input. It may contain
path-traversal entries (`../../etc/passwd`), absolute paths, symlinks that
escape the extraction directory, decompression bombs, or files disguised
with misleading extensions. None of the extracted code is ever executed.
"""
import fnmatch
import logging
import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from django.conf import settings

from common.exceptions import UnsafeUploadError
from common.utilities import safe_filename, sha256_of_file

from .constants import BINARY_EXTENSIONS, LANGUAGE_BY_EXTENSION

logger = logging.getLogger("security")

ALLOWED_UPLOAD_EXTENSIONS = {".zip"}
ALLOWED_UPLOAD_MIME_TYPES = {"application/zip", "application/x-zip-compressed", "application/octet-stream"}

MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024  # 2GB safety cap regardless of setting
MAX_ENTRY_UNCOMPRESSED_BYTES = 300 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100  # guards against zip bombs
MAX_ENTRIES = 50_000

DEFAULT_EXCLUDED_DIR_NAMES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox",
    "dist", "build", ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
    "scan_temp", "snapshots",
}


def validate_upload_metadata(uploaded_file):
    ext = Path(uploaded_file.name).suffix.lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise UnsafeUploadError(f"Unsupported file extension '{ext}'. Only .zip archives are accepted.")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if uploaded_file.size > max_bytes:
        raise UnsafeUploadError(f"File exceeds the {settings.MAX_UPLOAD_SIZE_MB}MB upload limit.")

    content_type = getattr(uploaded_file, "content_type", None)
    if content_type and content_type not in ALLOWED_UPLOAD_MIME_TYPES:
        logger.warning("Upload with unexpected content-type: %s", content_type)


def _is_within_directory(directory: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def _should_exclude(rel_path: str, exclusion_patterns) -> bool:
    parts = Path(rel_path).parts
    if any(part in DEFAULT_EXCLUDED_DIR_NAMES for part in parts):
        return True
    for pattern in exclusion_patterns or []:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(os.path.basename(rel_path), pattern):
            return True
    return False


def extract_zip_safely(zip_path: str, exclusion_patterns=None) -> str:
    """Extracts `zip_path` into a fresh isolated temp directory under
    settings.SCAN_TEMP_DIR, rejecting any entry that would traverse or
    escape the destination, any symlink entry, and enforcing size/ratio/
    entry-count limits to prevent decompression-bomb denial of service.

    Returns the path to the extraction directory. Caller is responsible
    for cleanup (see cleanup_extracted_dir).
    """
    settings.SCAN_TEMP_DIR.mkdir(parents=True, exist_ok=True)
    dest_dir = Path(tempfile.mkdtemp(prefix=f"upload_{uuid.uuid4().hex}_", dir=str(settings.SCAN_TEMP_DIR)))

    try:
        with zipfile.ZipFile(zip_path) as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ENTRIES:
                raise UnsafeUploadError("Archive contains too many entries.")

            total_uncompressed = 0
            for info in infolist:
                name = info.filename

                if name.startswith("/") or name.startswith("\\"):
                    raise UnsafeUploadError("Archive contains an absolute path entry.")
                if ".." in Path(name).parts:
                    raise UnsafeUploadError("Archive contains a path-traversal entry.")
                if os.path.isabs(name):
                    raise UnsafeUploadError("Archive contains an absolute path entry.")

                # Reject symlinks (unix mode bits stored in the high 16 bits
                # of external_attr; 0xA000 == S_IFLNK).
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and (mode & 0xF000) == 0xA000:
                    raise UnsafeUploadError("Archive contains a symbolic link entry, which is not allowed.")

                if info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
                    raise UnsafeUploadError(f"Archive entry '{name}' exceeds the per-file size limit.")

                if info.compress_size > 0:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > MAX_COMPRESSION_RATIO and info.file_size > 10 * 1024 * 1024:
                        raise UnsafeUploadError("Archive entry has a suspicious compression ratio (possible zip bomb).")

                total_uncompressed += info.file_size
                if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise UnsafeUploadError("Archive exceeds the maximum total uncompressed size.")

                target_path = dest_dir / name
                if not _is_within_directory(dest_dir, target_path):
                    raise UnsafeUploadError(f"Archive entry '{name}' resolves outside the extraction directory.")

            # All entries validated up-front; now extract.
            for info in infolist:
                rel_path = info.filename
                if _should_exclude(rel_path, exclusion_patterns):
                    continue
                zf.extract(info, path=str(dest_dir))

        return str(dest_dir)
    except zipfile.BadZipFile as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise UnsafeUploadError("The uploaded file is not a valid ZIP archive.") from exc
    except UnsafeUploadError:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise
    except Exception as exc:  # noqa: BLE001 - convert unexpected extraction errors safely
        shutil.rmtree(dest_dir, ignore_errors=True)
        logger.exception("Unexpected error extracting archive")
        raise UnsafeUploadError("Failed to safely extract the archive.") from exc


def cleanup_extracted_dir(path: str):
    shutil.rmtree(path, ignore_errors=True)


def index_directory_to_project(project, root_dir: str, exclusion_patterns=None):
    """Walks the extracted/cloned project directory and creates/updates
    ProjectFile rows. Skips binaries beyond a content preview, computes a
    sha256 hash per file, and infers a coarse language from extension."""
    from .models import ProjectFile  # local import to avoid app-loading cycles

    root = Path(root_dir)
    seen_paths = set()
    created_or_updated = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDED_DIR_NAMES]
        for fname in filenames:
            abs_path = Path(dirpath) / fname
            rel_path = str(abs_path.relative_to(root)).replace(os.sep, "/")

            if _should_exclude(rel_path, exclusion_patterns):
                continue

            try:
                size = abs_path.stat().st_size
            except OSError:
                continue

            ext = abs_path.suffix.lower()
            is_binary = ext in BINARY_EXTENSIONS
            file_hash = "" if is_binary or size > 50 * 1024 * 1024 else sha256_of_file(abs_path)
            language = LANGUAGE_BY_EXTENSION.get(ext, "")

            ProjectFile.objects.update_or_create(
                project=project,
                path=rel_path,
                defaults={
                    "filename": safe_filename(fname),
                    "language": language,
                    "size": size,
                    "hash": file_hash,
                    "is_binary": is_binary,
                },
            )
            seen_paths.add(rel_path)
            created_or_updated += 1

    # Remove records for files that no longer exist on disk (re-upload/re-scan case).
    project.files.exclude(path__in=seen_paths).delete()
    return created_or_updated
