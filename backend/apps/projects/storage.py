"""Resolves the on-disk storage location for a project's source tree, and
provides path-traversal-safe helpers used by both the scanner engine and
the browser code editor. Every function here re-validates that the
resolved path stays inside the project's root directory."""
import shutil
from pathlib import Path

from django.conf import settings

from common.exceptions import UnsafeUploadError


def project_root(project) -> Path:
    root = settings.SCAN_TEMP_DIR / "projects" / str(project.id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_safe_path(project, relative_path: str) -> Path:
    root = project_root(project).resolve()
    if relative_path is None:
        raise UnsafeUploadError("A file path is required.")
    candidate = (root / relative_path.lstrip("/\\")).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise UnsafeUploadError("Path resolves outside the project directory.")
    return candidate


def read_file(project, relative_path: str, max_bytes: int = 2 * 1024 * 1024) -> str:
    path = resolve_safe_path(project, relative_path)
    if not path.is_file():
        raise UnsafeUploadError("File not found.")
    if path.stat().st_size > max_bytes:
        raise UnsafeUploadError("File is too large to open in the editor.")
    return path.read_text(encoding="utf-8", errors="replace")


def write_file(project, relative_path: str, content: str, max_bytes: int = 2 * 1024 * 1024):
    if len(content.encode("utf-8")) > max_bytes:
        raise UnsafeUploadError("File content exceeds the editor size limit.")
    path = resolve_safe_path(project, relative_path)
    if path.exists() and path.is_dir():
        try:
            next(path.iterdir())
        except StopIteration:
            path.rmdir()
        else:
            raise UnsafeUploadError(
                f"A folder named '{path.name}' already exists at this path. "
                "Delete the folder first, or choose a different file name."
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(content, encoding="utf-8")
    except PermissionError as exc:
        raise UnsafeUploadError(
            "Could not write that file. A folder may already exist at this path."
        ) from exc
    except OSError as exc:
        raise UnsafeUploadError("Could not write that file.") from exc


def delete_file(project, relative_path: str):
    path = resolve_safe_path(project, relative_path)
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def rename_path(project, old_relative_path: str, new_relative_path: str):
    old_path = resolve_safe_path(project, old_relative_path)
    new_path = resolve_safe_path(project, new_relative_path)
    if not old_path.exists():
        raise UnsafeUploadError("Source path does not exist.")
    new_path.parent.mkdir(parents=True, exist_ok=True)
    old_path.rename(new_path)


def create_directory(project, relative_path: str):
    path = resolve_safe_path(project, relative_path)
    path.mkdir(parents=True, exist_ok=True)


def list_tree(project):
    """Returns a nested dict describing the file tree for the editor's
    file-explorer panel."""
    root = project_root(project)

    def walk(dir_path: Path):
        entries = []
        try:
            children = sorted(dir_path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except FileNotFoundError:
            return entries
        for child in children:
            if child.name in {".git", "node_modules", "__pycache__", ".venv", "venv", "scan_temp", "snapshots"}:
                continue
            rel = str(child.relative_to(root)).replace("\\", "/")
            if child.is_dir():
                entries.append({"type": "directory", "name": child.name, "path": rel, "children": walk(child)})
            else:
                entries.append({"type": "file", "name": child.name, "path": rel, "size": child.stat().st_size})
        return entries

    return walk(root)


SCAN_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", "dist", "build", ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
    "scan_temp", "snapshots", "*.pyc",
)


def copy_tree_for_scan(source_root: Path, dest_root: Path) -> Path:
    """Copy the editor working tree to an isolated snapshot the scanners can
    read without touching the files the user still has open."""
    dest_root.parent.mkdir(parents=True, exist_ok=True)
    if dest_root.exists():
        shutil.rmtree(dest_root, ignore_errors=True)
    shutil.copytree(source_root, dest_root, ignore=SCAN_COPY_IGNORE, dirs_exist_ok=False)
    return dest_root
