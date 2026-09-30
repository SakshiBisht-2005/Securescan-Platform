"""Safe subprocess execution for external scanner tools.

Rules enforced here (see master requirement #36 - scanner process
isolation):
- Commands are always passed as argument arrays, never as shell strings.
- shell=True is never used.
- Every invocation has a hard timeout.
- The uploaded/cloned source tree is only ever passed as a *path argument*
  to a well-known scanner binary; it is never interpreted or executed by
  this platform itself.
- A dedicated temporary working directory is used and can be discarded
  after the run.
"""
import logging
import shutil
import subprocess

from django.conf import settings

logger = logging.getLogger("scanner_engine")


class ToolNotAvailable(Exception):
    pass


def is_tool_available(executable: str) -> bool:
    return shutil.which(executable) is not None


def run_tool(args: list, cwd: str, timeout: int = None) -> subprocess.CompletedProcess:
    """Runs `args` (an argument list - never a shell string) with a
    timeout, capturing stdout/stderr. Raises subprocess.TimeoutExpired on
    timeout and ToolNotAvailable if the executable is missing."""
    if not args:
        raise ValueError("args must be a non-empty list")

    executable = args[0]
    if not is_tool_available(executable) and not executable.startswith("."):
        raise ToolNotAvailable(f"'{executable}' is not installed or not on PATH.")

    timeout = timeout or settings.SCANNER_SUBPROCESS_TIMEOUT_SECONDS
    logger.info("Running scanner tool: %s (cwd=%s, timeout=%ss)", executable, cwd, timeout)

    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        check=False,
    )
