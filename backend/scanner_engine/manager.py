"""Scanner Manager: orchestrates the full scan pipeline described in the
platform spec:

    Validate -> SAST -> SCA -> Secrets -> IaC -> Container ->
    Normalize -> Deduplicate -> Severity -> Save -> Statistics

Each adapter can be enabled/disabled independently (per-scan `enabled_scanners`
config, falling back to the global settings.SCANNER_ENABLED map), and the
manager records a ScannerRun row per adapter so the dashboard can show
which tools actually ran vs were skipped/unavailable/failed.
"""
import logging
import time

from scanner_engine.adapters.bandit import BanditAdapter
from scanner_engine.adapters.checkov import CheckovAdapter
from scanner_engine.adapters.dependency_check import DependencyCheckAdapter
from scanner_engine.adapters.gitleaks import GitleaksAdapter
from scanner_engine.adapters.semgrep import SemgrepAdapter
from scanner_engine.adapters.trivy import TrivyAdapter
from scanner_engine.deduplicator import deduplicate_findings

logger = logging.getLogger("scanner_engine")

SAST_ADAPTERS = [BanditAdapter(), SemgrepAdapter()]
SCA_ADAPTERS = [DependencyCheckAdapter()]
SECRET_ADAPTERS = [GitleaksAdapter()]
IAC_ADAPTERS = [CheckovAdapter()]
CONTAINER_ADAPTERS = [TrivyAdapter()]

STAGE_WEIGHTS = [
    ("preparing", 5),
    ("sast", 30),
    ("sca", 20),
    ("secrets", 15),
    ("iac", 10),
    ("container", 10),
    ("normalizing", 8),
    ("finalizing", 2),
]


class ScanRunResult:
    def __init__(self):
        self.findings = []          # list[NormalizedFinding] for source-code categories
        self.dependencies = []      # list[DependencyEntry]
        self.secret_findings = []   # list[NormalizedFinding] with category=secrets
        self.scanner_runs = []      # list[dict] describing each adapter execution


def run_full_scan(project_dir: str, enabled_scanners: dict, exclusions: list, progress_callback=None) -> ScanRunResult:
    """`enabled_scanners` example: {"sast": True, "sca": True, "secrets": True, "iac": True, "container": True}
    `progress_callback(stage: str, percent: int)` is invoked as each stage completes.
    """
    result = ScanRunResult()
    enabled_scanners = enabled_scanners or {}

    def enabled(key):
        return enabled_scanners.get(key, True)

    def report(stage, percent):
        if progress_callback:
            progress_callback(stage, percent)

    report("preparing", 5)

    cumulative = 5
    stage_plan = [
        ("sast", "sast", SAST_ADAPTERS, result.findings),
        ("sca", "sca", SCA_ADAPTERS, result.dependencies),
        ("secrets", "secrets", SECRET_ADAPTERS, result.secret_findings),
        ("iac", "iac", IAC_ADAPTERS, result.findings),
        ("container", "container", CONTAINER_ADAPTERS, result.findings),
    ]

    for key, label, adapters, sink in stage_plan:
        weight = dict(STAGE_WEIGHTS)[key]
        if not enabled(key):
            for adapter in adapters:
                result.scanner_runs.append({"scanner_name": adapter.name, "status": "skipped_unavailable",
                                             "findings_count": 0, "duration_seconds": 0, "output_log": "Disabled for this scan."})
            cumulative += weight
            report(label, cumulative)
            continue

        for adapter in adapters:
            run_record = _execute_adapter(adapter, project_dir, exclusions)
            sink.extend(run_record.pop("_items"))
            result.scanner_runs.append(run_record)

        cumulative += weight
        report(label, cumulative)

    report("normalizing", min(cumulative + STAGE_WEIGHTS[-2][1], 98))
    result.findings = deduplicate_findings(result.findings)
    result.secret_findings = deduplicate_findings(result.secret_findings)

    report("finalizing", 100)
    return result


def _execute_adapter(adapter, project_dir, exclusions) -> dict:
    started = time.monotonic()
    if not adapter.is_available():
        return {
            "scanner_name": adapter.name, "status": "skipped_unavailable",
            "findings_count": 0, "duration_seconds": 0,
            "output_log": f"{adapter.name} is not installed/available on this system.",
            "_items": [],
        }

    try:
        items = adapter.run(project_dir, exclusions) or []
        duration = round(time.monotonic() - started, 2)
        return {
            "scanner_name": adapter.name, "status": "success",
            "findings_count": len(items), "duration_seconds": duration,
            "output_log": "", "_items": items,
        }
    except Exception as exc:  # noqa: BLE001 - one adapter failing must not abort the whole scan
        duration = round(time.monotonic() - started, 2)
        logger.exception("Adapter %s failed", adapter.name)
        return {
            "scanner_name": adapter.name, "status": "failed",
            "findings_count": 0, "duration_seconds": duration,
            "output_log": f"{type(exc).__name__}: {exc}"[:2000], "_items": [],
        }
