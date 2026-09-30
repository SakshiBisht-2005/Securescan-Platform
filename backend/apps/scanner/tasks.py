"""Celery tasks implementing the asynchronous scan pipeline:

    start_scan -> preparing -> run_sast/run_sca/run_secret_scan/run_iac_scan/
    run_container_scan (all orchestrated by scanner_engine.manager) ->
    normalize_results -> deduplicate -> calculate_severity -> save_findings
    -> generate_statistics -> generate_report -> notify_user -> cleanup

The heavy lifting lives in scanner_engine/manager.py; these tasks are
mostly responsible for state transitions, persistence, and error
handling so a single scan is never run inside the HTTP request/response
cycle.
"""
import logging
import shutil
import time
from pathlib import Path

from celery import Task, shared_task
from django.conf import settings
from django.utils import timezone

from apps.audit.services import log_action
from apps.notifications.services import notify
from apps.vulnerabilities.services import (
    compute_and_apply_scan_statistics,
    save_dependencies,
    save_findings,
    save_secret_findings,
)
from common.constants import ScanStatus, Severity
from scanner_engine.manager import run_full_scan

logger = logging.getLogger("scanner_engine")


class _StartScanTask(Task):
    abstract = True
    """If the worker rejects the message before start_scan runs, mark the Scan failed."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id = args[0] if args else kwargs.get("scan_id")
        if not scan_id:
            return
        from .models import Scan

        Scan.objects.filter(pk=scan_id, status__in=ScanStatus.ACTIVE).update(
            status=ScanStatus.FAILED,
            error_message="Scan worker failed before the scan could finish. Restart python start.py and run the scan again.",
            completed_at=timezone.now(),
        )


@shared_task(bind=True, base=_StartScanTask, name="scanner.start_scan")
def start_scan(self, scan_id: int):
    from apps.projects import storage
    from common.constants import ScanTrigger
    from .models import Scan, ScannerRun

    scan = Scan.objects.select_related("project").get(pk=scan_id)
    scan.status = ScanStatus.PREPARING
    scan.progress_stage = "preparing"
    scan.progress_percent = 5
    scan.started_at = timezone.now()
    scan.celery_task_id = self.request.id or ""
    scan.save(update_fields=["status", "progress_stage", "progress_percent", "started_at", "celery_task_id"])

    project_dir = str(storage.project_root(scan.project))
    start_time = time.monotonic()
    snapshot_dir = None
    refresh_git = (
        scan.trigger_source in (ScanTrigger.CI, ScanTrigger.WEBHOOK, ScanTrigger.SCHEDULED)
        and bool(scan.project.repository_url)
    )

    try:
        if refresh_git and scan.project.repository_url:
            scan.progress_stage = "cloning"
            scan.save(update_fields=["progress_stage"])
            from apps.repositories.services import refresh_project_from_git

            sha = refresh_project_from_git(scan.project, scan.branch)
            if sha and not scan.git_sha:
                scan.git_sha = sha
                scan.save(update_fields=["git_sha"])

        scan.status = ScanStatus.RUNNING
        scan.save(update_fields=["status"])

        def progress_callback(stage, percent):
            Scan.objects.filter(pk=scan.id).update(progress_stage=stage, progress_percent=min(percent, 99))

        snapshot_dir = settings.SCAN_TEMP_DIR / "snapshots" / f"scan_{scan.id}_{int(start_time)}"
        try:
            storage.copy_tree_for_scan(storage.project_root(scan.project), snapshot_dir)
            scan_root = str(snapshot_dir)
        except OSError:
            logger.exception("Could not snapshot project %s for scan %s; scanning the live tree.", scan.project_id, scan.id)
            scan_root = project_dir

        result = run_full_scan(
            project_dir=scan_root,
            enabled_scanners=scan.enabled_scanners,
            exclusions=scan.exclusions or scan.project.exclusion_patterns,
            progress_callback=progress_callback,
        )

        from .compare import path_in_scope

        if scan.scope_path:
            result.findings = [f for f in result.findings if path_in_scope(getattr(f, "file_path", ""), scan.scope_path)]
            result.secret_findings = [
                f for f in result.secret_findings if path_in_scope(getattr(f, "file_path", ""), scan.scope_path)
            ]

        for run_data in result.scanner_runs:
            ScannerRun.objects.create(
                scan=scan,
                scanner_name=run_data["scanner_name"],
                status=run_data["status"],
                findings_count=run_data["findings_count"],
                duration_seconds=run_data["duration_seconds"],
                output_log=run_data["output_log"],
                started_at=scan.started_at,
                finished_at=timezone.now(),
            )

        save_findings(scan, result.findings)
        save_secret_findings(scan, result.secret_findings)
        save_dependencies(scan, result.dependencies)

        scan.total_files = scan.project.files.count()
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = timezone.now()
        scan.duration_seconds = round(time.monotonic() - start_time, 2)
        scan.progress_stage = "completed"
        scan.progress_percent = 100
        scan.save(update_fields=[
            "total_files", "status", "completed_at", "duration_seconds", "progress_stage", "progress_percent",
        ])

        compute_and_apply_scan_statistics(scan)

        _notify_scan_completed(scan)
        log_action(scan.triggered_by, "scan_completed", "Scan", scan.id, None, {"project_id": scan.project_id})

        generate_report.delay(scan.id, "json")

    except Exception as exc:  # noqa: BLE001 - a scan failure must be recorded, not silently dropped
        logger.exception("Scan %s failed", scan_id)
        scan.status = ScanStatus.FAILED
        scan.error_message = "Scan failed. See server logs for details."
        scan.completed_at = timezone.now()
        scan.duration_seconds = round(time.monotonic() - start_time, 2)
        scan.save(update_fields=["status", "error_message", "completed_at", "duration_seconds"])
        if scan.triggered_by:
            notify(scan.triggered_by, "scan_failed", f"Scan failed for {scan.project.name}",
                   "The scan could not complete. Check the scan's error details.", link=f"/scanner.html?scan={scan.id}")
        raise
    finally:
        if snapshot_dir and Path(snapshot_dir).exists():
            shutil.rmtree(snapshot_dir, ignore_errors=True)
        cleanup_scan_files.delay(scan_id)


def _notify_scan_completed(scan):
    user = scan.triggered_by or scan.project.owner
    notify(
        user, "scan_completed", f"Scan completed for {scan.project.name}",
        f"{scan.total_findings} findings ({scan.critical_count} critical, {scan.high_count} high). "
        f"Security score: {scan.security_score}.",
        link=f"/vulnerabilities.html?scan={scan.id}",
    )
    if scan.critical_count > 0:
        notify(
            user, "critical_vulnerability", f"{scan.critical_count} critical finding(s) in {scan.project.name}",
            "Review and remediate critical findings as soon as possible.",
            link=f"/vulnerabilities.html?scan={scan.id}&severity={Severity.CRITICAL}",
        )
    if scan.secret_findings.exists():
        notify(
            user, "secret_detected", f"Secrets detected in {scan.project.name}",
            "One or more exposed secrets were found. Rotate the affected credentials immediately.",
            link=f"/vulnerabilities.html?scan={scan.id}&category=secrets",
        )


@shared_task(name="scanner.generate_report")
def generate_report(scan_id: int, report_type: str = "json"):
    from apps.reports.services import generate_report_for_scan
    from .models import Scan

    scan = Scan.objects.get(pk=scan_id)
    report = generate_report_for_scan(scan, report_type, generated_by=scan.triggered_by)
    notify(
        scan.triggered_by or scan.project.owner, "report_generated",
        f"{report_type.upper()} report ready for {scan.project.name}",
        link=f"/reports.html?report={report.id}",
    )
    return report.id


@shared_task(name="scanner.cleanup_scan_files")
def cleanup_scan_files(scan_id: int):
    """Remove leftover clone/upload temp dirs. Never touch the editor
    working tree under scan_temp/projects/ — that is the user's code."""
    import time as _time

    protected = {"projects", "snapshots"}
    cutoff = _time.time() - 24 * 3600
    if not settings.SCAN_TEMP_DIR.exists():
        return
    projects_root = (settings.SCAN_TEMP_DIR / "projects").resolve()
    for entry in settings.SCAN_TEMP_DIR.iterdir():
        if entry.name in protected:
            continue
        try:
            resolved = entry.resolve()
            if projects_root == resolved or projects_root in resolved.parents:
                continue
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue
    snapshots = settings.SCAN_TEMP_DIR / "snapshots"
    if snapshots.exists():
        for entry in snapshots.iterdir():
            try:
                if entry.stat().st_mtime < cutoff:
                    shutil.rmtree(entry, ignore_errors=True)
            except OSError:
                continue


@shared_task(name="scanner.run_weekly_scheduled_scans")
def run_weekly_scheduled_scans():
    """Sunday (or whenever beat fires): scan every project with weekly scans enabled."""
    from apps.projects.models import Project
    from common.constants import ProjectStatus, ScanTrigger

    from .services import queue_project_scan

    queued = 0
    skipped = 0
    for project in Project.objects.filter(weekly_scan_enabled=True, status=ProjectStatus.ACTIVE):
        try:
            queue_project_scan(
                project,
                user=project.owner,
                trigger_source=ScanTrigger.SCHEDULED,
                refresh_git=bool(project.repository_url),
            )
            queued += 1
        except Exception:
            skipped += 1
            logger.exception("Weekly scan not queued for project %s", project.id)
    logger.info("Weekly scheduled scans: queued=%s skipped=%s", queued, skipped)
    return {"queued": queued, "skipped": skipped}
