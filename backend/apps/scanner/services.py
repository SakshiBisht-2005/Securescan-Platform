"""Shared scan-queue helpers used by the UI, CI, webhooks, and Celery beat."""
import logging
from datetime import timedelta

from django.utils import timezone

from apps.audit.services import log_action
from common.constants import ScanStatus, ScanTrigger
from common.exceptions import ConflictAppError, ServiceUnavailableAppError

from . import tasks
from .models import Scan
from .serializers import ScanCreateSerializer, ScanSerializer

logger = logging.getLogger("scanner_engine")

DEFAULT_ENABLED = {"sast": True, "sca": True, "secrets": True, "iac": True, "container": True}

# Queued scans whose Celery worker never started them still block the
# project. Fail them after a short grace, even if a task id was stored
# (the worker may have rejected the message and never entered start_scan).
ORPHANED_QUEUE_GRACE = timedelta(minutes=2)


def fail_orphaned_queued_scans(project):
    cutoff = timezone.now() - ORPHANED_QUEUE_GRACE
    project.scans.filter(
        status=ScanStatus.QUEUED,
        created_at__lte=cutoff,
    ).update(
        status=ScanStatus.FAILED,
        error_message="Scan never started. The Celery worker did not pick it up — restart python start.py and try again.",
        completed_at=timezone.now(),
    )


def queue_project_scan(
    project,
    *,
    user=None,
    scan_type="full",
    enabled_scanners=None,
    branch="",
    exclusions=None,
    severity_threshold="",
    trigger_source=ScanTrigger.UI,
    git_sha="",
    refresh_git=False,
    request=None,
    scope_path="",
):
    fail_orphaned_queued_scans(project)
    if project.scans.filter(status__in=ScanStatus.ACTIVE).exists():
        raise ConflictAppError("A scan is already in progress for this project.")

    scan = Scan.objects.create(
        project=project,
        scan_type=scan_type,
        enabled_scanners=enabled_scanners or DEFAULT_ENABLED,
        severity_threshold=severity_threshold or "",
        branch=branch or project.default_branch,
        exclusions=exclusions or [],
        triggered_by=user,
        trigger_source=trigger_source,
        git_sha=git_sha or "",
        scope_path=(scope_path or "").replace("\\", "/").lstrip("./"),
    )

    try:
        async_result = tasks.start_scan.delay(scan.id)
    except Exception:
        logger.exception("Failed to queue scan %s", scan.id)
        scan.status = ScanStatus.FAILED
        scan.error_message = "Could not queue the scan. Redis or the Celery worker is unavailable."
        scan.completed_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "completed_at"])
        raise ServiceUnavailableAppError(
            "Could not queue the scan. Redis or the Celery worker is unavailable."
        )

    task_id = getattr(async_result, "id", None) or ""
    if task_id:
        scan.celery_task_id = task_id
        scan.save(update_fields=["celery_task_id"])

    if request is not None:
        log_action(user, "scan_started", "Scan", scan.id, request, {
            "project_id": project.id,
            "trigger_source": trigger_source,
        })
    return scan


def queue_from_request(project, request, trigger_source=ScanTrigger.UI):
    payload = request.data if hasattr(request, "data") else {}
    serializer = ScanCreateSerializer(data=payload)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    user = getattr(request, "user", None)
    if user is not None and not getattr(user, "is_authenticated", False):
        user = None
    refresh = bool(project.repository_url) and trigger_source != ScanTrigger.UI
    return queue_project_scan(
        project,
        user=user,
        scan_type=data["scan_type"],
        enabled_scanners=serializer.to_enabled_scanners(),
        branch=data.get("branch") or project.default_branch,
        exclusions=data.get("exclusions", []),
        severity_threshold=data.get("severity_threshold", ""),
        trigger_source=trigger_source,
        refresh_git=refresh,
        request=request,
        scope_path=data.get("scope_path") or "",
    )


def scan_gate_failed(scan, fail_on: str) -> bool:
    fail_on = (fail_on or "high").lower()
    if fail_on in ("never", "none"):
        return False
    counts = {
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "info": scan.info_count,
    }
    order = ["critical", "high", "medium", "low", "info"]
    if fail_on not in order:
        fail_on = "high"
    start = order.index(fail_on)
    return any(counts[level] > 0 for level in order[: start + 1])


def ci_scan_payload(scan, fail_on="high"):
    completed_gate = scan.status == ScanStatus.COMPLETED and scan_gate_failed(scan, fail_on)
    return {
        "scan": ScanSerializer(scan).data,
        "fail_on": fail_on,
        "gate_failed": completed_gate,
        "ok": scan.status == ScanStatus.COMPLETED and not scan_gate_failed(scan, fail_on),
    }
