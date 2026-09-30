from django.db import models

from apps.projects.models import Project
from common.constants import ScanStatus, ScanType, ScanTrigger


class Scan(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="scans")
    scan_type = models.CharField(max_length=20, choices=ScanType.CHOICES, default=ScanType.FULL)
    status = models.CharField(max_length=20, choices=ScanStatus.CHOICES, default=ScanStatus.QUEUED)
    progress_percent = models.PositiveSmallIntegerField(default=0)
    progress_stage = models.CharField(max_length=100, blank=True)

    enabled_scanners = models.JSONField(default=dict, blank=True)  # {"sast": true, "sca": true, ...}
    severity_threshold = models.CharField(max_length=20, blank=True)  # optional filter for the run
    branch = models.CharField(max_length=100, blank=True)
    exclusions = models.JSONField(default=list, blank=True)

    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)

    total_files = models.PositiveIntegerField(default=0)
    total_findings = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    info_count = models.PositiveIntegerField(default=0)
    security_score = models.PositiveSmallIntegerField(null=True, blank=True)

    error_message = models.TextField(blank=True)
    celery_task_id = models.CharField(max_length=100, blank=True)
    trigger_source = models.CharField(max_length=20, choices=ScanTrigger.CHOICES, default=ScanTrigger.UI)
    git_sha = models.CharField(max_length=64, blank=True)
    scope_path = models.CharField(max_length=1000, blank=True)

    triggered_by = models.ForeignKey(
        "accounts.User", null=True, on_delete=models.SET_NULL, related_name="triggered_scans"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "scans"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["project", "status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"Scan #{self.id} ({self.project.name})"


class ScannerRun(models.Model):
    """Per-scanner execution record within a Scan (bandit, semgrep,
    pip-audit, gitleaks, checkov, trivy, ...). Lets the dashboard show
    which individual tools ran, were skipped (not installed), or failed."""

    STATUS_CHOICES = [
        ("skipped_unavailable", "Skipped (unavailable)"),
        ("running", "Running"),
        ("success", "Success"),
        ("failed", "Failed"),
        ("timeout", "Timeout"),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="scanner_runs")
    scanner_name = models.CharField(max_length=50)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES)
    findings_count = models.PositiveIntegerField(default=0)
    duration_seconds = models.FloatField(null=True, blank=True)
    output_log = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "scanner_runs"
        indexes = [models.Index(fields=["scan", "scanner_name"])]
