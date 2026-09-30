from django.conf import settings
from django.db import models

from apps.projects.models import Project
from apps.scanner.models import Scan
from common.constants import ReportType


class Report(models.Model):
    STATUS_CHOICES = [
        ("generating", "Generating"),
        ("ready", "Ready"),
        ("failed", "Failed"),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="reports")
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="reports")
    report_type = models.CharField(max_length=10, choices=ReportType.CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="generating")
    file_path = models.CharField(max_length=1000, blank=True)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "reports"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Report #{self.id} ({self.report_type})"
