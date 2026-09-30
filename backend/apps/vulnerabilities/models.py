from django.db import models

from apps.projects.models import Project
from apps.scanner.models import Scan
from common.constants import Confidence, FindingCategory, FindingStatus, Severity


class Finding(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="findings")

    scanner = models.CharField(max_length=50)  # e.g. "bandit", "semgrep", "gitleaks"
    rule_id = models.CharField(max_length=200)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=Severity.CHOICES)
    scanner_severity = models.CharField(max_length=20, blank=True)  # preserved as reported by the tool
    confidence = models.CharField(max_length=20, choices=Confidence.CHOICES, default=Confidence.MEDIUM)
    category = models.CharField(max_length=50, choices=FindingCategory.CHOICES, default=FindingCategory.OTHER)
    cwe = models.CharField(max_length=20, blank=True)
    owasp_category = models.CharField(max_length=100, blank=True)

    file_path = models.CharField(max_length=1000, blank=True)
    line_start = models.PositiveIntegerField(null=True, blank=True)
    line_end = models.PositiveIntegerField(null=True, blank=True)
    column_start = models.PositiveIntegerField(null=True, blank=True)
    column_end = models.PositiveIntegerField(null=True, blank=True)
    code_snippet = models.TextField(blank=True)

    remediation = models.TextField(blank=True)
    references = models.JSONField(default=list, blank=True)

    fingerprint = models.CharField(max_length=64, db_index=True)
    status = models.CharField(max_length=20, choices=FindingStatus.CHOICES, default=FindingStatus.OPEN)
    status_changed_by = models.ForeignKey(
        "accounts.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    status_changed_at = models.DateTimeField(null=True, blank=True)

    first_detected_at = models.DateTimeField(auto_now_add=True)
    last_detected_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "findings"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["project", "status"]),
            models.Index(fields=["scan", "severity"]),
            models.Index(fields=["fingerprint"]),
            models.Index(fields=["category"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.title}"


class Dependency(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="dependencies")
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="dependencies", null=True, blank=True)
    package_name = models.CharField(max_length=200)
    version = models.CharField(max_length=100)
    ecosystem = models.CharField(max_length=50)  # pypi, npm, maven, composer, go, rubygems
    manifest_file = models.CharField(max_length=500)
    vulnerability_id = models.CharField(max_length=100, blank=True)  # CVE / GHSA / OSV id
    severity = models.CharField(max_length=20, choices=Severity.CHOICES, blank=True)
    description = models.TextField(blank=True)
    fixed_version = models.CharField(max_length=100, blank=True)
    fingerprint = models.CharField(max_length=64, db_index=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "dependencies"
        indexes = [
            models.Index(fields=["project", "severity"]),
            models.Index(fields=["package_name", "ecosystem"]),
        ]

    def __str__(self):
        return f"{self.package_name}=={self.version} ({self.ecosystem})"


class SecretFinding(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="secret_findings")
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="secret_findings")
    secret_type = models.CharField(max_length=100)  # e.g. "AWS Access Key", "Generic API Key"
    file_path = models.CharField(max_length=1000)
    line_number = models.PositiveIntegerField(null=True, blank=True)
    masked_value = models.CharField(max_length=200)  # never store the raw secret
    fingerprint = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=20, choices=Severity.CHOICES, default=Severity.HIGH)
    status = models.CharField(max_length=20, choices=FindingStatus.CHOICES, default=FindingStatus.OPEN)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "secret_findings"
        indexes = [
            models.Index(fields=["project", "status"]),
            models.Index(fields=["fingerprint"]),
        ]

    def __str__(self):
        return f"{self.secret_type} in {self.file_path}"
