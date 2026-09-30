from django.conf import settings
from django.db import models

from apps.projects.models import Project


class GitCredential(models.Model):
    """Stores a reference to a credential used for private repository
    import. The actual token is encrypted at rest using Django's signing
    utilities (see services.py) and is never returned by any API or logged.
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="git_credentials")
    label = models.CharField(max_length=100)
    provider = models.CharField(max_length=50, default="generic")  # github, gitlab, bitbucket, generic
    encrypted_token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "git_credentials"

    def __str__(self):
        return f"{self.label} ({self.provider})"


class RepositoryImport(models.Model):
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("cloning", "Cloning"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="repository_imports")
    repository_url = models.CharField(max_length=500)
    branch = models.CharField(max_length=100, default="main")
    credential = models.ForeignKey(GitCredential, null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="queued")
    commit_sha = models.CharField(max_length=64, blank=True)
    error_message = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "repository_imports"
        ordering = ["-created_at"]
