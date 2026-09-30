from django.conf import settings
from django.db import models

from common.constants import ProjectStatus


class Project(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="projects")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    repository_url = models.CharField(max_length=500, blank=True)
    default_branch = models.CharField(max_length=100, default="main")
    language = models.CharField(max_length=50, blank=True)
    status = models.CharField(max_length=20, choices=ProjectStatus.CHOICES, default=ProjectStatus.ACTIVE)
    exclusion_patterns = models.JSONField(default=list, blank=True)
    weekly_scan_enabled = models.BooleanField(default=False)
    ci_token_hash = models.CharField(max_length=64, blank=True)
    ci_token_encrypted = models.TextField(blank=True)
    ci_token_prefix = models.CharField(max_length=16, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "projects"
        ordering = ["-updated_at"]
        unique_together = [("owner", "name")]
        indexes = [
            models.Index(fields=["owner", "status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return self.name


class ProjectMembership(models.Model):
    ROLE_OWNER = "owner"
    ROLE_ADMIN = "admin"
    ROLE_ANALYST = "analyst"
    ROLE_DEVELOPER = "developer"
    ROLE_CHOICES = [
        (ROLE_OWNER, "Owner"),
        (ROLE_ADMIN, "Project admin"),
        (ROLE_ANALYST, "Analyst"),
        (ROLE_DEVELOPER, "Developer"),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="project_memberships")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_DEVELOPER)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="sent_project_invites"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "project_memberships"
        unique_together = [("project", "user")]
        indexes = [models.Index(fields=["user", "role"])]

    def __str__(self):
        return f"{self.user} @ {self.project} ({self.role})"


class ProjectInvite(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="invites")
    email = models.EmailField()
    role = models.CharField(max_length=20, choices=ProjectMembership.ROLE_CHOICES, default=ProjectMembership.ROLE_DEVELOPER)
    token = models.CharField(max_length=128, unique=True)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    accepted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        db_table = "project_invites"
        indexes = [models.Index(fields=["token"]), models.Index(fields=["email"])]

    def __str__(self):
        return f"Invite {self.email} to {self.project_id}"


class ProjectFile(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="files")
    # `path` can be long (deep nested repos) and is stored with no index of
    # its own - MySQL/InnoDB caps index key length at 3072 bytes, and with
    # utf8mb4 (4 bytes/char) a straight index on a long CharField blows
    # past that. `path_hash` (sha256 of `path`) is what's actually indexed
    # and enforces per-project uniqueness instead.
    path = models.CharField(max_length=1000)
    path_hash = models.CharField(max_length=64, editable=False)
    filename = models.CharField(max_length=255)
    language = models.CharField(max_length=50, blank=True)
    size = models.PositiveBigIntegerField(default=0)
    hash = models.CharField(max_length=64, blank=True)
    is_binary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "project_files"
        indexes = [
            models.Index(fields=["project", "path_hash"]),
            models.Index(fields=["hash"]),
        ]
        unique_together = [("project", "path_hash")]

    def save(self, *args, **kwargs):
        from common.utilities import compute_fingerprint
        self.path_hash = compute_fingerprint(self.path)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.path
