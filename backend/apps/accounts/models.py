from django.contrib.auth.models import AbstractUser
from django.db import models

from common.constants import Role


class User(AbstractUser):
    """Custom user model. Extends Django's built-in auth (password hashing,
    is_active, is_staff, date_joined, last_login all inherited) with a
    platform role used for authorization."""

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=Role.CHOICES, default=Role.USER)
    is_email_verified = models.BooleanField(default=False)
    organization = models.CharField(max_length=150, blank=True)

    class Meta:
        db_table = "users"
        indexes = [
            models.Index(fields=["role"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return self.username

    @property
    def is_admin(self):
        return self.role == Role.ADMIN


class EmailVerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="verification_tokens")
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        db_table = "email_verification_tokens"


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        db_table = "password_reset_tokens"
