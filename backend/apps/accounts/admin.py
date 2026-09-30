from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import EmailVerificationToken, PasswordResetToken, User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("username", "email", "role", "is_active", "is_email_verified", "date_joined")
    list_filter = ("role", "is_active", "is_email_verified")
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Platform", {"fields": ("role", "is_email_verified", "organization")}),
    )


admin.site.register(EmailVerificationToken)
admin.site.register(PasswordResetToken)
