from django.contrib import admin

from .models import Dependency, Finding, SecretFinding


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "project", "severity", "status", "scanner", "file_path", "line_start")
    list_filter = ("severity", "status", "scanner", "category")
    search_fields = ("title", "file_path", "rule_id")


@admin.register(Dependency)
class DependencyAdmin(admin.ModelAdmin):
    list_display = ("package_name", "version", "ecosystem", "severity", "vulnerability_id")
    list_filter = ("ecosystem", "severity")
    search_fields = ("package_name", "vulnerability_id")


@admin.register(SecretFinding)
class SecretFindingAdmin(admin.ModelAdmin):
    list_display = ("secret_type", "project", "file_path", "severity", "status")
    list_filter = ("secret_type", "status")
    readonly_fields = ("masked_value",)
