from django.contrib import admin

from .models import Scan, ScannerRun


class ScannerRunInline(admin.TabularInline):
    model = ScannerRun
    extra = 0
    readonly_fields = ("scanner_name", "status", "findings_count", "duration_seconds")


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "project", "scan_type", "status", "total_findings", "security_score", "created_at")
    list_filter = ("status", "scan_type")
    inlines = [ScannerRunInline]


@admin.register(ScannerRun)
class ScannerRunAdmin(admin.ModelAdmin):
    list_display = ("scan", "scanner_name", "status", "findings_count", "duration_seconds")
    list_filter = ("scanner_name", "status")
