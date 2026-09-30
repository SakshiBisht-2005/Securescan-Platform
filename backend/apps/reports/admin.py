from django.contrib import admin

from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("id", "project", "scan", "report_type", "status", "created_at")
    list_filter = ("report_type", "status")
