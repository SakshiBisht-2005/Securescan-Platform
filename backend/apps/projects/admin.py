from django.contrib import admin

from .models import Project, ProjectFile


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "status", "language", "created_at")
    list_filter = ("status", "language")
    search_fields = ("name", "owner__username")


@admin.register(ProjectFile)
class ProjectFileAdmin(admin.ModelAdmin):
    list_display = ("path", "project", "language", "size", "is_binary")
    search_fields = ("path",)
