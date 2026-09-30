from django.contrib import admin

from .models import GitCredential, RepositoryImport


@admin.register(GitCredential)
class GitCredentialAdmin(admin.ModelAdmin):
    list_display = ("label", "provider", "owner", "created_at")
    # Never expose the encrypted token in the list/detail readonly display.
    exclude = ()
    readonly_fields = ("encrypted_token",)


@admin.register(RepositoryImport)
class RepositoryImportAdmin(admin.ModelAdmin):
    list_display = ("project", "repository_url", "branch", "status", "created_at")
    list_filter = ("status",)
