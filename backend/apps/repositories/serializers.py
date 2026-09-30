from rest_framework import serializers

from .models import GitCredential, RepositoryImport


class GitCredentialSerializer(serializers.ModelSerializer):
    token = serializers.CharField(write_only=True)

    class Meta:
        model = GitCredential
        fields = ["id", "label", "provider", "token", "created_at"]
        read_only_fields = ["id", "created_at"]


class RepositoryImportRequestSerializer(serializers.Serializer):
    repository_url = serializers.CharField(max_length=500)
    branch = serializers.CharField(max_length=100, required=False, default="main")
    credential_id = serializers.IntegerField(required=False, allow_null=True)


class RepositoryImportSerializer(serializers.ModelSerializer):
    class Meta:
        model = RepositoryImport
        fields = ["id", "project", "repository_url", "branch", "status", "commit_sha",
                  "error_message", "started_at", "completed_at", "created_at"]
        read_only_fields = fields
