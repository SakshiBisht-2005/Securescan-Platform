import shutil

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.audit.services import log_action
from apps.projects.access import EDIT_FILES, require_project_access
from apps.projects.models import Project
from apps.projects.upload_service import index_directory_to_project
from apps.projects import storage
from common.exceptions import PermissionDeniedAppError

from . import services
from .models import GitCredential, RepositoryImport
from .serializers import (
    GitCredentialSerializer,
    RepositoryImportRequestSerializer,
    RepositoryImportSerializer,
)


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


def _get_owned_project(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    require_project_access(request.user, project, EDIT_FILES)
    return project


class GitCredentialListCreateView(APIView):
    def get(self, request):
        qs = GitCredential.objects.filter(owner=request.user)
        return ok({"credentials": GitCredentialSerializer(qs, many=True).data})

    def post(self, request):
        serializer = GitCredentialSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data.pop("token")
        credential = GitCredential.objects.create(
            owner=request.user,
            label=serializer.validated_data["label"],
            provider=serializer.validated_data.get("provider", "generic"),
            encrypted_token=services.encrypt_token(token),
        )
        log_action(request.user, "git_credential_added", "GitCredential", credential.id, request)
        return ok({"credential": GitCredentialSerializer(credential).data}, status.HTTP_201_CREATED)


class GitCredentialDeleteView(APIView):
    def delete(self, request, pk):
        credential = get_object_or_404(GitCredential, pk=pk, owner=request.user)
        credential.delete()
        log_action(request.user, "git_credential_removed", "GitCredential", pk, request)
        return ok({"message": "Credential removed."})


class RepositoryImportView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "upload"

    def post(self, request, project_id):
        project = _get_owned_project(request, project_id)
        serializer = RepositoryImportRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        services.validate_repository_url(data["repository_url"])

        credential_token = None
        credential = None
        if data.get("credential_id"):
            credential = get_object_or_404(GitCredential, pk=data["credential_id"], owner=request.user)
            credential_token = services.decrypt_token(credential.encrypted_token)

        record = RepositoryImport.objects.create(
            project=project,
            repository_url=data["repository_url"],
            branch=data.get("branch") or "main",
            credential=credential,
            status="cloning",
            started_at=timezone.now(),
        )

        cloned_dir = None
        try:
            cloned_dir = services.clone_repository(data["repository_url"], record.branch, credential_token)
            commit_sha = services.get_head_commit_sha(data["repository_url"], record.branch, credential_token)

            root = storage.project_root(project)
            shutil.rmtree(root, ignore_errors=True)
            shutil.move(cloned_dir, str(root))

            count = index_directory_to_project(project, str(root), project.exclusion_patterns)

            project.repository_url = data["repository_url"]
            project.default_branch = record.branch
            project.save(update_fields=["repository_url", "default_branch", "updated_at"])

            record.status = "completed"
            record.commit_sha = commit_sha
            record.completed_at = timezone.now()
            record.save(update_fields=["status", "commit_sha", "completed_at"])

            log_action(request.user, "repository_imported", "Project", project.id, request,
                       {"branch": record.branch, "files_indexed": count})
            return ok({"import": RepositoryImportSerializer(record).data, "files_indexed": count})
        except Exception as exc:  # noqa: BLE001
            record.status = "failed"
            record.error_message = "Import failed. See server logs for details."
            record.completed_at = timezone.now()
            record.save(update_fields=["status", "error_message", "completed_at"])
            if cloned_dir:
                shutil.rmtree(cloned_dir, ignore_errors=True)
            raise


class RepositoryImportHistoryView(APIView):
    def get(self, request, project_id):
        project = _get_owned_project(request, project_id)
        qs = project.repository_imports.all()
        return ok({"imports": RepositoryImportSerializer(qs, many=True).data})
