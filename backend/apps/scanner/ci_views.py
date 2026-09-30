"""CI token management, GitHub Action scan API, and GitHub push webhooks."""
import logging

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.audit.services import log_action
from apps.projects.access import MANAGE, require_project_access
from apps.projects.models import Project
from common.constants import ScanTrigger
from common.exceptions import PermissionDeniedAppError
from common.permissions import IsOwnerOrAdmin

from . import ci_auth, services
from .models import Scan
from .serializers import ScanSerializer

logger = logging.getLogger("scanner_engine")


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


def _owned_project(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    require_project_access(request.user, project, MANAGE)
    return project


class ProjectCiTokenView(APIView):
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def get(self, request, project_id):
        project = _owned_project(request, project_id)
        return ok({
            "has_ci_token": bool(project.ci_token_hash),
            "ci_token_prefix": project.ci_token_prefix,
            "weekly_scan_enabled": project.weekly_scan_enabled,
            "webhook_path": f"/api/webhooks/github/{project.id}/",
            "ci_scan_path": f"/api/ci/projects/{project.id}/scan/",
        })

    def post(self, request, project_id):
        project = _owned_project(request, project_id)
        raw, digest, prefix, encrypted = ci_auth.issue_ci_token()
        project.ci_token_hash = digest
        project.ci_token_encrypted = encrypted
        project.ci_token_prefix = prefix
        project.save(update_fields=["ci_token_hash", "ci_token_encrypted", "ci_token_prefix", "updated_at"])
        log_action(request.user, "ci_token_rotated", "Project", project.id, request)
        return ok({
            "token": raw,
            "ci_token_prefix": prefix,
            "message": "Store this token now. It is not shown again.",
            "webhook_path": f"/api/webhooks/github/{project.id}/",
            "ci_scan_path": f"/api/ci/projects/{project.id}/scan/",
        })


class CiStartScanView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "scan"

    def post(self, request, project_id):
        project = ci_auth.authenticate_ci_project(request, project_id)
        git_sha = (request.data.get("sha") or request.data.get("after") or "")[:64]
        branch = request.data.get("branch") or ""
        ref = request.data.get("ref") or ""
        if not branch and isinstance(ref, str) and ref.startswith("refs/heads/"):
            branch = ref[len("refs/heads/"):]
        scan = services.queue_project_scan(
            project,
            user=project.owner,
            branch=branch or project.default_branch,
            git_sha=git_sha,
            trigger_source=ScanTrigger.CI,
            refresh_git=bool(project.repository_url),
            request=request,
        )
        fail_on = request.data.get("fail_on") or "high"
        return ok(services.ci_scan_payload(scan, fail_on), status.HTTP_202_ACCEPTED)


class CiScanStatusView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "scan"

    def get(self, request, project_id, scan_id):
        project = ci_auth.authenticate_ci_project(request, project_id)
        scan = get_object_or_404(Scan, pk=scan_id, project=project)
        fail_on = request.query_params.get("fail_on") or "high"
        return ok(services.ci_scan_payload(scan, fail_on))


class GitHubWebhookView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "scan"

    def post(self, request, project_id):
        project = ci_auth.authenticate_ci_project(request, project_id, allow_hmac=True)
        event = (request.META.get("HTTP_X_GITHUB_EVENT") or "").lower()
        if event == "ping":
            return ok({"message": "pong"})
        if event and event != "push":
            return ok({"message": f"Ignored GitHub event '{event}'."})

        payload = request.data
        if isinstance(payload, list):
            payload = {}
        if payload.get("deleted"):
            return ok({"message": "Ignored branch deletion."})
        after = str(payload.get("after") or "")
        if after == "0" * 40:
            return ok({"message": "Ignored empty push."})
        ref = str(payload.get("ref") or "")
        branch = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else project.default_branch
        scan = services.queue_project_scan(
            project,
            user=project.owner,
            branch=branch,
            git_sha=after[:64],
            trigger_source=ScanTrigger.WEBHOOK,
            refresh_git=bool(project.repository_url),
            request=request,
        )
        return ok({"scan": ScanSerializer(scan).data}, status.HTTP_202_ACCEPTED)
