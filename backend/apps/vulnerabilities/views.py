from django.db.models import OuterRef, Subquery
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.audit.services import log_action
from apps.projects.access import visible_projects
from apps.scanner.models import Scan
from common.constants import ScanStatus
from common.pagination import StandardResultsSetPagination

from .models import Dependency, Finding, SecretFinding
from .serializers import (
    DependencySerializer,
    FindingSerializer,
    FindingStatusUpdateSerializer,
    SecretFindingSerializer,
)


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


def _owned_queryset(user, qs):
    return qs.filter(project__in=visible_projects(user))


def _limit_to_requested_scans(qs, request):
    """If `scan` is passed, django-filter applies it.

    Otherwise only keep rows from each project's latest completed scan so
    an older folder's secrets do not show up after you scan a different project.
    """
    if (request.query_params.get("scan") or "").strip():
        return qs
    latest = Scan.objects.filter(
        project_id=OuterRef("project_id"),
        status=ScanStatus.COMPLETED,
    ).order_by("-completed_at", "-id")
    return qs.filter(scan_id=Subquery(latest.values("id")[:1]))


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = FindingSerializer
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["severity", "scanner", "category", "status", "project", "scan"]
    search_fields = ["title", "file_path", "rule_id", "cwe"]
    ordering_fields = ["created_at", "severity", "first_detected_at"]

    def get_queryset(self):
        qs = _owned_queryset(self.request.user, Finding.objects.select_related("project", "scan"))
        if self.action == "list":
            return _limit_to_requested_scans(qs, self.request)
        return qs

    @action(detail=True, methods=["patch"], url_path="status")
    def update_status(self, request, pk=None):
        finding = self.get_object()
        serializer = FindingStatusUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        finding.status = serializer.validated_data["status"]
        finding.status_changed_by = request.user
        finding.status_changed_at = timezone.now()
        finding.save(update_fields=["status", "status_changed_by", "status_changed_at"])

        log_action(request.user, "finding_status_changed", "Finding", finding.id, request,
                   {"new_status": finding.status, "note": serializer.validated_data.get("note", "")})
        return ok({"finding": FindingSerializer(finding).data})


class DependencyViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DependencySerializer
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["ecosystem", "severity", "project", "scan"]
    search_fields = ["package_name", "vulnerability_id"]

    def get_queryset(self):
        qs = _owned_queryset(self.request.user, Dependency.objects.select_related("project", "scan"))
        if self.action == "list":
            return _limit_to_requested_scans(qs, self.request)
        return qs


class SecretFindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SecretFindingSerializer
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["secret_type", "status", "project", "scan"]

    def get_queryset(self):
        qs = _owned_queryset(self.request.user, SecretFinding.objects.select_related("project", "scan"))
        if self.action == "list":
            return _limit_to_requested_scans(qs, self.request)
        return qs

    @action(detail=True, methods=["patch"], url_path="status")
    def update_status(self, request, pk=None):
        finding = self.get_object()
        serializer = FindingStatusUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        finding.status = serializer.validated_data["status"]
        finding.save(update_fields=["status"])
        log_action(request.user, "secret_status_changed", "SecretFinding", finding.id, request,
                   {"new_status": finding.status, "note": serializer.validated_data.get("note", "")})
        return ok({"finding": SecretFindingSerializer(finding).data})
