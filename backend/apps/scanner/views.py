import logging

from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.audit.services import log_action
from apps.projects.access import SCAN, visible_projects
from apps.projects.models import Project
from common.constants import ScanStatus, ScanTrigger
from common.exceptions import ConflictAppError
from common.pagination import StandardResultsSetPagination

from . import services
from .models import Scan
from .serializers import ScanSerializer

logger = logging.getLogger("scanner_engine")


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class StartScanView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "scan"

    def post(self, request, project_id):
        project = get_object_or_404(Project, pk=project_id)
        from apps.projects.access import require_project_access
        require_project_access(request.user, project, SCAN)
        scan = services.queue_from_request(project, request, trigger_source=ScanTrigger.UI)
        return ok({"scan": ScanSerializer(scan).data}, status.HTTP_202_ACCEPTED)


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ScanSerializer
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["project", "status", "scan_type"]
    ordering_fields = ["created_at", "completed_at"]

    def get_queryset(self):
        return Scan.objects.select_related("project").prefetch_related("scanner_runs").filter(
            project__in=visible_projects(self.request.user)
        )

    @action(detail=True, methods=["get"], url_path="status")
    def scan_status(self, request, pk=None):
        scan = self.get_object()
        return ok({
            "id": scan.id, "status": scan.status,
            "progress_percent": scan.progress_percent, "progress_stage": scan.progress_stage,
            "error_message": scan.error_message,
        })

    @action(detail=True, methods=["get"], url_path="findings")
    def findings(self, request, pk=None):
        scan = self.get_object()
        qs = scan.findings.all()
        severity = request.query_params.get("severity")
        category = request.query_params.get("category")
        if severity:
            qs = qs.filter(severity=severity)
        if category:
            qs = qs.filter(category=category)

        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = FindingSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request, pk=None):
        scan = self.get_object()
        if scan.status not in ScanStatus.ACTIVE:
            raise ConflictAppError("Only an active scan can be cancelled.")
        scan.status = ScanStatus.CANCELLED
        scan.save(update_fields=["status"])
        log_action(request.user, "scan_cancelled", "Scan", scan.id, request)
        return ok({"message": "Scan cancelled."})

    @action(detail=False, methods=["get"], url_path="compare")
    def compare(self, request):
        scan_a_id = request.query_params.get("scan_a")
        scan_b_id = request.query_params.get("scan_b")
        if not scan_a_id or not scan_b_id:
            return ok({"error": "scan_a and scan_b query parameters are required."}, status.HTTP_400_BAD_REQUEST)

        scan_a = get_object_or_404(self.get_queryset(), pk=scan_a_id)
        scan_b = get_object_or_404(self.get_queryset(), pk=scan_b_id)

        from .compare import compare_scans
        from .serializers import ScanSerializer

        diff = compare_scans(scan_a, scan_b, scope_path=scan_b.scope_path or scan_a.scope_path or "")
        return ok({
            "scan_a": ScanSerializer(scan_a).data,
            "scan_b": ScanSerializer(scan_b).data,
            **diff,
        })

    @action(detail=True, methods=["get"], url_path="vs-previous")
    def vs_previous(self, request, pk=None):
        scan = self.get_object()
        previous = (
            Scan.objects.filter(
                project_id=scan.project_id,
                status=ScanStatus.COMPLETED,
                id__lt=scan.id,
            )
            .order_by("-id")
            .first()
        )
        if previous is None:
            return ok({
                "scan": ScanSerializer(scan).data,
                "previous": None,
                "new_findings": [],
                "resolved_findings": [],
                "still_open_findings": [],
                "new_count": 0,
                "resolved_count": 0,
                "still_open_count": 0,
                "unchanged_count": 0,
                "security_score_delta": None,
                "scope_path": scan.scope_path or "",
            })
        from .compare import compare_scans

        scope = scan.scope_path or ""
        diff = compare_scans(previous, scan, scope_path=scope)
        return ok({
            "scan": ScanSerializer(scan).data,
            "previous": ScanSerializer(previous).data,
            **diff,
        })
