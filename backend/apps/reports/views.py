from pathlib import Path

from django.conf import settings
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.audit.services import log_action
from apps.projects.access import SCAN, VIEW, require_project_access, visible_projects
from apps.scanner.models import Scan
from common.exceptions import NotFoundAppError
from common.pagination import StandardResultsSetPagination

from . import services
from .models import Report
from .serializers import ReportGenerateSerializer, ReportSerializer


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ReportSerializer
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["project", "scan", "report_type", "status"]

    def get_queryset(self):
        return Report.objects.select_related("project").filter(project__in=visible_projects(self.request.user))


class GenerateReportView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "report"

    def post(self, request, scan_id):
        scan = get_object_or_404(Scan, pk=scan_id)
        require_project_access(request.user, scan.project, SCAN)

        serializer = ReportGenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        report = services.generate_report_for_scan(scan, serializer.validated_data["report_type"], generated_by=request.user)
        log_action(request.user, "report_generated", "Report", report.id, request, {"scan_id": scan.id})
        return ok({"report": ReportSerializer(report).data}, status.HTTP_201_CREATED)


class DownloadReportView(APIView):
    def get(self, request, pk):
        report = get_object_or_404(Report, pk=pk)
        require_project_access(request.user, report.project, VIEW)
        if report.status != "ready" or not report.file_path:
            raise NotFoundAppError("Report is not ready for download.")

        relative = Path(str(report.file_path).replace("\\", "/"))
        full_path = (settings.MEDIA_ROOT / relative).resolve()
        media_root = settings.MEDIA_ROOT.resolve()
        if media_root not in full_path.parents or not full_path.exists() or not full_path.is_file():
            raise NotFoundAppError("Report file is missing.")

        log_action(request.user, "report_downloaded", "Report", report.id, request)
        ext = "pdf" if report.report_type == "pdf" else "json"
        filename = f"security_report_{report.id}.{ext}"
        content_type = "application/pdf" if ext == "pdf" else "application/json"
        response = FileResponse(
            full_path.open("rb"),
            as_attachment=True,
            filename=filename,
            content_type=content_type,
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Access-Control-Expose-Headers"] = "Content-Disposition"
        return response
