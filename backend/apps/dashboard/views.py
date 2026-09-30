from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.projects.access import VIEW, require_project_access
from apps.projects.models import Project
from common.exceptions import PermissionDeniedAppError

from . import services


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class DashboardSummaryView(APIView):
    def get(self, request):
        return ok(services.get_dashboard_summary(request.user))


class SecurityTrendView(APIView):
    def get(self, request):
        project_id = request.query_params.get("project")
        return ok({"trend": services.get_security_trend(request.user, project_id=project_id)})


class ProjectStatisticsView(APIView):
    def get(self, request, project_id):
        project = get_object_or_404(Project, pk=project_id)
        require_project_access(request.user, project, VIEW)
        return ok(services.get_project_statistics(project))
