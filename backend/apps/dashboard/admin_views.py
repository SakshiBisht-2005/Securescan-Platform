"""System-health / scanner-availability endpoint for the admin dashboard."""
from django.db.models import Count
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.projects.models import Project
from apps.scanner.models import Scan, ScannerRun
from common.constants import ScanStatus
from common.permissions import IsAdminOrAnalyst
from scanner_engine.manager import (
    CONTAINER_ADAPTERS,
    IAC_ADAPTERS,
    SAST_ADAPTERS,
    SCA_ADAPTERS,
    SECRET_ADAPTERS,
)


def ok(data):
    return Response({"success": True, "data": data})


class SystemHealthView(APIView):
    permission_classes = [IsAdminOrAnalyst]

    def get(self, request):
        all_adapters = SAST_ADAPTERS + SCA_ADAPTERS + SECRET_ADAPTERS + IAC_ADAPTERS + CONTAINER_ADAPTERS
        scanner_status = [
            {"name": a.name, "category": a.category_label, "available": a.is_available()}
            for a in all_adapters
        ]

        recent_failed_scans = Scan.objects.filter(status=ScanStatus.FAILED).order_by("-created_at")[:20]

        return ok({
            "users": {
                "total": User.objects.count(),
                "active": User.objects.filter(is_active=True).count(),
                "disabled": User.objects.filter(is_active=False).count(),
            },
            "projects": {"total": Project.objects.count()},
            "scans": {
                "total": Scan.objects.count(),
                "active": Scan.objects.filter(status__in=list(ScanStatus.ACTIVE)).count(),
                "failed": Scan.objects.filter(status=ScanStatus.FAILED).count(),
                "completed": Scan.objects.filter(status=ScanStatus.COMPLETED).count(),
            },
            "scanner_status": scanner_status,
            "recent_failed_scans": [
                {"id": s.id, "project": s.project.name, "error": s.error_message, "created_at": s.created_at.isoformat()}
                for s in recent_failed_scans
            ],
        })
