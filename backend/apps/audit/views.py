from rest_framework import viewsets

from common.pagination import StandardResultsSetPagination
from common.permissions import IsAdminOrAnalyst

from .models import AuditLog
from .serializers import AuditLogSerializer


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """Admin/analyst-only view of security-sensitive actions across the
    platform. Regular users cannot see other users' audit trails."""

    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminOrAnalyst]
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["action", "object_type", "user"]
    ordering_fields = ["timestamp"]

    def get_queryset(self):
        return AuditLog.objects.select_related("user").all()
