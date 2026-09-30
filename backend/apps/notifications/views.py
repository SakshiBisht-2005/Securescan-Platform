from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from common.pagination import StandardResultsSetPagination

from .models import Notification
from .serializers import NotificationSerializer


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = NotificationSerializer
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["is_read", "notification_type"]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)

    @action(detail=True, methods=["post"], url_path="read")
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        notification.is_read = True
        notification.save(update_fields=["is_read"])
        return ok({"message": "Marked as read."})

    @action(detail=False, methods=["post"], url_path="read-all")
    def mark_all_read(self, request):
        self.get_queryset().filter(is_read=False).update(is_read=True)
        return ok({"message": "All notifications marked as read."})

    @action(detail=False, methods=["get"], url_path="unread-count")
    def unread_count(self, request):
        return ok({"unread_count": self.get_queryset().filter(is_read=False).count()})
