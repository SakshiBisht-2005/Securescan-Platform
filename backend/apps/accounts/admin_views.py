"""Admin-only user management API, backing the custom HTML/JS admin
dashboard (in addition to Django's built-in /django-admin/)."""
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.audit.services import log_action
from common.pagination import StandardResultsSetPagination
from common.permissions import IsAdmin

from .models import User
from .serializers import UserPublicSerializer


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class AdminUserViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserPublicSerializer
    permission_classes = [IsAdmin]
    pagination_class = StandardResultsSetPagination
    filterset_fields = ["role", "is_active", "is_email_verified"]
    search_fields = ["username", "email"]
    queryset = User.objects.all().order_by("-date_joined")

    @action(detail=True, methods=["post"], url_path="disable")
    def disable(self, request, pk=None):
        user = self.get_object()
        if user.id == request.user.id:
            return ok({"error": "You cannot disable your own account."}, status.HTTP_400_BAD_REQUEST)
        user.is_active = False
        user.save(update_fields=["is_active"])
        log_action(request.user, "admin_user_disabled", "User", user.id, request)
        return ok({"user": UserPublicSerializer(user).data})

    @action(detail=True, methods=["post"], url_path="enable")
    def enable(self, request, pk=None):
        user = self.get_object()
        user.is_active = True
        user.save(update_fields=["is_active"])
        log_action(request.user, "admin_user_enabled", "User", user.id, request)
        return ok({"user": UserPublicSerializer(user).data})

    @action(detail=True, methods=["post"], url_path="set-role")
    def set_role(self, request, pk=None):
        from common.constants import Role
        user = self.get_object()
        new_role = request.data.get("role")
        if new_role not in dict(Role.CHOICES):
            return ok({"error": "Invalid role."}, status.HTTP_400_BAD_REQUEST)
        user.role = new_role
        user.save(update_fields=["role"])
        log_action(request.user, "admin_user_role_changed", "User", user.id, request, {"new_role": new_role})
        return ok({"user": UserPublicSerializer(user).data})
