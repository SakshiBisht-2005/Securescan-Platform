from rest_framework.permissions import BasePermission, SAFE_METHODS

from apps.projects.access import DELETE, EDIT_FILES, MANAGE, VIEW, can_access
from common.constants import Role


def _project_from(obj):
    if obj is None:
        return None
    if obj.__class__.__name__ == "Project":
        return obj
    return getattr(obj, "project", None)


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == Role.ADMIN)


class IsAdminOrAnalyst(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.role in (Role.ADMIN, Role.SECURITY_ANALYST)
        )


class IsOwnerOrAdmin(BasePermission):
    """Object-level permission: only the owning user (via `owner` or
    `project.owner`) or an admin may access/modify. Read-only analysts can
    view but not modify, when `allow_analyst_read` is used by the view."""

    owner_field = "owner"

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        project = _project_from(obj)
        if project is None:
            owner = obj
            for part in self.owner_field.split("."):
                owner = getattr(owner, part, None)
                if owner is None:
                    break
            return owner == user or user.role == Role.ADMIN

        action = getattr(view, "action", "") or ""
        if request.method in SAFE_METHODS:
            perm = VIEW
        elif action == "destroy":
            perm = DELETE
        elif action in ("editor_file", "editor_create", "editor_rename", "upload"):
            perm = EDIT_FILES
        elif action == "member_detail" and request.method == "DELETE":
            perm = VIEW
        elif action in ("members", "member_detail", "invites", "invite_detail"):
            perm = VIEW if request.method in SAFE_METHODS else MANAGE
        else:
            perm = MANAGE
        return can_access(user, project, perm)


class ProjectScopedPermission(IsOwnerOrAdmin):
    owner_field = "owner"


class ProjectChildScopedPermission(IsOwnerOrAdmin):
    owner_field = "project.owner"
