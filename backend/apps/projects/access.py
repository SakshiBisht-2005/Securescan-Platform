"""Project-level access: owner plus invited teammates.

Global User.role (ADMIN / SECURITY_ANALYST / USER) still applies:
admins see everything; platform analysts can view and scan any project.
Everyone else needs to own the project or hold a membership.
"""
from django.db.models import Q

from common.constants import Role
from common.exceptions import PermissionDeniedAppError


class ProjectRole:
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"

    CHOICES = [
        (OWNER, "Owner"),
        (ADMIN, "Project admin"),
        (ANALYST, "Analyst"),
        (DEVELOPER, "Developer"),
    ]


VIEW = "view"
SCAN = "scan"
EDIT_FILES = "edit_files"
MANAGE = "manage"
DELETE = "delete"

_PERMISSIONS = {
    ProjectRole.OWNER: {VIEW, SCAN, EDIT_FILES, MANAGE, DELETE},
    ProjectRole.ADMIN: {VIEW, SCAN, EDIT_FILES, MANAGE},
    ProjectRole.ANALYST: {VIEW, SCAN},
    ProjectRole.DEVELOPER: {VIEW, SCAN, EDIT_FILES},
}


def visible_projects(user):
    from apps.projects.models import Project

    if not user or not user.is_authenticated:
        return Project.objects.none()
    if user.role in (Role.ADMIN, Role.SECURITY_ANALYST):
        return Project.objects.all()
    return Project.objects.filter(Q(owner=user) | Q(memberships__user=user)).distinct()


def project_role_for(user, project) -> str | None:
    if not user or not user.is_authenticated:
        return None
    if user.role == Role.ADMIN:
        return ProjectRole.OWNER
    if project.owner_id == user.id:
        return ProjectRole.OWNER
    membership = getattr(project, "memberships", None)
    if membership is not None:
        row = project.memberships.filter(user=user).first()
    else:
        from apps.projects.models import ProjectMembership
        row = ProjectMembership.objects.filter(project=project, user=user).first()
    if row:
        return row.role
    if user.role == Role.SECURITY_ANALYST:
        return ProjectRole.ANALYST
    return None


def can_access(user, project, permission: str = VIEW) -> bool:
    role = project_role_for(user, project)
    if not role:
        return False
    return permission in _PERMISSIONS.get(role, set())


def require_project_access(user, project, permission: str = VIEW):
    if can_access(user, project, permission):
        return project_role_for(user, project)
    raise PermissionDeniedAppError("You do not have access to this project.")
