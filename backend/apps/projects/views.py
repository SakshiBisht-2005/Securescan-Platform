import shutil
import tempfile
from pathlib import Path

from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from apps.accounts.services import _frontend_base_url
from apps.audit.services import log_action
from apps.projects.access import MANAGE, VIEW, can_access, project_role_for, require_project_access, visible_projects
from common.exceptions import NotFoundAppError, UnsafeUploadError, ValidationAppError
from common.permissions import IsOwnerOrAdmin

from . import members as member_service
from . import storage, upload_service
from .models import Project, ProjectFile, ProjectInvite, ProjectMembership
from .serializers import (
    InviteMemberSerializer,
    ProjectFileContentSerializer,
    ProjectFileSerializer,
    ProjectInviteSerializer,
    ProjectMembershipSerializer,
    ProjectSerializer,
)


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class ProjectViewSet(viewsets.ModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    filterset_fields = ["status", "language"]
    search_fields = ["name", "description"]
    ordering_fields = ["created_at", "updated_at", "name"]

    def get_queryset(self):
        return visible_projects(self.request.user)

    def perform_create(self, serializer):
        project = serializer.save(owner=self.request.user)
        member_service.ensure_owner_membership(project)
        log_action(self.request.user, "project_created", "Project", project.id, self.request)

    def perform_destroy(self, instance):
        project_id = instance.id
        storage.project_root(instance)  # ensure created before we try to remove
        shutil.rmtree(storage.project_root(instance), ignore_errors=True)
        instance.delete()
        log_action(self.request.user, "project_deleted", "Project", project_id, self.request)

    def perform_update(self, serializer):
        project = serializer.save()
        log_action(self.request.user, "project_updated", "Project", project.id, self.request)

    # -- Upload ------------------------------------------------------
    @action(detail=True, methods=["post"], url_path="upload", throttle_classes=[ScopedRateThrottle])
    def upload(self, request, pk=None):
        self.throttle_scope = "upload"
        project = self.get_object()
        uploaded_file = request.FILES.get("file")
        if not uploaded_file:
            raise UnsafeUploadError("No file was uploaded. Expected multipart field 'file'.")

        upload_service.validate_upload_metadata(uploaded_file)

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            for chunk in uploaded_file.chunks():
                tmp.write(chunk)
            tmp_path = tmp.name

        extracted_dir = None
        try:
            extracted_dir = upload_service.extract_zip_safely(tmp_path, project.exclusion_patterns)

            # Replace the project's working tree with the freshly extracted one.
            root = storage.project_root(project)
            shutil.rmtree(root, ignore_errors=True)
            shutil.move(extracted_dir, str(root))

            count = upload_service.index_directory_to_project(project, str(root), project.exclusion_patterns)
            project.save(update_fields=["updated_at"])
            log_action(request.user, "project_files_uploaded", "Project", project.id, request, {"file_count": count})
            return ok({"message": "Upload processed successfully.", "files_indexed": count})
        finally:
            Path(tmp_path).unlink(missing_ok=True)
            if extracted_dir and Path(extracted_dir).exists():
                upload_service.cleanup_extracted_dir(extracted_dir)

    # -- Files (read-only listing used outside the editor, e.g. findings drill-down) --
    @action(detail=True, methods=["get"], url_path="files")
    def files(self, request, pk=None):
        project = self.get_object()
        qs = project.files.all().order_by("path")
        return ok({"files": ProjectFileSerializer(qs, many=True).data})

    # -- Code editor ---------------------------------------------------
    @action(detail=True, methods=["get"], url_path="editor/tree")
    def editor_tree(self, request, pk=None):
        project = self.get_object()
        return ok({"tree": storage.list_tree(project)})

    @action(detail=True, methods=["get", "put", "delete"], url_path="editor/file")
    def editor_file(self, request, pk=None):
        project = self.get_object()
        if request.method == "GET":
            path = request.query_params.get("path", "")
            content = storage.read_file(project, path)
            return ok({"path": path, "content": content})

        serializer = ProjectFileContentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        path = serializer.validated_data["path"]

        if request.method == "PUT":
            storage.write_file(project, path, serializer.validated_data.get("content", ""))
            log_action(request.user, "file_saved", "ProjectFile", path, request, {"project_id": project.id})
            return ok({"message": "File saved."})

        storage.delete_file(project, path)
        log_action(request.user, "file_deleted", "ProjectFile", path, request, {"project_id": project.id})
        return ok({"message": "File deleted."})

    @action(detail=True, methods=["post"], url_path="editor/create")
    def editor_create(self, request, pk=None):
        project = self.get_object()
        path = request.data.get("path", "")
        entry_type = request.data.get("type", "file")
        # A name with a file extension is always a file, even if the UI sent "directory".
        suffix = Path(str(path)).suffix.lower()
        if entry_type == "directory" and suffix in {
            ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
            ".c", ".h", ".cpp", ".cs", ".html", ".css", ".json", ".yml", ".yaml",
            ".md", ".txt", ".sql", ".sh", ".xml", ".tf",
        }:
            entry_type = "file"
        if entry_type == "directory":
            storage.create_directory(project, path)
        else:
            storage.write_file(project, path, request.data.get("content", ""))
        log_action(request.user, "file_created", "ProjectFile", path, request, {"project_id": project.id, "type": entry_type})
        return ok({"message": "Created successfully."}, status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="editor/rename")
    def editor_rename(self, request, pk=None):
        project = self.get_object()
        old_path = request.data.get("old_path", "")
        new_path = request.data.get("new_path", "")
        storage.rename_path(project, old_path, new_path)
        log_action(request.user, "file_renamed", "ProjectFile", new_path, request, {"project_id": project.id, "from": old_path})
        return ok({"message": "Renamed successfully."})

    @action(detail=True, methods=["get"], url_path="editor/search")
    def editor_search(self, request, pk=None):
        """Simple in-project text search across indexed (non-binary) files."""
        project = self.get_object()
        query = request.query_params.get("q", "").strip()
        if not query or len(query) < 2:
            return ok({"results": []})

        results = []
        root = storage.project_root(project)
        for pf in project.files.filter(is_binary=False)[:5000]:
            abs_path = root / pf.path
            try:
                text = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                if query.lower() in line.lower():
                    results.append({"path": pf.path, "line": i, "text": line.strip()[:300]})
                    if len(results) >= 200:
                        return ok({"results": results})
        return ok({"results": results})

    @action(detail=True, methods=["get", "post"], url_path="members")
    def members(self, request, pk=None):
        project = self.get_object()
        if request.method == "GET":
            require_project_access(request.user, project, VIEW)
            member_service.ensure_owner_membership(project)
            qs = project.memberships.select_related("user").order_by("created_at")
            pending = project.invites.filter(accepted=False).select_related("invited_by").order_by("-created_at")
            invite_rows = []
            base = _frontend_base_url(request)
            can_manage = can_access(request.user, project, MANAGE)
            for inv in pending:
                row = ProjectInviteSerializer(inv).data
                if can_manage:
                    row["accept_link"] = f"{base}/accept-invite.html?token={inv.token}"
                invite_rows.append(row)
            return ok({
                "members": ProjectMembershipSerializer(qs, many=True).data,
                "invites": invite_rows,
                "my_role": project_role_for(request.user, project),
            })
        require_project_access(request.user, project, MANAGE)
        serializer = InviteMemberSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = member_service.invite_member(
            project, request.user, serializer.validated_data["email"], serializer.validated_data["role"], request
        )
        log_action(request.user, "project_member_invited", "Project", project.id, request, {
            "email": serializer.validated_data["email"], "role": serializer.validated_data["role"],
        })
        if result["kind"] == "member":
            return ok({"member": ProjectMembershipSerializer(result["membership"]).data}, status.HTTP_201_CREATED)
        payload = {
            "invite": ProjectInviteSerializer(result["invite"]).data,
            "email_sent": result["email_sent"],
            "accept_link": result.get("accept_link"),
        }
        return ok(payload, status.HTTP_201_CREATED)

    @action(detail=True, methods=["patch", "delete"], url_path="members/(?P<member_id>[^/.]+)")
    def member_detail(self, request, pk=None, member_id=None):
        project = self.get_object()
        membership = ProjectMembership.objects.filter(project=project, pk=member_id).first()
        if not membership:
            raise NotFoundAppError("Member not found.")
        if request.method == "DELETE":
            if membership.user_id != request.user.id:
                require_project_access(request.user, project, MANAGE)
            member_service.remove_member(project, request.user, membership)
            log_action(request.user, "project_member_removed", "Project", project.id, request, {"member_id": member_id})
            return ok({"message": "Member removed."})
        require_project_access(request.user, project, MANAGE)
        role = request.data.get("role")
        if not role:
            raise ValidationAppError("role is required.")
        member_service.change_member_role(project, request.user, membership, role)
        return ok({"member": ProjectMembershipSerializer(membership).data})

    @action(detail=True, methods=["delete"], url_path="invites/(?P<invite_id>[^/.]+)")
    def invite_detail(self, request, pk=None, invite_id=None):
        project = self.get_object()
        require_project_access(request.user, project, MANAGE)
        invite = ProjectInvite.objects.filter(project=project, pk=invite_id, accepted=False).first()
        if not invite:
            raise NotFoundAppError("Invite not found.")
        invite.delete()
        return ok({"message": "Invite cancelled."})
