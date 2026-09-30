import io
import os
import shutil
import zipfile

import pytest

from common.exceptions import UnsafeUploadError

from .models import Project
from .upload_service import extract_zip_safely, validate_upload_metadata

pytestmark = pytest.mark.django_db


class TestProjectCreation:
    def test_create_project(self, auth_client):
        client, user = auth_client
        resp = client.post("/api/projects/", {"name": "My App", "description": "test project"}, format="json")
        assert resp.status_code == 201
        assert resp.data["data"]["owner"] == user.id

    def test_duplicate_project_name_for_same_owner_rejected(self, auth_client):
        client, user = auth_client
        Project.objects.create(owner=user, name="Dup")
        resp = client.post("/api/projects/", {"name": "Dup"}, format="json")
        assert resp.status_code in (400, 409)

    def test_users_only_see_own_projects(self, auth_client, make_user):
        client, user = auth_client
        other = make_user(username="bob", email="bob@example.com")
        Project.objects.create(owner=other, name="Bob's Project")
        Project.objects.create(owner=user, name="My Project")

        resp = client.get("/api/projects/")
        names = [p["name"] for p in resp.data["data"]["results"]]
        assert "My Project" in names
        assert "Bob's Project" not in names

    def test_cannot_access_other_users_project_detail(self, auth_client, make_user):
        client, user = auth_client
        other = make_user(username="carol", email="carol@example.com")
        project = Project.objects.create(owner=other, name="Carol's Project")

        resp = client.get(f"/api/projects/{project.id}/")
        assert resp.status_code in (403, 404)


def _make_zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


class TestZipUploadSecurity:
    def test_valid_zip_extracts_successfully(self, tmp_path):
        zip_bytes = _make_zip({"app.py": "print('hello')", "src/utils.py": "x = 1"})
        zip_path = tmp_path / "valid.zip"
        zip_path.write_bytes(zip_bytes)

        extracted_dir = extract_zip_safely(str(zip_path))
        try:
            assert os.path.exists(os.path.join(extracted_dir, "app.py"))
            assert os.path.exists(os.path.join(extracted_dir, "src", "utils.py"))
        finally:
            import shutil
            shutil.rmtree(extracted_dir, ignore_errors=True)

    def test_path_traversal_entry_rejected(self, tmp_path):
        zip_bytes = _make_zip({"../../etc/passwd": "malicious"})
        zip_path = tmp_path / "traversal.zip"
        zip_path.write_bytes(zip_bytes)

        with pytest.raises(UnsafeUploadError):
            extract_zip_safely(str(zip_path))

    def test_absolute_path_entry_rejected(self, tmp_path):
        zip_bytes = _make_zip({"/etc/passwd": "malicious"})
        zip_path = tmp_path / "absolute.zip"
        zip_path.write_bytes(zip_bytes)

        with pytest.raises(UnsafeUploadError):
            extract_zip_safely(str(zip_path))

    def test_bad_zip_file_rejected(self, tmp_path):
        zip_path = tmp_path / "notazip.zip"
        zip_path.write_bytes(b"this is not a zip file")

        with pytest.raises(UnsafeUploadError):
            extract_zip_safely(str(zip_path))

    def test_non_zip_extension_rejected(self):
        class FakeUpload:
            name = "malware.exe"
            size = 1000
            content_type = "application/octet-stream"

        with pytest.raises(UnsafeUploadError):
            validate_upload_metadata(FakeUpload())

    def test_oversized_file_rejected(self, settings):
        settings.MAX_UPLOAD_SIZE_MB = 1

        class FakeUpload:
            name = "big.zip"
            size = 5 * 1024 * 1024
            content_type = "application/zip"

        with pytest.raises(UnsafeUploadError):
            validate_upload_metadata(FakeUpload())


class TestEditorPathSafety:
    def test_resolve_safe_path_blocks_traversal(self, auth_client):
        from . import storage

        _, user = auth_client
        project = Project.objects.create(owner=user, name="Editor Safety Test")

        with pytest.raises(UnsafeUploadError):
            storage.resolve_safe_path(project, "../../../../etc/passwd")

    def test_resolve_safe_path_allows_nested_file(self, auth_client):
        from . import storage

        _, user = auth_client
        project = Project.objects.create(owner=user, name="Editor Safety Test 2")

        path = storage.resolve_safe_path(project, "src/app.py")
        assert str(storage.project_root(project)) in str(path)

    def test_write_file_replaces_empty_directory(self, auth_client, settings, tmp_path):
        from . import storage

        _, user = auth_client
        settings.SCAN_TEMP_DIR = tmp_path
        project = Project.objects.create(owner=user, name="Empty Dir File")
        storage.create_directory(project, "first.py")
        storage.write_file(project, "first.py", 'print("hi")')
        path = storage.project_root(project) / "first.py"
        assert path.is_file()
        assert path.read_text(encoding="utf-8") == 'print("hi")'

    def test_write_file_rejects_nonempty_directory(self, auth_client, settings, tmp_path):
        from . import storage

        _, user = auth_client
        settings.SCAN_TEMP_DIR = tmp_path
        project = Project.objects.create(owner=user, name="Nonempty Dir File")
        storage.create_directory(project, "src")
        storage.write_file(project, "src/a.py", "x = 1")
        with pytest.raises(UnsafeUploadError):
            storage.write_file(project, "src", "not a file")

    def test_scan_copy_leaves_original_tree_intact(self, auth_client, settings, tmp_path):
        from . import storage

        _, user = auth_client
        settings.SCAN_TEMP_DIR = tmp_path
        project = Project.objects.create(owner=user, name="Snapshot Safety")
        storage.write_file(project, "app.py", "print('keep me')")
        original = storage.project_root(project)
        snapshot = tmp_path / "snapshots" / "scan_copy"
        storage.copy_tree_for_scan(original, snapshot)
        assert (original / "app.py").read_text(encoding="utf-8") == "print('keep me')"
        assert (snapshot / "app.py").read_text(encoding="utf-8") == "print('keep me')"
        shutil.rmtree(snapshot)
        assert (original / "app.py").exists()


class TestProjectTeam:
    def test_invite_existing_user_adds_member(self, auth_client, make_user):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Shared App")
        from apps.projects.members import ensure_owner_membership
        ensure_owner_membership(project)
        teammate = make_user(username="dev1", email="dev1@example.com")
        resp = client.post(
            f"/api/projects/{project.id}/members/",
            {"email": teammate.email, "role": "developer"},
            format="json",
        )
        assert resp.status_code == 201
        assert resp.data["data"]["member"]["email"] == teammate.email

        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework.test import APIClient
        other = APIClient()
        token = RefreshToken.for_user(teammate)
        other.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
        listed = other.get("/api/projects/")
        names = [p["name"] for p in listed.data["data"]["results"]]
        assert "Shared App" in names

    def test_invite_unknown_email_returns_link(self, auth_client):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Invite Link App")
        from apps.projects.members import ensure_owner_membership
        ensure_owner_membership(project)
        resp = client.post(
            f"/api/projects/{project.id}/members/",
            {"email": "friend@example.com", "role": "developer"},
            format="json",
        )
        assert resp.status_code == 201
        body = resp.data["data"]
        assert body.get("accept_link")
        assert "friend@example.com" in body["invite"]["email"]

        from apps.projects.models import ProjectInvite
        invite = ProjectInvite.objects.get(project=project, email="friend@example.com")
        preview = client.get(f"/api/auth/invites/preview/?token={invite.token}")
        assert preview.status_code == 200
        assert preview.data["data"]["account_exists"] is False
        joined = client.post("/api/auth/invites/join/", {
            "token": invite.token,
            "username": "frienddev",
            "password": "StrongPass1!",
        }, format="json")
        assert joined.status_code == 201
        assert joined.data["data"]["access"]
        assert joined.data["data"]["role"] == "developer"

    def test_developer_cannot_invite(self, auth_client, make_user):
        client, owner = auth_client
        project = Project.objects.create(owner=owner, name="Locked App")
        from apps.projects.members import ensure_owner_membership
        from apps.projects.models import ProjectMembership
        ensure_owner_membership(project)
        dev = make_user(username="dev2", email="dev2@example.com")
        ProjectMembership.objects.create(project=project, user=dev, role="developer")
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework.test import APIClient
        other = APIClient()
        token = RefreshToken.for_user(dev)
        other.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
        resp = other.post(
            f"/api/projects/{project.id}/members/",
            {"email": "someone@example.com", "role": "analyst"},
            format="json",
        )
        assert resp.status_code == 403
