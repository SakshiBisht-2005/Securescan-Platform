import pytest

from .models import AuditLog
from .services import log_action

pytestmark = pytest.mark.django_db


class TestAuditLogging:
    def test_log_action_creates_entry(self, user):
        log_action(user, "project_created", "Project", 1, metadata={"name": "Test"})
        assert AuditLog.objects.filter(user=user, action="project_created").exists()

    def test_sensitive_metadata_keys_are_scrubbed(self, user):
        log_action(user, "git_credential_added", "GitCredential", 1, metadata={"token": "super-secret-value", "label": "prod"})
        entry = AuditLog.objects.get(user=user, action="git_credential_added")
        assert "token" not in entry.metadata
        assert entry.metadata.get("label") == "prod"

    def test_long_file_path_object_id_is_stored(self, user):
        path = "ATTENDANCE PORTAL/Attendance system/Attendance system/.env"
        log_action(user, "file_saved", "ProjectFile", path, metadata={"project_id": 1})
        entry = AuditLog.objects.get(user=user, action="file_saved")
        assert entry.object_id == path

    def test_extremely_long_object_id_is_truncated(self, user):
        path = "a/" * 400
        log_action(user, "file_saved", "ProjectFile", path)
        entry = AuditLog.objects.get(user=user, action="file_saved")
        assert len(entry.object_id) == 512


class TestAuditLogApiPermissions:
    def test_regular_user_cannot_view_audit_log(self, auth_client):
        client, _ = auth_client
        resp = client.get("/api/audit-logs/")
        assert resp.status_code == 403

    def test_admin_can_view_audit_log(self, admin_client):
        client, _ = admin_client
        resp = client.get("/api/audit-logs/")
        assert resp.status_code == 200
