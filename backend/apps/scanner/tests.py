from datetime import timedelta

import pytest

from apps.projects.models import Project

from .models import Scan

pytestmark = pytest.mark.django_db


class TestScanCreationApi:
    def test_start_scan_creates_queued_scan(self, auth_client, monkeypatch):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Scan API Test")

        # Prevent the actual Celery task from running during the test.
        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)

        resp = client.post(f"/api/projects/{project.id}/scan/", {
            "scan_type": "full", "enable_sast": True, "enable_sca": True,
            "enable_secrets": True, "enable_iac": True, "enable_container": True,
        }, format="json")
        assert resp.status_code == 202
        scan_id = resp.data["data"]["scan"]["id"]
        scan = Scan.objects.get(pk=scan_id)
        assert scan.project_id == project.id
        assert scan.status == "queued"
        assert scan.enabled_scanners["sast"] is True

    def test_cannot_start_second_scan_while_one_is_active(self, auth_client, monkeypatch):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Concurrent Scan Test")
        Scan.objects.create(project=project, status="running", triggered_by=user)

        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)
        resp = client.post(f"/api/projects/{project.id}/scan/", {}, format="json")
        assert resp.status_code == 409

    def test_queue_failure_marks_scan_failed_and_allows_retry(self, auth_client, monkeypatch):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Queue Failure Test")

        def boom(*a, **k):
            raise ConnectionError("Error 10061 connecting to localhost:6379")

        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", boom)
        resp = client.post(f"/api/projects/{project.id}/scan/", {
            "scan_type": "full", "enable_sast": True, "enable_sca": True,
            "enable_secrets": True, "enable_iac": True, "enable_container": True,
        }, format="json")
        assert resp.status_code == 503
        failed = Scan.objects.get(project=project)
        assert failed.status == "failed"
        assert failed.celery_task_id == ""

        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)
        retry = client.post(f"/api/projects/{project.id}/scan/", {
            "scan_type": "full", "enable_sast": True, "enable_sca": True,
            "enable_secrets": True, "enable_iac": True, "enable_container": True,
        }, format="json")
        assert retry.status_code == 202
        assert Scan.objects.filter(project=project, status="queued").count() == 1

    def test_orphaned_queued_scan_does_not_block_a_new_start(self, auth_client, monkeypatch):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Orphaned Scan Test")
        orphan = Scan.objects.create(project=project, status="queued", triggered_by=user)
        Scan.objects.filter(pk=orphan.pk).update(created_at=orphan.created_at - timedelta(minutes=5))

        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)
        resp = client.post(f"/api/projects/{project.id}/scan/", {
            "scan_type": "full", "enable_sast": True, "enable_sca": True,
            "enable_secrets": True, "enable_iac": True, "enable_container": True,
        }, format="json")
        assert resp.status_code == 202
        orphan.refresh_from_db()
        assert orphan.status == "failed"
        assert Scan.objects.filter(project=project, status="queued").count() == 1

    def test_stale_queued_scan_with_celery_id_does_not_block(self, auth_client, monkeypatch):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Stale Celery Scan")
        orphan = Scan.objects.create(project=project, status="queued", triggered_by=user, celery_task_id="abc")
        Scan.objects.filter(pk=orphan.pk).update(created_at=orphan.created_at - timedelta(minutes=5))

        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)
        resp = client.post(f"/api/projects/{project.id}/scan/", {
            "scan_type": "full", "enable_sast": True, "enable_sca": True,
            "enable_secrets": True, "enable_iac": True, "enable_container": True,
        }, format="json")
        assert resp.status_code == 202
        orphan.refresh_from_db()
        assert orphan.status == "failed"
        assert Scan.objects.filter(project=project, status="queued").count() == 1

    def test_invalid_scan_type_rejected(self, auth_client):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Invalid Scan Type Test")
        resp = client.post(f"/api/projects/{project.id}/scan/", {"scan_type": "not-a-real-type"}, format="json")
        assert resp.status_code == 400

    def test_cannot_scan_other_users_project(self, auth_client, make_user):
        client, user = auth_client
        other = make_user(username="erin", email="erin@example.com")
        other_project = Project.objects.create(owner=other, name="Erin Project")
        resp = client.post(f"/api/projects/{other_project.id}/scan/", {}, format="json")
        assert resp.status_code == 403

    def test_scan_status_endpoint(self, auth_client):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Status Endpoint Test")
        scan = Scan.objects.create(project=project, status="running", progress_percent=42,
                                    progress_stage="sast", triggered_by=user)
        resp = client.get(f"/api/scans/{scan.id}/status/")
        assert resp.status_code == 200
        assert resp.data["data"]["progress_percent"] == 42
        assert resp.data["data"]["progress_stage"] == "sast"


class TestCiAndScheduledScans:
    def test_rotate_ci_token_and_start_scan(self, auth_client, monkeypatch):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="CI Project")
        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)

        created = client.post(f"/api/projects/{project.id}/ci-token/", {}, format="json")
        assert created.status_code == 200
        token = created.data["data"]["token"]
        assert token.startswith("ssci_")

        client.credentials()
        denied = client.post(f"/api/ci/projects/{project.id}/scan/", {}, format="json")
        assert denied.status_code == 403

        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        started = client.post(
            f"/api/ci/projects/{project.id}/scan/",
            {"ref": "refs/heads/main", "sha": "abc123", "fail_on": "high"},
            format="json",
        )
        assert started.status_code == 202
        scan = Scan.objects.get(project=project)
        assert scan.trigger_source == "ci"
        assert scan.git_sha == "abc123"
        assert started.data["data"]["ok"] is False  # still queued

        status = client.get(f"/api/ci/projects/{project.id}/scans/{scan.id}/?fail_on=high")
        assert status.status_code == 200
        assert status.data["data"]["scan"]["id"] == scan.id

    def test_github_webhook_hmac_starts_scan(self, auth_client, monkeypatch):
        import hashlib
        import hmac
        import json

        client, user = auth_client
        project = Project.objects.create(owner=user, name="Webhook Project")
        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)
        created = client.post(f"/api/projects/{project.id}/ci-token/", {}, format="json")
        token = created.data["data"]["token"]
        body = json.dumps({"ref": "refs/heads/main", "after": "def456", "deleted": False}).encode()
        sig = "sha256=" + hmac.new(token.encode(), body, hashlib.sha256).hexdigest()
        client.credentials()
        resp = client.post(
            f"/api/webhooks/github/{project.id}/",
            data=body,
            content_type="application/json",
            HTTP_X_HUB_SIGNATURE_256=sig,
            HTTP_X_GITHUB_EVENT="push",
        )
        assert resp.status_code == 202
        scan = Scan.objects.get(project=project)
        assert scan.trigger_source == "webhook"
        assert scan.git_sha == "def456"
        assert scan.branch == "main"

    def test_weekly_task_queues_only_enabled_projects(self, user, make_user, monkeypatch):
        from apps.scanner.tasks import run_weekly_scheduled_scans

        enabled = Project.objects.create(owner=user, name="Weekly On", weekly_scan_enabled=True)
        Project.objects.create(owner=user, name="Weekly Off", weekly_scan_enabled=False)
        other = make_user(username="pat", email="pat@example.com")
        Project.objects.create(owner=other, name="Someone Else Off", weekly_scan_enabled=False)
        monkeypatch.setattr("apps.scanner.tasks.start_scan.delay", lambda *a, **k: None)
        result = run_weekly_scheduled_scans()
        assert result["queued"] == 1
        assert Scan.objects.filter(project=enabled, trigger_source="scheduled").count() == 1
        assert Scan.objects.filter(trigger_source="scheduled").count() == 1


class TestScanCompare:
    def test_vs_previous_classifies_new_still_open_resolved(self, auth_client):
        from apps.vulnerabilities.models import Finding
        from common.constants import FindingCategory, FindingStatus, ScanStatus, Severity

        client, user = auth_client
        project = Project.objects.create(owner=user, name="Compare App")
        older = Scan.objects.create(project=project, status=ScanStatus.COMPLETED, triggered_by=user, security_score=70)
        newer = Scan.objects.create(project=project, status=ScanStatus.COMPLETED, triggered_by=user, security_score=80)
        Finding.objects.create(
            scan=older, project=project, scanner="bandit", rule_id="B1", title="SQL",
            severity=Severity.HIGH, category=FindingCategory.INJECTION, fingerprint="aaa",
            status=FindingStatus.OPEN,
        )
        Finding.objects.create(
            scan=older, project=project, scanner="bandit", rule_id="B2", title="XSS",
            severity=Severity.MEDIUM, category=FindingCategory.XSS, fingerprint="bbb",
            status=FindingStatus.OPEN,
        )
        Finding.objects.create(
            scan=newer, project=project, scanner="bandit", rule_id="B2", title="XSS",
            severity=Severity.MEDIUM, category=FindingCategory.XSS, fingerprint="bbb",
            status=FindingStatus.OPEN,
        )
        Finding.objects.create(
            scan=newer, project=project, scanner="bandit", rule_id="B3", title="Path",
            severity=Severity.LOW, category=FindingCategory.PATH_TRAVERSAL, fingerprint="ccc",
            status=FindingStatus.OPEN,
        )
        resp = client.get(f"/api/scans/{newer.id}/vs-previous/")
        assert resp.status_code == 200
        data = resp.data["data"]
        assert data["previous"]["id"] == older.id
        assert data["new_count"] == 1
        assert data["still_open_count"] == 1
        assert data["resolved_count"] == 1
        assert data["new_findings"][0]["fingerprint"] == "ccc"
        assert data["still_open_findings"][0]["fingerprint"] == "bbb"
        assert data["resolved_findings"][0]["fingerprint"] == "aaa"
