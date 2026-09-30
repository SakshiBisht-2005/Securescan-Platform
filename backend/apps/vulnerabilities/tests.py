import pytest

from apps.projects.models import Project
from apps.scanner.models import Scan
from common.constants import Severity
from scanner_engine.normalizer import build_finding

from .models import Finding
from .services import compute_and_apply_scan_statistics, save_findings

pytestmark = pytest.mark.django_db


@pytest.fixture
def scan(user):
    project = Project.objects.create(owner=user, name="Scan Test Project")
    return Scan.objects.create(project=project, triggered_by=user)


class TestFindingPersistence:
    def test_save_findings_creates_rows_and_returns_counts(self, scan):
        normalized = [
            build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py", line_start=10),
            build_finding("bandit", "B105", "Hardcoded Password", "CRITICAL", file_path="config.py", line_start=3),
        ]
        counts = save_findings(scan, normalized)
        assert Finding.objects.filter(scan=scan).count() == 2
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.CRITICAL] == 1

    def test_compute_statistics_sets_scan_aggregates_and_score(self, scan):
        normalized = [build_finding("bandit", "B608", "SQL Injection", "CRITICAL", file_path="app.py")]
        save_findings(scan, normalized)
        score = compute_and_apply_scan_statistics(scan)
        scan.refresh_from_db()
        assert scan.critical_count == 1
        assert scan.total_findings == 1
        assert scan.security_score == score
        assert score < 100


class TestFindingStatusApi:
    def test_update_finding_status(self, auth_client):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Status Test")
        scan = Scan.objects.create(project=project, triggered_by=user)
        finding = Finding.objects.create(
            scan=scan, project=project, scanner="bandit", rule_id="B608", title="SQLi",
            severity=Severity.HIGH, file_path="app.py", fingerprint="abc123",
        )
        resp = client.patch(f"/api/findings/{finding.id}/status/", {"status": "resolved"}, format="json")
        assert resp.status_code == 200
        finding.refresh_from_db()
        assert finding.status == "resolved"
        assert finding.status_changed_by_id == user.id

    def test_invalid_status_rejected(self, auth_client):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Status Test 2")
        scan = Scan.objects.create(project=project, triggered_by=user)
        finding = Finding.objects.create(
            scan=scan, project=project, scanner="bandit", rule_id="B608", title="SQLi",
            severity=Severity.HIGH, file_path="app.py", fingerprint="abc456",
        )
        resp = client.patch(f"/api/findings/{finding.id}/status/", {"status": "not-a-real-status"}, format="json")
        assert resp.status_code == 400

    def test_users_cannot_see_other_users_findings(self, auth_client, make_user):
        client, user = auth_client
        other = make_user(username="dave", email="dave@example.com")
        other_project = Project.objects.create(owner=other, name="Dave Project")
        other_scan = Scan.objects.create(project=other_project, triggered_by=other)
        Finding.objects.create(
            scan=other_scan, project=other_project, scanner="bandit", rule_id="B1", title="X",
            severity=Severity.LOW, fingerprint="zzz",
        )
        resp = client.get("/api/findings/")
        assert resp.status_code == 200
        assert resp.data["data"]["count"] == 0


class TestFindingsAreScopedToScan:
    def _secret(self, project, scan, path):
        from .models import SecretFinding
        return SecretFinding.objects.create(
            project=project, scan=scan, secret_type="Hardcoded Password Assignment",
            file_path=path, line_number=1, masked_value="p***", fingerprint=path,
            severity=Severity.MEDIUM,
        )

    def test_secret_list_filters_by_scan(self, auth_client):
        client, user = auth_client
        project_a = Project.objects.create(owner=user, name="Folder A")
        project_b = Project.objects.create(owner=user, name="Folder B")
        scan_a = Scan.objects.create(project=project_a, triggered_by=user, status="completed")
        scan_b = Scan.objects.create(project=project_b, triggered_by=user, status="completed")
        self._secret(project_a, scan_a, "a/README.md")
        self._secret(project_b, scan_b, "b/app.py")

        resp = client.get(f"/api/secret-findings/?scan={scan_b.id}")
        assert resp.status_code == 200
        paths = [row["file_path"] for row in resp.data["data"]["results"]]
        assert paths == ["b/app.py"]

    def test_secret_list_without_scan_uses_latest_completed_per_project(self, auth_client):
        client, user = auth_client
        project = Project.objects.create(owner=user, name="Rescan Project")
        old_scan = Scan.objects.create(project=project, triggered_by=user, status="completed")
        new_scan = Scan.objects.create(project=project, triggered_by=user, status="completed")
        self._secret(project, old_scan, "old/secret.md")
        self._secret(project, new_scan, "new/secret.md")

        resp = client.get("/api/secret-findings/")
        assert resp.status_code == 200
        paths = [row["file_path"] for row in resp.data["data"]["results"]]
        assert paths == ["new/secret.md"]
