import json

import pytest

from apps.projects.models import Project
from apps.scanner.models import Scan
from apps.vulnerabilities.models import SecretFinding
from common.utilities import mask_secret

from .models import Report
from .services import build_report_payload, generate_report_for_scan

pytestmark = pytest.mark.django_db


@pytest.fixture
def completed_scan(user):
    project = Project.objects.create(owner=user, name="Report Test Project")
    return Scan.objects.create(
        project=project, status="completed", security_score=72,
        critical_count=1, high_count=2, total_files=10, triggered_by=user,
    )


class TestReportPayload:
    def test_payload_contains_required_sections(self, completed_scan):
        payload = build_report_payload(completed_scan)
        for key in [
            "executive_summary", "project_information", "scan_information", "security_score",
            "vulnerability_summary", "critical_findings", "high_findings", "medium_findings",
            "low_findings", "secret_findings", "dependency_findings", "iac_findings",
            "container_findings", "remediation_recommendations", "scanner_information", "scan_statistics",
        ]:
            assert key in payload

    def test_secrets_in_report_are_masked_not_raw(self, completed_scan):
        SecretFinding.objects.create(
            project=completed_scan.project, scan=completed_scan, secret_type="AWS Access Key",
            file_path="config.py", line_number=5, masked_value=mask_secret("AKIA1234567890ABCD1"),
            fingerprint="secret-fp-1",
        )
        payload = build_report_payload(completed_scan)
        assert len(payload["secret_findings"]) == 1
        masked = payload["secret_findings"][0]["masked_value"]
        assert "AKIA1234567890ABCD1" not in masked
        assert "*" in masked


class TestReportGeneration:
    def test_generate_json_report(self, completed_scan, user, tmp_path, settings):
        settings.MEDIA_ROOT = tmp_path
        report = generate_report_for_scan(completed_scan, "json", generated_by=user)
        assert report.status == "ready"
        assert report.report_type == "json"
        full_path = settings.MEDIA_ROOT / report.file_path
        assert full_path.exists()
        data = json.loads(full_path.read_text())
        assert data["executive_summary"]["security_score"] == 72

    def test_generate_pdf_report(self, completed_scan, user, tmp_path, settings):
        settings.MEDIA_ROOT = tmp_path
        report = generate_report_for_scan(completed_scan, "pdf", generated_by=user)
        assert report.status == "ready"
        full_path = settings.MEDIA_ROOT / report.file_path
        assert full_path.exists()
        assert full_path.read_bytes()[:4] == b"%PDF"

    def test_generate_pdf_escapes_special_characters(self, completed_scan, user, tmp_path, settings):
        from apps.vulnerabilities.models import Finding
        Finding.objects.create(
            project=completed_scan.project, scan=completed_scan, scanner="bandit",
            rule_id="B101", title="Use of assert <detected> & 'unsafe'",
            description="if x < 1 and y > 2: pass",
            severity="HIGH", category="security",
            file_path="app/<module>/main.py", remediation="Replace <assert> with an if-check.",
            fingerprint="special-char-fp",
        )
        settings.MEDIA_ROOT = tmp_path
        report = generate_report_for_scan(completed_scan, "pdf", generated_by=user)
        assert report.status == "ready"
        assert (settings.MEDIA_ROOT / report.file_path).read_bytes()[:4] == b"%PDF"

    def test_download_pdf_uses_pdf_filename(self, auth_client, completed_scan, tmp_path, settings):
        settings.MEDIA_ROOT = tmp_path
        client, user = auth_client
        completed_scan.project.owner = user
        completed_scan.project.save(update_fields=["owner"])
        report = generate_report_for_scan(completed_scan, "pdf", generated_by=user)
        resp = client.get(f"/api/reports/{report.id}/download/")
        assert resp.status_code == 200
        assert resp["Content-Type"].startswith("application/pdf")
        assert 'filename="security_report_' in resp["Content-Disposition"]
        assert resp["Content-Disposition"].endswith('.pdf"')
        body = b"".join(resp.streaming_content)
        assert body[:4] == b"%PDF"


class TestReportDownloadPermissions:
    def test_cannot_download_other_users_report(self, auth_client, make_user, tmp_path, settings):
        settings.MEDIA_ROOT = tmp_path
        client, user = auth_client
        other = make_user(username="frank", email="frank@example.com")
        project = Project.objects.create(owner=other, name="Frank Project")
        scan = Scan.objects.create(project=project, status="completed", triggered_by=other)
        report = generate_report_for_scan(scan, "json", generated_by=other)

        resp = client.get(f"/api/reports/{report.id}/download/")
        assert resp.status_code == 403
