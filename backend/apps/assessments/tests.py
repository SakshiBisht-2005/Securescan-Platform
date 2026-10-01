from django.test import SimpleTestCase

from apps.assessments.modes import MODE_MAP, MODES
from apps.assessments.analyzers import run_cloud, run_container, run_white_box


class AssessmentCatalogTests(SimpleTestCase):
    def test_eleven_modes(self):
        self.assertEqual(len(MODES), 11)
        self.assertIn("black_box", MODE_MAP)
        self.assertIn("code_security", MODE_MAP)

    def test_white_box_secret(self):
        data = run_white_box({"source": "api_key = 'supersecretvalue123'"}, False)
        self.assertTrue(any(f["severity"] == "high" for f in data["findings"]))

    def test_container_latest(self):
        data = run_container({"config_text": "FROM python:latest\nCMD python"}, False)
        ids = [f["id"] for f in data["findings"]]
        self.assertIn("latest-tag", ids)

    def test_cloud_principal(self):
        data = run_cloud({"config_text": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*"}]}'}, False)
        ids = [f["id"] for f in data["findings"]]
        self.assertTrue("principal-star" in ids or "action-star" in ids)
