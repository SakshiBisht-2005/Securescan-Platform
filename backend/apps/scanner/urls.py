from django.urls import path
from rest_framework.routers import DefaultRouter

from . import ci_views, views

router = DefaultRouter()
router.register(r"scans", views.ScanViewSet, basename="scan")

urlpatterns = [
    path("projects/<int:project_id>/scan/", views.StartScanView.as_view(), name="project-start-scan"),
    path("projects/<int:project_id>/ci-token/", ci_views.ProjectCiTokenView.as_view(), name="project-ci-token"),
    path("ci/projects/<int:project_id>/scan/", ci_views.CiStartScanView.as_view(), name="ci-start-scan"),
    path(
        "ci/projects/<int:project_id>/scans/<int:scan_id>/",
        ci_views.CiScanStatusView.as_view(),
        name="ci-scan-status",
    ),
    path(
        "webhooks/github/<int:project_id>/",
        ci_views.GitHubWebhookView.as_view(),
        name="github-webhook",
    ),
] + router.urls
