from django.urls import path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"reports", views.ReportViewSet, basename="report")

urlpatterns = [
    path("reports/<int:scan_id>/generate/", views.GenerateReportView.as_view(), name="report-generate"),
    path("reports/<int:pk>/download/", views.DownloadReportView.as_view(), name="report-download"),
] + router.urls
