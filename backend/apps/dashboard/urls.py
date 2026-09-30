from django.urls import path

from . import views
from .admin_views import SystemHealthView

urlpatterns = [
    path("dashboard/summary/", views.DashboardSummaryView.as_view(), name="dashboard-summary"),
    path("dashboard/trend/", views.SecurityTrendView.as_view(), name="dashboard-trend"),
    path("projects/<int:project_id>/statistics/", views.ProjectStatisticsView.as_view(), name="project-statistics"),
    path("admin/system-health/", SystemHealthView.as_view(), name="admin-system-health"),
]
