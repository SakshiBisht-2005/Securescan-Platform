from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.HealthView.as_view(), name="health"),
    path("assessments/modes/", views.AssessmentCatalogView.as_view(), name="assessment-modes"),
    path("assessments/run/", views.AssessmentRunView.as_view(), name="assessment-run"),
]
