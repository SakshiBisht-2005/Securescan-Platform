from django.urls import path

from . import views

urlpatterns = [
    path("git-credentials/", views.GitCredentialListCreateView.as_view(), name="git-credentials"),
    path("git-credentials/<int:pk>/", views.GitCredentialDeleteView.as_view(), name="git-credential-detail"),
    path("projects/<int:project_id>/repository/", views.RepositoryImportView.as_view(), name="project-repository-import"),
    path("projects/<int:project_id>/repository/history/", views.RepositoryImportHistoryView.as_view(), name="project-repository-history"),
]
