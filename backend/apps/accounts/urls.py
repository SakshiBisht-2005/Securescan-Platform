from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from . import views
from .admin_views import AdminUserViewSet

router = DefaultRouter()
router.register(r"admin/users", AdminUserViewSet, basename="admin-user")

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="auth-register"),
    path("login/", views.LoginView.as_view(), name="auth-login"),
    path("logout/", views.LogoutView.as_view(), name="auth-logout"),
    path("token/refresh/", TokenRefreshView.as_view(), name="auth-token-refresh"),
    path("me/", views.MeView.as_view(), name="auth-me"),
    path("change-password/", views.ChangePasswordView.as_view(), name="auth-change-password"),
    path("password-reset/", views.PasswordResetRequestView.as_view(), name="auth-password-reset"),
    path("password-reset/confirm/", views.PasswordResetConfirmView.as_view(), name="auth-password-reset-confirm"),
    path("verify-email/", views.VerifyEmailView.as_view(), name="auth-verify-email"),
    path("verify-email/resend/", views.ResendVerificationView.as_view(), name="auth-verify-email-resend"),
    path("invites/", views.MyInvitesView.as_view(), name="auth-invites"),
    path("invites/preview/", views.InvitePreviewView.as_view(), name="auth-invites-preview"),
    path("invites/join/", views.JoinInviteView.as_view(), name="auth-invites-join"),
    path("invites/accept/", views.AcceptInviteView.as_view(), name="auth-invites-accept"),
] + router.urls
