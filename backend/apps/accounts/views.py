from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit.services import log_action

from . import services
from .models import User
from .serializers import (
    ChangePasswordSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfileUpdateSerializer,
    RegisterSerializer,
    UserPublicSerializer,
)


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        from apps.projects.members import accept_pending_for_user
        accept_pending_for_user(user)
        _token, verify_link, email_sent = services.issue_email_verification_token(user, request)
        log_action(user, "register", "User", user.id, request)
        payload = {"user": UserPublicSerializer(user).data, "email_sent": email_sent}
        if settings.DEBUG and not email_sent:
            payload["dev_verify_link"] = verify_link
        return ok(payload, status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        username_or_email = request.data.get("username", "")
        password = request.data.get("password", "")

        user_obj = User.objects.filter(email__iexact=username_or_email).first()
        username = user_obj.username if user_obj else username_or_email

        user = authenticate(request, username=username, password=password)
        if user is None or not user.is_active:
            log_action(None, "login_failed", "User", "", request, {"attempted_username": username_or_email})
            return Response(
                {"success": False, "error": {"code": "AUTHENTICATION_FAILED", "message": "Invalid credentials.", "details": {}}},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        log_action(user, "login", "User", user.id, request)
        return ok(_login_payload(user))


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if refresh_token:
            try:
                RefreshToken(refresh_token).blacklist()
            except TokenError:
                pass
        log_action(request.user, "logout", "User", request.user.id, request)
        return ok({"message": "Logged out."})


class MeView(APIView):
    def get(self, request):
        return ok({"user": UserPublicSerializer(request.user).data})

    def patch(self, request):
        serializer = ProfileUpdateSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        log_action(request.user, "profile_updated", "User", request.user.id, request)
        return ok({"user": UserPublicSerializer(request.user).data})


class ChangePasswordView(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save(update_fields=["password"])
        log_action(request.user, "password_changed", "User", request.user.id, request)
        return ok({"message": "Password updated successfully."})


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(email__iexact=serializer.validated_data["email"]).first()
        payload = {"message": "If an account with that email exists, a reset link has been sent."}
        if user:
            _token, reset_link, email_sent = services.issue_password_reset_token(user, request)
            payload["email_sent"] = email_sent
            if settings.DEBUG and not email_sent:
                payload["dev_reset_link"] = reset_link
        return ok(payload)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        success = services.consume_password_reset_token(
            serializer.validated_data["token"], serializer.validated_data["new_password"]
        )
        if not success:
            return Response(
                {"success": False, "error": {"code": "INVALID_TOKEN", "message": "Reset link is invalid or expired.", "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return ok({"message": "Password has been reset. You can now log in."})


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("token", "")
        success = services.verify_email_token(token)
        if not success:
            return Response(
                {"success": False, "error": {"code": "INVALID_TOKEN", "message": "Verification link is invalid or expired.", "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return ok({"message": "Email verified successfully."})


class ResendVerificationView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = {
            "message": "If an account with that email exists and is unverified, a verification email has been sent.",
        }
        user = User.objects.filter(email__iexact=serializer.validated_data["email"]).first()
        if user and not user.is_email_verified:
            _token, verify_link, email_sent = services.issue_email_verification_token(user, request)
            payload["email_sent"] = email_sent
            if settings.DEBUG and not email_sent:
                payload["dev_verify_link"] = verify_link
        return ok(payload)


def _login_payload(user):
    refresh = RefreshToken.for_user(user)
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
        "user": UserPublicSerializer(user).data,
    }


class InvitePreviewView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def get(self, request):
        from apps.projects.members import invite_preview
        from common.exceptions import ValidationAppError

        token = (request.query_params.get("token") or "").strip()
        if not token:
            raise ValidationAppError("token is required.")
        return ok(invite_preview(token))


class JoinInviteView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        from apps.projects.members import join_from_invite
        from common.exceptions import ValidationAppError

        token = (request.data.get("token") or "").strip()
        if not token:
            raise ValidationAppError("token is required.")
        invite, user = join_from_invite(
            token,
            request.data.get("password") or "",
            username=request.data.get("username") or "",
            first_name=request.data.get("first_name") or "",
            last_name=request.data.get("last_name") or "",
        )
        log_action(user, "register", "User", user.id, request)
        log_action(user, "invite_joined", "Project", invite.project_id, request, {"role": invite.role})
        payload = _login_payload(user)
        payload["project_id"] = invite.project_id
        payload["role"] = invite.role
        return ok(payload, status.HTTP_201_CREATED)


class MyInvitesView(APIView):
    def get(self, request):
        from django.utils import timezone
        from apps.projects.models import ProjectInvite
        from apps.projects.serializers import ProjectInviteSerializer

        qs = ProjectInvite.objects.filter(
            email__iexact=request.user.email, accepted=False, expires_at__gte=timezone.now()
        ).select_related("project", "invited_by")
        rows = []
        for invite in qs:
            row = ProjectInviteSerializer(invite).data
            row["token"] = invite.token
            rows.append(row)
        return ok({"invites": rows})


class AcceptInviteView(APIView):
    def post(self, request):
        from apps.projects.members import accept_invite

        token = (request.data.get("token") or "").strip()
        if not token:
            from common.exceptions import ValidationAppError
            raise ValidationAppError("token is required.")
        invite = accept_invite(request.user, token)
        return ok({"project_id": invite.project_id, "role": invite.role})
