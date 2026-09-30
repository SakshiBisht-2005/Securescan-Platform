import pytest
from django.urls import reverse

pytestmark = pytest.mark.django_db


class TestRegistration:
    def test_register_creates_user(self, api_client):
        resp = api_client.post("/api/auth/register/", {
            "username": "newuser", "email": "newuser@example.com",
            "password": "StrongPass1!", "password_confirm": "StrongPass1!",
        }, format="json")
        assert resp.status_code == 201
        assert resp.data["success"] is True
        assert resp.data["data"]["user"]["username"] == "newuser"

    def test_register_rejects_mismatched_passwords(self, api_client):
        resp = api_client.post("/api/auth/register/", {
            "username": "newuser2", "email": "newuser2@example.com",
            "password": "StrongPass1!", "password_confirm": "Different1!",
        }, format="json")
        assert resp.status_code == 400
        assert resp.data["success"] is False
        assert resp.data["error"]["code"] == "VALIDATION_ERROR"

    def test_register_rejects_weak_password(self, api_client):
        resp = api_client.post("/api/auth/register/", {
            "username": "newuser3", "email": "newuser3@example.com",
            "password": "weak", "password_confirm": "weak",
        }, format="json")
        assert resp.status_code == 400

    def test_register_skips_smtp_and_returns_debug_link(self, api_client, settings):
        settings.DEBUG = True
        settings.EMAIL_HOST = ""
        settings.EMAIL_HOST_USER = ""
        settings.EMAIL_HOST_PASSWORD = ""
        settings.EMAIL_SMTP_CONFIGURED = False
        resp = api_client.post("/api/auth/register/", {
            "username": "smtpnone", "email": "smtpnone@example.com",
            "password": "StrongPass1!", "password_confirm": "StrongPass1!",
        }, format="json")
        assert resp.status_code == 201
        assert resp.data["data"]["email_sent"] is False
        assert "verify-email.html?token=" in resp.data["data"]["dev_verify_link"]

    def test_register_sends_verification_when_smtp_configured(self, api_client, settings, mailoutbox):
        settings.DEBUG = True
        settings.EMAIL_HOST = "smtp.gmail.com"
        settings.EMAIL_HOST_USER = "platform@gmail.com"
        settings.EMAIL_HOST_PASSWORD = "app-password"
        settings.EMAIL_SMTP_CONFIGURED = True
        settings.DEFAULT_FROM_EMAIL = "platform@gmail.com"
        resp = api_client.post("/api/auth/register/", {
            "username": "smtpon", "email": "smtpon@example.com",
            "password": "StrongPass1!", "password_confirm": "StrongPass1!",
        }, format="json")
        assert resp.status_code == 201
        assert resp.data["data"]["email_sent"] is True
        assert "dev_verify_link" not in resp.data["data"]
        assert len(mailoutbox) == 1
        assert mailoutbox[0].to == ["smtpon@example.com"]
        assert "verify-email.html?token=" in mailoutbox[0].body

    def test_register_rejects_duplicate_email(self, api_client, user):
        resp = api_client.post("/api/auth/register/", {
            "username": "someoneelse", "email": user.email,
            "password": "StrongPass1!", "password_confirm": "StrongPass1!",
        }, format="json")
        assert resp.status_code == 400


class TestLogin:
    def test_login_success_returns_tokens(self, api_client, user):
        resp = api_client.post("/api/auth/login/", {"username": user.username, "password": "StrongPass1!"}, format="json")
        assert resp.status_code == 200
        assert "access" in resp.data["data"]
        assert "refresh" in resp.data["data"]

    def test_login_wrong_password_fails(self, api_client, user):
        resp = api_client.post("/api/auth/login/", {"username": user.username, "password": "wrong"}, format="json")
        assert resp.status_code == 401
        assert resp.data["success"] is False

    def test_login_disabled_account_fails(self, api_client, user):
        user.is_active = False
        user.save()
        resp = api_client.post("/api/auth/login/", {"username": user.username, "password": "StrongPass1!"}, format="json")
        assert resp.status_code == 401

    def test_me_requires_authentication(self, api_client):
        resp = api_client.get("/api/auth/me/")
        assert resp.status_code == 401

    def test_me_returns_current_user(self, auth_client):
        client, user = auth_client
        resp = client.get("/api/auth/me/")
        assert resp.status_code == 200
        assert resp.data["data"]["user"]["username"] == user.username


class TestAdminUserManagement:
    def test_non_admin_cannot_list_users(self, auth_client):
        client, _ = auth_client
        resp = client.get("/api/auth/admin/users/")
        assert resp.status_code == 403

    def test_admin_can_list_and_disable_users(self, admin_client, user):
        client, _ = admin_client
        resp = client.get("/api/auth/admin/users/")
        assert resp.status_code == 200

        resp = client.post(f"/api/auth/admin/users/{user.id}/disable/")
        assert resp.status_code == 200
        user.refresh_from_db()
        assert user.is_active is False


class TestPasswordReset:
    def test_reset_request_returns_dev_link_when_debug(self, api_client, user, settings):
        settings.DEBUG = True
        resp = api_client.post("/api/auth/password-reset/", {"email": user.email}, format="json")
        assert resp.status_code == 200
        link = resp.data["data"].get("dev_reset_link") or ""
        assert "reset-password.html?token=" in link

    def test_reset_request_hides_link_when_not_debug(self, api_client, user, settings):
        settings.DEBUG = False
        resp = api_client.post("/api/auth/password-reset/", {"email": user.email}, format="json")
        assert resp.status_code == 200
        assert "dev_reset_link" not in resp.data["data"]

    def test_unknown_email_does_not_include_link(self, api_client, settings):
        settings.DEBUG = True
        resp = api_client.post(
            "/api/auth/password-reset/", {"email": "nobody@example.com"}, format="json"
        )
        assert resp.status_code == 200
        assert not resp.data["data"].get("dev_reset_link")

    def test_can_confirm_reset_with_issued_token(self, api_client, user, settings):
        settings.DEBUG = True
        resp = api_client.post("/api/auth/password-reset/", {"email": user.email}, format="json")
        link = resp.data["data"]["dev_reset_link"]
        token = link.split("token=", 1)[1]
        confirm = api_client.post(
            "/api/auth/password-reset/confirm/",
            {"token": token, "new_password": "NewStrongPass1!"},
            format="json",
        )
        assert confirm.status_code == 200
        login = api_client.post(
            "/api/auth/login/",
            {"username": user.username, "password": "NewStrongPass1!"},
            format="json",
        )
        assert login.status_code == 200
