"""Business logic for account lifecycle: email verification and password
reset tokens. Kept out of views so views stay thin and testable."""
import logging
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .models import EmailVerificationToken, PasswordResetToken

logger = logging.getLogger(__name__)

TOKEN_TTL_HOURS = 24


def _generate_token():
    return secrets.token_urlsafe(48)


def _frontend_base_url(request=None) -> str:
    """Prefer the browser Origin so local reset links hit the running frontend."""
    if request is not None:
        origin = request.META.get("HTTP_ORIGIN") or ""
        if origin:
            return origin.rstrip("/")
        referer = request.META.get("HTTP_REFERER") or ""
        if referer:
            parsed = urlparse(referer)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
    return (settings.FRONTEND_BASE_URL or "http://127.0.0.1:5500").rstrip("/")


def smtp_configured() -> bool:
    from config.settings import refresh_email_settings

    refresh_email_settings(settings)
    return bool(
        getattr(settings, "EMAIL_SMTP_CONFIGURED", False)
        or (
            getattr(settings, "EMAIL_HOST", "")
            and getattr(settings, "EMAIL_HOST_USER", "")
            and getattr(settings, "EMAIL_HOST_PASSWORD", "")
        )
    )


def _html_message(title: str, intro: str, link: str, button: str) -> str:
    safe_link = link.replace("&", "&amp;")
    return (
        f"<p>{intro}</p>"
        f'<p><a href="{safe_link}">{button}</a></p>'
        f"<p>If the button does not work, paste this URL into your browser:<br>{safe_link}</p>"
        f"<p>SecureScan — {title}</p>"
    )


def _send_account_email(subject: str, message: str, recipient: str, html_message: str | None = None) -> bool:
    """Send via SMTP when configured. Returns True only if the provider accepted the message."""
    if not smtp_configured():
        logger.warning(
            "SMTP is not configured (set EMAIL_HOST, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD). "
            "Did not send '%s' to %s.",
            subject,
            recipient,
        )
        if settings.DEBUG:
            logger.info("Dev email body for %s:\n%s", recipient, message)
        return False
    try:
        sent = send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            fail_silently=False,
            html_message=html_message,
        )
        logger.info(
            "SMTP send of '%s' accepted for %s via %s",
            subject,
            recipient,
            getattr(settings, "EMAIL_HOST", ""),
        )
        return sent > 0
    except Exception:
        logger.exception("Failed to send email '%s' to %s", subject, recipient)
        if settings.DEBUG:
            logger.info("Dev email body for %s:\n%s", recipient, message)
        return False


def issue_email_verification_token(user, request=None):
    token = _generate_token()
    EmailVerificationToken.objects.create(
        user=user, token=token, expires_at=timezone.now() + timedelta(hours=TOKEN_TTL_HOURS)
    )
    link = f"{_frontend_base_url(request)}/verify-email.html?token={token}"
    plain = (
        f"Click to verify your SecureScan email address:\n{link}\n\n"
        f"This link expires in {TOKEN_TTL_HOURS} hours. If you did not create an account, ignore this email."
    )
    sent = _send_account_email(
        "Verify your SecureScan account",
        plain,
        user.email,
        html_message=_html_message(
            "email verification",
            "Welcome to SecureScan. Confirm your email address to finish creating your account.",
            link,
            "Verify email",
        ),
    )
    return token, link, sent


def verify_email_token(token: str) -> bool:
    try:
        record = EmailVerificationToken.objects.select_related("user").get(token=token, used=False)
    except EmailVerificationToken.DoesNotExist:
        return False
    if record.expires_at < timezone.now():
        return False
    record.used = True
    record.save(update_fields=["used"])
    record.user.is_email_verified = True
    record.user.save(update_fields=["is_email_verified"])
    return True


def issue_password_reset_token(user, request=None):
    token = _generate_token()
    PasswordResetToken.objects.create(
        user=user, token=token, expires_at=timezone.now() + timedelta(hours=2)
    )
    link = f"{_frontend_base_url(request)}/reset-password.html?token={token}"
    plain = (
        f"Click to reset your SecureScan password:\n{link}\n\n"
        "This link expires in 2 hours. If you did not request this, you can ignore this email."
    )
    sent = _send_account_email(
        "Reset your SecureScan password",
        plain,
        user.email,
        html_message=_html_message(
            "password reset",
            "We received a request to reset your SecureScan password.",
            link,
            "Reset password",
        ),
    )
    return token, link, sent


def consume_password_reset_token(token: str, new_password: str) -> bool:
    try:
        record = PasswordResetToken.objects.select_related("user").get(token=token, used=False)
    except PasswordResetToken.DoesNotExist:
        return False
    if record.expires_at < timezone.now():
        return False
    record.used = True
    record.save(update_fields=["used"])
    user = record.user
    user.set_password(new_password)
    user.save(update_fields=["password"])
    return True
