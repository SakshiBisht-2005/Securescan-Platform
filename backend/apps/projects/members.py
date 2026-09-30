"""Invite teammates onto a project and resolve pending invites."""
import logging
import secrets
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from apps.accounts.services import _frontend_base_url, _html_message, _send_account_email
from apps.notifications.services import notify
from common.exceptions import ConflictAppError, PermissionDeniedAppError, ValidationAppError

from .models import ProjectInvite, ProjectMembership

logger = logging.getLogger(__name__)

INVITE_TTL_DAYS = 14
INVITABLE_ROLES = {
    ProjectMembership.ROLE_ADMIN,
    ProjectMembership.ROLE_ANALYST,
    ProjectMembership.ROLE_DEVELOPER,
}


def ensure_owner_membership(project):
    ProjectMembership.objects.get_or_create(
        project=project,
        user_id=project.owner_id,
        defaults={"role": ProjectMembership.ROLE_OWNER},
    )


def _token():
    return secrets.token_urlsafe(32)


@transaction.atomic
def invite_member(project, inviter, email: str, role: str, request=None):
    email = (email or "").strip().lower()
    if not email:
        raise ValidationAppError("Email is required.")
    if role not in INVITABLE_ROLES:
        raise ValidationAppError("Choose analyst, developer, or project admin.")
    if inviter.email and inviter.email.lower() == email:
        raise ConflictAppError("You are already on this project.")

    User = get_user_model()
    existing = User.objects.filter(email__iexact=email).first()
    if existing and existing.id == project.owner_id:
        raise ConflictAppError("That user already owns this project.")
    if existing and ProjectMembership.objects.filter(project=project, user=existing).exists():
        raise ConflictAppError("That user is already a member of this project.")

    if existing:
        membership = ProjectMembership.objects.create(
            project=project, user=existing, role=role, invited_by=inviter
        )
        notify(
            existing,
            "system",
            f"Added to {project.name}",
            f"{inviter.username} added you as {role} on {project.name}.",
            link=f"/project.html?id={project.id}",
        )
        return {"kind": "member", "membership": membership, "email_sent": False}

    ProjectInvite.objects.filter(project=project, email__iexact=email, accepted=False).delete()
    invite = ProjectInvite.objects.create(
        project=project,
        email=email,
        role=role,
        token=_token(),
        invited_by=inviter,
        expires_at=timezone.now() + timedelta(days=INVITE_TTL_DAYS),
    )
    base = _frontend_base_url(request)
    link = f"{base}/accept-invite.html?token={invite.token}"
    intro = (
        f"{inviter.username} invited you to the SecureScan project “{project.name}” "
        f"as {role}. Open the link, choose a password, and you will be signed in on that project."
    )
    email_sent = _send_account_email(
        f"You were invited to {project.name} on SecureScan",
        f"{intro}\n\n{link}",
        email,
        html_message=_html_message("Open invite and set your login", intro, link, "Join and sign in"),
    )
    return {"kind": "invite", "invite": invite, "email_sent": email_sent, "accept_link": link}


def accept_invite(user, token: str):
    invite = ProjectInvite.objects.select_related("project").filter(token=token, accepted=False).first()
    if not invite:
        raise ValidationAppError("Invite is invalid or already used.")
    if invite.expires_at and invite.expires_at < timezone.now():
        raise ValidationAppError("This invite has expired.")
    if user.email.lower() != invite.email.lower():
        raise PermissionDeniedAppError("Sign in with the invited email address to join this project.")
    if ProjectMembership.objects.filter(project=invite.project, user=user).exists():
        invite.accepted = True
        invite.save(update_fields=["accepted"])
        return invite
    ProjectMembership.objects.create(
        project=invite.project, user=user, role=invite.role, invited_by=invite.invited_by
    )
    invite.accepted = True
    invite.save(update_fields=["accepted"])
    notify(
        user,
        "system",
        f"Joined {invite.project.name}",
        f"You joined as {invite.role}.",
        link=f"/project.html?id={invite.project_id}",
    )
    return invite


def invite_preview(token: str):
    invite = ProjectInvite.objects.select_related("project", "invited_by").filter(token=token, accepted=False).first()
    if not invite:
        raise ValidationAppError("Invite is invalid or already used.")
    if invite.expires_at and invite.expires_at < timezone.now():
        raise ValidationAppError("This invite has expired.")
    User = get_user_model()
    return {
        "project_name": invite.project.name,
        "email": invite.email,
        "role": invite.role,
        "invited_by": invite.invited_by.username if invite.invited_by_id else "",
        "account_exists": User.objects.filter(email__iexact=invite.email).exists(),
        "expires_at": invite.expires_at.isoformat(),
    }


def _unique_username(email: str, requested: str = ""):
    User = get_user_model()
    raw = (requested or email.split("@")[0] or "user").strip()
    base = "".join(ch for ch in raw if ch.isalnum() or ch in "._-")[:24] or "user"
    candidate = base
    n = 1
    while User.objects.filter(username__iexact=candidate).exists():
        n += 1
        candidate = f"{base}{n}"
    return candidate


@transaction.atomic
def join_from_invite(token: str, password: str, username: str = "", first_name: str = "", last_name: str = ""):
    """Create the invited user's login from the email link and attach them to the project."""
    from django.contrib.auth.password_validation import validate_password

    invite = ProjectInvite.objects.select_related("project").filter(token=token, accepted=False).first()
    if not invite:
        raise ValidationAppError("Invite is invalid or already used.")
    if invite.expires_at and invite.expires_at < timezone.now():
        raise ValidationAppError("This invite has expired.")

    User = get_user_model()
    if User.objects.filter(email__iexact=invite.email).exists():
        raise ConflictAppError("An account already uses this email. Log in with that password, then open the invite link again.")

    if not password:
        raise ValidationAppError("Choose a password so you can sign in.")
    try:
        validate_password(password)
    except Exception as exc:
        from django.core.exceptions import ValidationError as DjangoValidationError
        if isinstance(exc, DjangoValidationError):
            raise ValidationAppError(exc.messages[0] if exc.messages else "Choose a stronger password.") from exc
        raise

    user = User(
        username=_unique_username(invite.email, username),
        email=invite.email,
        first_name=(first_name or "").strip(),
        last_name=(last_name or "").strip(),
        is_active=True,
        is_email_verified=True,
    )
    user.set_password(password)
    user.save()
    return accept_invite(user, token), user


def accept_pending_for_user(user):
    if not user.email:
        return 0
    now = timezone.now()
    invites = ProjectInvite.objects.filter(
        email__iexact=user.email, accepted=False, expires_at__gte=now
    )
    count = 0
    for invite in invites:
        try:
            accept_invite(user, invite.token)
            count += 1
        except Exception:
            logger.exception("Could not auto-accept invite %s", invite.id)
    return count


def change_member_role(project, actor, membership, role: str):
    if membership.user_id == project.owner_id or membership.role == ProjectMembership.ROLE_OWNER:
        raise PermissionDeniedAppError("The project owner’s role cannot be changed here.")
    if role not in INVITABLE_ROLES:
        raise ValidationAppError("Choose analyst, developer, or project admin.")
    if membership.user_id == actor.id and role != membership.role:
        raise PermissionDeniedAppError("You cannot change your own role.")
    membership.role = role
    membership.save(update_fields=["role"])
    return membership


def remove_member(project, actor, membership):
    if membership.user_id == project.owner_id or membership.role == ProjectMembership.ROLE_OWNER:
        raise PermissionDeniedAppError("The project owner cannot be removed.")
    if membership.user_id == actor.id:
        membership.delete()
        return
    membership.delete()
