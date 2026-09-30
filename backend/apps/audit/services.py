"""Central helper for writing audit log entries. Never pass credentials,
tokens, or secret values into `metadata`."""
from .models import AuditLog

_SENSITIVE_KEYS = {"password", "token", "secret", "credential", "authorization", "key"}


def _scrub(metadata: dict) -> dict:
    clean = {}
    for k, v in (metadata or {}).items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            continue
        clean[k] = v
    return clean


def log_action(user, action, object_type="", object_id="", request=None, metadata=None):
    ip = getattr(request, "client_ip", None) if request else None
    max_len = AuditLog._meta.get_field("object_id").max_length
    object_id_value = str(object_id) if object_id else ""
    AuditLog.objects.create(
        user=user if user and getattr(user, "is_authenticated", False) else None,
        action=action,
        object_type=object_type,
        object_id=object_id_value[:max_len],
        ip_address=ip,
        metadata=_scrub(metadata or {}),
    )
