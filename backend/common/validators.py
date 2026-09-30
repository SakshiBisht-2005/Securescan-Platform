import re

from django.core.exceptions import ValidationError


class PasswordComplexityValidator:
    """Requires at least one uppercase, one lowercase, one digit, and one
    special character, in addition to Django's built-in validators."""

    def validate(self, password, user=None):
        errors = []
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[^A-Za-z0-9]", password):
            errors.append("Password must contain at least one special character.")
        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return "Your password must include an uppercase letter, a lowercase letter, a digit, and a special character."
