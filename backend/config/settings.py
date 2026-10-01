"""
Django settings for the Secure Code Scanning Platform.

All secrets and environment-specific values are read from environment
variables (see .env.example). Nothing sensitive is hard-coded here.
"""
import os
import sys
from datetime import timedelta
from pathlib import Path

from celery.schedules import crontab
from dotenv import dotenv_values, load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def env_list(name, default=""):
    val = os.environ.get(name, default)
    return [item.strip() for item in val.split(",") if item.strip()]


SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if env_bool("DEBUG", True):
        # Development-only fallback so `runserver` works out of the box.
        # Production MUST set SECRET_KEY via environment variable.
        SECRET_KEY = "dev-insecure-key-change-me-" + "x" * 40
    else:
        raise RuntimeError("SECRET_KEY environment variable is required in production.")

DEBUG = env_bool("DEBUG", False)

ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third-party
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "django_filters",
    "django_celery_results",
    "django_celery_beat",
    "drf_spectacular",
    # first-party
    "apps.accounts",
    "apps.projects",
    "apps.repositories",
    "apps.scanner",
    "apps.vulnerabilities",
    "apps.reports",
    "apps.notifications",
    "apps.dashboard",
    "apps.audit",
    "apps.network",
    "apps.assessments",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "common.middleware.AuditRequestMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("DATABASE_NAME", "securescan"),
        "USER": os.environ.get("DATABASE_USER", "root"),
        "PASSWORD": os.environ.get("DATABASE_PASSWORD", ""),
        "HOST": os.environ.get("DATABASE_HOST", "localhost"),
        "PORT": os.environ.get("DATABASE_PORT", "3306"),
        "OPTIONS": {
            "charset": "utf8mb4",
        },
        "CONN_MAX_AGE": 60,
    }
}

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "common.validators.PasswordComplexityValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# REST Framework / JWT
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": (
        "common.renderers.EnvelopeJSONRenderer",
    ),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "common.pagination.StandardResultsSetPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "EXCEPTION_HANDLER": "common.exceptions.custom_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.ScopedRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "auth": "10/min",
        "upload": "20/hour",
        "scan": "30/hour",
        "report": "60/hour",
        "network": "40/hour",
        "assessments": "30/hour",
    },
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=int(os.environ.get("JWT_ACCESS_TOKEN_LIFETIME_MINUTES", 30))),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=int(os.environ.get("JWT_REFRESH_TOKEN_LIFETIME_DAYS", 7))),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": os.environ.get("JWT_SIGNING_KEY") or SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Secure Code Scanning Platform API",
    "DESCRIPTION": "Defensive application-security scanning platform: SAST, SCA, secret detection, IaC and container config scanning.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

# ---------------------------------------------------------------------------
# CORS / CSRF / cookies
# ---------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080")
CORS_ALLOW_CREDENTIALS = True
CORS_EXPOSE_HEADERS = ["Content-Disposition"]

CSRF_TRUSTED_ORIGINS = CORS_ALLOWED_ORIGINS
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False  # DRF needs to read it via JS header on unsafe methods when using session auth

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
if not DEBUG:
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", True)
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "django-db")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 60 * 30
CELERY_TASK_SOFT_TIME_LIMIT = 60 * 25
CELERY_WORKER_MAX_TASKS_PER_CHILD = 50
CELERY_TIMEZONE = TIME_ZONE
CELERY_ENABLE_UTC = True
CELERY_BEAT_SCHEDULE = {
    "weekly-project-scans": {
        "task": "scanner.run_weekly_scheduled_scans",
        "schedule": crontab(hour=2, minute=0, day_of_week=0),
    },
}

# ---------------------------------------------------------------------------
# Application / scanner configuration
# ---------------------------------------------------------------------------
MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", 200))
SCAN_TEMP_DIR = BASE_DIR / os.environ.get("SCAN_TEMP_DIR", "scan_temp")
SCANNER_SUBPROCESS_TIMEOUT_SECONDS = int(os.environ.get("SCANNER_SUBPROCESS_TIMEOUT_SECONDS", 300))
GIT_IMPORT_TIMEOUT_SECONDS = int(os.environ.get("GIT_IMPORT_TIMEOUT_SECONDS", 120))

SCANNER_ENABLED = {
    "semgrep": env_bool("ENABLE_SEMGREP", True),
    "bandit": env_bool("ENABLE_BANDIT", True),
    "pip_audit": env_bool("ENABLE_PIP_AUDIT", True),
    "checkov": env_bool("ENABLE_CHECKOV", True),
    "gitleaks": env_bool("ENABLE_GITLEAKS", True),
    "trivy": env_bool("ENABLE_TRIVY", True),
}

DEFAULT_EXCLUDED_PATTERNS = [
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", "dist", "build", ".idea", ".vscode", "*.min.js", "*.map",
]

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
def _clean_env(value, default=""):
    if value is None:
        return default
    return str(value).strip().strip('"').strip("'")


def refresh_email_settings(target=None):
    """Read EMAIL_* from backend/.env even if the process still has empty values.

    python-dotenv does not override existing env vars, so filling Gmail
    credentials after `python start.py` used to leave SMTP disabled until a
    full restart. Password-reset/verification call this on every send.
    """
    if target is None:
        target = sys.modules[__name__]

    testing = "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ
    if testing and target is not sys.modules[__name__]:
        host = _clean_env(getattr(target, "EMAIL_HOST", ""))
        user = _clean_env(getattr(target, "EMAIL_HOST_USER", ""))
        password = _clean_env(getattr(target, "EMAIL_HOST_PASSWORD", "")).replace(" ", "")
        configured = bool(host and user and password)
        target.EMAIL_SMTP_CONFIGURED = configured
        return configured

    file_vals = dotenv_values(BASE_DIR / ".env") or {}

    def grab(name, default=""):
        if name in file_vals and file_vals[name] not in (None, ""):
            return _clean_env(file_vals[name], default)
        return _clean_env(os.environ.get(name), default)

    host = grab("EMAIL_HOST")
    user = grab("EMAIL_HOST_USER")
    # Gmail App Passwords are 16 characters; spaces are display-only.
    password = grab("EMAIL_HOST_PASSWORD").replace(" ", "")
    port = int(grab("EMAIL_PORT") or 587)
    timeout = int(grab("EMAIL_TIMEOUT") or 20)
    use_tls = (file_vals.get("EMAIL_USE_TLS") or os.environ.get("EMAIL_USE_TLS") or "true")
    use_ssl = (file_vals.get("EMAIL_USE_SSL") or os.environ.get("EMAIL_USE_SSL") or "false")
    use_tls = str(use_tls).strip().lower() in ("1", "true", "yes", "on")
    use_ssl = str(use_ssl).strip().lower() in ("1", "true", "yes", "on")
    if use_tls and use_ssl:
        use_ssl = False
    from_email = grab("DEFAULT_FROM_EMAIL") or user or "security-platform@example.com"
    configured = bool(host and user and password)

    target.EMAIL_HOST = host
    target.EMAIL_PORT = port
    target.EMAIL_HOST_USER = user
    target.EMAIL_HOST_PASSWORD = password
    target.EMAIL_USE_TLS = use_tls
    target.EMAIL_USE_SSL = use_ssl
    target.EMAIL_TIMEOUT = timeout
    target.DEFAULT_FROM_EMAIL = from_email
    target.EMAIL_SMTP_CONFIGURED = configured
    target.EMAIL_BACKEND = (
        "django.core.mail.backends.smtp.EmailBackend"
        if configured
        else "django.core.mail.backends.console.EmailBackend"
    )
    return configured


refresh_email_settings()

FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://127.0.0.1:5500")

# ---------------------------------------------------------------------------
# Logging - never leak tracebacks to clients; log server-side only.
# ---------------------------------------------------------------------------
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "application.log",
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
            "formatter": "verbose",
        },
        "security_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "security.log",
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 10,
            "formatter": "verbose",
        },
    },
    "root": {"handlers": ["console", "file"], "level": "INFO"},
    "loggers": {
        "django": {"handlers": ["console", "file"], "level": "INFO", "propagate": False},
        "security": {"handlers": ["console", "security_file"], "level": "INFO", "propagate": False},
        "scanner_engine": {"handlers": ["console", "file"], "level": "INFO", "propagate": False},
    },
}
