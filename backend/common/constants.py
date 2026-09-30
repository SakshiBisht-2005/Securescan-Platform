"""Shared enumerations and constants used across the platform."""


class Role:
    USER = "USER"
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"

    CHOICES = [
        (USER, "User"),
        (ADMIN, "Administrator"),
        (SECURITY_ANALYST, "Security Analyst"),
    ]


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
    CHOICES = [(s, s.title()) for s in ORDER]

    # Numeric weight used by the security-score formula (see scanner_engine/severity.py)
    WEIGHT = {CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0}


class Confidence:
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CHOICES = [(HIGH, "High"), (MEDIUM, "Medium"), (LOW, "Low")]


class FindingCategory:
    INJECTION = "injection"
    XSS = "xss"
    AUTH = "authentication"
    ACCESS_CONTROL = "access_control"
    CRYPTO = "cryptography"
    SECRETS = "secrets"
    DEPENDENCY = "vulnerable_dependency"
    CONFIGURATION = "insecure_configuration"
    IAC = "infrastructure_as_code"
    CONTAINER = "container_security"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    INFO_DISCLOSURE = "information_disclosure"
    OTHER = "other"

    CHOICES = [
        (INJECTION, "Injection"),
        (XSS, "Cross-Site Scripting"),
        (AUTH, "Authentication"),
        (ACCESS_CONTROL, "Access Control"),
        (CRYPTO, "Cryptography"),
        (SECRETS, "Secrets Exposure"),
        (DEPENDENCY, "Vulnerable Dependency"),
        (CONFIGURATION, "Insecure Configuration"),
        (IAC, "Infrastructure as Code"),
        (CONTAINER, "Container Security"),
        (DESERIALIZATION, "Insecure Deserialization"),
        (SSRF, "Server-Side Request Forgery"),
        (PATH_TRAVERSAL, "Path Traversal"),
        (INFO_DISCLOSURE, "Information Disclosure"),
        (OTHER, "Other"),
    ]


class FindingStatus:
    OPEN = "open"
    RESOLVED = "resolved"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"

    CHOICES = [
        (OPEN, "Open"),
        (RESOLVED, "Resolved"),
        (IGNORED, "Ignored"),
        (FALSE_POSITIVE, "False Positive"),
    ]


class ScanType:
    FULL = "full"
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"
    CONTAINER = "container"

    CHOICES = [
        (FULL, "Full Scan"),
        (SAST, "SAST Only"),
        (SCA, "SCA Only"),
        (SECRETS, "Secrets Only"),
        (IAC, "IaC Only"),
        (CONTAINER, "Container Only"),
    ]


class ScanStatus:
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    CHOICES = [
        (QUEUED, "Queued"),
        (PREPARING, "Preparing"),
        (RUNNING, "Running"),
        (COMPLETED, "Completed"),
        (FAILED, "Failed"),
        (CANCELLED, "Cancelled"),
    ]

    ACTIVE = {QUEUED, PREPARING, RUNNING}
    TERMINAL = {COMPLETED, FAILED, CANCELLED}


class ScanTrigger:
    UI = "ui"
    CI = "ci"
    WEBHOOK = "webhook"
    SCHEDULED = "scheduled"

    CHOICES = [
        (UI, "UI"),
        (CI, "CI"),
        (WEBHOOK, "Webhook"),
        (SCHEDULED, "Scheduled"),
    ]


class ProjectStatus:
    ACTIVE = "active"
    ARCHIVED = "archived"
    CHOICES = [(ACTIVE, "Active"), (ARCHIVED, "Archived")]


class ReportType:
    JSON = "json"
    PDF = "pdf"
    CHOICES = [(JSON, "JSON"), (PDF, "PDF")]
