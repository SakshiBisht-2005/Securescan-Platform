"""Severity normalization and the security-score formula.

Scoring formula (documented, replaceable):

    score = 100 - penalty, clamped to [0, 100]

    penalty = min(100,
        critical * 12 + high * 6 + medium * 2.5 + low * 0.5
        + secrets * 8
        + vulnerable_dependencies_by_severity_weight
        + iac_or_container_misconfigs * 3
    )

Rationale: critical findings and exposed secrets should be able to drive
the score to near-zero on their own (a handful of criticals or secrets is
enough to saturate the penalty), while low/info findings have a small but
non-zero effect so that "clean but many low-severity notes" projects are
still distinguishable from truly clean ones. The algorithm lives in one
function (`calculate_security_score`) specifically so it can be swapped
out later without touching call sites.
"""
from common.constants import Severity

_SEVERITY_ALIASES = {
    "CRITICAL": Severity.CRITICAL, "SEVERE": Severity.CRITICAL, "BLOCKER": Severity.CRITICAL,
    "HIGH": Severity.HIGH, "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "MODERATE": Severity.MEDIUM, "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW, "MINOR": Severity.LOW, "NOTE": Severity.LOW,
    "INFO": Severity.INFO, "INFORMATIONAL": Severity.INFO, "UNKNOWN": Severity.INFO,
}


def normalize_severity(raw_severity: str) -> str:
    """Map a scanner-specific severity string onto the platform's 5-level
    scale. Unknown values default to INFO rather than silently dropping
    the finding or over/under-stating its risk. Serious findings are
    never auto-downgraded when a scanner already reports CRITICAL/HIGH."""
    if not raw_severity:
        return Severity.INFO
    key = str(raw_severity).strip().upper()
    return _SEVERITY_ALIASES.get(key, Severity.INFO if key not in Severity.ORDER else key)


def calculate_security_score(
    critical=0, high=0, medium=0, low=0, info=0,
    secrets=0, dependency_critical=0, dependency_high=0,
    dependency_medium=0, dependency_low=0, config_issues=0,
) -> int:
    penalty = (
        critical * 12
        + high * 6
        + medium * 2.5
        + low * 0.5
        + secrets * 8
        + dependency_critical * 10
        + dependency_high * 5
        + dependency_medium * 2
        + dependency_low * 0.5
        + config_issues * 3
    )
    penalty = min(penalty, 100)
    score = round(100 - penalty)
    return max(0, min(100, score))
