"""The common finding schema every scanner adapter must produce, plus the
normalization helpers shared by adapters."""
from dataclasses import dataclass, field

from common.constants import Confidence, FindingCategory
from common.utilities import compute_fingerprint

from .severity import normalize_severity


@dataclass
class NormalizedFinding:
    scanner: str
    rule_id: str
    title: str
    severity: str
    confidence: str = Confidence.MEDIUM
    category: str = FindingCategory.OTHER
    file_path: str = ""
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    description: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    code_snippet: str = ""
    cwe: str = ""
    owasp_category: str = ""
    scanner_severity: str = ""

    def with_fingerprint(self) -> "NormalizedFinding":
        return self

    @property
    def fingerprint(self) -> str:
        # Deliberately excludes exact line number so that a finding which
        # shifts by a few lines between scans (due to unrelated edits
        # elsewhere in the file) is still recognized as "the same" issue
        # by the deduplicator/history comparison.
        return compute_fingerprint(self.scanner, self.rule_id, self.file_path, self.title)


def build_finding(scanner, rule_id, title, raw_severity, **kwargs) -> NormalizedFinding:
    severity = normalize_severity(raw_severity)
    return NormalizedFinding(
        scanner=scanner,
        rule_id=rule_id,
        title=title,
        severity=severity,
        scanner_severity=str(raw_severity or ""),
        **kwargs,
    )
