"""Deduplicates normalized findings, both within a single scan run (e.g.
two scanners flagging the same secret) and across scan history (used by
scan-comparison to classify new/resolved/unchanged findings)."""


def deduplicate_findings(findings: list) -> list:
    seen = {}
    for finding in findings:
        key = finding.fingerprint
        existing = seen.get(key)
        if existing is None:
            seen[key] = finding
            continue
        # Keep whichever instance has higher confidence / more detail.
        if _rank(finding) > _rank(existing):
            seen[key] = finding
    return list(seen.values())


def _rank(finding) -> tuple:
    confidence_rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(finding.confidence, 0)
    has_snippet = 1 if finding.code_snippet else 0
    has_remediation = 1 if finding.remediation else 0
    return (confidence_rank, has_snippet, has_remediation)


def diff_findings(previous_fingerprints: set, current_fingerprints: set):
    new = current_fingerprints - previous_fingerprints
    resolved = previous_fingerprints - current_fingerprints
    unchanged = previous_fingerprints & current_fingerprints
    return {"new": new, "resolved": resolved, "unchanged": unchanged}
