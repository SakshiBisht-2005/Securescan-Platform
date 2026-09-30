"""Persistence layer that takes normalized scanner-engine output and
writes it into the database, computing aggregate scan statistics and the
security score along the way."""
from common.constants import Severity
from common.utilities import mask_secret
from scanner_engine.severity import calculate_security_score

from .models import Dependency, Finding, SecretFinding


def save_findings(scan, normalized_findings) -> dict:
    """normalized_findings: list[NormalizedFinding] (SAST + IaC + Container).
    Returns severity counts."""
    counts = {s: 0 for s in Severity.ORDER}
    objs = []
    for nf in normalized_findings:
        counts[nf.severity] += 1
        objs.append(Finding(
            scan=scan,
            project=scan.project,
            scanner=nf.scanner,
            rule_id=nf.rule_id,
            title=nf.title,
            description=nf.description,
            severity=nf.severity,
            scanner_severity=nf.scanner_severity,
            confidence=nf.confidence,
            category=nf.category,
            cwe=nf.cwe,
            owasp_category=nf.owasp_category,
            file_path=nf.file_path,
            line_start=nf.line_start,
            line_end=nf.line_end,
            column_start=nf.column_start,
            column_end=nf.column_end,
            code_snippet=nf.code_snippet,
            remediation=nf.remediation,
            references=nf.references,
            fingerprint=nf.fingerprint,
        ))
    Finding.objects.bulk_create(objs, batch_size=500)
    return counts


def save_secret_findings(scan, normalized_secret_findings) -> int:
    objs = []
    for nf in normalized_secret_findings:
        objs.append(SecretFinding(
            project=scan.project,
            scan=scan,
            secret_type=nf.title.replace("Exposed ", "").replace("secret: ", ""),
            file_path=nf.file_path,
            line_number=nf.line_start,
            masked_value=mask_secret(nf.code_snippet or nf.title),
            fingerprint=nf.fingerprint,
            severity=nf.severity,
        ))
    SecretFinding.objects.bulk_create(objs, batch_size=500)
    return len(objs)


def save_dependencies(scan, dependency_entries) -> int:
    objs = []
    for dep in dependency_entries:
        objs.append(Dependency(
            project=scan.project,
            scan=scan,
            package_name=dep.package_name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            manifest_file=dep.manifest_file,
            vulnerability_id=dep.vulnerability_id,
            severity=dep.severity,
            description=dep.description,
            fixed_version=dep.fixed_version,
        ))
    Dependency.objects.bulk_create(objs, batch_size=500)
    return len(objs)


def compute_and_apply_scan_statistics(scan):
    """Aggregates Finding/SecretFinding/Dependency rows for this scan into
    the Scan model's summary fields and security_score."""
    findings_qs = scan.findings.all()
    severity_counts = {s: findings_qs.filter(severity=s).count() for s in Severity.ORDER}

    secrets_qs = scan.secret_findings.all()
    secrets_count = secrets_qs.count()
    for secret in secrets_qs:
        if secret.severity in severity_counts:
            severity_counts[secret.severity] += 1
    dep_qs = scan.dependencies.exclude(vulnerability_id="")
    dep_counts = {s: dep_qs.filter(severity=s).count() for s in Severity.ORDER}

    config_issues = findings_qs.filter(category__in=["infrastructure_as_code", "container_security"]).count()

    score = calculate_security_score(
        critical=severity_counts[Severity.CRITICAL],
        high=severity_counts[Severity.HIGH],
        medium=severity_counts[Severity.MEDIUM],
        low=severity_counts[Severity.LOW],
        info=severity_counts[Severity.INFO],
        secrets=secrets_count,
        dependency_critical=dep_counts[Severity.CRITICAL],
        dependency_high=dep_counts[Severity.HIGH],
        dependency_medium=dep_counts[Severity.MEDIUM],
        dependency_low=dep_counts[Severity.LOW],
        config_issues=config_issues,
    )

    scan.total_findings = findings_qs.count() + secrets_count
    scan.critical_count = severity_counts[Severity.CRITICAL]
    scan.high_count = severity_counts[Severity.HIGH]
    scan.medium_count = severity_counts[Severity.MEDIUM]
    scan.low_count = severity_counts[Severity.LOW]
    scan.info_count = severity_counts[Severity.INFO]
    scan.security_score = score
    scan.save(update_fields=[
        "total_findings", "critical_count", "high_count", "medium_count",
        "low_count", "info_count", "security_score",
    ])
    return score
