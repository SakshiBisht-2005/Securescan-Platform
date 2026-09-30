"""Report generation service. Produces both JSON and PDF reports covering
the full outline required by the platform spec (executive summary through
scanner information/statistics). Secret values are always masked - reports
read from SecretFinding.masked_value, never anything that could be a raw
credential.
"""
import json
import uuid
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from apps.vulnerabilities.models import Dependency, Finding, SecretFinding
from common.constants import Severity

from .models import Report

REPORTS_DIR = settings.MEDIA_ROOT / "reports"


def _severity_breakdown(findings_qs):
    return {s: findings_qs.filter(severity=s).count() for s in Severity.ORDER}


def build_report_payload(scan) -> dict:
    project = scan.project
    findings = scan.findings.all()
    secrets = scan.secret_findings.all()
    dependencies = scan.dependencies.exclude(vulnerability_id="")
    scanner_runs = scan.scanner_runs.all()

    def finding_summary(qs):
        return [
            {
                "id": f.id, "title": f.title, "severity": f.severity, "confidence": f.confidence,
                "category": f.category, "scanner": f.scanner, "rule_id": f.rule_id, "cwe": f.cwe,
                "file_path": f.file_path, "line_start": f.line_start, "line_end": f.line_end,
                "description": f.description, "remediation": f.remediation, "references": f.references,
                "status": f.status,
            }
            for f in qs
        ]

    return {
        "report_metadata": {
            "generated_at": timezone.now().isoformat(),
            "report_id": str(uuid.uuid4()),
        },
        "executive_summary": {
            "project_name": project.name,
            "security_score": scan.security_score,
            "total_findings": scan.total_findings,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "info_count": scan.info_count,
            "secrets_detected": secrets.count(),
            "vulnerable_dependencies": dependencies.count(),
            "summary_text": (
                f"This scan of '{project.name}' analyzed {scan.total_files} files and identified "
                f"{scan.total_findings} findings, resulting in a security score of {scan.security_score}/100. "
                "This assessment reflects automated static analysis and does not guarantee the absence of "
                "vulnerabilities; manual review is recommended for critical systems."
            ),
        },
        "project_information": {
            "id": project.id, "name": project.name, "description": project.description,
            "repository_url": project.repository_url, "language": project.language,
            "default_branch": project.default_branch,
        },
        "scan_information": {
            "id": scan.id, "scan_type": scan.scan_type, "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds, "total_files": scan.total_files,
        },
        "security_score": {
            "value": scan.security_score,
            "formula": "See scanner_engine/severity.py:calculate_security_score - weighted penalty by severity, "
                       "secrets, vulnerable-dependency severity, and config issues, subtracted from 100.",
        },
        "vulnerability_summary": _severity_breakdown(findings),
        "critical_findings": finding_summary(findings.filter(severity=Severity.CRITICAL)),
        "high_findings": finding_summary(findings.filter(severity=Severity.HIGH)),
        "medium_findings": finding_summary(findings.filter(severity=Severity.MEDIUM)),
        "low_findings": finding_summary(findings.filter(severity=Severity.LOW)),
        "secret_findings": [
            {
                "id": s.id, "secret_type": s.secret_type, "file_path": s.file_path,
                "line_number": s.line_number, "masked_value": s.masked_value, "severity": s.severity,
                "status": s.status,
            }
            for s in secrets
        ],
        "dependency_findings": [
            {
                "package_name": d.package_name, "version": d.version, "ecosystem": d.ecosystem,
                "vulnerability_id": d.vulnerability_id, "severity": d.severity,
                "fixed_version": d.fixed_version, "description": d.description,
            }
            for d in dependencies
        ],
        "iac_findings": finding_summary(findings.filter(category="infrastructure_as_code")),
        "container_findings": finding_summary(findings.filter(category="container_security")),
        "remediation_recommendations": _top_remediations(findings),
        "scanner_information": [
            {"scanner_name": r.scanner_name, "status": r.status, "findings_count": r.findings_count,
             "duration_seconds": r.duration_seconds}
            for r in scanner_runs
        ],
        "scan_statistics": {
            "total_files_scanned": scan.total_files,
            "scanners_run": scanner_runs.filter(status="success").count(),
            "scanners_skipped": scanner_runs.filter(status="skipped_unavailable").count(),
            "scanners_failed": scanner_runs.filter(status="failed").count(),
        },
    }


def _top_remediations(findings_qs, limit=10):
    seen = {}
    for f in findings_qs.exclude(remediation="").order_by("-severity")[:200]:
        if f.rule_id not in seen:
            seen[f.rule_id] = {"rule_id": f.rule_id, "title": f.title, "severity": f.severity, "remediation": f.remediation}
        if len(seen) >= limit:
            break
    return list(seen.values())


def generate_report_for_scan(scan, report_type: str, generated_by=None) -> Report:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = Report.objects.create(project=scan.project, scan=scan, report_type=report_type, generated_by=generated_by)

    try:
        payload = build_report_payload(scan)
        filename = f"report_{report.id}_{uuid.uuid4().hex[:8]}.{report_type}"
        file_path = REPORTS_DIR / filename

        if report_type == "json":
            file_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        elif report_type == "pdf":
            from .pdf_builder import build_pdf_report
            build_pdf_report(payload, str(file_path))
        else:
            raise ValueError(f"Unsupported report type: {report_type}")

        report.file_path = file_path.relative_to(settings.MEDIA_ROOT).as_posix()
        report.status = "ready"
        report.save(update_fields=["file_path", "status"])
    except Exception:
        report.status = "failed"
        report.save(update_fields=["status"])
        raise

    return report
