from django.db.models import Avg, Count, Q

from apps.projects.access import visible_projects
from apps.projects.models import Project
from apps.scanner.models import Scan
from apps.vulnerabilities.models import Dependency, Finding, SecretFinding
from common.constants import FindingStatus, ScanStatus, Severity


def _scoped_projects(user):
    return visible_projects(user)


def get_dashboard_summary(user):
    projects = _scoped_projects(user)
    scans = Scan.objects.filter(project__in=projects)
    open_findings = Finding.objects.filter(project__in=projects, status=FindingStatus.OPEN)

    latest_scans = scans.order_by("-created_at")[:10]
    avg_score = scans.filter(status=ScanStatus.COMPLETED).aggregate(avg=Avg("security_score"))["avg"]

    return {
        "total_projects": projects.count(),
        "total_scans": scans.count(),
        "open_vulnerabilities": open_findings.count(),
        "critical_count": open_findings.filter(severity=Severity.CRITICAL).count(),
        "high_count": open_findings.filter(severity=Severity.HIGH).count(),
        "medium_count": open_findings.filter(severity=Severity.MEDIUM).count(),
        "low_count": open_findings.filter(severity=Severity.LOW).count(),
        "info_count": open_findings.filter(severity=Severity.INFO).count(),
        "secrets_detected": SecretFinding.objects.filter(project__in=projects, status=FindingStatus.OPEN).count(),
        "vulnerable_dependencies": Dependency.objects.filter(project__in=projects).exclude(vulnerability_id="").count(),
        "average_security_score": round(avg_score) if avg_score is not None else None,
        "latest_scans": [
            {
                "id": s.id, "project_id": s.project_id, "project_name": s.project.name,
                "status": s.status, "security_score": s.security_score,
                "total_findings": s.total_findings, "created_at": s.created_at.isoformat(),
            }
            for s in latest_scans
        ],
    }


def get_security_trend(user, project_id=None, limit=20):
    projects = _scoped_projects(user)
    scans = Scan.objects.filter(project__in=projects, status=ScanStatus.COMPLETED).order_by("-created_at")
    if project_id:
        scans = scans.filter(project_id=project_id)
    scans = list(scans[:limit])[::-1]
    return [
        {
            "scan_id": s.id, "date": s.completed_at.isoformat() if s.completed_at else s.created_at.isoformat(),
            "security_score": s.security_score, "critical": s.critical_count, "high": s.high_count,
            "medium": s.medium_count, "low": s.low_count, "total_findings": s.total_findings,
        }
        for s in scans
    ]


def get_project_statistics(project):
    findings = Finding.objects.filter(project=project)
    open_findings = findings.filter(status=FindingStatus.OPEN)
    latest_scan = project.scans.order_by("-created_at").first()

    by_category = list(
        open_findings.values("category").annotate(count=Count("id")).order_by("-count")
    )
    by_scanner = list(
        findings.values("scanner").annotate(count=Count("id")).order_by("-count")
    )

    return {
        "project_id": project.id,
        "total_scans": project.scans.count(),
        "open_findings": open_findings.count(),
        "critical_count": open_findings.filter(severity=Severity.CRITICAL).count(),
        "high_count": open_findings.filter(severity=Severity.HIGH).count(),
        "medium_count": open_findings.filter(severity=Severity.MEDIUM).count(),
        "low_count": open_findings.filter(severity=Severity.LOW).count(),
        "info_count": open_findings.filter(severity=Severity.INFO).count(),
        "secrets_detected": SecretFinding.objects.filter(project=project, status=FindingStatus.OPEN).count(),
        "vulnerable_dependencies": Dependency.objects.filter(project=project).exclude(vulnerability_id="").count(),
        "latest_security_score": latest_scan.security_score if latest_scan else None,
        "findings_by_category": by_category,
        "findings_by_scanner": by_scanner,
        "trend": get_security_trend(project.owner, project_id=project.id),
    }
