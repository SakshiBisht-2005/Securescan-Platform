"""IaC scanning adapter. Uses Checkov when installed (broad coverage of
Terraform/Kubernetes/CloudFormation/GitHub Actions policies); always also
runs the built-in IAC_RULES fallback so IaC scanning works with zero
extra installation."""
import json
import logging
import re
from pathlib import Path

from django.conf import settings

from common.constants import Confidence, FindingCategory
from scanner_engine.normalizer import build_finding
from scanner_engine.process_runner import ToolNotAvailable, run_tool
from scanner_engine.rules import IAC_RULES

from .base import BaseAdapter

logger = logging.getLogger("scanner_engine")

IAC_RELEVANT_EXTENSIONS = {".tf", ".tfvars", ".yml", ".yaml", ".json"}
IAC_RELEVANT_DIR_HINTS = ("terraform", ".github/workflows", "k8s", "kubernetes", "cloudformation")


class CheckovAdapter(BaseAdapter):
    name = "checkov"
    category_label = "iac"

    def is_available(self) -> bool:
        return True  # built-in fallback always available

    def run(self, project_dir: str, exclusions: list) -> list:
        findings = []
        if settings.SCANNER_ENABLED.get("checkov", True):
            findings.extend(self._run_checkov_binary(project_dir))
        findings.extend(self._run_builtin_rules(project_dir, exclusions))
        return findings

    def _run_checkov_binary(self, project_dir: str) -> list:
        from scanner_engine.process_runner import is_tool_available
        if not is_tool_available("checkov"):
            return []

        args = ["checkov", "-d", ".", "-o", "json", "--quiet", "--compact"]
        try:
            result = run_tool(args, cwd=project_dir, timeout=240)
        except ToolNotAvailable:
            return []
        except Exception:
            logger.warning("Checkov failed to execute; falling back to built-in IaC rules only.")
            return []

        if not result.stdout.strip():
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        # Checkov's JSON can be a single object or a list of objects (one per framework).
        reports = payload if isinstance(payload, list) else [payload]
        findings = []
        for report in reports:
            for item in report.get("results", {}).get("failed_checks", []):
                findings.append(
                    build_finding(
                        scanner="checkov",
                        rule_id=item.get("check_id", ""),
                        title=item.get("check_name", item.get("check_id", "")),
                        raw_severity=item.get("severity") or "MEDIUM",
                        confidence=Confidence.HIGH,
                        category=FindingCategory.IAC,
                        file_path=(item.get("file_path", "") or "").lstrip("/"),
                        line_start=(item.get("file_line_range") or [None])[0],
                        line_end=(item.get("file_line_range") or [None, None])[1],
                        description=item.get("check_name", ""),
                        remediation=item.get("guideline") or "Review the failed policy check and align the resource configuration with security best practices.",
                        references=[item.get("guideline")] if item.get("guideline") else [],
                    )
                )
        return findings

    def _run_builtin_rules(self, project_dir: str, exclusions: list) -> list:
        findings = []
        root = Path(project_dir)
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in IAC_RELEVANT_EXTENSIONS:
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            if _is_excluded(rel, exclusions):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for rule in IAC_RULES:
                if path.suffix.lower() not in rule["applies_to"]:
                    continue
                pattern = rule["pattern"]
                for i, line in enumerate(text.splitlines(), start=1):
                    if re.search(pattern, line):
                        if rule.get("invert_requires") and re.search(rule["invert_requires"], text):
                            continue
                        findings.append(
                            build_finding(
                                scanner="builtin-iac",
                                rule_id=rule["id"],
                                title=rule["title"],
                                raw_severity=rule["severity"],
                                confidence=Confidence.MEDIUM,
                                category=FindingCategory.IAC,
                                file_path=rel,
                                line_start=i,
                                line_end=i,
                                description=rule["title"],
                                code_snippet=line.strip()[:500],
                                remediation=rule["remediation"],
                            )
                        )
        return findings


def _is_excluded(rel_path: str, exclusions: list) -> bool:
    import fnmatch
    from apps.projects.upload_service import DEFAULT_EXCLUDED_DIR_NAMES

    parts = rel_path.split("/")
    if any(p in DEFAULT_EXCLUDED_DIR_NAMES for p in parts):
        return True
    for pattern in exclusions or []:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
    return False
