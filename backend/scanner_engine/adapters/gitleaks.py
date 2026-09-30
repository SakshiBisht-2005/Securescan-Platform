"""Secret-detection adapter. Uses the Gitleaks binary when available for
broad, well-maintained coverage; always ALSO runs the built-in regex
rule-set (scanner_engine/rules.py) as a dependable baseline, merging and
deduplicating results by fingerprint. This means secret detection works
out of the box even on a machine where the gitleaks binary hasn't been
installed.

Values are masked before ever leaving this module - the raw secret value
is used only transiently to compute the mask and is discarded."""
import json
import logging
import re
from pathlib import Path

from django.conf import settings

from common.constants import Confidence, FindingCategory, Severity
from common.utilities import mask_secret
from scanner_engine.normalizer import build_finding
from scanner_engine.process_runner import ToolNotAvailable, run_tool
from scanner_engine.rules import SECRET_PATTERNS, SECRET_SCAN_SKIP_EXTENSIONS

from .base import BaseAdapter

logger = logging.getLogger("scanner_engine")

_REMEDIATION = (
    "Revoke and rotate this credential immediately, remove it from source "
    "control history, and move it to an environment variable or a secrets "
    "manager (e.g. AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)."
)


class GitleaksAdapter(BaseAdapter):
    name = "gitleaks"
    category_label = "secrets"

    def is_available(self) -> bool:
        # Always "available" because the built-in regex fallback runs
        # regardless of whether the gitleaks binary is installed.
        return True

    def run(self, project_dir: str, exclusions: list) -> list:
        findings = []
        findings.extend(self._run_builtin_patterns(project_dir, exclusions))

        if settings.SCANNER_ENABLED.get("gitleaks", True):
            findings.extend(self._run_gitleaks_binary(project_dir))

        # Deduplicate by (file_path, secret_type, masked prefix)
        deduped = {}
        for f in findings:
            key = (f.file_path, f.rule_id, f.line_start)
            if key not in deduped:
                deduped[key] = f
        return list(deduped.values())

    def _run_builtin_patterns(self, project_dir: str, exclusions: list) -> list:
        findings = []
        root = Path(project_dir)
        compiled = [(name, re.compile(pattern), conf) for name, pattern, conf in SECRET_PATTERNS]

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in SECRET_SCAN_SKIP_EXTENSIONS:
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            if _is_excluded(rel, exclusions):
                continue
            try:
                if path.stat().st_size > 5 * 1024 * 1024:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for line_no, line in enumerate(text.splitlines(), start=1):
                for name, pattern, confidence in compiled:
                    match = pattern.search(line)
                    if not match:
                        continue
                    raw_value = match.group(0)
                    findings.append(
                        build_finding(
                            scanner="builtin-secrets",
                            rule_id=name.lower().replace(" ", "_"),
                            title=f"Exposed {name}",
                            raw_severity=Severity.HIGH if confidence == "HIGH" else Severity.MEDIUM,
                            confidence=confidence,
                            category=FindingCategory.SECRETS,
                            file_path=rel,
                            line_start=line_no,
                            line_end=line_no,
                            description=f"A potential {name} was found hardcoded in source code.",
                            code_snippet=mask_secret(line.strip())[:500],
                            remediation=_REMEDIATION,
                            references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                        )
                    )
        return findings

    def _run_gitleaks_binary(self, project_dir: str) -> list:
        findings = []
        args = ["gitleaks", "detect", "--source", ".", "--no-git", "--report-format", "json", "--report-path", "-", "--exit-code", "0"]
        try:
            result = run_tool(args, cwd=project_dir)
        except ToolNotAvailable:
            return []
        except Exception:
            logger.exception("Gitleaks execution failed")
            return []

        if not result.stdout.strip():
            return findings
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return findings

        for item in payload:
            secret_value = item.get("Secret", "")
            findings.append(
                build_finding(
                    scanner=self.name,
                    rule_id=item.get("RuleID", "gitleaks-rule"),
                    title=f"Exposed secret: {item.get('Description', item.get('RuleID', 'secret'))}",
                    raw_severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.SECRETS,
                    file_path=item.get("File", ""),
                    line_start=item.get("StartLine"),
                    line_end=item.get("EndLine"),
                    description="Gitleaks detected a hardcoded secret matching a known credential pattern.",
                    code_snippet=mask_secret(secret_value)[:500],
                    remediation=_REMEDIATION,
                    references=["https://github.com/gitleaks/gitleaks"],
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
