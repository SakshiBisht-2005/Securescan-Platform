"""Adapter for Semgrep (multi-language SAST). Optional - Semgrep has
limited native Windows support, so this adapter degrades gracefully
(skips with a clear "unavailable" status) rather than failing the scan
when it isn't installed."""
import json
import logging

from django.conf import settings

from common.constants import Confidence
from scanner_engine.normalizer import build_finding
from scanner_engine.process_runner import ToolNotAvailable, run_tool

from .base import BaseAdapter

logger = logging.getLogger("scanner_engine")

_SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


class SemgrepAdapter(BaseAdapter):
    name = "semgrep"
    category_label = "sast"

    def is_available(self) -> bool:
        if not settings.SCANNER_ENABLED.get("semgrep", True):
            return False
        from scanner_engine.process_runner import is_tool_available
        return is_tool_available("semgrep")

    def run(self, project_dir: str, exclusions: list) -> list:
        findings = []
        args = ["semgrep", "scan", "--config", "auto", "--json", "--quiet", "--timeout", "120"]
        for pattern in exclusions or []:
            args += ["--exclude", pattern]
        args.append(".")

        try:
            result = run_tool(args, cwd=project_dir)
        except ToolNotAvailable:
            return []
        except Exception:
            logger.exception("Semgrep execution failed")
            raise

        if not result.stdout.strip():
            return findings

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Semgrep produced non-JSON output; skipping parse.")
            return findings

        for item in payload.get("results", []):
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            severity_raw = extra.get("severity", "WARNING")
            findings.append(
                build_finding(
                    scanner=self.name,
                    rule_id=item.get("check_id", ""),
                    title=metadata.get("shortDescription") or extra.get("message", item.get("check_id", ""))[:250],
                    raw_severity=_SEVERITY_MAP.get(severity_raw, severity_raw),
                    confidence=Confidence.HIGH if metadata.get("confidence") == "HIGH" else Confidence.MEDIUM,
                    category=_infer_category(metadata),
                    file_path=item.get("path", ""),
                    line_start=item.get("start", {}).get("line"),
                    line_end=item.get("end", {}).get("line"),
                    column_start=item.get("start", {}).get("col"),
                    column_end=item.get("end", {}).get("col"),
                    description=extra.get("message", ""),
                    code_snippet=(extra.get("lines") or "")[:2000],
                    cwe=",".join(metadata.get("cwe", [])) if isinstance(metadata.get("cwe"), list) else str(metadata.get("cwe", "")),
                    owasp_category=",".join(metadata.get("owasp", [])) if isinstance(metadata.get("owasp"), list) else str(metadata.get("owasp", "")),
                    remediation=metadata.get("fix") or "Review the flagged pattern and apply the safe alternative documented by the matched Semgrep rule.",
                    references=metadata.get("references", []) if isinstance(metadata.get("references"), list) else [],
                )
            )
        return findings


def _infer_category(metadata: dict) -> str:
    from common.constants import FindingCategory
    cwe = str(metadata.get("cwe", "")).lower()
    owasp = str(metadata.get("owasp", "")).lower()
    text = cwe + owasp
    if "sql" in text or "injection" in text:
        return FindingCategory.INJECTION
    if "xss" in text or "cross-site scripting" in text:
        return FindingCategory.XSS
    if "ssrf" in text:
        return FindingCategory.SSRF
    if "path" in text and "travers" in text:
        return FindingCategory.PATH_TRAVERSAL
    if "crypto" in text:
        return FindingCategory.CRYPTO
    if "auth" in text:
        return FindingCategory.AUTH
    return FindingCategory.OTHER
