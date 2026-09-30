"""Adapter for Bandit (Python SAST). Bandit is a mandatory pip dependency
(pure-python, works on Windows and Linux) so this adapter should normally
always be available; it still checks defensively."""
import json
import logging

from common.constants import Confidence, FindingCategory
from scanner_engine.normalizer import build_finding
from scanner_engine.process_runner import ToolNotAvailable, run_tool

from .base import BaseAdapter

logger = logging.getLogger("scanner_engine")

_CATEGORY_BY_TEST = {
    "B301": FindingCategory.DESERIALIZATION, "B302": FindingCategory.DESERIALIZATION,
    "B303": FindingCategory.CRYPTO, "B304": FindingCategory.CRYPTO, "B305": FindingCategory.CRYPTO,
    "B324": FindingCategory.CRYPTO,
    "B608": FindingCategory.INJECTION, "B610": FindingCategory.INJECTION, "B611": FindingCategory.INJECTION,
    "B601": FindingCategory.INJECTION, "B602": FindingCategory.INJECTION, "B603": FindingCategory.INJECTION,
    "B604": FindingCategory.INJECTION, "B605": FindingCategory.INJECTION, "B606": FindingCategory.INJECTION,
    "B609": FindingCategory.INJECTION,
    "B105": FindingCategory.SECRETS, "B106": FindingCategory.SECRETS, "B107": FindingCategory.SECRETS,
    "B108": FindingCategory.CONFIGURATION,
    "B201": FindingCategory.CONFIGURATION,
}

_CONFIDENCE_MAP = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}


class BanditAdapter(BaseAdapter):
    name = "bandit"
    category_label = "sast"

    def is_available(self) -> bool:
        from scanner_engine.process_runner import is_tool_available
        return is_tool_available("bandit")

    def run(self, project_dir: str, exclusions: list) -> list:
        findings = []
        exclude_arg = ",".join(exclusions) if exclusions else ""
        args = ["bandit", "-r", ".", "-f", "json", "-q"]
        if exclude_arg:
            args += ["-x", exclude_arg]

        try:
            result = run_tool(args, cwd=project_dir)
        except ToolNotAvailable:
            return []
        except Exception:
            logger.exception("Bandit execution failed")
            raise

        # Bandit exits non-zero when issues are found; that's expected.
        if not result.stdout.strip():
            return findings

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Bandit produced non-JSON output; skipping parse.")
            return findings

        for item in payload.get("results", []):
            test_id = item.get("test_id", "")
            findings.append(
                build_finding(
                    scanner=self.name,
                    rule_id=test_id,
                    title=item.get("test_name", test_id),
                    raw_severity=item.get("issue_severity", "MEDIUM"),
                    confidence=_CONFIDENCE_MAP.get(item.get("issue_confidence", "MEDIUM"), Confidence.MEDIUM),
                    category=_CATEGORY_BY_TEST.get(test_id, FindingCategory.OTHER),
                    file_path=item.get("filename", "").lstrip("./"),
                    line_start=item.get("line_number"),
                    line_end=item.get("line_range", [None])[-1] if item.get("line_range") else item.get("line_number"),
                    description=item.get("issue_text", ""),
                    code_snippet=(item.get("code") or "")[:2000],
                    cwe=str(item.get("issue_cwe", {}).get("id", "")) if isinstance(item.get("issue_cwe"), dict) else "",
                    remediation=_remediation_for(test_id),
                    references=[f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html"] if test_id else [],
                )
            )
        return findings


def _remediation_for(test_id: str) -> str:
    generic = {
        "B608": "Use parameterized queries / an ORM instead of building SQL via string formatting.",
        "B105": "Do not hardcode credentials; load them from environment variables or a secrets manager.",
        "B301": "Avoid unpickling untrusted data; use a safe serialization format such as JSON.",
        "B602": "Avoid shell=True; pass command arguments as a list.",
    }
    return generic.get(test_id, "Review the flagged code for the described security weakness and apply the recommended fix pattern for this rule.")
