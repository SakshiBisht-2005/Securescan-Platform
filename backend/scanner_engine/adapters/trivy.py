"""Container / Dockerfile configuration scanning adapter.

Only activates when the project actually contains a Dockerfile or
docker-compose file (per requirement #10) - it never requires or assumes
Docker is installed, and the platform itself never builds or runs the
scanned container. Uses Trivy's config-scanning mode when the `trivy`
binary is available, and always runs the built-in DOCKERFILE_RULES /
COMPOSE_RULES fallback."""
import json
import logging
import re
from pathlib import Path

from django.conf import settings

from common.constants import Confidence, FindingCategory
from scanner_engine.normalizer import build_finding
from scanner_engine.process_runner import ToolNotAvailable, run_tool
from scanner_engine.rules import COMPOSE_RULES, DOCKERFILE_RULES

from .base import BaseAdapter

logger = logging.getLogger("scanner_engine")


def _find_container_files(root: Path):
    dockerfiles, compose_files = [], []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            dockerfiles.append(path)
        elif name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            compose_files.append(path)
    return dockerfiles, compose_files


class TrivyAdapter(BaseAdapter):
    name = "trivy"
    category_label = "container"

    def is_available(self) -> bool:
        return True  # only runs its logic when container files are actually found

    def run(self, project_dir: str, exclusions: list) -> list:
        root = Path(project_dir)
        dockerfiles, compose_files = _find_container_files(root)
        if not dockerfiles and not compose_files:
            return []  # nothing to scan; not an error

        findings = []
        if settings.SCANNER_ENABLED.get("trivy", True):
            findings.extend(self._run_trivy_binary(project_dir))

        for path in dockerfiles:
            findings.extend(self._check_dockerfile(root, path))
        for path in compose_files:
            findings.extend(self._check_compose(root, path))
        return findings

    def _run_trivy_binary(self, project_dir: str) -> list:
        from scanner_engine.process_runner import is_tool_available
        if not is_tool_available("trivy"):
            return []

        args = ["trivy", "config", "--format", "json", "--quiet", "."]
        try:
            result = run_tool(args, cwd=project_dir, timeout=240)
        except ToolNotAvailable:
            return []
        except Exception:
            logger.warning("Trivy failed to execute; falling back to built-in Dockerfile/compose rules only.")
            return []

        if not result.stdout.strip():
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for report in payload.get("Results", []):
            target = report.get("Target", "")
            for item in report.get("Misconfigurations", []) or []:
                findings.append(
                    build_finding(
                        scanner="trivy",
                        rule_id=item.get("ID", ""),
                        title=item.get("Title", item.get("ID", "")),
                        raw_severity=item.get("Severity", "MEDIUM"),
                        confidence=Confidence.HIGH,
                        category=FindingCategory.CONTAINER,
                        file_path=target,
                        line_start=(item.get("CauseMetadata") or {}).get("StartLine"),
                        line_end=(item.get("CauseMetadata") or {}).get("EndLine"),
                        description=item.get("Description", ""),
                        remediation=item.get("Resolution") or "Follow Trivy's guidance for this misconfiguration.",
                        references=item.get("References", []) or [],
                    )
                )
        return findings

    def _check_dockerfile(self, root: Path, path: Path) -> list:
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []

        findings = []
        for rule in DOCKERFILE_RULES:
            try:
                triggered = rule["check"](lines)
            except Exception:  # noqa: BLE001 - a defensive rule must never crash the scan
                triggered = False
            if triggered:
                findings.append(
                    build_finding(
                        scanner="builtin-container",
                        rule_id=rule["id"],
                        title=rule["title"],
                        raw_severity=rule["severity"],
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.CONTAINER,
                        file_path=rel,
                        description=rule["title"],
                        remediation=rule["remediation"],
                    )
                )
        return findings

    def _check_compose(self, root: Path, path: Path) -> list:
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        findings = []
        for rule in COMPOSE_RULES:
            for i, line in enumerate(text.splitlines(), start=1):
                if re.search(rule["pattern"], line):
                    findings.append(
                        build_finding(
                            scanner="builtin-container",
                            rule_id=rule["id"],
                            title=rule["title"],
                            raw_severity=rule["severity"],
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.CONTAINER,
                            file_path=rel,
                            line_start=i,
                            line_end=i,
                            description=rule["title"],
                            code_snippet=line.strip()[:500],
                            remediation=rule["remediation"],
                        )
                    )
        return findings
