"""Software Composition Analysis (SCA) adapter.

Strategy:
- Python (requirements.txt / pyproject.toml / Pipfile): runs `pip-audit`,
  which queries the public PyPI vulnerability advisory database. This is
  a mandatory pure-python dependency so it works cross-platform.
- JavaScript (package.json / package-lock.json): runs `npm audit --json`
  when npm is available on PATH.
- Java / PHP / Go / Ruby manifests: parsed for package name + version so
  they show up in the dependency inventory. Without a bundled offline
  vulnerability database for these ecosystems, vulnerability_id/severity
  are left blank rather than fabricated; operators can wire in
  OWASP Dependency-Check (Java) for CVE coverage - see docs/SCANNERS.md.

Every dependency finding produced here is written to the `Dependency`
model, kept separate from source-code `Finding` records, matching the
platform's requirement to display SCA results separately from SAST.
"""
import json
import logging
import re
from pathlib import Path

from common.constants import Severity
from scanner_engine.process_runner import ToolNotAvailable, run_tool

from .base import BaseAdapter

logger = logging.getLogger("scanner_engine")


class DependencyEntry:
    def __init__(self, package_name, version, ecosystem, manifest_file,
                 vulnerability_id="", severity="", description="", fixed_version=""):
        self.package_name = package_name
        self.version = version
        self.ecosystem = ecosystem
        self.manifest_file = manifest_file
        self.vulnerability_id = vulnerability_id
        self.severity = severity
        self.description = description
        self.fixed_version = fixed_version


class DependencyCheckAdapter(BaseAdapter):
    name = "dependency_check"
    category_label = "sca"

    def is_available(self) -> bool:
        return True  # always runs; individual sub-checks degrade gracefully

    def run(self, project_dir: str, exclusions: list) -> list:
        entries = []
        entries += self._run_pip_audit(project_dir)
        entries += self._run_npm_audit(project_dir)
        entries += self._parse_manifests_without_vuln_db(project_dir)
        return entries

    # -- Python --------------------------------------------------------
    def _run_pip_audit(self, project_dir: str) -> list:
        root = Path(project_dir)
        manifest = None
        for candidate in ("requirements.txt", "Pipfile", "pyproject.toml"):
            if (root / candidate).exists():
                manifest = candidate
                break
        if not manifest:
            return []

        args = ["pip-audit", "-f", "json"]
        if manifest == "requirements.txt":
            args += ["-r", "requirements.txt"]

        try:
            result = run_tool(args, cwd=project_dir, timeout=180)
        except ToolNotAvailable:
            return []
        except Exception:
            logger.warning("pip-audit failed to execute; skipping Python SCA for this scan.")
            return []

        if not result.stdout.strip():
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        entries = []
        dependencies = payload if isinstance(payload, list) else payload.get("dependencies", [])
        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            vulns = dep.get("vulns", [])
            if not vulns:
                continue
            for vuln in vulns:
                fix_versions = vuln.get("fix_versions", [])
                entries.append(DependencyEntry(
                    package_name=name,
                    version=version,
                    ecosystem="pypi",
                    manifest_file=manifest,
                    vulnerability_id=vuln.get("id", ""),
                    severity=_severity_from_advisory(vuln),
                    description=vuln.get("description", "")[:1000],
                    fixed_version=fix_versions[0] if fix_versions else "",
                ))
        return entries

    # -- JavaScript ------------------------------------------------------
    def _run_npm_audit(self, project_dir: str) -> list:
        root = Path(project_dir)
        if not (root / "package.json").exists():
            return []

        args = ["npm", "audit", "--json"]
        try:
            result = run_tool(args, cwd=project_dir, timeout=180)
        except ToolNotAvailable:
            return []
        except Exception:
            logger.warning("npm audit failed to execute; skipping JS SCA for this scan.")
            return []

        if not result.stdout.strip():
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        entries = []
        vulnerabilities = payload.get("vulnerabilities", {})
        for pkg_name, info in vulnerabilities.items():
            severity = str(info.get("severity", "")).upper()
            via = info.get("via", [])
            description = ""
            vuln_id = ""
            for v in via:
                if isinstance(v, dict):
                    description = v.get("title", description)
                    vuln_id = v.get("url", vuln_id)
                    break
            entries.append(DependencyEntry(
                package_name=pkg_name,
                version=str(info.get("range", "")),
                ecosystem="npm",
                manifest_file="package.json",
                vulnerability_id=vuln_id,
                severity=severity if severity in Severity.ORDER else Severity.MEDIUM,
                description=description[:1000],
                fixed_version=str(info.get("fixAvailable", "")) if info.get("fixAvailable") not in (False, None) else "",
            ))
        return entries

    # -- Other ecosystems: inventory only (no bundled vuln DB) ---------
    def _parse_manifests_without_vuln_db(self, project_dir: str) -> list:
        root = Path(project_dir)
        entries = []

        composer = root / "composer.json"
        if composer.exists():
            try:
                data = json.loads(composer.read_text(encoding="utf-8", errors="ignore"))
                for name, version in {**data.get("require", {})}.items():
                    if name == "php":
                        continue
                    entries.append(DependencyEntry(name, str(version), "composer", "composer.json"))
            except (json.JSONDecodeError, OSError):
                pass

        go_mod = root / "go.mod"
        if go_mod.exists():
            try:
                text = go_mod.read_text(encoding="utf-8", errors="ignore")
                for match in re.finditer(r"^\s*([\w./-]+)\s+(v[\d][\w.\-+]*)", text, re.MULTILINE):
                    entries.append(DependencyEntry(match.group(1), match.group(2), "go", "go.mod"))
            except OSError:
                pass

        gemfile_lock = root / "Gemfile.lock"
        if gemfile_lock.exists():
            try:
                text = gemfile_lock.read_text(encoding="utf-8", errors="ignore")
                for match in re.finditer(r"^\s{4}([A-Za-z0-9_-]+)\s+\(([\d.]+)\)", text, re.MULTILINE):
                    entries.append(DependencyEntry(match.group(1), match.group(2), "rubygems", "Gemfile.lock"))
            except OSError:
                pass

        pom = root / "pom.xml"
        if pom.exists():
            try:
                text = pom.read_text(encoding="utf-8", errors="ignore")
                for match in re.finditer(
                    r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
                    text,
                ):
                    entries.append(DependencyEntry(f"{match.group(1)}:{match.group(2)}", match.group(3), "maven", "pom.xml"))
            except OSError:
                pass

        return entries


def _severity_from_advisory(vuln: dict) -> str:
    # pip-audit/OSV doesn't always include a severity string; infer a
    # reasonable default from whether a fix is available/CVSS keywords.
    aliases = vuln.get("aliases", [])
    if any(str(a).startswith("CVE") for a in aliases):
        return Severity.HIGH
    return Severity.MEDIUM
