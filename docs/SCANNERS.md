# Installing optional scanners

SecureScan's scanner engine (`backend/scanner_engine/manager.py`) checks
each tool's availability at scan time and degrades gracefully — a missing
tool is recorded as `skipped_unavailable` on the scan's `ScannerRun`
records and never fails the scan. Bandit and pip-audit are mandatory pure-
Python dependencies installed via `requirements.txt`, so SAST/SCA for
Python and secret/IaC/container rule-based scanning work with zero extra
setup. The tools below are optional and broaden coverage.

## Semgrep (multi-language SAST)

- Linux / macOS: `pip install semgrep` (already listed as optional in
  `requirements.txt` — uncomment or `pip install semgrep` directly)
- Windows: Semgrep's native Windows support is limited. Recommended: run
  it inside WSL2, or skip it — Bandit + the built-in rules still cover
  Python, and the built-in secret/IaC rule sets are OS-independent.

## Gitleaks (secret detection)

Standalone Go binary — not a Python package.

- Linux: download the release tarball from
  `https://github.com/gitleaks/gitleaks/releases`, extract, and place the
  `gitleaks` binary on your `PATH` (e.g. `/usr/local/bin`).
- Windows: download the Windows `.zip` release from the same page, extract
  `gitleaks.exe`, and add its folder to your `PATH`.
- Verify: `gitleaks version`

The platform's built-in regex secret-pattern engine
(`scanner_engine/rules.py`) runs regardless, so secret detection is never
fully dependent on this binary being present.

## Checkov (IaC scanning)

Pure Python — `pip install checkov`. Works on both Windows and Linux.
(Not added to mandatory `requirements.txt` to keep the base install light;
add it to your virtualenv when you want deeper IaC/Terraform/K8s/CFN
policy coverage beyond the built-in IAC rule set.)

## Trivy (container / IaC misconfiguration scanning)

Standalone Go binary.

- Linux: follow the official install script or your distro's package
  manager, e.g. `sudo apt-get install trivy` (after adding Aqua Security's
  apt repo) — see `https://aquasecurity.github.io/trivy/latest/getting-started/installation/`.
- Windows: download the Windows binary from the Trivy releases page and
  add it to `PATH`.
- Verify: `trivy --version`

## OWASP Dependency-Check (Java/Maven CVE coverage)

Not wired into an adapter by default (the built-in `dependency_check.py`
adapter currently inventories Maven/Gradle dependencies without a CVE
database). To add real Java CVE coverage:

1. Install Dependency-Check CLI: `https://jeremylong.github.io/DependencyCheck/dependency-check-cli/`
2. Add a new adapter under `backend/scanner_engine/adapters/` that shells
   out to `dependency-check.sh --format JSON ...` (or `.bat` on Windows)
   using `scanner_engine/process_runner.run_tool` (argument list, never a
   shell string), parses the JSON report into `DependencyEntry` objects,
   and register it in `manager.py`'s `SCA_ADAPTERS` list.

## npm audit (JavaScript SCA)

Requires Node.js/npm on `PATH` — used automatically by the dependency
adapter when a project contains `package.json`. Install Node from
`https://nodejs.org` on either OS; no further configuration is needed.

## Enabling/disabling scanners

Global defaults live in `.env` (`ENABLE_SEMGREP`, `ENABLE_BANDIT`,
`ENABLE_PIP_AUDIT`, `ENABLE_CHECKOV`, `ENABLE_GITLEAKS`, `ENABLE_TRIVY`).
Per-scan overrides are set from the Scanner page in the UI (or the
`enable_sast` / `enable_sca` / `enable_secrets` / `enable_iac` /
`enable_container` fields on `POST /api/projects/{id}/scan/`).
