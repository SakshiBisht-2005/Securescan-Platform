from scanner_engine.deduplicator import deduplicate_findings, diff_findings
from scanner_engine.normalizer import build_finding
from scanner_engine.severity import calculate_security_score, normalize_severity


class TestSeverityNormalization:
    def test_known_severities_pass_through(self):
        assert normalize_severity("CRITICAL") == "CRITICAL"
        assert normalize_severity("high") == "HIGH"

    def test_scanner_specific_aliases_map_correctly(self):
        assert normalize_severity("ERROR") == "HIGH"  # semgrep
        assert normalize_severity("WARNING") == "MEDIUM"  # semgrep/bandit style
        assert normalize_severity("BLOCKER") == "CRITICAL"

    def test_unknown_severity_defaults_to_info_not_dropped(self):
        assert normalize_severity("totally-unknown-value") == "INFO"

    def test_empty_severity_defaults_to_info(self):
        assert normalize_severity("") == "INFO"
        assert normalize_severity(None) == "INFO"

    def test_never_auto_downgrades_critical(self):
        # A scanner reporting CRITICAL must stay CRITICAL, not get bucketed down.
        assert normalize_severity("CRITICAL") == "CRITICAL"


class TestSecurityScore:
    def test_clean_scan_scores_100(self):
        assert calculate_security_score() == 100

    def test_critical_findings_reduce_score_significantly(self):
        score = calculate_security_score(critical=3)
        assert score < 70

    def test_score_never_goes_below_zero(self):
        score = calculate_security_score(critical=100, high=100, secrets=100)
        assert score == 0

    def test_score_never_exceeds_100(self):
        assert calculate_security_score() <= 100

    def test_secrets_penalize_score(self):
        clean = calculate_security_score()
        with_secret = calculate_security_score(secrets=1)
        assert with_secret < clean


class TestFindingFingerprint:
    def test_same_finding_has_stable_fingerprint(self):
        f1 = build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py")
        f2 = build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py")
        assert f1.fingerprint == f2.fingerprint

    def test_different_rule_has_different_fingerprint(self):
        f1 = build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py")
        f2 = build_finding("bandit", "B105", "Hardcoded Password", "HIGH", file_path="app.py")
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_stable_across_line_number_shifts(self):
        f1 = build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py", line_start=10)
        f2 = build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py", line_start=14)
        assert f1.fingerprint == f2.fingerprint


class TestDeduplication:
    def test_exact_duplicates_collapsed(self):
        findings = [
            build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py"),
            build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1

    def test_distinct_findings_preserved(self):
        findings = [
            build_finding("bandit", "B608", "SQL Injection", "HIGH", file_path="app.py"),
            build_finding("gitleaks", "aws-key", "Exposed AWS Key", "HIGH", file_path="config.py"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_higher_confidence_instance_kept(self):
        low = build_finding("semgrep", "rule1", "Issue", "HIGH", file_path="a.py", confidence="LOW")
        high = build_finding("semgrep", "rule1", "Issue", "HIGH", file_path="a.py", confidence="HIGH")
        result = deduplicate_findings([low, high])
        assert len(result) == 1
        assert result[0].confidence == "HIGH"


class TestScanDiff:
    def test_new_resolved_unchanged_classification(self):
        previous = {"fp1", "fp2"}
        current = {"fp2", "fp3"}
        diff = diff_findings(previous, current)
        assert diff["new"] == {"fp3"}
        assert diff["resolved"] == {"fp1"}
        assert diff["unchanged"] == {"fp2"}
