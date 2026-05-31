from openhack.categories import (
    CATEGORIES,
    CATEGORY_SEVERITY,
    normalize_category,
    normalize_severity,
)


class TestNormalizeCategory:
    def test_exact_match_case_insensitive(self):
        assert normalize_category("sql injection") == "SQL Injection"
        assert normalize_category("XSS") == "XSS"
        assert normalize_category("CSRF") == "CSRF"

    def test_keyword_match(self):
        assert normalize_category("sqli in login") == "SQL Injection"
        assert normalize_category("cross-site scripting via input") == "XSS"
        assert normalize_category("server-side request forgery") == "SSRF"
        assert normalize_category("local file inclusion") == "Path Traversal"
        assert normalize_category("insecure direct object reference") == "IDOR"
        assert normalize_category("broken authentication") == "Authentication Bypass"
        assert normalize_category("remote code execution") == "RCE"

    def test_empty_returns_misconfiguration(self):
        assert normalize_category("") == "Security Misconfiguration"

    def test_unknown_returns_titlecased(self):
        assert normalize_category("something weird") == "Something Weird"

    def test_whitespace_handling(self):
        assert normalize_category("  sql injection  ") == "SQL Injection"


class TestNormalizeSeverity:
    def test_upgrades_low_to_category_default(self):
        findings = [{"category": "SQL Injection", "severity": "low"}]
        result = normalize_severity(findings)
        assert result[0]["severity"] == "critical"

    def test_does_not_downgrade(self):
        findings = [{"category": "Information Disclosure", "severity": "critical"}]
        result = normalize_severity(findings)
        assert result[0]["severity"] == "critical"

    def test_no_mutation_of_input(self):
        findings = [{"category": "XSS", "severity": "info"}]
        normalize_severity(findings)
        assert findings[0]["severity"] == "info"

    def test_skip_category_default(self):
        findings = [{"category": "SQL Injection", "severity": "low"}]
        result = normalize_severity(findings, use_category_default=False)
        assert result[0]["severity"] == "low"


class TestCategoryConsistency:
    def test_all_categories_have_severity(self):
        for cat in CATEGORIES:
            assert cat in CATEGORY_SEVERITY, f"{cat} missing severity mapping"

    def test_no_extra_severities(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for cat, sev in CATEGORY_SEVERITY.items():
            assert sev in valid, f"{cat} has invalid severity {sev}"
