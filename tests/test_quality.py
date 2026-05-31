from openhack.quality import (
    cross_file_dedup,
    has_chained_prerequisite,
    run_quality_gates,
)


class TestHasChainedPrerequisite:
    def test_detects_xss_chain(self):
        finding = {"description": "This vulnerability can be exploited via XSS on the admin panel"}
        assert has_chained_prerequisite(finding) is True

    def test_detects_mitm(self):
        finding = {"description": "Requires MITM to intercept the token"}
        assert has_chained_prerequisite(finding) is True

    def test_detects_dns_rebinding(self):
        finding = {"description": "Exploitable via DNS rebinding attack"}
        assert has_chained_prerequisite(finding) is True

    def test_clean_finding(self):
        finding = {"description": "SQL injection in login form allows data extraction"}
        assert has_chained_prerequisite(finding) is False

    def test_checks_poc_field(self):
        finding = {"description": "XSS", "poc": "requires subdomain control"}
        assert has_chained_prerequisite(finding) is True


class TestCrossFileDedup:
    def test_no_dedup_different_categories(self):
        validated = [
            {"original_index": 0},
            {"original_index": 1},
        ]
        potential = [
            {"category": "SQL Injection", "file_path": "src/users/login.py", "severity": "critical"},
            {"category": "XSS", "file_path": "src/users/profile.py", "severity": "medium"},
        ]
        result = cross_file_dedup(validated, potential)
        assert len(result) == 2

    def test_dedup_same_category_similar_path(self):
        validated = [
            {"original_index": 0},
            {"original_index": 1},
        ]
        potential = [
            {"category": "SQL Injection", "file_path": "src/users/login.py", "severity": "critical", "description": "full"},
            {"category": "SQL Injection", "file_path": "src/users/register.py", "severity": "high", "description": "x"},
        ]
        result = cross_file_dedup(validated, potential)
        assert len(result) == 1

    def test_single_item_no_change(self):
        validated = [{"original_index": 0}]
        potential = [{"category": "XSS", "file_path": "a.ts", "severity": "high"}]
        result = cross_file_dedup(validated, potential)
        assert len(result) == 1

    def test_empty_list(self):
        assert cross_file_dedup([], []) == []


class TestRunQualityGates:
    def test_downgrades_chained(self):
        validated = [{"original_index": 0}]
        potential = [
            {"category": "CSRF", "severity": "high", "file_path": "a.ts",
             "description": "Exploitable via XSS on the same domain"},
        ]
        result, stats = run_quality_gates(validated, potential)
        assert potential[0]["severity"] == "low"
        assert stats["chained_prereq_downgraded"] == 1

    def test_passes_clean_findings(self):
        validated = [{"original_index": 0}]
        potential = [
            {"category": "SQL Injection", "severity": "critical", "file_path": "db.py",
             "description": "Direct SQL injection in search"},
        ]
        result, stats = run_quality_gates(validated, potential)
        assert potential[0]["severity"] == "critical"
        assert stats["chained_prereq_downgraded"] == 0
