"""
Fatah2 — Unit Tests
Tests Target validation, Deduplicator, RiskScorer, BaseScanner helpers.
Run: pytest tests/unit/ -v
"""

import asyncio
import pytest
from unittest.mock import patch, MagicMock


# ─────────────────────────────────────────────────────────────────────────────
# Target validation
# ─────────────────────────────────────────────────────────────────────────────

class TestTarget:

    def test_valid_apex_domain(self):
        from src.core.target import Target
        t = Target("example.com")
        assert t.domain == "example.com"

    def test_strips_https_scheme(self):
        from src.core.target import Target
        t = Target("https://example.com/path?q=1")
        assert t.domain == "example.com"

    def test_strips_http_scheme(self):
        from src.core.target import Target
        t = Target("http://sub.example.com")
        assert t.domain == "sub.example.com"

    def test_strips_trailing_slash(self):
        from src.core.target import Target
        t = Target("https://example.com/")
        assert t.domain == "example.com"

    def test_lowercases_domain(self):
        from src.core.target import Target
        t = Target("EXAMPLE.COM")
        assert t.domain == "example.com"

    def test_subdomain_valid(self):
        from src.core.target import Target
        t = Target("api.example.com")
        assert t.domain == "api.example.com"

    def test_deep_subdomain_valid(self):
        from src.core.target import Target
        t = Target("a.b.c.example.com")
        assert t.domain == "a.b.c.example.com"

    def test_invalid_plain_string_raises(self):
        from src.core.target import Target
        with pytest.raises(ValueError):
            Target("not_a_domain")

    def test_invalid_bare_tld_raises(self):
        from src.core.target import Target
        with pytest.raises(ValueError):
            Target("com")

    def test_invalid_ip_raises(self):
        from src.core.target import Target
        with pytest.raises(ValueError):
            Target("192.168.1.1")

    def test_invalid_with_spaces_raises(self):
        from src.core.target import Target
        with pytest.raises(ValueError):
            Target("example .com")

    def test_wildcard_pattern(self):
        from src.core.target import Target
        t = Target("example.com")
        assert t.wildcard_pattern == "*.example.com"

    def test_str_returns_domain(self):
        from src.core.target import Target
        t = Target("example.com")
        assert str(t) == "example.com"

    def test_dns_failure_sets_none(self):
        from src.core.target import Target
        with patch("socket.gethostbyname", side_effect=Exception("no dns")):
            t = Target("example.com")
        assert t.apex_ip is None


# ─────────────────────────────────────────────────────────────────────────────
# Deduplicator
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplicator:

    def setup_method(self):
        from src.utils.deduplicator import Deduplicator
        self.d = Deduplicator()

    def test_merges_two_lists(self):
        result = self.d.merge([
            ["api.example.com", "mail.example.com"],
            ["dev.example.com", "api.example.com"],
        ])
        assert sorted(result) == ["api.example.com", "dev.example.com", "mail.example.com"]

    def test_deduplicates_exact_duplicates(self):
        result = self.d.merge([
            ["api.example.com", "api.example.com", "api.example.com"]
        ])
        assert result == ["api.example.com"]

    def test_deduplicates_case_insensitive(self):
        result = self.d.merge([["API.EXAMPLE.COM", "api.example.com"]])
        assert result == ["api.example.com"]

    def test_strips_trailing_dot(self):
        result = self.d.merge([["api.example.com."]])
        assert result == ["api.example.com"]

    def test_filters_invalid_entries(self):
        result = self.d.merge([
            ["valid.example.com", "not valid", "", "192.168.1.1", "nodot"]
        ])
        assert result == ["valid.example.com"]

    def test_empty_lists(self):
        assert self.d.merge([[], [], []]) == []

    def test_single_empty_list(self):
        assert self.d.merge([[]]) == []

    def test_output_is_sorted(self):
        result = self.d.merge([["z.example.com", "a.example.com", "m.example.com"]])
        assert result == sorted(result)

    def test_merges_five_lists(self):
        lists = [
            ["a.example.com"],
            ["b.example.com"],
            ["c.example.com"],
            ["a.example.com"],
            ["d.example.com"],
        ]
        result = self.d.merge(lists)
        assert len(result) == 4

    def test_wildcard_subdomain_accepted(self):
        result = self.d.merge([["*.example.com"]])
        assert "*.example.com" in result


# ─────────────────────────────────────────────────────────────────────────────
# Risk Scorer
# ─────────────────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestRiskScorer:

    def setup_method(self):
        from src.scoring.risk_scorer import RiskScorer
        self.scorer = RiskScorer()

    def test_admin_subdomain_high_sensitivity(self):
        hosts = [{"subdomain": "admin.example.com",
                  "status_code": 200, "technologies": []}]
        scores = _run(self.scorer.score_all(hosts, []))
        assert scores["admin.example.com"].sensitivity >= 9

    def test_jenkins_sensitivity(self):
        hosts = [{"subdomain": "jenkins.example.com",
                  "status_code": 200, "technologies": []}]
        scores = _run(self.scorer.score_all(hosts, []))
        risk = scores["jenkins.example.com"]
        assert risk.sensitivity >= 9

    def test_phpmyadmin_critical(self):
        hosts = [{"subdomain": "phpmyadmin.example.com",
                  "status_code": 200, "technologies": ["phpMyAdmin"]}]
        scores = _run(self.scorer.score_all(hosts, []))
        risk = scores["phpmyadmin.example.com"]
        assert risk.overall >= 9
        assert risk.severity == "critical"

    def test_env_endpoint_max_leakage(self):
        hosts = [{"subdomain": "app.example.com",
                  "status_code": 200, "technologies": []}]
        eps = [{"url": "https://app.example.com/.env", "method": "GET"}]
        scores = _run(self.scorer.score_all(hosts, eps))
        assert scores["app.example.com"].data_leakage == 10.0

    def test_git_endpoint_flagged(self):
        hosts = [{"subdomain": "app.example.com",
                  "status_code": 200, "technologies": []}]
        eps = [{"url": "https://app.example.com/.git/config", "method": "GET"}]
        scores = _run(self.scorer.score_all(hosts, eps))
        assert scores["app.example.com"].data_leakage >= 10.0

    def test_swagger_endpoint_flagged(self):
        hosts = [{"subdomain": "api.example.com",
                  "status_code": 200, "technologies": []}]
        eps = [{"url": "https://api.example.com/swagger/index.html",
                "method": "GET"}]
        scores = _run(self.scorer.score_all(hosts, eps))
        risk = scores["api.example.com"]
        assert any("swagger" in f.lower() or "api doc" in f.lower()
                   for f in risk.findings)

    def test_regular_www_info_or_low(self):
        hosts = [{"subdomain": "www.example.com",
                  "status_code": 200, "technologies": []}]
        scores = _run(self.scorer.score_all(hosts, []))
        assert scores["www.example.com"].severity in ("info", "low", "medium")

    def test_auth_gated_reduces_exposure(self):
        hosts = [{"subdomain": "secret.example.com",
                  "status_code": 403, "technologies": []}]
        scores = _run(self.scorer.score_all(hosts, []))
        risk = scores["secret.example.com"]
        assert risk.exposure < 6.0
        assert any("403" in f or "Auth" in f for f in risk.findings)

    def test_risky_tech_raises_attack_surface(self):
        hosts = [{"subdomain": "blog.example.com",
                  "status_code": 200, "technologies": ["WordPress"]}]
        scores = _run(self.scorer.score_all(hosts, []))
        assert scores["blog.example.com"].attack_surface >= 6

    def test_elasticsearch_critical_score(self):
        hosts = [{"subdomain": "elastic.example.com",
                  "status_code": 200, "technologies": ["Elasticsearch"]}]
        scores = _run(self.scorer.score_all(hosts, []))
        risk = scores["elastic.example.com"]
        assert risk.attack_surface >= 9

    def test_findings_list_populated(self):
        hosts = [{"subdomain": "admin.example.com",
                  "status_code": 200, "technologies": ["Jenkins"]}]
        scores = _run(self.scorer.score_all(hosts, []))
        assert len(scores["admin.example.com"].findings) >= 1

    def test_empty_hosts_returns_empty_dict(self):
        assert _run(self.scorer.score_all([], [])) == {}

    def test_severity_thresholds(self):
        from src.scoring.risk_scorer import AssetRisk
        cases = [
            (9.5, "critical"), (7.0, "high"), (5.0, "medium"),
            (2.5, "low"),      (0.0, "info"),
        ]
        for score, expected in cases:
            sev = ("critical" if score >= 9 else "high" if score >= 7 else
                   "medium" if score >= 4 else "low" if score >= 2 else "info")
            assert sev == expected

    def test_multiple_hosts_scored(self, sample_live_hosts, sample_endpoints):
        scores = _run(self.scorer.score_all(sample_live_hosts, sample_endpoints))
        assert len(scores) == len(sample_live_hosts)


# ─────────────────────────────────────────────────────────────────────────────
# BaseScanner helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestBaseScanner:

    def _make_scanner(self, binary="__nonexistent_xyz__"):
        from src.scanners.base import BaseScanner
        from src.core.orchestrator import ScanConfig

        class FakeScanner(BaseScanner):
            name = "fake"
            install_hint = "n/a"
            async def _scan(self, target): return ["found.example.com"]

        s = FakeScanner(ScanConfig(domain="example.com"))
        s.binary = binary
        return s

    def test_unavailable_binary_returns_empty(self):
        scanner = self._make_scanner("__nonexistent_xyz__")
        from src.core.target import Target
        t = Target.__new__(Target)
        t.domain = "example.com"
        t.apex_ip = None
        result = _run(scanner.scan(t))
        assert result == []

    def test_available_binary_calls_scan(self):
        scanner = self._make_scanner("python3")  # python3 always exists
        from src.core.target import Target
        t = Target.__new__(Target)
        t.domain = "example.com"
        t.apex_ip = None
        result = _run(scanner.scan(t))
        assert result == ["found.example.com"]

    def test_parse_lines_keeps_matching_subdomains(self):
        scanner = self._make_scanner()
        raw = "api.example.com\nmail.example.com\nother.org\n"
        result = scanner._parse_lines(raw, "example.com")
        assert "api.example.com" in result
        assert "mail.example.com" in result
        assert "other.org" not in result

    def test_parse_lines_case_insensitive(self):
        scanner = self._make_scanner()
        raw = "API.EXAMPLE.COM\nMAIL.Example.Com\n"
        result = scanner._parse_lines(raw, "example.com")
        assert "api.example.com" in result
        assert "mail.example.com" in result

    def test_parse_lines_deep_subdomain(self):
        scanner = self._make_scanner()
        raw = "a.b.c.example.com\n"
        result = scanner._parse_lines(raw, "example.com")
        assert "a.b.c.example.com" in result

    def test_parse_lines_filters_unrelated(self):
        scanner = self._make_scanner()
        raw = "notexample.com\nexample.com.evil.org\n"
        result = scanner._parse_lines(raw, "example.com")
        assert result == []

    def test_is_available_caches_result(self):
        scanner = self._make_scanner("__nonexistent_xyz__")
        assert scanner.is_available() is False
        assert scanner._available is False
        # Second call should use cache
        assert scanner.is_available() is False


# ─────────────────────────────────────────────────────────────────────────────
# ReportGenerator
# ─────────────────────────────────────────────────────────────────────────────

class TestReportGenerator:

    def _make_result(self):
        from src.core.orchestrator import ScanResult
        return ScanResult(
            domain="example.com",
            started_at="2025-01-01T00:00:00",
            finished_at="2025-01-01T00:05:00",
            subdomains=[
                {"subdomain": "api.example.com",   "url": "https://api.example.com",
                 "status_code": 200, "technologies": ["nginx"], "ip": "1.2.3.4"},
                {"subdomain": "admin.example.com", "url": "https://admin.example.com",
                 "status_code": 200, "technologies": [], "ip": "1.2.3.5"},
            ],
            endpoints=[
                {"url": "https://api.example.com/v1/users", "method": "GET", "status": 200},
                {"url": "https://admin.example.com/.env",   "method": "GET", "status": 200},
            ],
            statistics={
                "total_subdomains": 2, "live_hosts": 2,
                "total_endpoints": 2,  "scan_duration_s": 120.5,
            },
            risk_scores={},
            errors=[],
        )

    def test_json_report_valid(self, tmp_path):
        import json
        from src.utils.reporter import ReportGenerator
        r = _run(ReportGenerator(tmp_path).generate(self._make_result(), ["json"]))
        assert len(r) == 1
        data = json.loads(r[0].read_text())
        assert data["meta"]["domain"] == "example.com"
        assert data["meta"]["author"] == "Pr0fessor SnApe"
        assert data["meta"]["tool"]   == "Fatah2"
        assert len(data["subdomains"]) == 2

    def test_txt_report_contains_domain(self, tmp_path):
        from src.utils.reporter import ReportGenerator
        r = _run(ReportGenerator(tmp_path).generate(self._make_result(), ["txt"]))
        content = r[0].read_text()
        assert "example.com" in content
        assert "Fatah2" in content
        assert "Pr0fessor SnApe" in content

    def test_html_report_contains_banner(self, tmp_path):
        from src.utils.reporter import ReportGenerator
        r = _run(ReportGenerator(tmp_path).generate(self._make_result(), ["html"]))
        content = r[0].read_text()
        assert "FATAH" in content or "Fatah" in content
        assert "Pr0fessor SnApe" in content
        assert "example.com" in content

    def test_all_three_formats(self, tmp_path):
        from src.utils.reporter import ReportGenerator
        r = _run(ReportGenerator(tmp_path).generate(
            self._make_result(), ["json", "txt", "html"]
        ))
        assert len(r) == 3
        exts = {p.suffix for p in r}
        assert exts == {".json", ".txt", ".html"}

    def test_output_dir_created_if_missing(self, tmp_path):
        from src.utils.reporter import ReportGenerator
        new_dir = tmp_path / "new" / "nested" / "dir"
        _run(ReportGenerator(new_dir).generate(self._make_result(), ["txt"]))
        assert new_dir.exists()

    def test_unknown_format_skipped(self, tmp_path):
        from src.utils.reporter import ReportGenerator
        r = _run(ReportGenerator(tmp_path).generate(
            self._make_result(), ["json", "xyz"]
        ))
        assert len(r) == 1
        assert r[0].suffix == ".json"
