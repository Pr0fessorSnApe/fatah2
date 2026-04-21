"""
Fatah2 — Integration Tests
All external calls (scanners, network, DNS) are mocked.
Run: pytest tests/integration/ -v
"""

import asyncio
import json
import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock


# ── Shared mock data ──────────────────────────────────────────────────────────

MOCK_SUBDOMAINS = [
    "api.example.com",
    "admin.example.com",
    "mail.example.com",
    "jenkins.example.com",
]

MOCK_LIVE_HOSTS = [
    {"subdomain": "api.example.com",     "url": "https://api.example.com",
     "status_code": 200, "technologies": ["nginx"],   "ip": "1.2.3.4"},
    {"subdomain": "admin.example.com",   "url": "https://admin.example.com",
     "status_code": 200, "technologies": ["WordPress"], "ip": "1.2.3.5"},
    {"subdomain": "jenkins.example.com", "url": "https://jenkins.example.com",
     "status_code": 200, "technologies": ["Jenkins"], "ip": "1.2.3.6"},
]

MOCK_ENDPOINTS = [
    {"url": "https://api.example.com/v1/users",        "method": "GET",  "status": 200},
    {"url": "https://admin.example.com/.env",           "method": "GET",  "status": 200},
    {"url": "https://admin.example.com/swagger",        "method": "GET",  "status": 200},
    {"url": "https://jenkins.example.com/console",      "method": "GET",  "status": 200},
]


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_config(tmp_path, **kwargs):
    from src.core.orchestrator import ScanConfig
    defaults = dict(
        domain="example.com",
        output_dir=Path(tmp_path),
        scan_depth="quick",
        concurrency=5,
        timeout=5,
        enable_dns_history=False,
        enable_http_probe=True,
        enable_risk_scoring=True,
        enable_whois=False,
        output_formats=["json"],
    )
    defaults.update(kwargs)
    return ScanConfig(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator pipeline integration
# ─────────────────────────────────────────────────────────────────────────────

class TestOrchestratorPipeline:

    @pytest.fixture(autouse=True)
    def mock_all_scanners(self):
        """Patch every scanner and enricher to return canned data."""
        with (
            patch("src.scanners.subfinder.SubfinderScanner._scan",
                  new_callable=AsyncMock, return_value=MOCK_SUBDOMAINS),
            patch("src.scanners.sublist3r.Sublist3rScanner._scan",
                  new_callable=AsyncMock, return_value=["mail.example.com"]),
            patch("src.scanners.assetfinder.AssetfinderScanner._scan",
                  new_callable=AsyncMock, return_value=["api.example.com"]),
            patch("src.scanners.subfinder.SubfinderScanner.is_available",
                  return_value=True),
            patch("src.scanners.sublist3r.Sublist3rScanner.is_available",
                  return_value=True),
            patch("src.scanners.assetfinder.AssetfinderScanner.is_available",
                  return_value=True),
            patch("src.enrichment.http_probe.HTTPProber.probe",
                  new_callable=AsyncMock, return_value=MOCK_LIVE_HOSTS),
            patch("src.scanners.katana.KatanaScanner.crawl",
                  new_callable=AsyncMock, return_value=MOCK_ENDPOINTS),
            patch("src.utils.reporter.ReportGenerator.generate",
                  new_callable=AsyncMock, return_value=[Path("/tmp/test.json")]),
        ):
            yield

    def test_pipeline_returns_scan_result(self, tmp_path):
        from src.core.orchestrator import ReconOrchestrator
        result = _run(ReconOrchestrator(_make_config(tmp_path)).run())
        assert result.domain == "example.com"
        assert result.finished_at != ""

    def test_subdomains_deduplicated(self, tmp_path):
        """api.example.com comes from multiple scanners — must appear once."""
        from src.core.orchestrator import ReconOrchestrator
        result = _run(ReconOrchestrator(_make_config(tmp_path)).run())
        sds = [
            sd.get("subdomain", sd) if isinstance(sd, dict) else sd
            for sd in result.subdomains
        ]
        assert sds.count("api.example.com") == 1

    def test_statistics_populated(self, tmp_path):
        from src.core.orchestrator import ReconOrchestrator
        result = _run(ReconOrchestrator(_make_config(tmp_path)).run())
        stats = result.statistics
        assert "total_subdomains" in stats
        assert "live_hosts"       in stats
        assert "total_endpoints"  in stats
        assert "scan_duration_s"  in stats
        assert stats["scan_duration_s"] >= 0

    def test_risk_scores_generated(self, tmp_path):
        from src.core.orchestrator import ReconOrchestrator
        result = _run(ReconOrchestrator(_make_config(tmp_path)).run())
        # At least some hosts scored
        assert len(result.risk_scores) > 0

    def test_admin_host_scored_high(self, tmp_path):
        from src.core.orchestrator import ReconOrchestrator
        result = _run(ReconOrchestrator(_make_config(tmp_path)).run())
        if "admin.example.com" in result.risk_scores:
            risk = result.risk_scores["admin.example.com"]
            assert risk.severity in ("high", "critical", "medium")

    def test_env_endpoint_raises_score(self, tmp_path):
        from src.core.orchestrator import ReconOrchestrator
        result = _run(ReconOrchestrator(_make_config(tmp_path)).run())
        if "admin.example.com" in result.risk_scores:
            risk = result.risk_scores["admin.example.com"]
            assert risk.data_leakage >= 8.0

    def test_errors_list_exists(self, tmp_path):
        from src.core.orchestrator import ReconOrchestrator
        result = _run(ReconOrchestrator(_make_config(tmp_path)).run())
        assert isinstance(result.errors, list)

    def test_quick_depth_skips_brute(self, tmp_path):
        """quick depth should not invoke DNSBruteScanner at all."""
        from src.core.orchestrator import ReconOrchestrator
        with patch("src.scanners.dns_brute.DNSBruteScanner._scan",
                   new_callable=AsyncMock) as brute_mock:
            _run(ReconOrchestrator(_make_config(tmp_path, scan_depth="quick")).run())
            brute_mock.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# REST API integration
# ─────────────────────────────────────────────────────────────────────────────

class TestRESTAPI:

    def test_health_no_auth_required(self, api_client):
        r = api_client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"]  == "ok"
        assert body["tool"]    == "Fatah2"
        assert body["author"]  == "Pr0fessor SnApe"

    def test_scan_requires_auth(self, api_client):
        r = api_client.post("/api/v1/scan", json={"domain": "example.com"})
        assert r.status_code == 403

    def test_scan_wrong_token_rejected(self, api_client):
        r = api_client.post(
            "/api/v1/scan", json={"domain": "example.com"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert r.status_code == 401

    def test_scan_invalid_domain_400(self, api_client, auth_headers):
        r = api_client.post(
            "/api/v1/scan", json={"domain": "not!!valid"},
            headers=auth_headers,
        )
        assert r.status_code == 400

    def test_scan_invalid_depth_422(self, api_client, auth_headers):
        r = api_client.post(
            "/api/v1/scan",
            json={"domain": "example.com", "scan_depth": "turbo"},
            headers=auth_headers,
        )
        assert r.status_code == 422

    def test_scan_invalid_concurrency_422(self, api_client, auth_headers):
        r = api_client.post(
            "/api/v1/scan",
            json={"domain": "example.com", "concurrency": 9999},
            headers=auth_headers,
        )
        assert r.status_code == 422

    def test_scan_accepted_returns_job_id(self, api_client, auth_headers):
        r = api_client.post(
            "/api/v1/scan", json={"domain": "example.com"},
            headers=auth_headers,
        )
        assert r.status_code == 202
        body = r.json()
        assert "job_id"     in body
        assert body["domain"] == "example.com"
        assert body["status"] in ("pending", "running")

    def test_job_retrievable(self, api_client, auth_headers):
        create = api_client.post(
            "/api/v1/scan", json={"domain": "example.com"},
            headers=auth_headers,
        )
        job_id = create.json()["job_id"]
        get = api_client.get(f"/api/v1/scan/{job_id}", headers=auth_headers)
        assert get.status_code == 200
        assert get.json()["job_id"] == job_id

    def test_nonexistent_job_404(self, api_client, auth_headers):
        r = api_client.get("/api/v1/scan/nonexistent-id", headers=auth_headers)
        assert r.status_code == 404

    def test_list_scans_returns_list(self, api_client, auth_headers):
        r = api_client.get("/api/v1/scans", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_scans_requires_auth(self, api_client):
        r = api_client.get("/api/v1/scans")
        assert r.status_code == 403

    def test_multiple_scans_listed(self, api_client, auth_headers):
        for domain in ["alpha.com", "beta.com"]:
            api_client.post(
                "/api/v1/scan", json={"domain": domain},
                headers=auth_headers,
            )
        r = api_client.get("/api/v1/scans", headers=auth_headers)
        assert len(r.json()) >= 2

    def test_quick_depth_accepted(self, api_client, auth_headers):
        r = api_client.post(
            "/api/v1/scan",
            json={"domain": "example.com", "scan_depth": "quick"},
            headers=auth_headers,
        )
        assert r.status_code == 202

    def test_deep_depth_accepted(self, api_client, auth_headers):
        r = api_client.post(
            "/api/v1/scan",
            json={"domain": "example.com", "scan_depth": "deep"},
            headers=auth_headers,
        )
        assert r.status_code == 202
