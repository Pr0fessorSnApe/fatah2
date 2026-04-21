"""
Fatah2 — shared pytest fixtures.
The `no_real_dns` fixture is autouse so no test ever makes a live DNS call.
"""
import os
import pytest
from pathlib import Path
from unittest.mock import patch


@pytest.fixture(autouse=True)
def no_real_dns():
    """Block all real DNS resolution in every test."""
    with patch("socket.gethostbyname", return_value="93.184.216.34"):
        yield


@pytest.fixture
def sample_config(tmp_path):
    from src.core.orchestrator import ScanConfig
    return ScanConfig(
        domain="example.com",
        output_dir=tmp_path,
        scan_depth="quick",
        concurrency=5,
        timeout=5,
        enable_dns_history=False,
        enable_http_probe=False,
        enable_risk_scoring=False,
        enable_whois=False,
    )


@pytest.fixture
def sample_subdomains():
    return [
        {"subdomain": "www.example.com",     "dns": {}, "history": [], "whois": {}},
        {"subdomain": "api.example.com",     "dns": {}, "history": [], "whois": {}},
        {"subdomain": "admin.example.com",   "dns": {}, "history": [], "whois": {}},
        {"subdomain": "staging.example.com", "dns": {}, "history": [], "whois": {}},
        {"subdomain": "jenkins.example.com", "dns": {}, "history": [], "whois": {}},
    ]


@pytest.fixture
def sample_live_hosts():
    return [
        {
            "subdomain": "www.example.com",
            "url": "https://www.example.com",
            "status_code": 200,
            "technologies": ["nginx"],
            "ip": "93.184.216.34",
        },
        {
            "subdomain": "admin.example.com",
            "url": "https://admin.example.com",
            "status_code": 200,
            "technologies": ["Apache", "WordPress"],
            "ip": "93.184.216.35",
        },
        {
            "subdomain": "jenkins.example.com",
            "url": "https://jenkins.example.com",
            "status_code": 200,
            "technologies": ["Jenkins"],
            "ip": "93.184.216.36",
        },
    ]


@pytest.fixture
def sample_endpoints():
    return [
        {"url": "https://www.example.com/",              "method": "GET",  "status": 200},
        {"url": "https://admin.example.com/login",       "method": "GET",  "status": 200},
        {"url": "https://admin.example.com/.env",        "method": "GET",  "status": 200},
        {"url": "https://admin.example.com/swagger",     "method": "GET",  "status": 200},
        {"url": "https://jenkins.example.com/console",   "method": "GET",  "status": 200},
        {"url": "https://jenkins.example.com/script",    "method": "POST", "status": 200},
    ]


@pytest.fixture
def api_client():
    os.environ["FATAH2_API_TOKEN"] = "test-token-fatah2"
    from fastapi.testclient import TestClient
    from src.api.app import app, _jobs
    _jobs.clear()
    return TestClient(app)


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-token-fatah2"}
