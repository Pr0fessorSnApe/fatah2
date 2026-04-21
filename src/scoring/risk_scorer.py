"""
RiskScorer — heuristic AI risk scoring engine.

Four scoring dimensions (each 0–10):
  exposure       — HTTP reachability & response code
  sensitivity    — subdomain name patterns (admin, jenkins, db, etc.)
  attack_surface — technology stack known-vulnerability risk
  data_leakage   — sensitive endpoint patterns (.env, /swagger, /.git, etc.)

Severity:  critical (≥9) · high (≥7) · medium (≥4) · low (≥2) · info
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Pattern libraries ─────────────────────────────────────────────────────────

SENSITIVE_SUBDOMAINS = [
    (r"\badmin\b",            9,  "Admin panel"),
    (r"\bapi\b",              7,  "API service"),
    (r"\bdev\b",              8,  "Development environment"),
    (r"\bstaging\b",          8,  "Staging environment"),
    (r"\btest\b",             7,  "Test environment"),
    (r"\binternal\b",         9,  "Internal service"),
    (r"\bvpn\b",              8,  "VPN gateway"),
    (r"\bmail\b",             6,  "Mail server"),
    (r"\bftp\b",              7,  "FTP server"),
    (r"\bjenkins\b",          9,  "CI/CD — Jenkins"),
    (r"\bjira\b",             7,  "Project tracker — Jira"),
    (r"\bconfluence\b",       7,  "Internal wiki — Confluence"),
    (r"\bgitlab\b",           8,  "Source code — GitLab"),
    (r"\bbackup\b",           9,  "Backup service"),
    (r"\bdb\b|\bdatabase\b",  9,  "Database service"),
    (r"\bphpmyadmin\b",       10, "phpMyAdmin exposed"),
    (r"\bkibana\b",           9,  "Kibana dashboard"),
    (r"\bgrafana\b",          8,  "Grafana dashboard"),
    (r"\belastic\b",          8,  "Elasticsearch"),
    (r"\bredis\b",            9,  "Redis service"),
    (r"\bmongo\b",            9,  "MongoDB service"),
    (r"\bk8s\b|\bkubernetes\b", 9, "Kubernetes cluster"),
    (r"\bprod\b|\bproduction\b", 7, "Production environment"),
    (r"\blegacy\b|\bold\b",   7,  "Legacy / old system"),
    (r"\bssh\b",              8,  "SSH service"),
    (r"\bportainer\b",        9,  "Portainer (Docker UI)"),
    (r"\bsonar\b",            8,  "SonarQube"),
    (r"\bvault\b",            9,  "Vault secrets manager"),
]

SENSITIVE_ENDPOINTS = [
    (r"\.env$",                    10, ".env file exposure"),
    (r"/\.git(/|$)",               10, "Git directory exposed"),
    (r"/admin",                     9, "Admin path"),
    (r"/api/v\d",                   7, "Versioned API"),
    (r"/swagger|/openapi|/redoc",   8, "API docs exposed"),
    (r"/actuator",                  9, "Spring Boot actuator"),
    (r"/__debug__|/debug",          9, "Debug endpoint"),
    (r"/phpinfo",                  10, "PHP info page"),
    (r"/server-status",             9, "Apache server-status"),
    (r"/wp-admin",                  8, "WordPress admin"),
    (r"/phpmyadmin",               10, "phpMyAdmin path"),
    (r"/config(\.php|\.json|$)",    8, "Config file/path"),
    (r"/backup",                    9, "Backup path"),
    (r"/upload",                    7, "Upload endpoint"),
    (r"graphql",                    7, "GraphQL endpoint"),
    (r"/console",                   9, "Web console"),
    (r"/manager",                   9, "Tomcat manager"),
    (r"\.bak$|\.old$|\.orig$",      9, "Backup file extension"),
    (r"/etc/passwd|/etc/shadow",   10, "Path traversal indicator"),
    (r"/_profiler",                 8, "Symfony profiler"),
    (r"/telescope",                 8, "Laravel Telescope"),
    (r"/horizon",                   8, "Laravel Horizon"),
    (r"/metrics",                   7, "Metrics endpoint"),
    (r"/health",                    5, "Health endpoint"),
    (r"/trace",                     7, "Trace endpoint"),
]

RISKY_TECH = {
    "WordPress":        6,
    "Drupal":           7,
    "Joomla":           7,
    "phpMyAdmin":      10,
    "Apache":           4,
    "nginx":            3,
    "Tomcat":           6,
    "Jenkins":          9,
    "Kibana":           9,
    "Grafana":          8,
    "Elasticsearch":    9,
    "MongoDB":          8,
    "Redis":            8,
    "Portainer":        9,
    "SonarQube":        8,
    "Struts":           9,
    "Laravel":          5,
    "Symfony":          5,
    "Spring Boot":      6,
}


@dataclass
class AssetRisk:
    subdomain:      str
    overall:        float       = 0.0
    exposure:       float       = 0.0
    sensitivity:    float       = 0.0
    attack_surface: float       = 0.0
    data_leakage:   float       = 0.0
    findings:       list[str]   = field(default_factory=list)
    severity:       str         = "info"


class RiskScorer:
    """Fully offline heuristic risk scorer."""

    async def score_all(
        self,
        live_hosts: list[dict],
        endpoints:  list[dict],
    ) -> dict[str, AssetRisk]:

        # Build endpoint-per-host map
        ep_map: dict[str, list[dict]] = {}
        for ep in endpoints:
            url = ep.get("url", "")
            for h in live_hosts:
                if h.get("subdomain", "") in url:
                    ep_map.setdefault(h["subdomain"], []).append(ep)
                    break

        tasks = [
            self._score_host(h, ep_map.get(h.get("subdomain", ""), []))
            for h in live_hosts
        ]
        results = await asyncio.gather(*tasks)
        return {r.subdomain: r for r in results}

    async def _score_host(self, host: dict, endpoints: list[dict]) -> AssetRisk:
        sd   = host.get("subdomain", "unknown")
        risk = AssetRisk(subdomain=sd)

        # ── Sensitivity ───────────────────────────────────────────────────────
        for pattern, score, label in SENSITIVE_SUBDOMAINS:
            if re.search(pattern, sd, re.IGNORECASE):
                risk.sensitivity = max(risk.sensitivity, score)
                risk.findings.append(f"Sensitive subdomain: {label}")

        # ── Exposure ──────────────────────────────────────────────────────────
        status = host.get("status_code")
        if status == 200:
            risk.exposure = 6.0
        elif status in (401, 403):
            risk.exposure = 4.0
            risk.findings.append(f"Auth-gated resource (HTTP {status})")
        elif status in (500, 502, 503):
            risk.exposure = 3.0
            risk.findings.append(f"Server error (HTTP {status}) — possible info leak")
        elif status and 300 <= status < 400:
            risk.exposure = 2.0

        # ── Attack surface (tech stack) ───────────────────────────────────────
        for tech in host.get("technologies", []):
            for known, score in RISKY_TECH.items():
                if known.lower() in tech.lower():
                    if score > risk.attack_surface:
                        risk.attack_surface = score
                        risk.findings.append(f"Technology detected: {known}")

        # ── Data leakage (endpoints) ──────────────────────────────────────────
        seen_findings: set[str] = set()
        for ep in endpoints:
            url = ep.get("url", "")
            for pattern, score, label in SENSITIVE_ENDPOINTS:
                if re.search(pattern, url, re.IGNORECASE):
                    if label not in seen_findings:
                        risk.data_leakage = max(risk.data_leakage, score)
                        risk.findings.append(f"Endpoint: {label}  →  {url[:80]}")
                        seen_findings.add(label)

        # ── Aggregate ─────────────────────────────────────────────────────────
        scores = [risk.exposure, risk.sensitivity, risk.attack_surface, risk.data_leakage]
        nonzero = [s for s in scores if s > 0]
        risk.overall = round(
            max(scores) * 0.5 + (sum(nonzero) / len(nonzero) if nonzero else 0) * 0.5,
            1,
        )
        risk.severity = (
            "critical" if risk.overall >= 9 else
            "high"     if risk.overall >= 7 else
            "medium"   if risk.overall >= 4 else
            "low"      if risk.overall >= 2 else
            "info"
        )
        return risk
