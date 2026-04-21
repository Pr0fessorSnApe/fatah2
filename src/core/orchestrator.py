"""
Fatah2 — ReconOrchestrator
Six-stage async pipeline that coordinates all scanning modules.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    domain:             str
    output_dir:         Path          = Path("reports")
    scan_depth:         str           = "standard"
    concurrency:        int           = 50
    timeout:            int           = 30
    enable_dns_history: bool          = True
    enable_http_probe:  bool          = True
    enable_risk_scoring:bool          = True
    enable_whois:       bool          = True
    wordlist:           Optional[Path]= None
    resolvers:          Optional[Path]= None
    api_keys:           dict          = field(default_factory=dict)
    output_formats:     list          = field(default_factory=lambda: ["json","txt","html"])


@dataclass
class ScanResult:
    domain:       str
    started_at:   str
    finished_at:  str          = ""
    subdomains:   list         = field(default_factory=list)
    endpoints:    list         = field(default_factory=list)
    dns_records:  dict         = field(default_factory=dict)
    whois_data:   dict         = field(default_factory=dict)
    risk_scores:  dict         = field(default_factory=dict)
    statistics:   dict         = field(default_factory=dict)
    errors:       list         = field(default_factory=list)


# ── Stage printer (imports from main only if tty) ─────────────────────────────

def _stage_log(n: int, msg: str):
    """Print a coloured stage header without importing fatah2 at module level."""
    try:
        import sys
        if sys.stdout.isatty():
            print(f"\n\033[1;35m  ══ Stage {n}: {msg}\033[0m")
            return
    except Exception:
        pass
    logger.info(f"Stage {n}: {msg}")

def _sub_log(msg: str):
    try:
        import sys
        if sys.stdout.isatty():
            print(f"\033[0;36m  [*]\033[0m {msg}")
            return
    except Exception:
        pass
    logger.info(msg)


class ReconOrchestrator:
    """
    Fatah2 multi-stage pipeline.

    Stage 1 ─ Passive subdomain discovery
    Stage 2 ─ Active DNS brute-force
    Stage 3 ─ DNS history & WHOIS enrichment
    Stage 4 ─ HTTP probing + Katana endpoint crawl
    Stage 5 ─ AI risk scoring
    Stage 6 ─ Report generation
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(
            domain=config.domain,
            started_at=datetime.utcnow().isoformat(),
        )

        # Lazy imports to avoid circular deps
        from src.scanners.subfinder   import SubfinderScanner
        from src.scanners.sublist3r   import Sublist3rScanner
        from src.scanners.assetfinder import AssetfinderScanner
        from src.scanners.amass       import AmassScanner
        from src.scanners.dns_brute   import DNSBruteScanner
        from src.scanners.katana      import KatanaScanner
        from src.enrichment.dns_history   import DNSHistoryEnricher
        from src.enrichment.whois_enricher import WhoisEnricher
        from src.enrichment.http_probe    import HTTPProber
        from src.scoring.risk_scorer      import RiskScorer
        from src.utils.deduplicator       import Deduplicator
        from src.utils.reporter           import ReportGenerator
        from src.core.target              import Target

        self.target = Target(config.domain)
        self.dedup  = Deduplicator()

        self.passive_scanners = [
            SubfinderScanner(config),
            Sublist3rScanner(config),
            AssetfinderScanner(config),
        ]
        if config.scan_depth in ("standard", "deep"):
            self.passive_scanners.append(AmassScanner(config))

        self.active_scanners = [DNSBruteScanner(config)]
        self.katana          = KatanaScanner(config)

        self.enrichers = []
        if config.enable_dns_history:
            self.enrichers.append(DNSHistoryEnricher(config))
        if config.enable_whois:
            self.enrichers.append(WhoisEnricher(config))

        self.http_prober   = HTTPProber(config) if config.enable_http_probe else None
        self.risk_scorer   = RiskScorer()       if config.enable_risk_scoring else None
        self.reporter      = ReportGenerator(config.output_dir)

    # ── Pipeline ──────────────────────────────────────────────────────────────

    async def run(self) -> ScanResult:
        t0 = time.perf_counter()

        # Stage 1 — Passive discovery
        _stage_log(1, "Passive subdomain discovery")
        passive = await self._run_passive()
        raw = self.dedup.merge(passive)
        _sub_log(f"Passive total: {len(raw)} unique subdomains")

        # Stage 2 — Active brute-force
        if self.config.scan_depth in ("standard", "deep"):
            _stage_log(2, "Active DNS brute-force")
            brute = await self._run_active()
            raw = self.dedup.merge([raw, brute])
            _sub_log(f"Post-brute total: {len(raw)} subdomains")
        else:
            _sub_log("Brute-force skipped (quick depth)")

        # Stage 3 — Enrichment
        _stage_log(3, "DNS history & WHOIS enrichment")
        enriched = await self._enrich(raw)
        _sub_log(f"Enriched {len(enriched)} subdomains")

        # Stage 4 — HTTP probe + crawl
        _stage_log(4, "HTTP probing & endpoint crawl")
        live_hosts, endpoints = await self._probe_and_crawl(enriched)
        _sub_log(f"Live: {len(live_hosts)}  Endpoints: {len(endpoints)}")

        # Stage 5 — Risk scoring
        _stage_log(5, "AI risk scoring")
        risk_scores = {}
        if self.risk_scorer:
            risk_scores = await self.risk_scorer.score_all(live_hosts, endpoints)
            _sub_log(f"Scored {len(risk_scores)} hosts")

        # Finalise
        elapsed = time.perf_counter() - t0
        self.result.subdomains   = enriched
        self.result.endpoints    = endpoints
        self.result.risk_scores  = risk_scores
        self.result.finished_at  = datetime.utcnow().isoformat()
        self.result.statistics   = {
            "total_subdomains": len(enriched),
            "live_hosts":       len(live_hosts),
            "total_endpoints":  len(endpoints),
            "scan_duration_s":  round(elapsed, 2),
        }

        # Stage 6 — Reports
        _stage_log(6, "Generating reports")
        report_paths = await self.reporter.generate(
            self.result, self.config.output_formats
        )
        for p in report_paths:
            _sub_log(f"Report → {p}")

        return self.result

    # ── Internals ─────────────────────────────────────────────────────────────

    async def _run_passive(self) -> list[list[str]]:
        tasks = [s.scan(self.target) for s in self.passive_scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for scanner, res in zip(self.passive_scanners, results):
            if isinstance(res, Exception):
                logger.warning(f"[{scanner.name}] error: {res}")
                self.result.errors.append(f"{scanner.name}: {res}")
            else:
                _sub_log(f"[{scanner.name}] → {len(res)} subdomains")
                out.append(res)
        return out

    async def _run_active(self) -> list[str]:
        results = await asyncio.gather(
            *[s.scan(self.target) for s in self.active_scanners],
            return_exceptions=True,
        )
        merged = []
        for res in results:
            if not isinstance(res, Exception):
                merged.extend(res)
        return merged

    async def _enrich(self, subdomains: list[str]) -> list[dict]:
        enriched = [
            {"subdomain": s, "dns": {}, "history": [], "whois": {}}
            for s in subdomains
        ]
        for enricher in self.enrichers:
            try:
                enriched = await enricher.enrich(enriched)
            except Exception as exc:
                logger.warning(f"[{enricher.name}] enrichment error: {exc}")
        return enriched

    async def _probe_and_crawl(self, enriched: list[dict]):
        live_hosts, endpoints = [], []
        if self.http_prober:
            live_hosts = await self.http_prober.probe(enriched)
        if live_hosts and self.katana:
            endpoints = await self.katana.crawl(live_hosts)
        return live_hosts, endpoints
