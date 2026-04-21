"""WhoisEnricher — enriches apex domain with WHOIS data."""

import logging

logger = logging.getLogger(__name__)


class WhoisEnricher:
    name = "whois"

    def __init__(self, config):
        self.config = config
        self._cache: dict = {}

    async def enrich(self, subdomains: list[dict]) -> list[dict]:
        apex = self.config.domain
        if apex not in self._cache:
            try:
                import whois as python_whois
                w = python_whois.whois(apex)
                self._cache[apex] = {
                    "registrar":       w.registrar,
                    "creation_date":   str(w.creation_date),
                    "expiration_date": str(w.expiration_date),
                    "name_servers":    w.name_servers,
                    "org":             w.org,
                }
            except Exception as exc:
                logger.debug(f"[whois] lookup failed: {exc}")
                self._cache[apex] = {}

        data = self._cache[apex]
        for sd in subdomains:
            sd["whois"] = data
        return subdomains
