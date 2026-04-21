"""
DNSHistoryEnricher — historical DNS records via HackerTarget (free)
and SecurityTrails (API key optional).
"""

import asyncio
import logging

logger = logging.getLogger(__name__)


class DNSHistoryEnricher:
    name = "dns_history"

    def __init__(self, config):
        self.config = config
        self.st_key = config.api_keys.get("securitytrails")

    async def enrich(self, subdomains: list[dict]) -> list[dict]:
        try:
            import aiohttp
        except ImportError:
            logger.warning("[dns_history] aiohttp not installed; skipping")
            return subdomains

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": "Fatah2/2.0 (+authorized-scan)"}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            tasks = [self._enrich_one(session, sd) for sd in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        out = []
        for original, result in zip(subdomains, results):
            out.append(original if isinstance(result, Exception) else result)
        return out

    async def _enrich_one(self, session, sd: dict) -> dict:
        host = sd["subdomain"]
        sd["dns"]["current"] = await self._hackertarget(session, host)
        if self.st_key:
            sd["history"] = await self._securitytrails(session, host)
        return sd

    async def _hackertarget(self, session, host: str) -> dict:
        url = f"https://api.hackertarget.com/dnslookup/?q={host}"
        records: dict[str, list] = {}
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    for line in (await resp.text()).splitlines():
                        parts = line.split()
                        if len(parts) >= 4:
                            rtype = parts[3]
                            rdata = " ".join(parts[4:]) if len(parts) > 4 else ""
                            records.setdefault(rtype, []).append(rdata)
        except Exception as exc:
            logger.debug(f"[dns_history] hackertarget error for {host}: {exc}")
        return records

    async def _securitytrails(self, session, host: str) -> list[dict]:
        url = f"https://api.securitytrails.com/v1/history/{host}/dns/a"
        history = []
        try:
            async with session.get(url, headers={"apikey": self.st_key}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for rec in data.get("records", []):
                        history.append({
                            "type":       "A",
                            "first_seen": rec.get("first_seen"),
                            "last_seen":  rec.get("last_seen"),
                            "values":     [v.get("ip") for v in rec.get("values", [])],
                        })
        except Exception as exc:
            logger.debug(f"[dns_history] securitytrails error for {host}: {exc}")
        return history
