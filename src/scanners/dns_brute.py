"""
DNSBruteScanner — async DNS brute-force.
Uses massdns binary (fast) or dnspython (pure-Python fallback).
"""

import asyncio
import logging
from pathlib import Path

from src.core.target import Target
from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Bundled wordlist path
_WL = Path(__file__).parent.parent.parent / "configs" / "wordlists" / "subdomains.txt"


class DNSBruteScanner(BaseScanner):
    name         = "dns_brute"
    binary       = "massdns"
    install_hint = "apt install massdns  OR  pacman -S massdns"

    RTYPES = ("A", "AAAA", "CNAME")

    async def _scan(self, target: Target) -> list[str]:
        wl = self.config.wordlist or _WL
        if not Path(wl).exists():
            logger.warning(f"[dns_brute] wordlist not found: {wl}")
            return []

        words = [
            w.strip() for w in Path(wl).read_text().splitlines()
            if w.strip() and not w.startswith("#")
        ]

        if self.is_available():
            return await self._massdns(target, words)

        try:
            import dns.asyncresolver  # noqa
            return await self._python_brute(target, words)
        except ImportError:
            logger.warning("[dns_brute] neither massdns nor dnspython available")
            return []

    # ── massdns (fast) ────────────────────────────────────────────────────────

    async def _massdns(self, target: Target, words: list[str]) -> list[str]:
        import tempfile
        candidates = "\n".join(f"{w}.{target}" for w in words)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(candidates)
            in_path = Path(f.name)
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            out_path = Path(f.name)

        resolvers = self.config.resolvers or (
            Path(__file__).parent.parent.parent / "configs" / "resolvers.txt"
        )

        cmd = ["massdns", "-r", str(resolvers), "-t", "A", "-o", "S",
               str(in_path), "-w", str(out_path)]
        await self._run_cmd(cmd, timeout=600)

        found = set()
        if out_path.exists():
            for line in out_path.read_text().splitlines():
                parts = line.split()
                if parts:
                    host = parts[0].rstrip(".").lower()
                    if host.endswith(f".{target}"):
                        found.add(host)
            out_path.unlink(missing_ok=True)
        in_path.unlink(missing_ok=True)
        return sorted(found)

    # ── dnspython async (moderate speed) ─────────────────────────────────────

    async def _python_brute(self, target: Target, words: list[str]) -> list[str]:
        import dns.asyncresolver
        import dns.exception

        sem = asyncio.Semaphore(self.config.concurrency)
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        async def resolve(word: str) -> str | None:
            fqdn = f"{word}.{target}"
            async with sem:
                for rtype in self.RTYPES:
                    try:
                        await resolver.resolve(fqdn, rtype)
                        return fqdn
                    except Exception:
                        continue
            return None

        results = await asyncio.gather(*[resolve(w) for w in words])
        return sorted({r for r in results if r})
