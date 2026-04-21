"""
HTTPProber — probe subdomains for live HTTP/S services.
Uses httpx binary (ProjectDiscovery) or Python httpx fallback.
"""

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return m.group(1).strip()[:120] if m else ""


class HTTPProber:
    name = "http_probe"

    def __init__(self, config):
        self.config = config
        self._has_binary = bool(shutil.which("httpx"))

    async def probe(self, subdomains: list[dict]) -> list[dict]:
        if not subdomains:
            return []
        if self._has_binary:
            return await self._probe_binary(subdomains)
        return await self._probe_python(subdomains)

    # ── httpx binary ─────────────────────────────────────────────────────────

    async def _probe_binary(self, subdomains: list[dict]) -> list[dict]:
        hosts = [sd["subdomain"] for sd in subdomains]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hosts))
            in_path = Path(f.name)
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            out_path = Path(f.name)

        cmd = [
            "httpx", "-l", str(in_path), "-o", str(out_path),
            "-json", "-silent",
            "-threads", str(min(self.config.concurrency, 50)),
            "-timeout", str(self.config.timeout),
            "-follow-redirects", "-tech-detect", "-title",
            "-status-code", "-content-length",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()

        live = []
        host_map = {sd["subdomain"]: sd for sd in subdomains}

        if out_path.exists():
            for line in out_path.read_text().splitlines():
                try:
                    obj = json.loads(line)
                    host = obj.get("host", "").lower()
                    entry = dict(host_map.get(host, {"subdomain": host}))
                    entry.update({
                        "url":            obj.get("url", f"https://{host}"),
                        "status_code":    obj.get("status-code"),
                        "title":          obj.get("title", ""),
                        "content_length": obj.get("content-length"),
                        "technologies":   obj.get("tech", []),
                        "ip":             obj.get("ip", ""),
                    })
                    live.append(entry)
                except json.JSONDecodeError:
                    pass
            out_path.unlink(missing_ok=True)
        in_path.unlink(missing_ok=True)

        logger.info(f"[http_probe/binary] → {len(live)} live hosts")
        return live

    # ── Python httpx fallback ─────────────────────────────────────────────────

    async def _probe_python(self, subdomains: list[dict]) -> list[dict]:
        try:
            import httpx as _httpx
        except ImportError:
            logger.warning("[http_probe] httpx not installed; skipping HTTP probe")
            return []

        sem = asyncio.Semaphore(self.config.concurrency)
        live = []

        async def check(sd: dict):
            host = sd["subdomain"]
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                async with sem:
                    try:
                        async with _httpx.AsyncClient(
                            timeout=self.config.timeout,
                            follow_redirects=True,
                            verify=False,
                        ) as client:
                            resp = await client.get(url)
                            entry = dict(sd)
                            entry.update({
                                "url":          str(resp.url),
                                "status_code":  resp.status_code,
                                "title":        _extract_title(resp.text),
                                "technologies": [],
                                "ip":           "",
                            })
                            live.append(entry)
                            return
                    except Exception:
                        pass

        await asyncio.gather(*[check(sd) for sd in subdomains])
        logger.info(f"[http_probe/python] → {len(live)} live hosts")
        return live
