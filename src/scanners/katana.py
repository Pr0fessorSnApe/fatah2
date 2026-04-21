"""Katana endpoint crawler — https://github.com/projectdiscovery/katana"""

import json
import logging
import tempfile
from pathlib import Path

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class KatanaScanner(BaseScanner):
    name         = "katana"
    binary       = "katana"
    install_hint = "go install github.com/projectdiscovery/katana/cmd/katana@latest"

    async def crawl(self, live_hosts: list[dict]) -> list[dict]:
        if not self.is_available() or not live_hosts:
            return []

        urls = [h.get("url", "") for h in live_hosts if h.get("url")]
        if not urls:
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(urls))
            targets_path = Path(tf.name)

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as of:
            out_path = Path(of.name)

        depth = {"quick": 1, "standard": 2, "deep": 4}.get(
            self.config.scan_depth, 2
        )
        cmd = [
            "katana",
            "-list", str(targets_path),
            "-o", str(out_path),
            "-jsonl", "-silent",
            "-d", str(depth),
            "-c", str(min(self.config.concurrency, 20)),
            "-timeout", str(self.config.timeout),
            "-js-crawl",
            "-form-extraction",
        ]
        await self._run_cmd(cmd, timeout=self.config.timeout * 30)

        endpoints = []
        if out_path.exists():
            try:
                for line in out_path.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                        endpoints.append({
                            "url":    obj.get("request", {}).get("endpoint", ""),
                            "method": obj.get("request", {}).get("method", "GET"),
                            "source": obj.get("request", {}).get("source", ""),
                            "status": obj.get("response", {}).get("status_code"),
                            "tags":   obj.get("request", {}).get("tag", []),
                        })
                    except json.JSONDecodeError:
                        endpoints.append({"url": line.strip(), "method": "GET"})
            finally:
                out_path.unlink(missing_ok=True)
                targets_path.unlink(missing_ok=True)

        logger.info(f"[katana] → {len(endpoints)} endpoints")
        return endpoints

    async def _scan(self, target):
        return []
