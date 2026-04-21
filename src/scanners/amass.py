"""Amass wrapper — https://github.com/owasp-amass/amass"""

import logging
import tempfile
from pathlib import Path

from src.core.target import Target
from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class AmassScanner(BaseScanner):
    name         = "amass"
    binary       = "amass"
    install_hint = "go install -v github.com/owasp-amass/amass/v4/...@master"

    async def _scan(self, target: Target) -> list[str]:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            out_path = Path(tmp.name)

        depth_flags = {
            "quick":    ["-passive"],
            "standard": ["-passive"],
            "deep":     [],
        }

        cmd = [
            "amass", "enum",
            "-d", str(target),
            "-o", str(out_path),
            *depth_flags.get(self.config.scan_depth, ["-passive"]),
            "-timeout", str(max(self.config.timeout, 30)),
        ]

        await self._run_cmd(cmd, timeout=self.config.timeout * 20)

        subdomains = []
        if out_path.exists():
            try:
                subdomains = [
                    line.strip().lower()
                    for line in out_path.read_text().splitlines()
                    if line.strip().endswith(f".{target}") or line.strip() == str(target)
                ]
            finally:
                out_path.unlink(missing_ok=True)

        return sorted(set(subdomains))
