"""Assetfinder wrapper — https://github.com/tomnomnom/assetfinder"""

from src.core.target import Target
from src.scanners.base import BaseScanner


class AssetfinderScanner(BaseScanner):
    name         = "assetfinder"
    binary       = "assetfinder"
    install_hint = "go install github.com/tomnomnom/assetfinder@latest"

    async def _scan(self, target: Target) -> list[str]:
        flags = ["--subs-only"] if self.config.scan_depth != "deep" else []
        raw = await self._run_cmd(["assetfinder", *flags, str(target)])
        return self._parse_lines(raw, str(target))
