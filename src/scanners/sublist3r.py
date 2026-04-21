"""Sublist3r wrapper — https://github.com/aboul3la/Sublist3r"""

from src.core.target import Target
from src.scanners.base import BaseScanner


class Sublist3rScanner(BaseScanner):
    name         = "sublist3r"
    binary       = "sublist3r"
    install_hint = "pip install sublist3r"

    async def _scan(self, target: Target) -> list[str]:
        cmd = ["sublist3r", "-d", str(target), "-o", "/dev/stdout", "-n"]
        if self.config.scan_depth == "deep":
            cmd += ["-b"]
        raw = await self._run_cmd(cmd)
        return self._parse_lines(raw, str(target))
