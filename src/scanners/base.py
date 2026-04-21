"""BaseScanner — abstract interface all tool wrappers implement."""

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    name:         str = "base"
    binary:       str = ""
    install_hint: str = ""

    def __init__(self, config):
        self.config = config
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        if self._available is None:
            self._available = bool(shutil.which(self.binary))
            if not self._available:
                logger.debug(
                    f"[{self.name}] '{self.binary}' not found — "
                    f"install: {self.install_hint}"
                )
        return self._available

    async def scan(self, target) -> list[str]:
        if not self.is_available():
            return []
        try:
            return await self._scan(target)
        except Exception as exc:
            logger.error(f"[{self.name}] scan error: {exc}")
            return []

    @abstractmethod
    async def _scan(self, target) -> list[str]: ...

    async def _run_cmd(self, cmd: list[str], timeout: Optional[int] = None) -> str:
        t = timeout or self.config.timeout * 10
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=t)
            return stdout.decode(errors="replace")
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] timed out after {t}s")
            return ""
        except FileNotFoundError:
            self._available = False
            return ""

    @staticmethod
    def _parse_lines(raw: str, domain: str) -> list[str]:
        results = set()
        for line in raw.splitlines():
            line = line.strip().lower()
            if line.endswith(f".{domain}") or line == domain:
                results.add(line)
        return sorted(results)
