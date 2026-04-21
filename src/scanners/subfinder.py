"""Subfinder wrapper — https://github.com/projectdiscovery/subfinder"""

import json
import logging
import tempfile
from pathlib import Path

from src.core.target import Target
from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class SubfinderScanner(BaseScanner):
    name         = "subfinder"
    binary       = "subfinder"
    install_hint = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    async def _scan(self, target: Target) -> list[str]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = Path(tmp.name)

        cmd = [
            "subfinder", "-d", str(target),
            "-o", str(out_path), "-oJ",
            "-silent",
            "-t", str(self.config.concurrency),
            "-timeout", str(self.config.timeout),
        ]
        if self.config.scan_depth == "deep":
            cmd += ["-all"]

        provider_cfg = self._build_provider_config()
        if provider_cfg:
            cmd += ["-provider-config", provider_cfg]

        await self._run_cmd(cmd)

        subdomains = []
        if out_path.exists():
            try:
                for line in out_path.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        host = json.loads(line).get("host", "")
                    except json.JSONDecodeError:
                        host = line
                    if host:
                        subdomains.append(host.lower())
            finally:
                out_path.unlink(missing_ok=True)

        return sorted(set(subdomains))

    def _build_provider_config(self) -> str | None:
        keys = self.config.api_keys
        if not any(k in keys for k in ("virustotal","shodan","censys_id","github")):
            return None
        try:
            import yaml, tempfile
            cfg = {}
            if "virustotal" in keys:
                cfg["virustotal"] = [keys["virustotal"]]
            if "shodan" in keys:
                cfg["shodan"] = [keys["shodan"]]
            if "censys_id" in keys and "censys_secret" in keys:
                cfg["censys"] = [f"{keys['censys_id']}:{keys['censys_secret']}"]
            if "github" in keys:
                cfg["github"] = [keys["github"]]
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
            yaml.dump(cfg, f)
            f.close()
            return f.name
        except Exception:
            return None
