"""Target — validated domain wrapper."""

import re
import socket
from dataclasses import dataclass

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


@dataclass
class Target:
    raw: str

    def __post_init__(self):
        self.domain = (
            self.raw.strip().lower()
            .removeprefix("http://")
            .removeprefix("https://")
            .split("/")[0]
        )
        if not DOMAIN_RE.match(self.domain):
            raise ValueError(f"Invalid domain: '{self.domain}'")
        try:
            self.apex_ip = socket.gethostbyname(self.domain)
        except Exception:
            self.apex_ip = None

    @property
    def wildcard_pattern(self) -> str:
        return f"*.{self.domain}"

    def __str__(self) -> str:
        return self.domain
