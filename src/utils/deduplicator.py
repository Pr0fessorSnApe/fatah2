"""Deduplicator — merge, validate, and deduplicate subdomain lists."""

import re

VALID_RE = re.compile(
    r"^(?:[a-zA-Z0-9*](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class Deduplicator:
    def merge(self, result_lists: list[list[str]]) -> list[str]:
        seen = set()
        for lst in result_lists:
            for item in lst:
                cleaned = item.strip().lower().rstrip(".")
                if cleaned and VALID_RE.match(cleaned):
                    seen.add(cleaned)
        return sorted(seen)
