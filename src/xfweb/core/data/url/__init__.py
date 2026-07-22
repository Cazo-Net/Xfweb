"""URL parsing utilities for Xfweb."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Url:
    """Parsed URL representation."""

    scheme: str
    hostname: str
    port: int
    path: str
    query: str = ""
    fragment: str = ""
    raw_url: str = ""

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.hostname}:{self.port}" if self.port not in (80, 443) else f"{self.scheme}://{self.hostname}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.hostname}"

    def __str__(self) -> str:
        return self.raw_url or self._build_url()

    def _build_url(self) -> str:
        url = f"{self.scheme}://{self.hostname}"
        if self.port not in (80, 443):
            url += f":{self.port}"
        url += self.path
        if self.query:
            url += f"?{self.query}"
        if self.fragment:
            url += f"#{self.fragment}"
        return url


def parse_url(raw: str) -> Url:
    """Parse a raw URL string into a Url object."""
    from urllib.parse import urlparse

    parsed = urlparse(raw)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    return Url(
        scheme=parsed.scheme or "https",
        hostname=parsed.hostname or "",
        port=port,
        path=parsed.path or "/",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        raw_url=raw,
    )
