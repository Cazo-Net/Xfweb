"""Robots.txt parser — discovers hidden URLs from robots.txt files.

Ported from w3af's robots_txt.py.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class RobotsTxtPlugin(CrawlPlugin):
    """Parse robots.txt to discover hidden URLs."""

    plugin_name = "robots_txt"
    brief_description = "Discover URLs from robots.txt"

    def __init__(self) -> None:
        super().__init__()
        self._ran: bool = False

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        if self._ran:
            return []
        self._ran = True

        base = f"{freq.url.scheme}://{freq.url.hostname}"
        robots_url = f"{base}/robots.txt"

        resp = await http.get(robots_url)
        if resp.status_code != 200 or not resp.text.strip():
            return []

        discovered: list[FuzzableRequest] = []
        lines = resp.text.split("\n")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            upper = line.upper()
            if "ALLOW" in upper or "DISALLOW" in upper:
                if ":" in line:
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        try:
                            full_url = urljoin(robots_url, path)
                            discovered.append(FuzzableRequest.from_url(parse_url(full_url)))
                        except Exception:
                            pass

        logger.info("xfweb.robots_txt.found", url=robots_url, urls=len(discovered))
        return discovered
