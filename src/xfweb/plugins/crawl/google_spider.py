"""Google search spider — discovers URLs via Google dorking."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class GoogleSpiderPlugin(CrawlPlugin):
    """Discover URLs via Google search results."""

    plugin_name = "google_spider"
    brief_description = "Discover URLs via Google search results"

    def __init__(self) -> None:
        super().__init__()
        self._ran: bool = False

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url
        import re

        if self._ran:
            return []
        self._ran = True

        discovered: list[FuzzableRequest] = []
        domain = freq.url.hostname

        query = f"site:{domain}"
        search_url = f"https://www.google.com/search?q={query}&num=100"

        resp = await http.get(search_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

        url_pattern = re.compile(rf'https?://(?:www\.)?{re.escape(domain)}[^\s"\'<>]+')
        urls = set(url_pattern.findall(resp.text))

        for url in urls:
            url = url.rstrip(".,;:)")
            try:
                parsed = parse_url(url)
                if parsed.hostname == domain or parsed.hostname.endswith(f".{domain}"):
                    discovered.append(FuzzableRequest.from_url(parsed))
            except Exception:
                continue

        logger.info("xfweb.google_spider.found", domain=domain, urls=len(discovered))
        return discovered
