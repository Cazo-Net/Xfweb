"""Sitemap.xml parser — discovers URLs from XML sitemaps.

Ported from w3af's sitemap_xml.py.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urljoin

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class SitemapXmlPlugin(CrawlPlugin):
    """Parse sitemap.xml to discover URLs."""

    plugin_name = "sitemap_xml"
    brief_description = "Discover URLs from sitemap.xml"

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
        sitemap_url = f"{base}/sitemap.xml"

        resp = await http.get(sitemap_url)
        if resp.status_code != 200 or "</urlset>" not in resp.text:
            return []

        discovered: list[FuzzableRequest] = []

        try:
            root = ET.fromstring(resp.body)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

            for loc_elem in root.findall(".//sm:url/sm:loc", ns):
                if loc_elem.text:
                    url_str = loc_elem.text.strip()
                    try:
                        parsed = parse_url(url_str)
                        discovered.append(FuzzableRequest.from_url(parsed))
                    except Exception:
                        continue

            if not ns:
                for loc_elem in root.findall(".//url/loc"):
                    if loc_elem.text:
                        url_str = loc_elem.text.strip()
                        try:
                            parsed = parse_url(url_str)
                            discovered.append(FuzzableRequest.from_url(parsed))
                        except Exception:
                            continue

        except ET.ParseError as exc:
            logger.warning("xfweb.sitemap_xml.parse_error", error=str(exc))

        logger.info("xfweb.sitemap_xml.found", url=sitemap_url, urls=len(discovered))
        return discovered
