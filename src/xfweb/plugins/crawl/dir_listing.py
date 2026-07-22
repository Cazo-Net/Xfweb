"""Directory listing detection — finds exposed directory listings and .listing files.

Ported from w3af's dir_listing.py and dot_listing.py.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

LISTING_MARKERS = [
    "<title>Index of /",
    "<title>Index of ",
    "Directory listing for",
    "Parent Directory</a>",
    "<pre>\n<a href",
    "HREF=\"/",
]

LISTING_PARSER_RE = re.compile(
    r"[a-z-]{10}\s+\d+\s+(.*?)\s+(.*?)\s+\d+\s+\w+\s+\d+\s+[0-9:]{4,5}\s+(.*)"
)


class DirListingPlugin(CrawlPlugin):
    """Detect exposed directory listings."""

    plugin_name = "dir_listing"
    brief_description = "Detect exposed directory listings and extract URLs"

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        resp = await http.get(freq.url.raw_url)
        if resp.status_code != 200:
            return []

        is_listing = any(marker in resp.text for marker in LISTING_MARKERS)
        if not is_listing:
            return []

        logger.warning("xfweb.dir_listing.found", url=freq.url.raw_url)

        discovered: list[FuzzableRequest] = []
        link_pattern = re.compile(r'href="([^"]+)"')

        for match in link_pattern.finditer(resp.text):
            href = match.group(1).strip()
            if href.startswith("?") or href == "../" or href == "/":
                continue

            full_url = urljoin(freq.url.raw_url, href)
            if full_url.startswith("http"):
                try:
                    discovered.append(FuzzableRequest.from_url(parse_url(full_url)))
                except Exception:
                    pass

        return discovered


class DotListingPlugin(CrawlPlugin):
    """Detect .listing files (FTP wget artifacts) that leak OS user/group names."""

    plugin_name = "dot_listing"
    brief_description = "Detect .listing files that expose filenames and OS users"

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        discovered: list[FuzzableRequest] = []

        dirs_to_check = self._get_parent_dirs(freq.url.raw_url)
        for dir_url in dirs_to_check:
            listing_url = f"{dir_url.rstrip('/')}/.listing"
            resp = await http.get(listing_url)

            if resp.status_code != 200:
                continue

            users: set[str] = set()
            groups: set[str] = set()
            files: set[str] = set()

            for user, group, filename in LISTING_PARSER_RE.findall(resp.text):
                if filename.strip() in (".", ".."):
                    continue
                files.add(filename.strip())
                if not user.isdigit():
                    users.add(user)
                if not group.isdigit():
                    groups.add(group)

            for f in files:
                try:
                    file_url = urljoin(dir_url, f)
                    discovered.append(FuzzableRequest.from_url(parse_url(file_url)))
                except Exception:
                    pass

            if users or groups:
                logger.warning(
                    "xfweb.dot_listing.user_leak",
                    url=listing_url,
                    users=list(users),
                    groups=list(groups),
                )

        return discovered

    def _get_parent_dirs(self, url: str) -> list[str]:
        """Get all parent directories of a URL."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        parts = parsed.path.rstrip("/").split("/")
        dirs: list[str] = []

        for i in range(1, len(parts)):
            path = "/".join(parts[:i]) + "/"
            dirs.append(f"{parsed.scheme}://{parsed.netloc}{path}")

        return dirs
