"""Web Spider — the primary crawl plugin for Xfweb.

Ported from w3af's web_spider.py and modernized with:
- Async httpx HTTP client
- Python 3.11+ syntax
- Regex-based URL filtering
- Form detection and smart filling
- Domain scope enforcement
- Extension-based filtering
- Broken link tracking
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

IGNORE_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp",
    "mp3", "mp4", "avi", "mov", "wmv", "flv", "webm",
    "zip", "rar", "7z", "tar", "gz",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "css", "woff", "woff2", "ttf", "eot",
}

LINK_PATTERNS = [
    re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'url\(["\']?([^"\')]+)["\']?\)', re.IGNORECASE),
]

FORM_PATTERN = re.compile(
    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)

INPUT_PATTERN = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'](?:[^>]*value=["\']([^"\']*)["\'])?[^>]*/?>',
    re.IGNORECASE,
)


class WebSpiderPlugin(CrawlPlugin):
    """The main web spider — discovers URLs, forms, and endpoints."""

    plugin_name = "web_spider"
    brief_description = "Crawl web applications and discover endpoints"

    def __init__(self) -> None:
        super().__init__()
        self.options = {
            "only_forward": False,
            "follow_regex": ".*",
            "ignore_regex": "",
            "ignore_extensions": [],
        }
        self._visited: set[str] = set()
        self._target_domain: str = ""

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        if not self._target_domain:
            self._target_domain = freq.url.hostname

        resp = await http.get(freq.url.raw_url)
        if resp.status_code in (401, 403):
            return []

        if resp.status_code == 0:
            return []

        if not resp.is_text:
            return []

        discovered: list[FuzzableRequest] = []

        links = self._extract_links(resp.text, freq.url)
        forms = self._extract_forms(resp.text, freq.url)

        for link_url in links:
            if self._should_follow(link_url):
                if link_url not in self._visited:
                    self._visited.add(link_url)
                    discovered.append(FuzzableRequest.from_url(parse_url(link_url)))

        for form_url, method, data in forms:
            if self._should_follow(form_url):
                parsed = parse_url(form_url)
                freq_new = FuzzableRequest.from_parts(
                    url=parsed,
                    method=method,
                    post_data=data if method == "POST" else None,
                )
                discovered.append(freq_new)

        logger.debug(
            "xfweb.spider.crawled",
            url=freq.url.raw_url,
            new_links=len(discovered),
            forms=len(forms),
        )

        return discovered

    def _extract_links(self, html: str, base_url: Any) -> list[str]:
        """Extract all URLs from HTML content."""
        links: list[str] = []
        seen: set[str] = set()

        for pattern in LINK_PATTERNS:
            for match in pattern.finditer(html):
                raw = match.group(1).strip()
                if raw.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                if raw in seen:
                    continue
                seen.add(raw)

                try:
                    full_url = urljoin(base_url.raw_url, raw)
                    parsed = urlparse(full_url)
                    if parsed.scheme in ("http", "https"):
                        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if parsed.query:
                            clean += f"?{parsed.query}"
                        links.append(clean)
                except Exception:
                    continue

        return links

    def _extract_forms(self, html: str, base_url: Any) -> list[tuple[str, str, str]]:
        """Extract HTML forms with their action, method, and data."""
        forms: list[tuple[str, str, str]] = []

        for form_match in FORM_PATTERN.finditer(html):
            action = form_match.group(1) or ""
            form_body = form_match.group(2)

            method = "GET"
            method_match = re.search(r'method=["\'](\w+)["\']', form_match.group(0), re.IGNORECASE)
            if method_match:
                method = method_match.group(1).upper()

            params: list[str] = []
            for input_match in INPUT_PATTERN.finditer(form_body):
                name = input_match.group(1)
                value = input_match.group(2) or ""
                params.append(f"{name}={value}")

            data = "&".join(params)
            full_action = urljoin(base_url.raw_url, action)
            forms.append((full_action, method, data))

        return forms

    def _should_follow(self, url: str) -> bool:
        """Check if a URL should be followed based on configuration."""
        parsed = urlparse(url)

        if parsed.hostname and parsed.hostname != self._target_domain:
            if not parsed.hostname.endswith(f".{self._target_domain}"):
                return False

        if self.options.get("only_forward"):
            if not url.startswith(f"{parsed.scheme}://{parsed.netloc}/"):
                return False

        ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path.split("/")[-1] else ""
        ignore_exts = set(self.options.get("ignore_extensions", IGNORE_EXTENSIONS))
        if ext in ignore_exts:
            return False

        follow_re = self.options.get("follow_regex", ".*")
        if follow_re and not re.match(follow_re, url):
            return False

        ignore_re = self.options.get("ignore_regex", "")
        if ignore_re and re.match(ignore_re, url):
            return False

        return True
