"""Web Spider — the primary crawl plugin for Xfweb.

Ported from w3af's web_spider.py and modernized with:
- Async httpx HTTP client
- Python 3.11+ syntax
- Regex-based URL filtering
- Form detection and smart filling
- Domain scope enforcement
- Extension-based filtering
- Broken link tracking
- KB integration for responses and fuzzable requests
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

SCRIPT_SRC_PATTERN = re.compile(
    r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE
)

META_REFRESH_PATTERN = re.compile(
    r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']\d+;\s*url=([^"\']+)["\']',
    re.IGNORECASE,
)

FORM_PATTERN = re.compile(
    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)

INPUT_PATTERN = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'](?:[^>]*value=["\']([^"\']*)["\'])?[^>]*/?>',
    re.IGNORECASE,
)

SELECT_PATTERN = re.compile(
    r'<select[^>]*name=["\']([^"\']+)["\'].*?</select>',
    re.IGNORECASE | re.DOTALL,
)

TEXTAREA_PATTERN = re.compile(
    r'<textarea[^>]*name=["\']([^"\']+)["\'].*?</textarea>',
    re.IGNORECASE | re.DOTALL,
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
            "max_depth": 10,
        }
        self._visited: set[str] = set()
        self._target_domain: str = ""

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        if not self._target_domain:
            self._target_domain = freq.url.hostname

        resp = await http.get(freq.url.raw_url)

        if resp.status_code == 0:
            return []

        if self.kb:
            self.kb.store_response(resp)

        if resp.status_code in (401, 403):
            return []

        if not resp.is_text:
            return []

        discovered: list[FuzzableRequest] = []

        links = self._extract_links(resp.text, freq.url)
        scripts = self._extract_script_srcs(resp.text, freq.url)
        meta_redirects = self._extract_meta_refresh(resp.text, freq.url)
        forms = self._extract_forms(resp.text, freq.url)

        all_urls = links + scripts + meta_redirects

        for link_url in all_urls:
            if self._should_follow(link_url):
                if link_url not in self._visited:
                    self._visited.add(link_url)
                    freq_new = FuzzableRequest.from_url(parse_url(link_url))
                    discovered.append(freq_new)
                    if self.kb:
                        self.kb.store_fuzzable_request(freq_new)

        for form_url, method, data in forms:
            if self._should_follow(form_url):
                parsed = parse_url(form_url)
                freq_new = FuzzableRequest.from_parts(
                    url=parsed,
                    method=method,
                    post_data=data if method == "POST" else None,
                )
                if form_url not in self._visited:
                    self._visited.add(form_url)
                    discovered.append(freq_new)
                    if self.kb:
                        self.kb.store_fuzzable_request(freq_new)

        logger.debug(
            "xfweb.spider.crawled",
            url=freq.url.raw_url,
            new_links=len(discovered),
            forms=len(forms),
        )

        return discovered

    def _extract_links(self, html: str, base_url: Any) -> list[str]:
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

    def _extract_script_srcs(self, html: str, base_url: Any) -> list[str]:
        scripts: list[str] = []
        for match in SCRIPT_SRC_PATTERN.finditer(html):
            try:
                full_url = urljoin(base_url.raw_url, match.group(1))
                parsed = urlparse(full_url)
                if parsed.scheme in ("http", "https"):
                    scripts.append(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
            except Exception:
                continue
        return scripts

    def _extract_meta_refresh(self, html: str, base_url: Any) -> list[str]:
        redirects: list[str] = []
        for match in META_REFRESH_PATTERN.finditer(html):
            try:
                full_url = urljoin(base_url.raw_url, match.group(1))
                parsed = urlparse(full_url)
                if parsed.scheme in ("http", "https"):
                    redirects.append(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
            except Exception:
                continue
        return redirects

    def _extract_forms(self, html: str, base_url: Any) -> list[tuple[str, str, str]]:
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
                input_type = re.search(r'type=["\']([^"\']+)["\']', input_match.group(0), re.IGNORECASE)
                if input_type and input_type.group(1).lower() in ("submit", "button", "image"):
                    continue
                params.append(f"{name}={value}")

            for select_match in SELECT_PATTERN.finditer(form_body):
                name = re.search(r'name=["\']([^"\']+)["\']', select_match.group(0), re.IGNORECASE)
                if name:
                    value_match = re.search(r'value=["\']([^"\']*)["\']', select_match.group(0), re.IGNORECASE)
                    params.append(f"{name.group(1)}={value_match.group(1) if value_match else ''}")

            for textarea_match in TEXTAREA_PATTERN.finditer(form_body):
                name = re.search(r'name=["\']([^"\']+)["\']', textarea_match.group(0), re.IGNORECASE)
                if name:
                    params.append(f"{name.group(1)}=")

            data = "&".join(params)
            full_action = urljoin(base_url.raw_url, action)
            forms.append((full_action, method, data))

        return forms

    def _should_follow(self, url: str) -> bool:
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
