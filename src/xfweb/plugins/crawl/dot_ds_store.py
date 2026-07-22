"""DS_Store file detection plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class DotDsStorePlugin(CrawlPlugin):
    """Detect and parse .DS_Store files for directory enumeration."""

    plugin_name = "dot_ds_store"
    brief_description = "Detect .DS_Store files and extract directory structure"

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        discovered: list[FuzzableRequest] = []
        dirs = self._get_dirs(freq.url.raw_url)

        for dir_url in dirs:
            ds_url = f"{dir_url.rstrip('/')}/.DS_Store"
            resp = await http.get(ds_url)
            if resp.status_code == 200 and len(resp.body) > 8:
                if b"DS_Store" in resp.body[:8] or b"Bud1" in resp.body[:4]:
                    logger.warning("xfweb.ds_store.found", url=ds_url)
                    entries = self._parse_ds_store(resp.body)
                    for entry in entries:
                        full_url = f"{dir_url.rstrip('/')}/{entry}"
                        try:
                            discovered.append(FuzzableRequest.from_url(parse_url(full_url)))
                        except Exception:
                            pass
        return discovered

    def _get_dirs(self, url: str) -> list[str]:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        parts = parsed.path.rstrip("/").split("/")
        return [f"{parsed.scheme}://{parsed.netloc}/" + "/".join(parts[:i]) for i in range(1, len(parts))]

    def _parse_ds_store(self, data: bytes) -> list[str]:
        results: list[str] = []
        i = 0
        while i < len(data) - 8:
            if data[i:i+4] == b'\x00\x00\x00\x01':
                name_len = int.from_bytes(data[i+8:i+12], 'big') * 2
                if 0 < name_len < 500:
                    try:
                        name = data[i+12:i+12+name_len].decode('utf-16-be', errors='ignore').rstrip('\x00')
                        if name and name != '.DS_Store':
                            results.append(name)
                    except Exception:
                        pass
            i += 1
        return results[:50]
