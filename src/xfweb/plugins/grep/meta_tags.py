"""Meta tags analysis plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

META_GENERATOR = re.compile(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', re.IGNORECASE)
META_REFRESH = re.compile(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']([^"\']+)', re.IGNORECASE)


class MetaTagsPlugin(GrepPlugin):
    """Analyze meta tags for information disclosure."""

    plugin_name = "meta_tags"
    brief_description = "Analyze meta tags for technology and version disclosure"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        gen_match = META_GENERATOR.search(resp.text)
        if gen_match:
            generator = gen_match.group(1)
            logger.info(
                "xfweb.meta_tags.generator",
                url=freq.url.raw_url,
                generator=generator,
            )

        refresh_match = META_REFRESH.search(resp.text)
        if refresh_match:
            content = refresh_match.group(1)
            logger.info(
                "xfweb.meta_tags.refresh",
                url=freq.url.raw_url,
                content=content,
            )
