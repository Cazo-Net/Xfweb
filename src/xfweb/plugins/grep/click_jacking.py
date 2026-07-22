"""Clickjacking detection grep plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class ClickJackingPlugin(GrepPlugin):
    """Detect clickjacking vulnerabilities via missing X-Frame-Options and CSP."""

    plugin_name = "click_jacking"
    brief_description = "Detect clickjacking vulnerabilities"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        xfo = resp.headers.get("x-frame-options", "")
        csp = resp.headers.get("content-security-policy", "")

        has_frame_ancestors = "frame-ancestors" in csp.lower() if csp else False
        has_xfo = bool(xfo)

        if not has_xfo and not has_frame_ancestors:
            logger.info(
                "xfweb.click_jacking.vulnerable",
                url=freq.url.raw_url,
                description="No X-Frame-Options or CSP frame-ancestors found",
            )
