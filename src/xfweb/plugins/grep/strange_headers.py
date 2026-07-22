"""Strange/unusual HTTP headers grep plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

INTERESTING_HEADERS = {
    "x-debug", "x-debug-token", "x-debug-token-link", "x-debugging",
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-rack-cache",
    "x-runtime", "x-version", "x-backside", "x-application",
    "x-varnish", "x-akamai", "x-cdn", "x-served-by",
    "x-cache", "x-cached", "x-upstream",
    "x-real-ip", "x-forwarded-for", "x-forwarded-proto",
    "x-request-id", "x-trace-id", "x-correlation-id",
    "via", "x-powered-by-cluster",
}


class StrangeHeadersPlugin(GrepPlugin):
    """Detect unusual or information-disclosing HTTP headers."""

    plugin_name = "strange_headers"
    brief_description = "Detect unusual HTTP headers that disclose information"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        found: dict[str, str] = {}
        for header_name in resp.headers:
            if header_name.lower() in INTERESTING_HEADERS:
                found[header_name] = resp.headers[header_name]

        if found:
            for h, v in found.items():
                logger.info(
                    "xfweb.strange_headers.found",
                    url=freq.url.raw_url,
                    header=h,
                    value=v,
                )
