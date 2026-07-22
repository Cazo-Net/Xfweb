"""Reverse proxy detection plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import InfrastructurePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

REVERSE_PROXY_SIGNATURES = {
    "X-Forwarded-For": "Load balancer / reverse proxy detected",
    "X-Real-IP": "Reverse proxy detected",
    "X-Forwarded-Proto": "SSL termination proxy detected",
    "X-Forwarded-Host": "Host header proxy detected",
    "Via": "Proxy server detected",
    "X-CDN": "CDN detected",
    "X-Cache": "Caching proxy detected",
    "X-Varnish": "Varnish cache detected",
    "X-Upstream": "Upstream server detected",
}


class DetectReverseProxyPlugin(InfrastructurePlugin):
    """Detect reverse proxy configurations."""

    plugin_name = "detect_reverse_proxy"
    brief_description = "Detect reverse proxy, CDN, and load balancer configurations"

    async def discover(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        for header, desc in REVERSE_PROXY_SIGNATURES.items():
            value = resp.headers.get(header.lower(), "")
            if value:
                logger.info(
                    "xfweb.reverse_proxy.detected",
                    url=freq.url.raw_url,
                    header=header,
                    value=value[:100],
                    description=desc,
                )
