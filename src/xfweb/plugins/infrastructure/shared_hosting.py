"""Shared hosting detection plugin."""

from __future__ import annotations

import socket
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import InfrastructurePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class SharedHostingPlugin(InfrastructurePlugin):
    """Detect if the target is on shared hosting."""

    plugin_name = "shared_hosting"
    brief_description = "Detect shared hosting environments via DNS analysis"

    async def discover(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        server = resp.headers.get("server", "").lower()
        shared_indicators = [
            "cpanel", "plesk", "directadmin", "webmin",
            "shared", "sharedserver", "cloudlinux",
        ]

        for indicator in shared_indicators:
            if indicator in server:
                logger.info(
                    "xfweb.shared_hosting.detected",
                    url=freq.url.raw_url,
                    indicator=indicator,
                )
                return

        try:
            ips = socket.getaddrinfo(freq.url.hostname, None)
            unique_ips = set(addr[4][0] for addr in ips)
            if len(unique_ips) > 1:
                logger.info(
                    "xfweb.shared_hosting.multiple_ips",
                    url=freq.url.raw_url,
                    ips=list(unique_ips),
                )
        except Exception:
            pass
