"""OS fingerprinting plugin based on HTTP response analysis."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import InfrastructurePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

OS_SIGNATURES = {
    "Linux": [r"linux", r"ubuntu", r"debian", r"centos", r"red hat", r"fedora"],
    "Windows": [r"windows", r"iis", r"microsoft", r"asp\.net"],
    "macOS": [r"macos", r"mac os x", r"darwin"],
    "FreeBSD": [r"freebsd"],
}

SERVER_OS_MAP = {
    "Apache": "likely Linux",
    "nginx": "likely Linux",
    "IIS": "Windows",
    "Microsoft-IIS": "Windows",
    "lighttpd": "likely Linux",
    "Caddy": "likely Linux",
}


class FingerprintOsPlugin(InfrastructurePlugin):
    """Fingerprint the operating system from HTTP headers."""

    plugin_name = "fingerprint_os"
    brief_description = "Fingerprint OS from HTTP response headers"

    async def discover(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        server = resp.headers.get("server", "").lower()
        x_powered = resp.headers.get("x-powered-by", "").lower()
        all_headers = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()

        detected_os = "unknown"

        for os_name, patterns in OS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, all_headers):
                    detected_os = os_name
                    break
            if detected_os != "unknown":
                break

        if detected_os == "unknown":
            for server_name, os_hint in SERVER_OS_MAP.items():
                if server_name.lower() in server:
                    detected_os = os_hint
                    break

        if detected_os != "unknown":
            logger.info(
                "xfweb.fingerprint_os.detected",
                url=freq.url.raw_url,
                os=detected_os,
                server=resp.headers.get("server", ""),
            )
