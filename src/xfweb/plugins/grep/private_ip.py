"""Private IP address detection grep plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

PRIVATE_IP_PATTERN = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False

    if nums[0] == 10:
        return True
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return True
    if nums[0] == 192 and nums[1] == 168:
        return True
    if nums[0] == 127:
        return True
    if nums[0] == 169 and nums[1] == 254:
        return True
    if nums[0] == 0:
        return True
    return False


class PrivateIpPlugin(GrepPlugin):
    """Detect private/internal IP addresses in HTTP responses."""

    plugin_name = "private_ip"
    brief_description = "Detect private/internal IP addresses leaked in responses"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        ips = PRIVATE_IP_PATTERN.findall(resp.text)
        private_ips = [ip for ip in ips if _is_private_ip(ip)]

        if private_ips:
            unique_ips = list(set(private_ips))[:10]
            logger.warning(
                "xfweb.private_ip.found",
                url=freq.url.raw_url,
                ips=unique_ips,
            )
