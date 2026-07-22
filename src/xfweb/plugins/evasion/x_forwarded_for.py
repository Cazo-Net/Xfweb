"""X-Forwarded-For evasion plugin."""

from __future__ import annotations

import random
from typing import Any

from xfweb.core.plugins.plugin_base import EvasionPlugin


class XForwardedForPlugin(EvasionPlugin):
    """Add random X-Forwarded-For headers to bypass IP-based restrictions."""

    plugin_name = "x_forwarded_for"
    brief_description = "Add random X-Forwarded-For headers for IP spoofing"

    def modify_request(self, request: Any) -> Any:
        if hasattr(request, "headers"):
            ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            request.headers["X-Forwarded-For"] = ip
            request.headers["X-Real-IP"] = ip
            request.headers["X-Client-IP"] = ip
        return request
