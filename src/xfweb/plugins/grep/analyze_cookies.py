"""Cookie security analysis plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class AnalyzeCookiesPlugin(GrepPlugin):
    """Analyze cookies for security weaknesses."""

    plugin_name = "analyze_cookies"
    brief_description = "Analyze cookies for security weaknesses (missing Secure, HttpOnly, SameSite)"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        set_cookie = resp.headers.get("set-cookie", "")
        if not set_cookie:
            return

        cookies = [c.strip() for c in set_cookie.split(",")]

        for cookie in cookies:
            name = cookie.split("=")[0].strip() if "=" in cookie else ""
            lower = cookie.lower()

            issues: list[str] = []

            if "secure" not in lower:
                issues.append("missing Secure flag")
            if "httponly" not in lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in lower:
                issues.append("missing SameSite attribute")

            if issues:
                logger.info(
                    "xfweb.analyze_cookies.weakness",
                    url=freq.url.raw_url,
                    cookie=name,
                    issues=issues,
                )
