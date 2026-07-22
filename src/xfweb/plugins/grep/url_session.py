"""URL session token detection plugin."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, parse_qs

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

SESSION_PARAMS = [
    "session", "sid", "sessid", "sessionid", "session_id",
    "token", "csrf", "nonce", "state", "auth",
    "access_token", "refresh_token", "jwt",
]


class UrlSessionPlugin(GrepPlugin):
    """Detect session tokens exposed in URLs."""

    plugin_name = "url_session"
    brief_description = "Detect session tokens exposed in URLs"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        link_pattern = re.compile(r'href=["\']([^"\']+)', re.IGNORECASE)
        for match in link_pattern.finditer(resp.text):
            url = match.group(1)
            if "?" not in url:
                continue
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params:
                    if param.lower() in SESSION_PARAMS:
                        logger.warning(
                            "xfweb.url_session.found",
                            url=freq.url.raw_url,
                            param=param,
                        )
                        return
            except Exception:
                continue
