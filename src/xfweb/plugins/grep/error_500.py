"""HTTP 500 error detection plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

ERROR_SIGNATURES = [
    "exception", "traceback", "stack trace", "error in",
    "unhandled exception", "fatal error", "debug mode",
    "django.debug", "rails.env", "laravel", "symfony",
    "stacktrace", "at line", "in file", "internal server error",
]


class Error500Plugin(GrepPlugin):
    """Detect HTTP 500 errors that may leak sensitive information."""

    plugin_name = "error_500"
    brief_description = "Detect HTTP 500 errors with information disclosure"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        if resp.status_code >= 500:
            body_lower = resp.text.lower()
            for sig in ERROR_SIGNATURES:
                if sig.lower() in body_lower:
                    logger.warning(
                        "xfweb.error_500.info_leak",
                        url=freq.url.raw_url,
                        status=resp.status_code,
                        signature=sig,
                    )
                    return
