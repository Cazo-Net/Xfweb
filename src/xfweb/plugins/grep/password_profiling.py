"""Password profiling plugin — detects potential passwords in responses."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

PASSWORD_PATTERNS = [
    re.compile(r"(?:password|passwd|pwd|pass)\s*[=:]\s*[\"']?([^\s\"';>]+)", re.IGNORECASE),
    re.compile(r"(?:api[_\-]?key|apikey|api_key)\s*[=:]\s*[\"']?([^\s\"';>]+)", re.IGNORECASE),
    re.compile(r"(?:secret|token|auth_token|access_token)\s*[=:]\s*[\"']?([^\s\"';>]+)", re.IGNORECASE),
    re.compile(r"(?:jdbc:|mysql://|postgres://|mongodb://)([^\s\"';>]+)", re.IGNORECASE),
    re.compile(r"BEGIN RSA PRIVATE KEY", re.IGNORECASE),
    re.compile(r"BEGIN DSA PRIVATE KEY", re.IGNORECASE),
    re.compile(r"BEGIN EC PRIVATE KEY", re.IGNORECASE),
]


class PasswordProfilingPlugin(GrepPlugin):
    """Detect potential passwords and secrets in HTTP responses."""

    plugin_name = "password_profiling"
    brief_description = "Detect potential passwords and secrets in responses"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        for pattern in PASSWORD_PATTERNS:
            matches = pattern.findall(resp.text)
            for match in matches:
                if match and len(match) > 3 and match not in ("", "xxx", "password", "secret"):
                    logger.warning(
                        "xfweb.password_profiling.found",
                        url=freq.url.raw_url,
                        context=pattern.pattern[:50],
                    )
                    return
