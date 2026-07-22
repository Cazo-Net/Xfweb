"""Path disclosure detection plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

PATH_PATTERNS = [
    re.compile(r'(?:file|path|dir|folder|directory)\s*[:=]\s*["\']?([A-Za-z]:\\[^\s"\'<>]+)', re.IGNORECASE),
    re.compile(r'(?:file|path|dir|folder|directory)\s*[:=]\s*["\']?(/(?:home|var|usr|etc|opt|tmp)[^\s"\'<>]+)', re.IGNORECASE),
    re.compile(r'(?:include|require|require_once|include_once)\s*["\']([^"\']+)', re.IGNORECASE),
]


class PathDisclosurePlugin(GrepPlugin):
    """Detect file system path disclosure in responses."""

    plugin_name = "path_disclosure"
    brief_description = "Detect file system path disclosure in responses"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        for pattern in PATH_PATTERNS:
            matches = pattern.findall(resp.text)
            for match in matches:
                if len(match) > 10:
                    logger.info(
                        "xfweb.path_disclosure.found",
                        url=freq.url.raw_url,
                        path=match[:100],
                    )
                    return
