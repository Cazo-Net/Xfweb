"""HTML comment extraction plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

HTML_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)

SENSITIVE_PATTERNS = [
    re.compile(r"(password|passwd|pwd)\s*[:=]", re.IGNORECASE),
    re.compile(r"(api[_\-]?key|apikey)\s*[:=]", re.IGNORECASE),
    re.compile(r"(secret|token|auth)\s*[:=]", re.IGNORECASE),
    re.compile(r"(todo|fixme|hack|xxx|bug)\s*[:=]", re.IGNORECASE),
    re.compile(r"(admin|root|debug)\s*[:=]", re.IGNORECASE),
    re.compile(r"(database|db|mysql|postgres|mongo)\s*[:=]", re.IGNORECASE),
]


class HtmlCommentsPlugin(GrepPlugin):
    """Extract HTML comments and look for sensitive information."""

    plugin_name = "html_comments"
    brief_description = "Extract HTML comments and detect sensitive data leakage"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        comments = HTML_COMMENT_PATTERN.findall(resp.text)
        for comment in comments:
            comment_stripped = comment.strip()
            if not comment_stripped or len(comment_stripped) < 3:
                continue

            for pattern in SENSITIVE_PATTERNS:
                if pattern.search(comment_stripped):
                    logger.warning(
                        "xfweb.html_comments.sensitive",
                        url=freq.url.raw_url,
                        comment=comment_stripped[:200],
                    )
                    return
