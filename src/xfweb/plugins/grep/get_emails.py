"""Email address extraction plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)

IGNORE_DOMAINS = {
    "example.com", "localhost", "test.com", "sentry.io",
    "w3.org", "schema.org", "jquery.com", "cloudflare.com",
}


class GetEmailsPlugin(GrepPlugin):
    """Extract email addresses from HTTP responses."""

    plugin_name = "get_emails"
    brief_description = "Extract email addresses from HTTP responses"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        emails = set(EMAIL_PATTERN.findall(resp.text))
        for email in emails:
            domain = email.split("@")[1].lower()
            if domain not in IGNORE_DOMAINS:
                logger.info(
                    "xfweb.get_emails.found",
                    url=freq.url.raw_url,
                    email=email,
                )
