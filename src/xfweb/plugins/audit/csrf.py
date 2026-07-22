"""CSRF audit plugin — detects Cross-Site Request Forgery vulnerabilities.

Ported from w3af's csrf.py with modernized detection logic.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

CSRF_TOKEN_PATTERNS = [
    re.compile(r'csrf[_\-]?token', re.IGNORECASE),
    re.compile(r'_token', re.IGNORECASE),
    re.compile(r'authenticity[_\-]?token', re.IGNORECASE),
    re.compile(r'xsrf[_\-]?token', re.IGNORECASE),
    re.compile(r'__RequestVerificationToken', re.IGNORECASE),
    re.compile(r'anti[_\-]?forgery', re.IGNORECASE),
    re.compile(r'nonce', re.IGNORECASE),
]

FORM_PATTERN = re.compile(
    r'<form[^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)

HIDDEN_INPUT_PATTERN = re.compile(
    r'<input[^>]*type=["\']hidden["\'][^>]*>',
    re.IGNORECASE,
)


class CsrfPlugin(AuditPlugin):
    """Detect missing CSRF protection on state-changing forms."""

    plugin_name = "csrf"
    brief_description = "Detect missing CSRF protection on forms"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        if freq.method.upper() != "GET":
            return

        resp = await http.get(freq.url.raw_url)
        if resp.status_code != 200 or not resp.is_text:
            return

        forms = FORM_PATTERN.findall(resp.text)
        for form_body in forms:
            if self._is_state_changing(form_body):
                if not self._has_csrf_token(form_body):
                    logger.warning(
                        "xfweb.csrf.missing_token",
                        url=freq.url.raw_url,
                        description="Form without CSRF token found",
                    )

    def _is_state_changing(self, form_body: str) -> bool:
        """Check if the form performs a state-changing operation."""
        lower = form_body.lower()
        return any(method in lower for method in ["method=\"post\"", "method='post'", "method=post"])

    def _has_csrf_token(self, form_body: str) -> bool:
        """Check if the form contains a CSRF token."""
        hidden_inputs = HIDDEN_INPUT_PATTERN.findall(form_body)
        for input_tag in hidden_inputs:
            for pattern in CSRF_TOKEN_PATTERNS:
                if pattern.search(input_tag):
                    return True

        for pattern in CSRF_TOKEN_PATTERNS:
            if pattern.search(form_body):
                return True

        return False
