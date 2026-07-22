"""CSRF audit plugin — detects Cross-Site Request Forgery vulnerabilities.

Checks for missing CSRF tokens, SameSite cookie attributes, custom header
requirements, and tests actual token enforcement.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

CSRF_TOKEN_PATTERNS = [
    re.compile(r"csrf[_\-]?token", re.IGNORECASE),
    re.compile(r"_token", re.IGNORECASE),
    re.compile(r"authenticity[_\-]?token", re.IGNORECASE),
    re.compile(r"xsrf[_\-]?token", re.IGNORECASE),
    re.compile(r"__RequestVerificationToken", re.IGNORECASE),
    re.compile(r"anti[_\-]?forgery", re.IGNORECASE),
    re.compile(r"nonce", re.IGNORECASE),
    re.compile(r"_csrf", re.IGNORECASE),
    re.compile(r"csrfmiddlewaretoken", re.IGNORECASE),
]

FORM_PATTERN = re.compile(
    r"<form[^>]*>(.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)

FORM_ATTRS = re.compile(
    r'<form[^>]*method=["\'](\w+)["\'][^>]*action=["\']([^"\']*)["\'][^>]*>',
    re.IGNORECASE,
)

FORM_ATTRS_REV = re.compile(
    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](\w+)["\'][^>]*>',
    re.IGNORECASE,
)

HIDDEN_INPUT_PATTERN = re.compile(
    r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class CsrfPlugin(AuditPlugin):
    """Detect missing CSRF protection and test token enforcement."""

    plugin_name = "csrf"
    brief_description = "Detect missing CSRF protection and token enforcement issues"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if resp.status_code != 200 or not resp.is_text:
            return

        await self._check_same_site_cookies(freq, resp)
        await self._check_custom_header_protection(freq, resp)
        await self._check_forms(freq, resp, http)

    async def _check_same_site_cookies(self, freq: Any, resp: Any) -> None:
        cookie_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
        for cookie in cookie_headers:
            lower = cookie.lower()
            if "samesite" not in lower:
                self.report_finding(
                    name=f"Cookie missing SameSite attribute on {freq.url.raw_url}",
                    severity="low",
                    url=freq.url.raw_url,
                    description="A cookie is set without the SameSite attribute. "
                    "This may allow CSRF attacks from cross-origin requests.",
                    evidence=f"Set-Cookie: {cookie}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    http_response={"status": resp.status_code},
                    remediation="Set SameSite=Lax or SameSite=Strict on all cookies.",
                )

    async def _check_custom_header_protection(self, freq: Any, resp: Any) -> None:
        if "x-requested-with" in resp.text.lower():
            test_url = freq.url.raw_url
            no_header_resp = await http.post(test_url, data="test=1")
            with_header_resp = await http.post(
                test_url,
                data="test=1",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            if no_header_resp.status_code == with_header_resp.status_code:
                if no_header_resp.status_code == 200:
                    self.report_finding(
                        name=f"Custom header not enforced on {freq.url.raw_url}",
                        severity="low",
                        url=freq.url.raw_url,
                        description="Application accepts POST requests without custom CSRF "
                        "headers. The X-Requested-With header is present in responses but "
                        "not enforced server-side.",
                        evidence="POST without header: 200\nPOST with header: 200",
                        http_request={"method": "POST", "url": freq.url.raw_url},
                        remediation="Enforce custom headers for all state-changing AJAX requests.",
                    )

    async def _check_forms(self, freq: Any, resp: Any, http: HttpEngine) -> None:
        forms = FORM_PATTERN.finditer(resp.text)
        for form_match in forms:
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            method = self._get_form_method(form_html)
            if method != "POST":
                continue

            has_token = self._has_csrf_token(form_body)
            if not has_token:
                self.report_finding(
                    name=f"Missing CSRF token on {freq.url.raw_url}",
                    severity="medium",
                    url=freq.url.raw_url,
                    description="A state-changing form was found without CSRF token protection. "
                    "This form could be used in cross-site request forgery attacks.",
                    evidence=f"Form HTML: {form_html[:300]}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    http_response={"status": resp.status_code},
                    remediation="Add anti-CSRF tokens to all state-changing forms. "
                    "Verify tokens server-side on every request.",
                )
                continue

            await self._test_token_enforcement(freq, form_match, http)

    async def _test_token_enforcement(self, freq: Any, form_match: Any, http: HttpEngine) -> None:
        form_html = form_match.group(0)
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
        if not action_match:
            return

        from urllib.parse import urljoin
        action_url = urljoin(freq.url.raw_url, action_match.group(1))

        token_input = re.search(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']',
            form_html,
        )
        if not token_input:
            return

        token_name = token_input.group(1)
        token_value = token_input.group(2)

        valid_data = f"{token_name}={token_value}&test=value"
        invalid_data = f"{token_name}=invalid_token&test=value"

        valid_resp = await http.post(action_url, data=valid_data)
        invalid_resp = await http.post(action_url, data=invalid_data)

        if valid_resp.status_code == invalid_resp.status_code:
            if valid_resp.status_code in (200, 302):
                self.report_finding(
                    name=f"CSRF token not validated on {action_url}",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"A form includes a CSRF token field ('{token_name}') but the "
                    "server does not appear to validate it. Both valid and invalid tokens "
                    "received the same response.",
                    parameter=token_name,
                    evidence=f"Valid token response: {valid_resp.status_code}\n"
                    f"Invalid token response: {invalid_resp.status_code}\n"
                    f"Token field: {token_name}",
                    http_request={"method": "POST", "url": action_url},
                    remediation="Validate CSRF tokens server-side. Reject requests with "
                    "missing or invalid tokens.",
                )

    def _get_form_method(self, form_html: str) -> str:
        match = re.search(r'method=["\'](\w+)["\']', form_html, re.IGNORECASE)
        return match.group(1).upper() if match else "GET"

    def _has_csrf_token(self, form_body: str) -> bool:
        hidden_inputs = HIDDEN_INPUT_PATTERN.findall(form_body)
        for input_name in hidden_inputs:
            for pattern in CSRF_TOKEN_PATTERNS:
                if pattern.search(input_name):
                    return True
        for pattern in CSRF_TOKEN_PATTERNS:
            if pattern.search(form_body):
                return True
        return False
