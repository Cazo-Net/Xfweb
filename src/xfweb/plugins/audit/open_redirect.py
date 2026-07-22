"""Open Redirect audit plugin — detects open redirect vulnerabilities.

Tests redirect parameters for unvalidated external redirects
that could be used in phishing attacks.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "redirect_to",
    "return", "return_to", "returnurl", "return_url",
    "next", "next_url", "nexturl",
    "url", "dest", "destination",
    "continue", "callback", "comeback",
    "redir", "returnto", "rurl",
    "ref", "referer", "referrer",
]

REDIRECT_PAYLOADS = [
    ("https://evil.example.com", "evil.example.com"),
    ("//evil.example.com", "evil.example.com"),
    ("//evil%00.example.com", "evil.example.com"),
    ("https://evil.example.com%252f..", "evil.example.com"),
    ("////evil.example.com", "evil.example.com"),
]

EVIL_DOMAIN = "evil.example.com"


class OpenRedirectPlugin(AuditPlugin):
    """Detect open redirect vulnerabilities in URL parameters."""

    plugin_name = "open_redirect"
    brief_description = "Detect open redirect vulnerabilities via URL parameters"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            await self._test_url_params(freq, http)
            return

        tasks = [self._test_param(freq, p, v, http) for p, v in params.items()]
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._test_url_params(freq, http)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        params: dict[str, str] = {}
        if freq.url.query:
            for pair in freq.url.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if k.lower() in REDIRECT_PARAMS:
                        params[k] = v
        if freq.post_data and isinstance(freq.post_data, str):
            for pair in freq.post_data.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if k.lower() in REDIRECT_PARAMS:
                        params[k] = v
        return params

    async def _test_url_params(self, freq: Any, http: HttpEngine) -> None:
        if not freq.url.query:
            return
        for pair in freq.url.query.split("&"):
            if "=" not in pair:
                continue
            k, v = pair.split("=", 1)
            if k.lower() not in REDIRECT_PARAMS:
                continue
            await self._test_param(freq, k, v, http)

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine) -> None:
        for payload, indicator in REDIRECT_PAYLOADS:
            if freq.method.upper() == "POST" and freq.post_data:
                new_data = freq.post_data.replace(f"{param}={value}", f"{param}={payload}")
                resp = await http.post(freq.url.raw_url, data=new_data, follow_redirects=False)
            else:
                new_url = freq.url.raw_url.replace(f"{param}={value}", f"{param}={payload}")
                resp = await http.get(new_url, follow_redirects=False)

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", resp.headers.get("Location", ""))
                if indicator in location:
                    self.report_finding(
                        name=f"Open redirect via '{param}' parameter",
                        severity="high",
                        url=freq.url.raw_url,
                        description=f"Open redirect vulnerability found in parameter '{param}'. "
                        f"The application redirects to an attacker-controlled URL.",
                        parameter=param,
                        evidence=f"Payload: {payload}\nRedirect location: {location}\n"
                        f"Status: {resp.status_code}",
                        http_request={"method": freq.method, "url": freq.url.raw_url},
                        http_response={"status": resp.status_code, "location": location},
                        remediation="Validate redirect targets against a strict allowlist "
                        "of trusted domains. Use relative URLs for same-site redirects.",
                    )
                    return

            if not resp.is_text:
                continue
            if indicator in resp.text and f'href="{payload}"' in resp.text.lower():
                self.report_finding(
                    name=f"Potential open redirect via '{param}'",
                    severity="medium",
                    url=freq.url.raw_url,
                    description=f"Possible open redirect: the injected URL appears in the "
                    "response body as a link, though no server-side redirect was triggered.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nFound in response body",
                    http_request={"method": freq.method, "url": freq.url.raw_url},
                    remediation="Validate redirect targets against an allowlist.",
                )
                return
