"""Host Header Injection audit plugin.

Detects host header injection vulnerabilities that could enable
password reset poisoning, cache poisoning, and SSRF.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class HostHeaderInjectionPlugin(AuditPlugin):
    """Detect host header injection vulnerabilities."""

    plugin_name = "host_header_injection"
    brief_description = "Detect host header injection and password reset poisoning"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if resp.status_code == 0:
            return

        body_lower = resp.text.lower()
        has_reset = any(w in body_lower for w in ["password", "reset", "forgot", "recover"])
        has_link = "link" in body_lower or "token" in body_lower or "href" in body_lower

        if has_reset and has_link:
            await self._test_password_reset_poisoning(freq, http)

        await self._test_host_header_reflection(freq, http)
        await self._test_x_forwarded_host(freq, http)

    async def _test_password_reset_poisoning(self, freq: Any, http: HttpEngine) -> None:
        evil_host = "evil.example.com"
        resp_normal = await http.get(freq.url.raw_url)
        resp_poisoned = await http.get(
            freq.url.raw_url,
            headers={"Host": evil_host},
        )

        if resp_poisoned.status_code == 200:
            if evil_host in resp_poisoned.text and evil_host not in resp_normal.text:
                self.report_finding(
                    name=f"Password reset poisoning via Host header on {freq.url.raw_url}",
                    severity="critical",
                    url=freq.url.raw_url,
                    description="Host header injection allows password reset poisoning. "
                    f"The application reflects the injected Host header ('{evil_host}') "
                    "in password reset emails/links.",
                    evidence=f"Injected Host: {evil_host}\nEvil host found in response but not in normal response",
                    http_request={"method": "GET", "url": freq.url.raw_url, "headers": {"Host": evil_host}},
                    http_response={"status": resp_poisoned.status_code},
                    remediation="Do not use the Host header to construct URLs for email links. "
                    "Use a fixed, configured base URL instead.",
                )

    async def _test_host_header_reflection(self, freq: Any, http: HttpEngine) -> None:
        evil_host = "xfweb-test.example.com"
        resp = await http.get(
            freq.url.raw_url,
            headers={"Host": evil_host},
        )
        if resp.status_code == 200 and evil_host in resp.text:
            self.report_finding(
                name=f"Host header reflection on {freq.url.raw_url}",
                severity="medium",
                url=freq.url.raw_url,
                description="The application reflects the Host header value in the response body. "
                "This could lead to cache poisoning, virtual host confusion, or XSS.",
                evidence=f"Injected Host: {evil_host}\nFound reflected in response body",
                http_request={"method": "GET", "url": freq.url.raw_url, "headers": {"Host": evil_host}},
                http_response={"status": resp.status_code},
                remediation="Do not reflect the Host header in response content.",
            )

    async def _test_x_forwarded_host(self, freq: Any, http: HttpEngine) -> None:
        evil_host = "xfweb-xff-test.example.com"

        resp1 = await http.get(freq.url.raw_url)
        resp2 = await http.get(
            freq.url.raw_url,
            headers={
                "X-Forwarded-Host": evil_host,
                "X-Host": evil_host,
                "X-Forwarded-Server": evil_host,
            },
        )

        if resp2.status_code == 200 and resp2.status_code == resp1.status_code:
            if evil_host in resp2.text and evil_host not in resp1.text:
                self.report_finding(
                    name=f"X-Forwarded-Host injection on {freq.url.raw_url}",
                    severity="medium",
                    url=freq.url.raw_url,
                    description="The application processes X-Forwarded-Host header and reflects "
                    "the value in the response. This could enable cache poisoning or phishing.",
                    evidence=f"Injected X-Forwarded-Host: {evil_host}\nReflected in response",
                    http_request={"method": "GET", "url": freq.url.raw_url, "headers": {"X-Forwarded-Host": evil_host}},
                    http_response={"status": resp2.status_code},
                    remediation="Do not trust X-Forwarded-Host from untrusted clients. "
                    "Use a whitelist of allowed hostnames.",
                )
