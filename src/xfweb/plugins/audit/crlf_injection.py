"""CRLF Injection / HTTP Header Injection audit plugin.

Detects CRLF injection vulnerabilities that allow HTTP response
header injection and response splitting.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

CRLF_PAYLOADS = [
    "%0d%0a",
    "%0D%0A",
    "%0d%0a%0d%0a",
    "\r\n",
    "%E5%98%8A%E5%98%8D",
    "%c0%8d%c0%8a",
    "%0d%0aInjected-Header: xfweb-crlf-test",
]

INJECTED_MARKER = "xfweb-crlf-test"


class CrlfInjectionPlugin(AuditPlugin):
    """Detect CRLF injection and HTTP header injection vulnerabilities."""

    plugin_name = "crlf_injection"
    brief_description = "Detect CRLF injection and HTTP header injection"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return

        tasks = [self._test_param(freq, p, v, http) for p, v in params.items()]
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._test_path_traversal(freq, http)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        params: dict[str, str] = {}
        if freq.post_data and isinstance(freq.post_data, str):
            for pair in freq.post_data.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        if freq.url.query:
            for pair in freq.url.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        return params

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine) -> None:
        for payload in CRLF_PAYLOADS:
            header_inject = payload + "Xfweb-Test: injected"
            resp = await self._inject(freq, param, header_inject, http)

            if resp.status_code == 0:
                continue

            if INJECTED_MARKER in str(resp.headers) or "Xfweb-Test" in str(resp.headers):
                self.report_finding(
                    name=f"CRLF injection via '{param}' parameter",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"CRLF injection detected in parameter '{param}'. "
                    "Attacker can inject arbitrary HTTP response headers.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nInjected header found in response",
                    http_request={"method": freq.method, "url": freq.url.raw_url},
                    http_response={"status": resp.status_code, "headers": resp.headers},
                    remediation="URL-encode all CRLF characters (%0d, %0a) in user input "
                    "before including in HTTP headers. Validate and sanitize all header values.",
                )
                return

            body_payload = payload + "<script>alert('crlf')</script>"
            resp2 = await self._inject(freq, param, body_payload, http)
            if resp2.status_code == 200 and "<script>alert('crlf')</script>" in resp2.text:
                self.report_finding(
                    name=f"CRLF response splitting via '{param}'",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"HTTP response splitting via CRLF injection in '{param}'. "
                    "Injected content appears in response body.",
                    parameter=param,
                    evidence=f"Payload: {body_payload}\nInjected content in response body",
                    http_request={"method": freq.method, "url": freq.url.raw_url},
                    http_response={"status": resp2.status_code},
                    remediation="Sanitize all user input used in HTTP responses.",
                )
                return

    async def _test_path_traversal(self, freq: Any, http: HttpEngine) -> None:
        test_url = freq.url.raw_url
        if "?" not in test_url:
            return
        path_payload = "/%0d%0aSet-Cookie:crlf=injection"
        test_url_with_crlf = test_url + path_payload
        resp = await http.get(test_url_with_crlf)
        if resp.status_code != 404:
            for key in resp.headers:
                if "crlf" in key.lower() and "injection" in resp.headers.get(key, "").lower():
                    self.report_finding(
                        name=f"CRLF injection via URL path on {freq.url.raw_url}",
                        severity="high",
                        url=freq.url.raw_url,
                        description="CRLF injection detected via URL path manipulation.",
                        evidence=f"Injected Set-Cookie header: {key}={resp.headers[key]}",
                        http_request={"method": "GET", "url": test_url_with_crlf},
                        http_response={"status": resp.status_code},
                        remediation="Filter CRLF characters from all URL parameters and paths.",
                    )
                    return

    async def _inject(self, freq: Any, param: str, payload: str, http: HttpEngine) -> Any:
        if freq.method.upper() == "POST" and freq.post_data:
            new_data = freq.post_data.replace(f"{param}=", f"{param}={payload}")
            return await http.post(freq.url.raw_url, data=new_data)
        else:
            new_url = freq.url.raw_url.replace(f"{param}=", f"{param}={payload}")
            return await http.get(new_url)
