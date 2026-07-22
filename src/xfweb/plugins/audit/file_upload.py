"""Unrestricted file upload audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

DANGEROUS_EXTENSIONS = [
    "php", "php3", "php4", "php5", "php7", "phtml", "phar",
    "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx",
    "jsp", "jspx", "jspa", "jsw", "jsv", "jtml",
    "cer", "cdx", "htr", "shtml",
]

SHELL_CONTENTS = [
    '<?php echo "XFWEB_TEST"; ?>',
    '<% Response.Write("XFWEB_TEST") %>',
    '<?php echo md5("xfweb"); ?>',
]


class FileUploadPlugin(AuditPlugin):
    """Detect unrestricted file upload vulnerabilities."""

    plugin_name = "file_upload"
    brief_description = "Detect unrestricted file upload vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if resp.status_code != 200 or not resp.is_text:
            return

        if "upload" not in resp.text.lower() and "file" not in resp.text.lower():
            if "multipart/form-data" not in resp.text:
                return

        import re
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*enctype=["\']multipart/form-data["\'][^>]*>',
            re.IGNORECASE,
        )

        forms = form_pattern.findall(resp.text)
        if not forms:
            form_pattern2 = re.compile(
                r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*action=["\']([^"\']*)["\'][^>]*>',
                re.IGNORECASE,
            )
            forms = form_pattern2.findall(resp.text)

        for action in forms:
            logger.info(
                "xfweb.file_upload.found",
                url=freq.url.raw_url,
                action=action,
            )


class ResponseSplittingPlugin(AuditPlugin):
    """HTTP Response Splitting (CRLF injection) audit plugin."""

    plugin_name = "response_splitting"
    brief_description = "Detect HTTP response splitting vulnerabilities"

    CRLF_PAYLOADS = [
        "%0d%0aInjected-Header: xfweb",
        "\r\nInjected-Header: xfweb",
        "%0D%0AInjected-Header:%20xfweb",
        "%0d%0a%0d%0a<script>alert(1)</script>",
    ]

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return

        tasks = [self._test_param(freq, p, v, http) for p, v in params.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

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
        for payload in self.CRLF_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={value}{payload}",
            )
            resp = await http.get(modified_url)
            if "Injected-Header" in resp.headers.get("", "") or "Injected-Header" in resp.text:
                logger.warning(
                    "xfweb.response_splitting.vuln_found",
                    url=freq.url.raw_url,
                    param=param,
                )
                return


class CorsOriginPlugin(AuditPlugin):
    """CORS misconfiguration audit plugin."""

    plugin_name = "cors_origin"
    brief_description = "Detect CORS misconfigurations and origin reflection"

    ORIGIN_PAYLOADS = [
        "https://evil.com",
        "null",
        "https://{hostname}.evil.com",
        "https://evil-{hostname}.com",
    ]

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        tasks = [self._test_origin(freq, http, origin) for origin in self.ORIGIN_PAYLOADS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_origin(self, freq: Any, http: HttpEngine, origin_template: str) -> None:
        origin = origin_template.replace("{hostname}", freq.url.hostname)
        headers = {"Origin": origin}

        resp = await http.get(freq.url.raw_url, headers=headers)
        acao = resp.headers.get("access-control-allow-origin", "")

        if acao == "*" or acao == origin:
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acac.lower() == "true":
                logger.warning(
                    "xfweb.cors.vuln_found",
                    url=freq.url.raw_url,
                    origin=origin,
                    credentials="true",
                )
            elif acao == "*":
                logger.info(
                    "xfweb.cors.wildcard",
                    url=freq.url.raw_url,
                )
