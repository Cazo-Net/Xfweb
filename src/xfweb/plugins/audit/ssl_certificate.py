"""SSL/TLS certificate audit plugin."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class SslCertificatePlugin(AuditPlugin):
    """Analyze SSL/TLS certificates for weaknesses."""

    plugin_name = "ssl_certificate"
    brief_description = "Analyze SSL/TLS certificates for weaknesses and misconfigurations"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        if freq.url.scheme != "https":
            return

        hostname = freq.url.hostname
        port = freq.url.port or 443

        try:
            cert_info = self._get_cert_info(hostname, port)
        except Exception:
            return

        if not cert_info:
            return

        self._check_expiry(cert_info, freq)
        self._check_self_signed(cert_info, freq)
        self._check_weak_key(cert_info, freq)
        self._check_weak_cipher(cert_info, freq)

    def _get_cert_info(self, hostname: str, port: int) -> dict[str, Any] | None:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "serialNumber": cert.get("serialNumber", ""),
                    "version": cert.get("version", ""),
                    "cipher": cipher[0] if cipher else "",
                    "protocol": version or "",
                    "san": cert.get("subjectAltName", []),
                }

    def _check_expiry(self, cert: dict[str, Any], freq: Any) -> None:
        try:
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            now = datetime.now(timezone.utc)
            days_left = (not_after.replace(tzinfo=timezone.utc) - now).days
            if days_left < 0:
                self.report_finding(
                    name=f"Expired SSL certificate on {freq.url.hostname}",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"SSL certificate expired on {cert['notAfter']}.",
                    evidence=f"Expired: {cert['notAfter']}\nIssuer: {cert.get('issuer', {})}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    remediation="Renew the SSL certificate immediately.",
                )
            elif days_left < 30:
                self.report_finding(
                    name=f"SSL certificate expiring soon on {freq.url.hostname}",
                    severity="medium",
                    url=freq.url.raw_url,
                    description=f"SSL certificate expires in {days_left} days.",
                    evidence=f"Expires: {cert['notAfter']}\nDays left: {days_left}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    remediation="Renew the SSL certificate before expiration.",
                )
        except Exception:
            pass

    def _check_self_signed(self, cert: dict[str, Any], freq: Any) -> None:
        if cert.get("subject") == cert.get("issuer"):
            self.report_finding(
                name=f"Self-signed SSL certificate on {freq.url.hostname}",
                severity="medium",
                url=freq.url.raw_url,
                description="The SSL certificate is self-signed. Browsers will show security warnings.",
                evidence=f"Subject: {cert.get('subject')}\nIssuer: {cert.get('issuer')}",
                http_request={"method": "GET", "url": freq.url.raw_url},
                remediation="Use a certificate from a trusted Certificate Authority.",
            )

    def _check_weak_key(self, cert: dict[str, Any], freq: Any) -> None:
        protocol = cert.get("protocol", "")
        if "TLSv1.0" in protocol or "TLSv1.1" in protocol:
            self.report_finding(
                name=f"Weak TLS protocol on {freq.url.hostname}",
                severity="high",
                url=freq.url.raw_url,
                description=f"Server uses weak TLS protocol: {protocol}.",
                evidence=f"Protocol: {protocol}",
                http_request={"method": "GET", "url": freq.url.raw_url},
                remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3.",
            )

    def _check_weak_cipher(self, cert: dict[str, Any], freq: Any) -> None:
        cipher = cert.get("cipher", "")
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
        for weak in weak_ciphers:
            if weak.lower() in cipher.lower():
                self.report_finding(
                    name=f"Weak SSL cipher on {freq.url.hostname}",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"Weak cipher suite detected: {cipher}.",
                    evidence=f"Cipher: {cipher}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    remediation="Configure strong cipher suites (AES-GCM, CHACHA20).",
                )
                return
