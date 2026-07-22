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
        except Exception as exc:
            logger.debug("xfweb.ssl.cert_error", host=hostname, error=str(exc))
            return

        if not cert_info:
            return

        self._check_expiry(cert_info, hostname)
        self._check_self_signed(cert_info, hostname)
        self._check_weak_key(cert_info, hostname)
        self._check_weak_cipher(cert_info, hostname)

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

    def _check_expiry(self, cert: dict[str, Any], hostname: str) -> None:
        try:
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            now = datetime.now(timezone.utc)
            days_left = (not_after.replace(tzinfo=timezone.utc) - now).days

            if days_left < 0:
                logger.warning(
                    "xfweb.ssl.expired",
                    host=hostname,
                    expired_on=cert["notAfter"],
                )
            elif days_left < 30:
                logger.warning(
                    "xfweb.ssl.expiring_soon",
                    host=hostname,
                    days_left=days_left,
                )
        except Exception:
            pass

    def _check_self_signed(self, cert: dict[str, Any], hostname: str) -> None:
        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        if subject == issuer:
            logger.warning("xfweb.ssl.self_signed", host=hostname)

    def _check_weak_key(self, cert: dict[str, Any], hostname: str) -> None:
        protocol = cert.get("protocol", "")
        if "TLSv1.0" in protocol or "TLSv1.1" in protocol:
            logger.warning(
                "xfweb.ssl.weak_protocol",
                host=hostname,
                protocol=protocol,
            )

    def _check_weak_cipher(self, cert: dict[str, Any], hostname: str) -> None:
        cipher = cert.get("cipher", "")
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
        for weak in weak_ciphers:
            if weak.lower() in cipher.lower():
                logger.warning(
                    "xfweb.ssl.weak_cipher",
                    host=hostname,
                    cipher=cipher,
                )
                return
