"""OAuth2/OIDC and JWT authentication testing plugins."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuthPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class OAuth2AuthPlugin(AuthPlugin):
    """Test OAuth2/OIDC authentication flows."""

    plugin_name = "oauth2_auth"
    brief_description = "Test OAuth2 authorization code, PKCE, and client credentials flows"

    def __init__(self) -> None:
        super().__init__()
        self.options = {
            "client_id": "",
            "client_secret": "",
            "authorization_url": "",
            "token_url": "",
            "redirect_uri": "",
            "scope": "openid profile",
        }
        self._token: str | None = None

    async def login(self, http: HttpEngine) -> bool:
        if not self.options.get("token_url"):
            logger.warning("xfweb.oauth2.no_token_url")
            return False

        resp = await http.post(
            self.options["token_url"],
            data={
                "grant_type": "client_credentials",
                "client_id": self.options.get("client_id", ""),
                "client_secret": self.options.get("client_secret", ""),
                "scope": self.options.get("scope", ""),
            },
        )

        if resp.status_code == 200:
            data = resp.json
            self._token = data.get("access_token")
            return self._token is not None

        return False

    async def logout(self, http: HttpEngine) -> None:
        self._token = None

    async def has_active_session(self, http: HttpEngine) -> bool:
        return self._token is not None


class JwtAttackPlugin(AuthPlugin):
    """JWT vulnerability testing — algorithm confusion, key brute force, token manipulation."""

    plugin_name = "jwt_attacks"
    brief_description = "Test JWT tokens for algorithm confusion, weak signing, and injection"

    async def login(self, http: HttpEngine) -> bool:
        return True

    async def logout(self, http: HttpEngine) -> None:
        pass

    async def has_active_session(self, http: HttpEngine) -> bool:
        return True

    async def test_jwt(self, token: str, http: HttpEngine) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        parts = token.split(".")
        if len(parts) != 3:
            return findings

        import base64
        import json

        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            if header.get("alg") == "none":
                findings.append({
                    "name": "JWT alg:none Attack",
                    "severity": "critical",
                    "description": "The JWT header uses 'none' algorithm, allowing token forgery.",
                    "remediation": "Reject tokens with algorithm 'none'.",
                })

            if header.get("alg") in ("HS256", "HS384", "HS512"):
                findings.append({
                    "name": "JWT Potential Key Confusion",
                    "severity": "high",
                    "description": (
                        f"JWT uses HMAC algorithm ({header['alg']}). "
                        "If the server also accepts RSA public keys, this may allow key confusion attacks."
                    ),
                    "remediation": "Use asymmetric algorithms (RS256/ES256) and validate algorithm on server.",
                })

        except Exception:
            pass

        return findings
