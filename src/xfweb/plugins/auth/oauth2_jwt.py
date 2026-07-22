"""OAuth2/OIDC and JWT authentication testing plugins.

Tests OAuth2 flows, JWT algorithm confusion, token forgery,
weak signing keys, and injection attacks.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "key123",
    "changeme", "supersecret", "mysecret", "test", "admin",
    "your-256-bit-secret", "shhhhh", "keyboard_cat",
]


class OAuth2AuthPlugin(AuditPlugin):
    """Test OAuth2/OIDC authentication flows and misconfigurations."""

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

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if resp.status_code != 200 or not resp.is_text:
            return

        await self._check_oauth_endpoints(freq, resp)
        await self._check_token_in_url(freq, resp)
        await self._check_open_redirect(freq, resp, http)

    async def _check_oauth_endpoints(self, freq: Any, resp: Any) -> None:
        body_lower = resp.text.lower()
        oauth_indicators = ["oauth", "authorize", "access_token", "refresh_token", "code="]
        if any(ind in body_lower for ind in oauth_indicators):
            if "state=" not in resp.text.lower():
                self.report_finding(
                    name=f"OAuth2 missing state parameter on {freq.url.raw_url}",
                    severity="high",
                    url=freq.url.raw_url,
                    description="OAuth2 authorization endpoint does not appear to use a 'state' parameter. "
                    "This makes it vulnerable to CSRF attacks.",
                    evidence="OAuth endpoint found but no state parameter detected",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    http_response={"status": resp.status_code},
                    remediation="Always use the state parameter in OAuth2 authorization requests. "
                    "Validate the state parameter on callback.",
                )

    async def _check_token_in_url(self, freq: Any, resp: Any) -> None:
        import re
        token_patterns = [
            re.compile(r"access_token=([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE),
            re.compile(r"token=([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE),
        ]
        for pattern in token_patterns:
            match = pattern.search(freq.url.raw_url)
            if match:
                self.report_finding(
                    name=f"Token exposed in URL on {freq.url.raw_url}",
                    severity="high",
                    url=freq.url.raw_url,
                    description="An authentication token is exposed in the URL. "
                    "Tokens in URLs can be leaked via browser history, referrer headers, and logs.",
                    evidence=f"Token found in URL query string",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    remediation="Never include tokens in URLs. Use POST body or Authorization header.",
                )

    async def _check_open_redirect(self, freq: Any, resp: Any, http: HttpEngine) -> None:
        import re
        redirect_params = re.findall(
            r'(?:redirect|return|next|url|continue|dest|destination|redir|callback)[=_](https?://[^\s&"\']+)',
            freq.url.raw_url,
            re.IGNORECASE,
        )
        for param_url in redirect_params:
            test_url = freq.url.raw_url.replace(param_url, "https://evil.example.com")
            resp2 = await http.get(test_url)
            if resp2.status_code in (301, 302, 303, 307, 308):
                location = resp2.headers.get("location", "")
                if "evil.example.com" in location:
                    self.report_finding(
                        name=f"Open redirect via OAuth callback on {freq.url.raw_url}",
                        severity="high",
                        url=freq.url.raw_url,
                        description="Open redirect vulnerability found in OAuth callback URL. "
                        "An attacker could hijack the OAuth flow.",
                        evidence=f"Redirected to: {location}",
                        http_request={"method": "GET", "url": test_url},
                        http_response={"status": resp2.status_code, "location": location},
                        remediation="Validate redirect URLs against a strict allowlist of trusted domains.",
                    )

    async def login(self, http: HttpEngine) -> bool:
        if not self.options.get("token_url"):
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
            try:
                data = resp.json
                self._token = data.get("access_token")
                return self._token is not None
            except Exception:
                pass
        return False

    async def logout(self, http: HttpEngine) -> None:
        self._token = None

    async def has_active_session(self, http: HttpEngine) -> bool:
        return self._token is not None


class JwtAttackPlugin(AuditPlugin):
    """JWT vulnerability testing — algorithm confusion, weak signing, token forgery."""

    plugin_name = "jwt_attacks"
    brief_description = "Test JWT tokens for algorithm confusion, weak signing, and injection"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if resp.status_code != 200:
            return

        token = self._extract_jwt_from_response(resp)
        if not token:
            token = self._extract_jwt_from_cookies(resp)
        if not token:
            return

        await self._analyze_jwt(token, freq, http)

    def _extract_jwt_from_response(self, resp: Any) -> str | None:
        import re
        patterns = [
            re.compile(r"eyJ[A-Za-z0-9\-._~+/]+=*\.eyJ[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*"),
            re.compile(r"Bearer\s+(eyJ[A-Za-z0-9\-._~+/]+\.eyJ[A-Za-z0-9\-._~+/]+\.[A-Za-z0-9\-._~+/]+)"),
        ]
        for pattern in patterns:
            match = pattern.search(resp.text)
            if match:
                return match.group(0).replace("Bearer ", "")
        return None

    def _extract_jwt_from_cookies(self, resp: Any) -> str | None:
        import re
        for key, value in resp.headers.items():
            if key.lower() == "set-cookie":
                match = re.search(r"eyJ[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*", value)
                if match:
                    return match.group(0)
        return None

    async def _analyze_jwt(self, token: str, freq: Any, http: HttpEngine) -> None:
        parts = token.split(".")
        if len(parts) != 3:
            return

        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
        except Exception:
            return

        alg = header.get("alg", "")

        if alg.lower() == "none":
            self.report_finding(
                name=f"JWT alg:none vulnerability on {freq.url.raw_url}",
                severity="critical",
                url=freq.url.raw_url,
                description="The JWT uses 'none' algorithm, which allows complete token forgery "
                "without any signing key. An attacker can create arbitrary JWT tokens.",
                evidence=f"JWT Header: {json.dumps(header)}",
                http_request={"method": "GET", "url": freq.url.raw_url},
                remediation="Reject tokens with algorithm 'none'. Always validate the algorithm "
                "on the server side and use a strict allowlist of permitted algorithms.",
            )
            return

        if alg in ("HS256", "HS384", "HS512"):
            await self._test_weak_secret(token, parts, header, freq, http)

        if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            await self._test_key_confusion(token, parts, header, freq, http)

        await self._check_jwt_claims(token, parts, freq)

    async def _test_weak_secret(self, token: str, parts: list, header: dict, freq: Any, http: HttpEngine) -> None:
        alg = header.get("alg", "HS256")
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)

        import hashlib
        import hmac

        for secret in WEAK_JWT_SECRETS:
            try:
                key = secret.encode()
                if alg == "HS256":
                    sig = hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
                elif alg == "HS384":
                    sig = hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha384).digest()
                elif alg == "HS512":
                    sig = hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha512).digest()
                else:
                    continue

                import base64
                sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                forged_token = f"{parts[0]}.{parts[1]}.{sig_b64}"

                resp = await http.get(freq.url.raw_url, headers={"Authorization": f"Bearer {forged_token}"})
                if resp.status_code in (200, 302) and resp.status_code != 401:
                    self.report_finding(
                        name=f"JWT weak signing key on {freq.url.raw_url}",
                        severity="critical",
                        url=freq.url.raw_url,
                        description=f"JWT signed with weak secret key. The token was accepted "
                        f"using the common secret '{secret}'. An attacker can forge arbitrary tokens.",
                        evidence=f"Algorithm: {alg}\nWeak secret used: {secret}\nForged token accepted",
                        http_request={"method": "GET", "url": freq.url.raw_url},
                        remediation="Use a strong, randomly generated signing key (minimum 256 bits). "
                        "Consider using asymmetric algorithms (RS256, ES256).",
                    )
                    return
            except Exception:
                continue

    async def _test_key_confusion(self, token: str, parts: list, header: dict, freq: Any, http: HttpEngine) -> None:
        try:
            alg = "HS256"
            payload_b64 = parts[1]
            header_b64 = base64.urlsafe_b64encode(
                json.dumps({"alg": "HS256", "typ": header.get("typ", "JWT")}).encode()
            ).rstrip(b"=").decode()

            test_token = f"{header_b64}.{payload_b64}.fake_sig"
            resp = await http.get(freq.url.raw_url, headers={"Authorization": f"Bearer {test_token}"})
            if resp.status_code not in (401, 403):
                self.report_finding(
                    name=f"JWT algorithm confusion possible on {freq.url.raw_url}",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"JWT accepts RS256 algorithm but may be vulnerable to key confusion. "
                    f"The server accepted a token with alg={alg}.",
                    evidence=f"Original algorithm: {header.get('alg')}\nAccepted alg: {alg}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    remediation="Explicitly validate the algorithm in the JWT header matches expected. "
                    "Do not allow algorithm switching.",
                )
        except Exception:
            pass

    async def _check_jwt_claims(self, token: str, parts: list, freq: Any) -> None:
        try:
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            if "exp" not in payload:
                self.report_finding(
                    name=f"JWT missing expiration claim on {freq.url.raw_url}",
                    severity="medium",
                    url=freq.url.raw_url,
                    description="JWT token does not have an 'exp' (expiration) claim. "
                    "Tokens without expiration can be used indefinitely.",
                    evidence=f"JWT payload claims: {list(payload.keys())}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    remediation="Always include an 'exp' claim in JWT tokens.",
                )

            if payload.get("role") in ("admin", "administrator", "superuser"):
                self.report_finding(
                    name=f"JWT contains elevated privileges on {freq.url.raw_url}",
                    severity="info",
                    url=freq.url.raw_url,
                    description=f"JWT contains elevated role claim: {payload.get('role')}. "
                    "Verify that privilege escalation is properly prevented.",
                    evidence=f"Role claim: {payload.get('role')}",
                    http_request={"method": "GET", "url": freq.url.raw_url},
                    remediation="Validate role assignments server-side. Never trust client-provided roles.",
                )
        except Exception:
            pass

    async def login(self, http: HttpEngine) -> bool:
        return True

    async def logout(self, http: HttpEngine) -> None:
        pass

    async def has_active_session(self, http: HttpEngine) -> bool:
        return True
