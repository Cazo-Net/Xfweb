"""HTTP Basic Authentication brute-force plugin."""

from __future__ import annotations

import asyncio
from itertools import product
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import BruteforcePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

DEFAULT_USERS = [
    "admin", "root", "user", "test", "guest", "info", "support",
    "administrator", "operator", "webmaster", "administrator",
    "manager", "service", "backup", "demo",
]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "root", "toor", "pass",
    "test", "guest", "changeme", "default", "secret", "1234",
    "12345", "123456789", "letmein", "welcome", "qwerty",
    "abc123", "monkey", "master", "dragon", "login",
]


class BasicAuthBrutePlugin(BruteforcePlugin):
    """Brute-force HTTP Basic Authentication endpoints."""

    plugin_name = "basic_auth_brute"
    brief_description = "Brute-force HTTP Basic Authentication"

    def __init__(self) -> None:
        super().__init__()
        self.options = {
            "users": DEFAULT_USERS,
            "passwords": DEFAULT_PASSWORDS,
            "threads": 5,
        }
        self._found: bool = False

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        import base64

        users = self.options.get("users", DEFAULT_USERS)
        passwords = self.options.get("passwords", DEFAULT_PASSWORDS)
        semaphore = asyncio.Semaphore(self.options.get("threads", 5))

        async def _try_login(user: str, password: str) -> tuple[str, str, bool] | None:
            if self._found:
                return None
            async with semaphore:
                creds = base64.b64encode(f"{user}:{password}".encode()).decode()
                headers = {"Authorization": f"Basic {creds}"}
                resp = await http.get(freq.url.raw_url, headers=headers)
                if resp.status_code in (200, 301, 302):
                    self._found = True
                    logger.warning(
                        "xfweb.basic_auth_brute.success",
                        url=freq.url.raw_url,
                        user=user,
                        password=password,
                    )
                    return (user, password, True)
                return None

        tasks = [_try_login(u, p) for u, p in product(users, passwords) if not self._found]
        await asyncio.gather(*tasks, return_exceptions=True)
