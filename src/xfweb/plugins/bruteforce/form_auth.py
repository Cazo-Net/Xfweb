"""Form-based authentication brute-force plugin."""

from __future__ import annotations

import asyncio
import re
from itertools import product
from typing import Any
from urllib.parse import urljoin

import structlog

from xfweb.core.plugins.plugin_base import BruteforcePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

DEFAULT_USERS = [
    "admin", "root", "user", "test", "guest",
    "administrator", "manager", "support", "info",
]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "root", "pass",
    "test", "guest", "changeme", "default", "secret",
    "letmein", "welcome", "qwerty", "abc123",
]


class FormAuthBrutePlugin(BruteforcePlugin):
    """Brute-force form-based authentication endpoints."""

    plugin_name = "form_auth_brute"
    brief_description = "Brute-force form-based authentication"

    def __init__(self) -> None:
        super().__init__()
        self.options = {
            "users": DEFAULT_USERS,
            "passwords": DEFAULT_PASSWORDS,
            "username_field": "username",
            "password_field": "password",
            "threads": 5,
        }
        self._found: bool = False

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        users = self.options.get("users", DEFAULT_USERS)
        passwords = self.options.get("passwords", DEFAULT_PASSWORDS)
        user_field = self.options.get("username_field", "username")
        pass_field = self.options.get("password_field", "password")
        semaphore = asyncio.Semaphore(self.options.get("threads", 5))

        resp = await http.get(freq.url.raw_url)
        form_match = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>',
            resp.text,
            re.IGNORECASE,
        )
        form_action = urljoin(freq.url.raw_url, form_match.group(1)) if form_match else freq.url.raw_url

        async def _try_login(user: str, password: str) -> None:
            if self._found:
                return
            async with semaphore:
                data = f"{user_field}={user}&{pass_field}={password}"
                resp = await http.post(
                    form_action,
                    content=data.encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if resp.status_code in (301, 302, 303, 307):
                    self._found = True
                    logger.warning(
                        "xfweb.form_auth_brute.success",
                        url=freq.url.raw_url,
                        user=user,
                        password=password,
                    )

        tasks = [_try_login(u, p) for u, p in product(users, passwords) if not self._found]
        await asyncio.gather(*tasks, return_exceptions=True)
