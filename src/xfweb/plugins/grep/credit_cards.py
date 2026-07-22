"""Credit card number detection plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

CC_PATTERNS = {
    "Visa": re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
    "MasterCard": re.compile(r"\b5[1-5][0-9]{14}\b"),
    "American Express": re.compile(r"\b3[47][0-9]{13}\b"),
    "Diners Club": re.compile(r"\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b"),
    "Discover": re.compile(r"\b6(?:011|5[0-9]{2})[0-9]{12}\b"),
    "JCB": re.compile(r"\b(?:2131|1800|35\d{3})\d{11}\b"),
    "UnionPay": re.compile(r"\b62[0-9]{14,17}\b"),
}


class CreditCardsPlugin(GrepPlugin):
    """Detect credit card numbers in HTTP responses."""

    plugin_name = "credit_cards"
    brief_description = "Detect credit card numbers in HTTP responses"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        if not resp.is_text:
            return

        for cc_type, pattern in CC_PATTERNS.items():
            matches = pattern.findall(resp.text)
            for match in matches:
                if self._luhn_check(match):
                    logger.warning(
                        "xfweb.credit_cards.found",
                        url=freq.url.raw_url,
                        type=cc_type,
                        last_four=match[-4:],
                    )

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13:
            return False

        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d

        return checksum % 10 == 0
