"""Random case evasion plugin — randomizes HTTP header casing."""

from __future__ import annotations

import random
import string
from typing import Any

from xfweb.core.plugins.plugin_base import EvasionPlugin


class RndCasePlugin(EvasionPlugin):
    """Randomize HTTP header casing to evade WAF/IDS."""

    plugin_name = "rnd_case"
    brief_description = "Randomize HTTP header casing for WAF evasion"

    def modify_request(self, request: Any) -> Any:
        if hasattr(request, "headers"):
            new_headers = {}
            for key, value in request.headers.items():
                new_key = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in key
                )
                new_headers[new_key] = value
            request.headers = new_headers
        return request
