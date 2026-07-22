"""Random hex encoding evasion plugin."""

from __future__ import annotations

import random
from typing import Any

from xfweb.core.plugins.plugin_base import EvasionPlugin


class RndHexEncodePlugin(EvasionPlugin):
    """Encode payload characters as hex to evade WAF pattern matching."""

    plugin_name = "rnd_hex_encode"
    brief_description = "Randomly encode characters as hex for WAF evasion"

    def modify_request(self, request: Any) -> Any:
        if hasattr(request, "post_data") and request.post_data:
            if isinstance(request.post_data, str):
                encoded = []
                for char in request.post_data:
                    if random.random() > 0.7 and char.isalnum():
                        encoded.append(f"%{ord(char):02x}")
                    else:
                        encoded.append(char)
                request.post_data = "".join(encoded)
        return request
