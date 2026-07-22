"""PHP info disclosure detection plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/test.php", "/pi.php",
    "/p.php", "/php.php", "/i.php", "/debug.php",
    "/php_info.php", "/info.php5", "/phpinfo.php5",
    "/~phpinfo", "/phpinfo.html",
]

PHPINFO_SIGNATURES = ["phpinfo()", "PHP Version", "php.ini", "Loaded Configuration File"]


class PhpinfoPlugin(CrawlPlugin):
    """Detect exposed phpinfo() pages."""

    plugin_name = "phpinfo"
    brief_description = "Detect exposed phpinfo() pages"

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        discovered: list[FuzzableRequest] = []
        base = f"{freq.url.scheme}://{freq.url.hostname}"

        for path in PHPINFO_PATHS:
            url = f"{base}{path}"
            resp = await http.get(url)
            if resp.status_code == 200:
                if any(sig in resp.text for sig in PHPINFO_SIGNATURES):
                    logger.warning("xfweb.phpinfo.found", url=url)
                    try:
                        discovered.append(FuzzableRequest.from_url(parse_url(url)))
                    except Exception:
                        pass
        return discovered
