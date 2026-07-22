"""Web shell / backdoor detection plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

BACKDOOR_PATHS = [
    "shell.php", "cmd.php", "c99.php", "r57.php", "b374k.php",
    "wso.php", "webshell.php", "backdoor.php", "hack.php", "test.php",
    "shell.asp", "shell.aspx", "cmd.asp", "cmd.aspx",
    "shell.jsp", "cmd.jsp", "cmd.jspa",
    "c57.php", "madm3l.php", "angel.php",
    "config.bak.php", "config.php.bak", "config.php~",
    ".config.php.swp", "index.php.bak",
]

BACKDOOR_SIGNATURES = [
    "c99shell", "r57shell", "wso shell", "b374k",
    "eval(base64_decode", "eval($_POST", "eval($_GET",
    "passthru($_", "system($_", "exec($_",
    "shell_exec($_", "popen($_", "proc_open($_",
]


class FindBackdoorsPlugin(CrawlPlugin):
    """Detect web shells and backdoors."""

    plugin_name = "find_backdoors"
    brief_description = "Detect web shells and backdoors on the server"

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        discovered: list[FuzzableRequest] = []
        base = f"{freq.url.scheme}://{freq.url.hostname}"

        for path in BACKDOOR_PATHS:
            url = f"{base}/{path}"
            resp = await http.get(url)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                for sig in BACKDOOR_SIGNATURES:
                    if sig.lower() in body_lower:
                        logger.warning("xfweb.backdoor.found", url=url, signature=sig)
                        try:
                            discovered.append(FuzzableRequest.from_url(parse_url(url)))
                        except Exception:
                            pass
                        break
        return discovered
