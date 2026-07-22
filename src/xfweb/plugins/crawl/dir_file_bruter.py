"""Directory and file brute-force crawler — discovers hidden files and directories.

Ported from w3af's dir_file_bruter.py with async architecture.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

COMMON_DIRS = [
    "admin", "backup", "config", "db", "database", "debug", "deploy",
    "dev", "docs", "dump", "env", "export", "files", "ftp", "git",
    "hidden", "img", "images", "inc", "include", "internal", "lib",
    "log", "logs", "media", "old", "private", "public", "resources",
    "scripts", "secret", "security", "src", "static", "storage",
    "temp", "tmp", "upload", "uploads", "user", "users", "v1", "v2",
    "v3", "api", "api/v1", "api/v2", "api/v3", "test", "testing",
    "staging", "production", "beta", "alpha", "demo", "sandbox",
    ".git", ".svn", ".env", ".htaccess", ".htpasswd", ".DS_Store",
    "wp-admin", "wp-content", "wp-includes", "wp-login.php",
    "phpmyadmin", "adminer", "console", "shell", "debug",
]

COMMON_FILES = [
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/HEAD", ".git/config", ".svn/entries", ".svn/wc.db",
    "web.config", "config.php", "config.inc.php", "config.json",
    "config.yml", "config.yaml", "settings.py", "database.yml",
    ".htaccess", ".htpasswd", "server-status", "server-info",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "readme.html", "README.md", "CHANGELOG.md", "LICENSE",
    "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "admin/", "login/", "wp-login.php", "administrator/",
    "console/", "phpmyadmin/", "adminer.php",
    "swagger.json", "openapi.json", "swagger.yaml", "openapi.yaml",
    ".well-known/security.txt", "security.txt",
]

EXTENSIONS = ["", ".php", ".asp", ".aspx", ".jsp", ".html", ".txt", ".json", ".xml", ".bak", ".old", ".orig"]


class DirFileBruterPlugin(CrawlPlugin):
    """Brute-force directories and files to discover hidden endpoints."""

    plugin_name = "dir_file_bruter"
    brief_description = "Brute-force directories and files to discover hidden endpoints"

    def __init__(self) -> None:
        super().__init__()
        self.options = {
            "wordlist": "common",
            "extensions": EXTENSIONS,
            "threads": 15,
        }
        self._tested: set[str] = set()

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        discovered: list[FuzzableRequest] = []
        base = f"{freq.url.scheme}://{freq.url.hostname}"

        urls_to_test: list[str] = []
        for d in COMMON_DIRS:
            url = f"{base}/{d}"
            if url not in self._tested:
                self._tested.add(url)
                urls_to_test.append(url)

        for f in COMMON_FILES:
            url = f"{base}/{f}"
            if url not in self._tested:
                self._tested.add(url)
                urls_to_test.append(url)

        semaphore = asyncio.Semaphore(self.options.get("threads", 15))

        async def _test_url(url: str) -> str | None:
            async with semaphore:
                resp = await http.head(url)
                if resp.status_code in (200, 301, 302, 303, 307, 308, 401, 403):
                    return url
                return None

        tasks = [_test_url(u) for u in urls_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str):
                logger.info("xfweb.dir_bruter.found", url=result)
                try:
                    discovered.append(FuzzableRequest.from_url(parse_url(result)))
                except Exception:
                    pass

        logger.info("xfweb.dir_bruter.complete", tested=len(urls_to_test), found=len(discovered))
        return discovered
