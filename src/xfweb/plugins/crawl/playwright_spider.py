"""Playwright-based SPA (Single Page Application) crawler.

This plugin uses Playwright to render JavaScript-heavy pages and discover
endpoints that a traditional HTML parser would miss. It handles:
- React/Vue/Angular SPA route discovery
- JavaScript-rendered content extraction
- Dynamic form detection
- Browser instance reuse for efficiency
"""

from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any
from urllib.parse import urljoin, urlparse

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

JS_ROUTE_PATTERNS = [
    re.compile(r'(?:push|replace)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'path\s*:\s*["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'route\s*[:=]\s*["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'href\s*[:=]\s*["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'url\s*[:=]\s*["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'endpoint\s*[:=]\s*["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'api\s*[:=]\s*["\']([^"\']+)', re.IGNORECASE),
]

API_PATTERN = re.compile(r'["\']/(api|v[0-9]+|graphql|rest)/[^"\']*["\']')

_playwright_ok: bool | None = None
_shared_browser: Any = None
_pw_instance: Any = None


def _check_playwright_driver() -> bool:
    """Check if the Playwright Node.js driver is compatible with this system."""
    global _playwright_ok
    if _playwright_ok is not None:
        return _playwright_ok

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("xfweb.playwright.python_package_missing")
        _playwright_ok = False
        return False

    node_bin = shutil.which("node")
    if node_bin is None:
        logger.warning("xfweb.playwright.node_not_found", hint="Install Node.js: apt install nodejs")
        _playwright_ok = False
        return False

    async def _test() -> None:
        pw = async_playwright()
        obj = await pw.start()
        await obj.stop()

    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, asyncio.wait_for(_test(), timeout=15.0))
                future.result(timeout=20)
        else:
            asyncio.run(asyncio.wait_for(_test(), timeout=15.0))
        _playwright_ok = True
        return True
    except Exception as exc:
        err = str(exc)
        if "backgroundColorNames" in err or "getter" in err:
            hint = (
                "Node.js version incompatible with system Playwright. "
                "Fix: pip install playwright && playwright install chromium"
            )
        elif "No such file" in err or "node" in err.lower():
            hint = "Run: playwright install chromium"
        else:
            hint = "Run: pip install playwright && playwright install chromium"
        logger.warning("xfweb.playwright.driver_broken", error=err, hint=hint)
        _playwright_ok = False
        return False


async def _get_shared_browser(headless: bool = True) -> Any:
    """Get or create a shared browser instance."""
    global _shared_browser, _pw_instance
    if _shared_browser and _shared_browser.is_connected():
        return _shared_browser

    from playwright.async_api import async_playwright
    _pw_instance = async_playwright()
    pw = await _pw_instance.start()
    _shared_browser = await pw.chromium.launch(headless=headless)
    return _shared_browser


async def close_shared_browser() -> None:
    """Close the shared browser instance."""
    global _shared_browser, _pw_instance
    if _shared_browser:
        try:
            await _shared_browser.close()
        except Exception:
            pass
        _shared_browser = None
    if _pw_instance:
        try:
            await _pw_instance.stop()
        except Exception:
            pass
        _pw_instance = None


class PlaywrightCrawlerPlugin(CrawlPlugin):
    """Crawl SPA applications using Playwright for JavaScript rendering."""

    plugin_name = "playwright_spider"
    brief_description = "Crawl SPA/JS-heavy apps using Playwright headless browser"

    def __init__(self) -> None:
        super().__init__()
        self.options = {
            "headless": True,
            "timeout": 30000,
            "wait_for_load": "networkidle",
            "javascript_enabled": True,
        }

    async def crawl(self, freq: Any, http: HttpEngine) -> list[Any]:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        discovered: list[FuzzableRequest] = []

        if not _check_playwright_driver():
            return []

        try:
            browser = await _get_shared_browser(self.options.get("headless", True))
            page = await browser.new_page()

            api_requests: list[str] = []
            page.on("request", lambda req: self._on_request(req, api_requests))

            try:
                await page.goto(
                    freq.url.raw_url,
                    wait_until=self.options.get("wait_for_load", "networkidle"),
                    timeout=self.options.get("timeout", 30000),
                )

                links = await self._extract_rendered_links(page)
                for link in links:
                    full_url = urljoin(freq.url.raw_url, link)
                    try:
                        parsed = parse_url(full_url)
                        discovered.append(FuzzableRequest.from_url(parsed))
                    except Exception:
                        pass

                js_routes = await self._extract_js_routes(page)
                for route in js_routes:
                    full_url = urljoin(freq.url.raw_url, route)
                    try:
                        parsed = parse_url(full_url)
                        discovered.append(FuzzableRequest.from_url(parsed))
                    except Exception:
                        pass

                forms = await self._extract_forms(page)
                for form_action, method, data in forms:
                    full_url = urljoin(freq.url.raw_url, form_action)
                    try:
                        parsed = parse_url(full_url)
                        discovered.append(FuzzableRequest.from_parts(
                            url=parsed,
                            method=method,
                            post_data=data if method == "POST" else None,
                        ))
                    except Exception:
                        pass

                # Add intercepted API requests
                for api_url in api_requests:
                    try:
                        parsed = parse_url(api_url)
                        discovered.append(FuzzableRequest.from_url(parsed))
                    except Exception:
                        pass

            except Exception as exc:
                logger.warning("xfweb.playwright.error", url=freq.url.raw_url, error=str(exc))
            finally:
                await page.close()

        except Exception as exc:
            logger.warning(
                "xfweb.playwright.crashed",
                url=freq.url.raw_url,
                error=str(exc),
                hint="Run: playwright install chromium && playwright install-deps",
            )
            return []

        logger.info("xfweb.playwright.crawled", url=freq.url.raw_url, discovered=len(discovered))
        return discovered

    async def _extract_rendered_links(self, page: Any) -> list[str]:
        """Extract all visible links from the rendered page."""
        links = await page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('a[href], area[href], [data-href]').forEach(el => {
                    const href = el.getAttribute('href') || el.getAttribute('data-href');
                    if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
                        links.push(href);
                    }
                });
                return [...new Set(links)];
            }
        """)
        return links

    async def _extract_js_routes(self, page: Any) -> list[str]:
        """Extract routes from JavaScript source code."""
        routes: set[str] = set()

        scripts = await page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script[src]').forEach(el => {
                    scripts.push(el.getAttribute('src'));
                });
                return scripts;
            }
        """)

        for script_url in scripts:
            if not script_url or not script_url.startswith("http"):
                continue
            try:
                resp = await page.context.request.get(script_url)
                if resp.ok:
                    body = await resp.text()
                    for pattern in JS_ROUTE_PATTERNS:
                        for match in pattern.finditer(body):
                            route = match.group(1)
                            if route.startswith("/") and len(route) > 1:
                                routes.add(route)
            except Exception:
                pass

        content = await page.content()
        for pattern in JS_ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                route = match.group(1)
                if route.startswith("/") and len(route) > 1:
                    routes.add(route)

        for match in API_PATTERN.finditer(content):
            api_path = match.group(0).strip("\"'")
            routes.add(api_path)

        return list(routes)

    async def _extract_forms(self, page: Any) -> list[tuple[str, str, str]]:
        """Extract forms from the rendered page."""
        forms_data = await page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const action = form.getAttribute('action') || '';
                    const method = (form.getAttribute('method') || 'GET').toUpperCase();
                    const inputs = {};
                    form.querySelectorAll('input, select, textarea').forEach(input => {
                        const name = input.getAttribute('name');
                        if (name) {
                            inputs[name] = input.value || '';
                        }
                    });
                    forms.push({
                        action: action,
                        method: method,
                        data: Object.entries(inputs).map(([k,v]) => k + '=' + v).join('&')
                    });
                });
                return forms;
            }
        """)

        return [(f["action"], f["method"], f["data"]) for f in forms_data]

    def _on_request(self, request: Any, discovered: list) -> None:
        """Capture API requests made by the SPA."""
        url = request.url
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https"):
            if "/api/" in parsed.path or "/v1/" in parsed.path or "/v2/" in parsed.path or "/graphql" in parsed.path:
                discovered.append(url)
