"""Async HTTP engine powered by httpx with HTTP/2 support.

Replaces w3af's urllib2-based ExtendedUrllib with a modern async client.
Features: HTTP/2, connection pooling, rate limiting, adaptive timeouts,
retry with exponential backoff, session/cookie management, custom headers.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


@dataclass
class HttpResponse:
    """Wrapper around httpx.Response with Xfweb-specific metadata."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    text: str
    url: str
    history: list[Any] = field(default_factory=list)
    elapsed_ms: float = 0.0
    http_version: str = "1.1"
    request_method: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    @property
    def is_text(self) -> bool:
        content_type = self.headers.get("content-type", "")
        return any(t in content_type for t in [
            "text/", "application/json", "application/xml",
            "text/html", "application/javascript",
        ])

    @property
    def json(self) -> Any:
        import json
        return json.loads(self.body)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def cookies(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for key, value in self.headers.items():
            if key.lower() == "set-cookie":
                parts = value.split(";")[0].split("=", 1)
                if len(parts) == 2:
                    result[parts[0].strip()] = parts[1].strip()
        return result

    @property
    def server(self) -> str:
        return self.headers.get("server", "")

    @property
    def content_length(self) -> int:
        return len(self.body)

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


class RateLimiter:
    """Token bucket rate limiter using asyncio primitives."""

    def __init__(self, rate: float) -> None:
        self._rate = rate
        self._tokens = rate
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


class HttpEngine:
    """Async HTTP client with HTTP/2, connection pooling, rate limiting,
    retry with backoff, session/cookie management, and custom headers."""

    def __init__(
        self,
        user_agent: str = "Xfweb/1.0",
        rate_limit: float = 0.0,
        proxy: str | None = None,
        timeout: float = 30.0,
        max_connections: int = 100,
        max_retries: int = 3,
        retry_delay: float = 0.5,
        extra_headers: dict[str, str] | None = None,
        extra_cookies: dict[str, str] | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.timeout = timeout
        self.max_connections = max_connections
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._extra_headers = extra_headers or {}
        self._extra_cookies = extra_cookies or {}
        self._client: httpx.AsyncClient | None = None
        self._rate_limiter: RateLimiter | None = None

        self.request_count: int = 0
        self.error_count: int = 0
        self.urls_crawled: int = 0
        self._crawled_urls: set[str] = set()

        if rate_limit > 0:
            self._rate_limiter = RateLimiter(rate_limit)

    def _track_crawl(self, url: str) -> None:
        if url not in self._crawled_urls:
            self._crawled_urls.add(url)
            self.urls_crawled += 1

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """Update session cookies (e.g., after login)."""
        self._extra_cookies.update(cookies)
        if self._client and not self._client.is_closed:
            for k, v in cookies.items():
                self._client.cookies.set(k, v)

    def set_headers(self, headers: dict[str, str]) -> None:
        """Update session headers (e.g., after auth token obtained)."""
        self._extra_headers.update(headers)

    def get_cookies(self) -> dict[str, str]:
        """Get all current session cookies."""
        cookies = dict(self._extra_cookies)
        if self._client and not self._client.is_closed:
            for k, v in self._client.cookies.items():
                cookies[k] = v
        return cookies

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            transport = httpx.AsyncHTTPTransport(
                http2=True,
                verify=True,
                limits=httpx.Limits(
                    max_connections=self.max_connections,
                    max_keepalive_connections=20,
                    keepalive_expiry=30,
                ),
            )

            headers = {"User-Agent": self.user_agent}
            headers.update(self._extra_headers)

            self._client = httpx.AsyncClient(
                transport=transport,
                headers=headers,
                cookies=self._extra_cookies,
                timeout=httpx.Timeout(self.timeout),
                proxy=self.proxy,
                follow_redirects=True,
                http2=True,
            )
        return self._client

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("OPTIONS", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self._request("PATCH", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        if self._rate_limiter:
            await self._rate_limiter.acquire()

        client = await self._get_client()
        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            start = time.monotonic()
            try:
                req_kwargs = dict(kwargs)
                response = await client.request(method, url, **req_kwargs)
                elapsed = (time.monotonic() - start) * 1000
                self.request_count += 1
                self._track_crawl(url)

                # Update cookies from response
                for name, value in response.cookies.items():
                    self._extra_cookies[name] = value

                logger.debug(
                    "xfweb.http.request",
                    method=method,
                    url=url,
                    status=response.status_code,
                    elapsed_ms=round(elapsed, 1),
                    attempt=attempt + 1,
                )

                return HttpResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.content,
                    text=response.text,
                    url=str(response.url),
                    history=[str(r.url) for r in response.history],
                    elapsed_ms=elapsed,
                    http_version=response.http_version,
                    request_method=method,
                    request_headers=dict(response.request.headers) if hasattr(response, "request") else {},
                    request_body=str(kwargs.get("data", "")) if "data" in kwargs else "",
                )

            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_error = exc
                self.error_count += 1
                logger.warning(
                    "xfweb.http.retry",
                    method=method,
                    url=url,
                    attempt=attempt + 1,
                    max_retries=self.max_retries,
                    error=str(exc),
                )
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
                continue

            except Exception as exc:
                self.error_count += 1
                logger.warning("xfweb.http.error", method=method, url=url, error=str(exc))
                break

        self.error_count += 1
        logger.warning("xfweb.http.failed", method=method, url=url, error=str(last_error))
        return HttpResponse(
            status_code=0,
            headers={},
            body=b"",
            text="",
            url=url,
            request_method=method,
            request_body=str(kwargs.get("data", "")) if "data" in kwargs else "",
        )

    async def send_websocket(self, url: str, messages: list[str] | None = None) -> dict[str, Any]:
        """Connect to a WebSocket endpoint and exchange messages."""
        import websockets

        results: dict[str, Any] = {"url": url, "connected": False, "messages": []}

        try:
            async with websockets.connect(url) as ws:
                results["connected"] = True
                if messages:
                    for msg in messages:
                        await ws.send(msg)
                        response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                        results["messages"].append({"sent": msg, "received": response})
                else:
                    pong = await ws.ping()
                    await asyncio.wait_for(pong, timeout=5.0)
                    results["ping_pong"] = True
        except Exception as exc:
            results["error"] = str(exc)

        return results

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
