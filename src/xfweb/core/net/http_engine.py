"""Async HTTP engine powered by httpx with HTTP/2 support.

Replaces w3af's urllib2-based ExtendedUrllib with a modern async client.
Features: HTTP/2, connection pooling, rate limiting, adaptive timeouts.
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

    @property
    def is_text(self) -> bool:
        content_type = self.headers.get("content-type", "")
        return any(t in content_type for t in ["text/", "application/json", "application/xml"])

    @property
    def json(self) -> Any:
        import json
        return json.loads(self.body)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


class HttpEngine:
    """Async HTTP client with HTTP/2, connection pooling, and rate limiting."""

    def __init__(
        self,
        user_agent: str = "Xfweb/1.0",
        rate_limit: float = 0.0,
        proxy: str | None = None,
        timeout: float = 30.0,
        max_connections: int = 100,
    ) -> None:
        self.user_agent = user_agent
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._rate_limiter: asyncio.TokenBucket | None = None

        self.request_count: int = 0
        self.error_count: int = 0
        self.urls_crawled: int = 0

        if rate_limit > 0:
            self._rate_limiter = asyncio.TokenBucket(rate_limit, rate_limit)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            transport = httpx.AsyncHTTPTransport(
                http2=True,
                verify=True,
                limits=httpx.Limits(
                    max_connections=self.timeout and 100,
                    max_keepalive_connections=20,
                    keepalive_expiry=30,
                ),
            )
            self._client = httpx.AsyncClient(
                transport=transport,
                headers={"User-Agent": self.user_agent},
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

    async def _request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        if self._rate_limiter:
            await self._rate_limiter.acquire()

        client = await self._get_client()
        start = time.monotonic()

        try:
            response = await client.request(method, url, **kwargs)
            elapsed = (time.monotonic() - start) * 1000
            self.request_count += 1

            logger.debug(
                "xfweb.http.request",
                method=method,
                url=url,
                status=response.status_code,
                elapsed_ms=round(elapsed, 1),
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
            )

        except Exception as exc:
            self.error_count += 1
            logger.warning("xfweb.http.error", method=method, url=url, error=str(exc))
            return HttpResponse(
                status_code=0,
                headers={},
                body=b"",
                text="",
                url=url,
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
