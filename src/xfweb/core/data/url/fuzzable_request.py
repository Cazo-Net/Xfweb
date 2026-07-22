"""FuzzableRequest — the core unit of work in Xfweb.

Represents an HTTP request with injection points (parameters) that can be fuzzed.
Inherited from w3af, modernized with Pydantic and HTTP/2 awareness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FuzzableRequest:
    """An HTTP request ready to be fuzzed for vulnerabilities."""

    url: Any
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    post_data: str | bytes | None = None
    post_data_type: str = ""  # "urlencoded", "multipart", "json", "xml"
    injection_points: list[str] = field(default_factory=list)
    source_plugin: str = ""
    tag: str = ""

    @classmethod
    def from_url(cls, url: Any) -> FuzzableRequest:
        return cls(url=url)

    @classmethod
    def from_http_response(cls, response: Any, url: Any) -> FuzzableRequest:
        return cls(url=url, headers=dict(response.headers))

    @classmethod
    def from_parts(
        cls,
        url: Any,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        post_data: str | bytes | None = None,
    ) -> FuzzableRequest:
        return cls(
            url=url,
            method=method,
            headers=headers or {},
            cookies=cookies or {},
            post_data=post_data,
        )

    def sent(self, needle: str) -> bool:
        """Check if a needle appears in the request (for false positive detection)."""
        if self.post_data:
            data_str = self.post_data if isinstance(self.post_data, str) else self.post_data.decode()
            if needle in data_str:
                return True
        for value in self.headers.values():
            if needle in value:
                return True
        return False

    def copy(self) -> FuzzableRequest:
        """Create a deep copy to prevent cross-plugin contamination."""
        return FuzzableRequest(
            url=self.url,
            method=self.method,
            headers=dict(self.headers),
            cookies=dict(self.cookies),
            post_data=self.post_data,
            post_data_type=self.post_data_type,
            injection_points=list(self.injection_points),
            source_plugin=self.source_plugin,
            tag=self.tag,
        )
