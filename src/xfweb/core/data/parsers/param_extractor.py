"""Parameter extraction utilities for audit plugins.

Extracts parameters from URL query strings, URL-encoded POST bodies,
JSON POST bodies, XML bodies, and multipart form data.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote


def extract_params(freq: Any) -> dict[str, str]:
    """Extract all injectable parameters from a fuzzable request.

    Handles:
    - URL query parameters (?key=value&key2=value2)
    - URL-encoded POST bodies (key=value&key2=value2)
    - JSON POST bodies ({"key": "value", "key2": "value2"})
    - Nested JSON (flattened with dot notation: {"user": {"name": "test"}} -> "user.name=test")

    Returns dict of param_name -> param_value.
    """
    params: dict[str, str] = {}

    # Extract from URL query
    if freq.url.query:
        params.update(_parse_urlencoded(freq.url.query))

    # Extract from POST body
    if freq.post_data:
        content_type = ""
        if hasattr(freq, "headers") and freq.headers:
            content_type = freq.headers.get("content-type", "").lower()

        if isinstance(freq.post_data, str):
            if "json" in content_type or _is_json(freq.post_data):
                params.update(_parse_json_body(freq.post_data))
            else:
                params.update(_parse_urlencoded(freq.post_data))
        elif isinstance(freq.post_data, bytes):
            try:
                text = freq.post_data.decode("utf-8", errors="replace")
                if "json" in content_type or _is_json(text):
                    params.update(_parse_json_body(text))
                else:
                    params.update(_parse_urlencoded(text))
            except Exception:
                pass

    return params


def extract_injection_context(freq: Any, param: str) -> dict[str, Any]:
    """Get context info about how a parameter is used (for context-aware payloads)."""
    context = {
        "location": "unknown",
        "content_type": "urlencoded",
        "method": freq.method.upper(),
    }

    if freq.url.query and f"{param}=" in freq.url.query:
        context["location"] = "query"

    if freq.post_data and isinstance(freq.post_data, str):
        if _is_json(freq.post_data):
            context["content_type"] = "json"
            context["location"] = "json_body"
        elif f"{param}=" in freq.post_data:
            context["location"] = "post_body"

    return context


def build_injected_body(freq: Any, param: str, payload: str) -> str | bytes | None:
    """Build a new POST body with the payload injected into the specified parameter.

    Handles JSON and URL-encoded bodies.
    """
    if not freq.post_data:
        return None

    content_type = ""
    if hasattr(freq, "headers") and freq.headers:
        content_type = freq.headers.get("content-type", "").lower()

    if isinstance(freq.post_data, str):
        if "json" in content_type or _is_json(freq.post_data):
            return _inject_json(freq.post_data, param, payload)
        else:
            return _inject_urlencoded(freq.post_data, param, payload)
    elif isinstance(freq.post_data, bytes):
        try:
            text = freq.post_data.decode("utf-8", errors="replace")
            if "json" in content_type or _is_json(text):
                return _inject_json(text, param, payload)
            else:
                return _inject_urlencoded(text, param, payload)
        except Exception:
            pass

    return freq.post_data


def build_injected_url(url: str, param: str, value: str, payload: str) -> str:
    """Build a new URL with the payload injected into the specified query parameter."""
    return url.replace(f"{param}={value}", f"{param}={payload}", 1)


def _is_json(text: str) -> bool:
    """Check if a string looks like JSON."""
    stripped = text.strip()
    return (stripped.startswith("{") and stripped.endswith("}")) or \
           (stripped.startswith("[") and stripped.endswith("]"))


def _parse_urlencoded(data: str) -> dict[str, str]:
    """Parse URL-encoded form data."""
    params: dict[str, str] = {}
    for pair in data.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[unquote(k)] = unquote(v)
    return params


def _parse_json_body(data: str) -> dict[str, str]:
    """Parse JSON body and flatten nested keys with dot notation."""
    try:
        obj = json.loads(data)
        if isinstance(obj, dict):
            return _flatten_json(obj)
        elif isinstance(obj, list):
            # Array of objects - extract from first element
            if obj and isinstance(obj[0], dict):
                return _flatten_json(obj[0])
    except (json.JSONDecodeError, IndexError):
        pass
    return {}


def _flatten_json(obj: dict, prefix: str = "") -> dict[str, str]:
    """Flatten nested JSON dict with dot notation."""
    params: dict[str, str] = {}
    for key, value in obj.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            params.update(_flatten_json(value, full_key))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    params.update(_flatten_json(item, f"{full_key}[{i}]"))
                else:
                    params[f"{full_key}[{i}]"] = str(item)
        elif value is not None:
            params[full_key] = str(value)
    return params


def _inject_json(data: str, param: str, payload: str) -> str:
    """Inject payload into a JSON body parameter."""
    try:
        obj = json.loads(data)
        if isinstance(obj, dict):
            _set_nested(obj, param, payload)
            return json.dumps(obj, separators=(",", ":"))
    except (json.JSONDecodeError, KeyError):
        pass
    # Fallback: string replacement
    return data.replace(f'"{param}"', f'"{param}"', 1)


def _inject_urlencoded(data: str, param: str, payload: str) -> str:
    """Inject payload into a URL-encoded body parameter."""
    return data.replace(f"{param}=", f"{param}={payload}", 1)


def _set_nested(obj: dict, key: str, value: str) -> None:
    """Set a value in a nested dict using dot notation."""
    parts = key.split(".")
    current = obj
    for part in parts[:-1]:
        if part in current and isinstance(current[part], dict):
            current = current[part]
        else:
            return  # Key path doesn't exist
    if parts[-1] in current:
        current[parts[-1]] = value
