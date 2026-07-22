"""WAF/IDS fingerprinting plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import InfrastructurePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": [r"cf-ray", r"cf-cache-status", r"cloudflare"],
        "cookies": [r"__cfduid", r"cf_clearance"],
        "body": [r"cloudflare", r"attention required.*cloudflare"],
    },
    "AWS WAF": {
        "headers": [r"x-amzn-requestid", r"x-amz-cf-id"],
        "cookies": [r"awsalb", r"awsalbcors"],
        "body": [r"aws", r"amazon"],
    },
    "Akamai": {
        "headers": [r"x-akamai", r"akamai"],
        "cookies": [r"akamai"],
        "body": [r"akamai", r"reference.*#.*"],
    },
    "ModSecurity": {
        "headers": [r"mod_security", r"modsecurity"],
        "body": [r"mod_security", r"modsecurity", r"this.*error.*was.*generated.*by.*mod_security"],
    },
    "Sucuri": {
        "headers": [r"x-sucuri-id", r"x-sucuri-cache"],
        "body": [r"sucuri", r"access denied.*sucuri"],
    },
    "Wordfence": {
        "cookies": [r"wf_loginalerted", r"wordfence"],
        "body": [r"wordfence", r"generated.*by.*wordfence"],
    },
    "Barracuda": {
        "headers": [r"barra_counter_session"],
        "body": [r"barracuda"],
    },
    "F5 BIG-IP": {
        "cookies": [r"BIGipServer", r"TS[0-9a-f]+"],
        "headers": [r"x-cnection"],
    },
    "Imperva": {
        "cookies": [r"incap_ses", r"visid_incap"],
        "headers": [r"x-iinfo"],
    },
}


class FingerprintWafPlugin(InfrastructurePlugin):
    """Detect WAF/IDS presence and identify the product."""

    plugin_name = "fingerprint_waf"
    brief_description = "Detect and identify WAF/IDS products"

    async def discover(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        cookies_str = " ".join(resp.headers.get("set-cookie", "").split()).lower()
        body_lower = resp.text.lower()

        detected_wafs: list[str] = []

        for waf_name, signatures in WAF_SIGNATURES.items():
            for pattern in signatures.get("headers", []):
                if re.search(pattern, headers_str):
                    detected_wafs.append(waf_name)
                    break

            if waf_name not in detected_wafs:
                for pattern in signatures.get("cookies", []):
                    if re.search(pattern, cookies_str):
                        detected_wafs.append(waf_name)
                        break

            if waf_name not in detected_wafs:
                for pattern in signatures.get("body", []):
                    if re.search(pattern, body_lower):
                        detected_wafs.append(waf_name)
                        break

        if detected_wafs:
            logger.info(
                "xfweb.fingerprint_waf.detected",
                url=freq.url.raw_url,
                wafs=detected_wafs,
            )
