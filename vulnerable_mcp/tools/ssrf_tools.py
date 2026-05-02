"""Tools demonstrating SSRF and out-of-band interactions."""

from __future__ import annotations

import logging

import httpx
from mcp.server.fastmcp import FastMCP

LOGGER = logging.getLogger(__name__)


async def _fetch_unvalidated_url(url: str) -> dict:
    # VULNERABILITY: The URL is completely caller-controlled. Redirects are
    # followed, localhost/private networks are allowed, and there is no scheme or
    # host validation.
    # Impact: callers can probe internal services, hit cloud metadata endpoints,
    # or trigger blind SSRF callbacks to external collaborator systems.
    # Normal fix: use strict allowlists, block private/link-local networks, limit
    # redirects, enforce timeouts, and separate outbound network egress.
    LOGGER.info("Outbound SSRF request to %s", url)
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(url)
        return {
            "url": url,
            "final_url": str(response.url),
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body_preview": response.text[:2000],
        }
    except Exception as exc:
        LOGGER.exception("Outbound SSRF request failed")
        return {"url": url, "error": str(exc)}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def fetch_url(url: str) -> dict:
        """Fetch any user-supplied URL and return a response preview."""
        return await _fetch_unvalidated_url(url)

    @mcp.tool()
    async def import_feed(feed_url: str) -> dict:
        """Pretend to import an RSS/feed URL, but fetch arbitrary destinations."""
        result = await _fetch_unvalidated_url(feed_url)
        result["imported"] = "error" not in result
        return result

    @mcp.tool()
    async def check_webhook(webhook_url: str) -> dict:
        """Check an arbitrary webhook URL, useful for blind SSRF training."""
        result = await _fetch_unvalidated_url(webhook_url)
        return {
            "checked": webhook_url,
            "reachable": "error" not in result,
            "request_result": result,
        }
