"""Tools demonstrating lack of authentication."""

from __future__ import annotations

import logging
import os
import platform

from mcp.server.fastmcp import FastMCP

from vulnerable_mcp.data import MOCK_NOTES, MOCK_USERS

LOGGER = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    def read_notes() -> list[dict]:
        """Return sensitive internal notes without authentication."""
        # VULNERABILITY: No authentication or authorization is checked.
        # Impact: anyone who can reach the MCP endpoint can read internal data.
        # Normal fix: require authentication and check that the caller is allowed
        # to access each record before returning it.
        LOGGER.info("Unauthenticated read_notes called")
        return MOCK_NOTES

    @mcp.tool()
    def list_users() -> list[dict]:
        """Return internal user records without authentication."""
        # VULNERABILITY: user enumeration is exposed as a public tool.
        # Impact: attackers can gather usernames and roles for later attacks.
        # Normal fix: restrict this to authorized administrators and minimize the
        # returned fields.
        LOGGER.info("Unauthenticated list_users called")
        return MOCK_USERS

    @mcp.tool()
    def system_info() -> dict:
        """Return host/container details without authentication."""
        # VULNERABILITY: environment and platform information is disclosed.
        # Impact: attackers can fingerprint the runtime and plan targeted attacks.
        # Normal fix: avoid exposing environment data, especially secrets and
        # deployment details, unless strictly required for an authorized user.
        LOGGER.info("Unauthenticated system_info called")
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cwd": os.getcwd(),
            "uid": os.getuid() if hasattr(os, "getuid") else "unknown",
            "debug": os.getenv("DEBUG", "true"),
            "interesting_paths": ["/etc/passwd", "/data/vulnerable_mcp.sqlite", "/app/secrets"],
            "environment_sample": {
                key: value
                for key, value in os.environ.items()
                if key in {"DEBUG", "APP_ENV", "TRAINING_SECRET", "MCP_TRANSPORT"}
            },
        }
