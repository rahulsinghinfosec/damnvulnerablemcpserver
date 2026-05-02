"""Tools demonstrating weak/default credentials."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from vulnerable_mcp.auth import is_valid_basic_auth
from vulnerable_mcp.data import MOCK_ADMIN_LOGS

LOGGER = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    def get_sensitive_logs(authorization: str = "") -> dict:
        """Return mock admin logs when supplied Basic admin:admin credentials."""
        # VULNERABILITY: This accepts hardcoded default credentials.
        # Impact: attackers commonly try admin:admin during credential stuffing
        # and default password attacks. If successful, they receive sensitive logs.
        # Normal fix: use unique credentials from a secret manager, enforce strong
        # password policy, rotate secrets, and apply proper per-user authorization.
        #
        # In streamable HTTP clients, pass the Basic value as this argument:
        # authorization="Basic YWRtaW46YWRtaW4=".
        LOGGER.info("get_sensitive_logs called with authorization=%r", authorization)
        if not is_valid_basic_auth(authorization):
            return {
                "authenticated": False,
                "error": "Unauthorized. Training hint: try Basic Auth for admin:admin.",
            }

        return {
            "authenticated": True,
            "warning": "These logs are intentionally exposed after weak default auth.",
            "logs": MOCK_ADMIN_LOGS,
        }

    @mcp.tool()
    def admin_panel(authorization: str = "") -> dict:
        """Return mock admin panel data protected by weak default credentials."""
        LOGGER.info("admin_panel called with authorization=%r", authorization)
        if not is_valid_basic_auth(authorization):
            return {"authenticated": False, "error": "Unauthorized"}

        return {
            "authenticated": True,
            "admin_users": ["admin"],
            "feature_flags": {"debug_sql": True, "allow_file_write": True},
            "secrets": {
                "training_api_key": "lab_admin_panel_key_123",
                "backup_location": "/lab-data/backups",
            },
        }
