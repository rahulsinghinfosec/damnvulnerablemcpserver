"""Intentionally weak Basic Authentication helpers."""

from __future__ import annotations

import base64
import logging

LOGGER = logging.getLogger(__name__)

# VULNERABILITY: These are hardcoded default credentials.
# Impact: attackers can guess or reuse well-known admin:admin credentials.
# Normal fix: use unique credentials, secret storage, rotation, MFA, and strong
# authorization checks. Never commit real credentials to source control.
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"


def is_valid_basic_auth(authorization: str | None) -> bool:
    """Return True only for the intentionally weak admin:admin credential."""
    LOGGER.info("Checking Basic Auth header: %r", authorization)

    if not authorization or not authorization.lower().startswith("basic "):
        return False

    encoded = authorization.split(" ", 1)[1].strip()
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return False

    username, _, password = decoded.partition(":")
    return username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD
