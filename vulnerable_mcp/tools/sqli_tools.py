"""Tools demonstrating SQL injection."""

from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import FastMCP

from vulnerable_mcp.database import DEFAULT_DB_PATH, get_connection

LOGGER = logging.getLogger(__name__)


def _db_path() -> str:
    return os.getenv("DATABASE_PATH", str(DEFAULT_DB_PATH))


def _rows_for_query(query: str) -> list[dict]:
    LOGGER.warning("Executing intentionally vulnerable SQL query: %s", query)
    with get_connection(_db_path()) as conn:
        return [dict(row) for row in conn.execute(query).fetchall()]


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    def search_user(username: str) -> dict:
        """Search users with unsafe string-concatenated SQL."""
        # VULNERABILITY: username is concatenated directly into SQL.
        # Impact: attackers can alter the WHERE clause, UNION-select secrets, or
        # dump unrelated tables.
        # Normal fix: parameterize queries, validate input, and use least
        # privilege database accounts.
        query = f"SELECT id, username, role, api_key FROM users WHERE username LIKE '%{username}%'"
        return {"query": query, "rows": _rows_for_query(query)}

    @mcp.tool()
    def login_user(username: str, password: str) -> dict:
        """Authenticate with unsafe SQL that can be bypassed."""
        # VULNERABILITY: both username and password are embedded in the query.
        # Impact: payloads such as ' OR '1'='1 can bypass authentication.
        # Normal fix: use password hashing and parameterized lookups.
        query = (
            "SELECT id, username, role, api_key FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        rows = _rows_for_query(query)
        return {
            "query": query,
            "authenticated": len(rows) > 0,
            "user": rows[0] if rows else None,
        }

    @mcp.tool()
    def get_order(order_id: str) -> dict:
        """Fetch an order using unsafe concatenation of caller input."""
        # VULNERABILITY: order_id is treated as trusted SQL.
        # Impact: UNION attacks can extract admin_records or users table data.
        # Normal fix: coerce IDs to integers and use parameterized queries.
        query = (
            "SELECT orders.id, users.username, orders.item, orders.total, orders.internal_note "
            "FROM orders JOIN users ON users.id = orders.user_id "
            f"WHERE orders.id = {order_id}"
        )
        return {"query": query, "rows": _rows_for_query(query)}
