"""Entrypoint for the deliberately vulnerable MCP server.

DO NOT deploy publicly. This service intentionally contains vulnerabilities for
local security education and controlled lab environments only.
"""

from __future__ import annotations

import argparse
import logging
import os

from mcp.server.fastmcp import FastMCP

from vulnerable_mcp.database import init_db
from vulnerable_mcp.tools import auth_tools, file_tools, sqli_tools, ssrf_tools, unauth_tools


def configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "DEBUG").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def create_server() -> FastMCP:
    """Create the MCP server and register intentionally vulnerable tools."""
    init_db(os.getenv("DATABASE_PATH", "/data/vulnerable_mcp.sqlite"))

    mcp = FastMCP(
        name="Vulnerable MCP Server",
        instructions=(
            "WARNING: Intentionally vulnerable MCP server for local education only. "
            "Do not deploy publicly or use in production."
        ),
        host=os.getenv("MCP_HOST", "0.0.0.0"),
        port=int(os.getenv("MCP_PORT", "8000")),
        stateless_http=True,
        json_response=True,
    )

    unauth_tools.register(mcp)
    auth_tools.register(mcp)
    file_tools.register(mcp)
    ssrf_tools.register(mcp)
    sqli_tools.register(mcp)
    return mcp


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser(description="Run the Vulnerable MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=os.getenv("MCP_TRANSPORT", "streamable-http"),
        help="MCP transport to use.",
    )
    args = parser.parse_args()

    logging.getLogger(__name__).warning(
        "Starting intentionally vulnerable MCP server using %s transport. "
        "DO NOT expose this server to public networks.",
        args.transport,
    )

    mcp = create_server()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
