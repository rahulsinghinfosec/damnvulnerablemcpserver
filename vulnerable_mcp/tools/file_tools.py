"""Tools demonstrating excessive filesystem permissions."""

from __future__ import annotations

import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

LOGGER = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    def read_file(path: str) -> dict:
        """Read any file path supplied by the caller."""
        # VULNERABILITY: The caller controls the full path and there is no
        # allowlist, sandbox, canonicalization, or traversal prevention.
        # Impact: callers can read sensitive files such as /etc/passwd, app
        # config, database files, and mounted secret directories.
        # Normal fix: constrain access to a dedicated safe directory, resolve
        # paths, block traversal, and run the service with least privilege.
        LOGGER.info("read_file called path=%s", path)
        target = Path(path)
        try:
            return {
                "path": str(target),
                "content": target.read_text(errors="replace"),
            }
        except Exception as exc:
            LOGGER.exception("read_file failed")
            return {"path": str(target), "error": str(exc)}

    @mcp.tool()
    def write_file(path: str, content: str) -> dict:
        """Write caller-supplied content to any path allowed by the container."""
        # VULNERABILITY: Arbitrary writes are allowed while the container runs as
        # root and has writable mounted volumes.
        # Impact: callers can overwrite application files, plant scripts, tamper
        # with lab data, or prepare persistence inside writable mounts.
        # Normal fix: avoid exposing write primitives, validate destinations,
        # enforce least-privilege users, and mount filesystems read-only.
        LOGGER.info("write_file called path=%s bytes=%s", path, len(content))
        target = Path(path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            return {"path": str(target), "written_bytes": len(content)}
        except Exception as exc:
            LOGGER.exception("write_file failed")
            return {"path": str(target), "error": str(exc)}

    @mcp.tool()
    def list_directory(path: str = ".") -> dict:
        """List any directory supplied by the caller."""
        # VULNERABILITY: Unrestricted directory listing leaks filesystem layout.
        # Impact: attackers can discover secrets, source files, mounted volumes,
        # and paths to target with read_file/write_file.
        # Normal fix: restrict directory browsing to explicitly allowed locations
        # and avoid returning hidden or sensitive files.
        LOGGER.info("list_directory called path=%s", path)
        target = Path(path)
        try:
            return {
                "path": str(target),
                "entries": [
                    {
                        "name": child.name,
                        "path": str(child),
                        "is_dir": child.is_dir(),
                        "size": child.stat().st_size,
                    }
                    for child in target.iterdir()
                ],
            }
        except Exception as exc:
            LOGGER.exception("list_directory failed")
            return {"path": str(target), "error": str(exc)}
