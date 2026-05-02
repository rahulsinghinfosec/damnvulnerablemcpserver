"""ASGI app for Docker HTTP deployment.

This wraps the MCP streamable HTTP app with intentionally weak Basic Auth for a
couple of admin tools. The rest of the tools remain unauthenticated by design.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount
from starlette.types import Message, Receive, Scope, Send

from vulnerable_mcp.auth import is_valid_basic_auth
from vulnerable_mcp.server import configure_logging, create_server

configure_logging()
LOGGER = logging.getLogger(__name__)
PROTECTED_TOOLS = {"get_sensitive_logs", "admin_panel"}

mcp = create_server()


@contextlib.asynccontextmanager
async def lifespan(app: Starlette):
    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(mcp.session_manager.run())
        yield


starlette_app = Starlette(
    routes=[Mount("/", app=mcp.streamable_http_app())],
    lifespan=lifespan,
)

starlette_app = CORSMiddleware(
    starlette_app,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
    expose_headers=["Mcp-Session-Id"],
)


class WeakBasicAuthMiddleware:
    """Protect selected training tools with hardcoded admin:admin credentials."""

    def __init__(self, wrapped_app: Callable[[Scope, Receive, Send], Awaitable[None]]) -> None:
        self.wrapped_app = wrapped_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.wrapped_app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")
        if method != "POST" or not path.endswith("/mcp"):
            await self.wrapped_app(scope, receive, send)
            return

        body = await self._read_body(receive)
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            await self._replay(scope, body, send)
            return

        tool_name = payload.get("params", {}).get("name")
        if payload.get("method") == "tools/call" and tool_name in PROTECTED_TOOLS:
            authorization = self._authorization_header(scope)
            LOGGER.info("HTTP Basic Auth check for protected MCP tool %s", tool_name)
            if not is_valid_basic_auth(authorization):
                await self._unauthorized(send)
                return

            # VULNERABILITY: The middleware accepts the default credential and
            # injects it into the tool arguments. This is deliberately simple so
            # learners can see the weak trust boundary.
            # Normal fix: use the MCP SDK's OAuth/resource-server auth support
            # or a real identity provider, then authorize per tool and per user.
            payload.setdefault("params", {}).setdefault("arguments", {})["authorization"] = authorization
            body = json.dumps(payload).encode("utf-8")

        await self._replay(scope, body, send)

    @staticmethod
    async def _read_body(receive: Receive) -> bytes:
        chunks: list[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)
        return b"".join(chunks)

    async def _replay(self, scope: Scope, body: bytes, send: Send) -> None:
        sent = False

        async def replay_receive() -> Message:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        mutable_headers = [
            (name, value)
            for name, value in scope.get("headers", [])
            if name.lower() != b"content-length"
        ]
        mutable_headers.append((b"content-length", str(len(body)).encode("ascii")))
        replay_scope: dict[str, Any] = {**scope, "headers": mutable_headers}
        await self.wrapped_app(replay_scope, replay_receive, send)

    @staticmethod
    def _authorization_header(scope: Scope) -> str | None:
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                return value.decode("latin-1")
        return None

    @staticmethod
    async def _unauthorized(send: Send) -> None:
        body = b'{"error":"Unauthorized. Training hint: default Basic admin:admin is accepted."}'
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b'Basic realm="Vulnerable MCP Training"'),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


app = WeakBasicAuthMiddleware(starlette_app)
