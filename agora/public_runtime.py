"""Fail-closed transport boundary for the public SAB application.

Read-only is the default deployment policy. Enabling local writes is an explicit
startup choice, never something a request, cookie, or proxy header can select.
"""

from __future__ import annotations

import os
from contextvars import ContextVar
from enum import Enum
from typing import Mapping

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class PublicMode(str, Enum):
    PUBLIC_READONLY = "public_readonly"
    LOCAL = "local"


READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
READONLY_ERROR_CODE = "public_readonly"
_PUBLIC_READ_REQUEST: ContextVar[bool] = ContextVar("sab_public_read_request", default=False)


def public_read_request() -> bool:
    """Whether execution is inside an allowed read-only public HTTP request.

    Database helpers use this context to prevent lazy schema repair or accidental
    writes in GET handlers. Startup and direct maintenance calls stay outside
    the request boundary. Context propagates into mounted apps and threadpool
    handlers, and resets when the request finishes or raises.
    """
    return _PUBLIC_READ_REQUEST.get()


def _validate_mode(value: str | PublicMode) -> PublicMode:
    try:
        return PublicMode(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "SAB_PUBLIC_MODE must be exactly 'public_readonly' or 'local'; "
            "unset it to use the safe public_readonly default."
        ) from exc


def read_public_mode(environ: Mapping[str, str] | None = None) -> PublicMode:
    """Read and validate startup policy, without normalizing an invalid opt-in."""
    source = os.environ if environ is None else environ
    return _validate_mode(source.get("SAB_PUBLIC_MODE", PublicMode.PUBLIC_READONLY.value))


class PublicReadonlyMiddleware:
    """Reject writes before routing, request-body reads, and handler dependencies.

    A pure ASGI boundary also covers mounts, redirects, missing routes, unusual
    methods, and future routes without an endpoint-by-endpoint denylist. Public
    WebSocket connections are refused because they cannot be limited by method.
    Lifespan initialization is passed through to the application.
    """

    def __init__(self, app: ASGIApp, mode: str | PublicMode = PublicMode.PUBLIC_READONLY):
        self.app = app
        self.mode = _validate_mode(mode)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.mode == PublicMode.PUBLIC_READONLY:
            if scope["type"] == "http" and scope.get("method") not in READ_METHODS:
                response = JSONResponse(
                    status_code=403,
                    content={
                        "code": READONLY_ERROR_CODE,
                        "mode": PublicMode.PUBLIC_READONLY.value,
                        "detail": "This SAB instance is read-only. Write operations are disabled.",
                    },
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
            if scope["type"] == "websocket":
                await send(
                    {"type": "websocket.close", "code": 1008, "reason": READONLY_ERROR_CODE}
                )
                return
            if scope["type"] == "http":
                token = _PUBLIC_READ_REQUEST.set(True)
                try:
                    await self.app(scope, receive, send)
                finally:
                    _PUBLIC_READ_REQUEST.reset(token)
                return
        await self.app(scope, receive, send)


def install_public_runtime(
    app: Starlette, mode: str | PublicMode | None = None
) -> PublicMode:
    """Validate policy and install the boundary before the first request.

    Call after other user middleware so this guard is the outermost user layer.
    ``read_public_mode`` may be called earlier to reject invalid configuration
    before application imports initialize databases or signing keys.
    """
    resolved = read_public_mode() if mode is None else _validate_mode(mode)
    app.add_middleware(PublicReadonlyMiddleware, mode=resolved)
    app.state.public_mode = resolved.value
    app.state.public_readonly = resolved == PublicMode.PUBLIC_READONLY
    return resolved
