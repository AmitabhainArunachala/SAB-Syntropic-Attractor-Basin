"""Fail-closed transport boundary for the public SAB application.

Read-only is the default deployment policy. Enabling local writes is an explicit
startup choice, never something a request, cookie, or proxy header can select.
"""

from __future__ import annotations

import os
import re
from contextlib import nullcontext
from contextvars import ContextVar
from enum import Enum
from typing import Callable, Mapping, Sequence

from .public_freshness import PublicationObservation, publication_context

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

    Context propagates into mounted apps and threadpool handlers, and resets
    when the request finishes or raises. This is an additional request guard;
    the public application's database remains frozen outside requests too.
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

    def __init__(
        self,
        app: ASGIApp,
        mode: str | PublicMode = PublicMode.PUBLIC_READONLY,
        public_read_paths: Sequence[str] | None = None,
        observation_provider: Callable[[], PublicationObservation] | None = None,
    ):
        self.app = app
        self.mode = _validate_mode(mode)
        self.observation_provider = observation_provider
        self.public_read_paths = (
            tuple(re.compile(pattern) for pattern in public_read_paths)
            if public_read_paths is not None
            else None
        )

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
                await send({"type": "websocket.close", "code": 1008, "reason": READONLY_ERROR_CODE})
                return
            if scope["type"] == "http":
                if self.public_read_paths is not None and not any(
                    pattern.fullmatch(scope.get("path", "")) for pattern in self.public_read_paths
                ):
                    response = JSONResponse(
                        status_code=404,
                        content={
                            "code": "not_published",
                            "detail": "This route is not part of the public inspection surface.",
                            "claims": "/claims",
                        },
                        headers={"Cache-Control": "no-store"},
                    )
                    await response(scope, receive, send)
                    return
                observation = self.observation_provider() if self.observation_provider else None
                token = _PUBLIC_READ_REQUEST.set(True)
                try:

                    async def public_send(message):
                        if message["type"] == "http.response.start":
                            message = dict(message)
                            headers = [
                                (k, v)
                                for k, v in message.get("headers", [])
                                if k.lower() != b"cache-control"
                            ]
                            observation_headers = []
                            if observation is not None:
                                observation_headers = [
                                    (
                                        b"sab-publication-age-status",
                                        observation.local_age_status.encode("ascii"),
                                    ),
                                    (b"sab-clock-state", observation.clock_state.encode("ascii")),
                                    (b"sab-currentness", b"unestablished"),
                                ]
                                names = {name for name, _ in observation_headers}
                                headers = [(k, v) for k, v in headers if k.lower() not in names]
                            message["headers"] = [
                                *headers,
                                (b"cache-control", b"no-store"),
                                *observation_headers,
                            ]
                        await send(message)

                    with (
                        publication_context(observation)
                        if observation is not None
                        else nullcontext()
                    ):
                        await self.app(scope, receive, public_send)
                finally:
                    _PUBLIC_READ_REQUEST.reset(token)
                return
        await self.app(scope, receive, send)


def install_public_runtime(
    app: Starlette,
    mode: str | PublicMode | None = None,
    *,
    public_read_paths: Sequence[str] | None = None,
    observation_provider: Callable[[], PublicationObservation] | None = None,
) -> PublicMode:
    """Validate policy and install the boundary before the first request.

    Call after other user middleware so this guard is the outermost user layer.
    ``read_public_mode`` may be called earlier to reject invalid configuration
    before application imports initialize databases or signing keys.
    """
    resolved = read_public_mode() if mode is None else _validate_mode(mode)
    app.add_middleware(
        PublicReadonlyMiddleware,
        mode=resolved,
        public_read_paths=public_read_paths,
        observation_provider=observation_provider,
    )
    app.state.public_mode = resolved.value
    app.state.public_readonly = resolved == PublicMode.PUBLIC_READONLY
    return resolved
