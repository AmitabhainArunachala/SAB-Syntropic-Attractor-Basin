"""Same-origin adapters for browser sessions; cookies never authorize SAB commands."""
from __future__ import annotations

import json
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders

from .browser_sessions import BrowserSessionError, BrowserSessionService
from .key_control import KeyControlError

SESSION_COOKIE = "sab_web_session"
SESSION_MAX_AGE = 21600
CSP = (
    "default-src 'self'; script-src 'self'; script-src-attr 'none'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'"
)


class BrowserSecurityMiddleware:
    """Block cross-origin browser writes before reading bodies and restrict scripts.

    A CLI without browser origin headers remains subject to the signed API's
    existing checks. The configured origin is never derived from proxy headers.
    """

    def __init__(self, app, *, audience: str | None = None):
        self.app = app
        self.audience = audience

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CSP
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["X-Frame-Options"] = "DENY"
                if (scope["path"].startswith("/api/v1/browser/")
                        or scope["path"] in {"/register", "/submit"}
                        or (self.audience and headers.get("content-type", "").startswith("text/html"))):
                    headers["Cache-Control"] = "no-store"
            await send(message)

        headers = Headers(scope=scope)
        if scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            origins = headers.getlist("origin")
            if (headers.get("sec-fetch-site") == "cross-site"
                    or (origins and origins != [self.audience])):
                return await JSONResponse(
                    {"detail": "Browser commands require this instance's configured origin."},
                    status_code=403,
                )(scope, receive, secure_send)
        await self.app(scope, receive, secure_send)


async def _body(request: Request, audience: str) -> dict[str, Any]:
    if request.headers.getlist("origin") != [audience]:
        raise BrowserSessionError("origin_required", 403, "Use this instance's configured browser origin.")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise BrowserSessionError("cross_site_request", 403, "Cross-site session commands are refused.")
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise BrowserSessionError("invalid_content_type", 415, "Session commands require application/json.")
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > 4096:
            raise BrowserSessionError("request_too_large", 413, "Session commands may contain at most 4096 bytes.")
        content.extend(chunk)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    def reject_number(value):
        raise ValueError("Session fields do not accept numbers.")

    try:
        value = json.loads(content, object_pairs_hook=pairs, parse_float=reject_number,
                           parse_int=reject_number, parse_constant=reject_number)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise BrowserSessionError("invalid_json", 400, "Session commands require an unambiguous JSON object.") from None


def create_browser_session_router(service: BrowserSessionService, db: Callable) -> APIRouter:
    router = APIRouter(prefix="/api/v1/browser/session", tags=["browser session"])
    audience = service.key_control.audience

    def response(payload, status_code=200):
        return JSONResponse(payload, status_code=status_code, headers={"Cache-Control": "no-store"})

    def failure(exc):
        return response({"code": exc.code, "detail": exc.detail,
                         "authority_effect": "none", "standing_effect": "none"}, exc.status)

    @router.post("/challenge")
    async def challenge(request: Request):
        try:
            payload = await _body(request, audience)
            with db() as conn:
                return response(service.issue(conn, payload))
        except (BrowserSessionError, KeyControlError) as exc:
            return failure(exc)

    @router.post("/verify")
    async def verify(request: Request):
        try:
            payload = await _body(request, audience)
            with db() as conn:
                observation = service.verify(conn, payload)
            token = observation.pop("_session_token")
            result = response(observation)
            result.set_cookie(SESSION_COOKIE, token, max_age=SESSION_MAX_AGE,
                              httponly=True, secure=audience.startswith("https://"),
                              samesite="strict", path="/")
            return result
        except (BrowserSessionError, KeyControlError) as exc:
            return failure(exc)

    @router.get("")
    async def session(request: Request):
        try:
            with db() as conn:
                observation = service.read(conn, request.cookies.get(SESSION_COOKIE, ""))
            return response({"schema": "sab.browser_session_observation.v1", "session": observation,
                             "authority_effect": "none", "standing_effect": "none"})
        except (BrowserSessionError, KeyControlError) as exc:
            return failure(exc)

    @router.post("/logout")
    async def logout(request: Request):
        try:
            payload = await _body(request, audience)
            if set(payload) != {"csrf_token"} or not isinstance(payload["csrf_token"], str):
                raise BrowserSessionError("invalid_logout", 400, "A session CSRF token is required.")
            with db() as conn:
                observation = service.logout(conn, request.cookies.get(SESSION_COOKIE, ""), payload["csrf_token"])
            result = response(observation)
            result.delete_cookie(SESSION_COOKIE, path="/", httponly=True,
                                 secure=audience.startswith("https://"), samesite="strict")
            return result
        except (BrowserSessionError, KeyControlError) as exc:
            return failure(exc)

    return router
