"""Private bounded HTTP adapter; assessment observations never grant authority."""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from .authority import AuthorityError
from .key_control import KeyControlError
from .operator_control import MAX_BYTES, OperatorControlError, hash_json


def _invalid(status=400):
    return OperatorControlError("operator_control_invalid_request", status,
                                "Use a bounded canonical operator-control JSON envelope.")


async def _body(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise _invalid(415)
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_BYTES:
            raise _invalid(413)
        data.extend(chunk)

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    def number(_):
        raise ValueError("integer required")

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_float=number, parse_constant=number)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise _invalid() from None


def create_operator_control_router(registry, db):
    class ControlRoute(APIRoute):
        def get_route_handler(self):
            handler = super().get_route_handler()

            async def guarded(request: Request):
                try:
                    response = await handler(request)
                except (OperatorControlError, AuthorityError, KeyControlError) as exc:
                    response = JSONResponse({"code": exc.code, "detail": exc.detail,
                                             "authority_effect": "none", "standing_effect": "none"},
                                            status_code=exc.status)
                response.headers["Cache-Control"] = "no-store"
                return response
            return guarded

    router = APIRouter(prefix="/api/operator-control", tags=["operator-control"], route_class=ControlRoute)

    @router.get("/policy")
    async def policy():
        policy = registry.policy
        if policy is None:
            raise OperatorControlError("operator_control_unconfigured", 503,
                                       "A reviewed pinned operator-control policy is required.")
        return {"policy": policy, "policy_sha256": hash_json(policy), "effects": []}

    @router.post("/assessments", status_code=201)
    async def issue(request: Request):
        envelope = await _body(request)
        with db() as conn:
            return registry.issue(conn, envelope)

    @router.get("/assessments/{assessment_id}")
    async def get(assessment_id: str):
        with db() as conn:
            return registry.get(conn, assessment_id)

    @router.post("/assessments/{assessment_id}/challenge")
    async def challenge(assessment_id: str, request: Request):
        envelope = await _body(request)
        inner = envelope.get("challenge")
        if not isinstance(inner, dict) or inner.get("assessment_id") != assessment_id:
            raise _invalid()
        with db() as conn:
            return registry.challenge(conn, envelope)

    @router.post("/assessments/{assessment_id}/revoke")
    async def revoke(assessment_id: str, request: Request):
        envelope = await _body(request)
        inner = envelope.get("revocation")
        if not isinstance(inner, dict) or inner.get("assessment_id") != assessment_id:
            raise _invalid()
        with db() as conn:
            return registry.revoke(conn, envelope)

    return router
