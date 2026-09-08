from __future__ import annotations

import json
import math
import secrets
import sqlite3
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Callable, Dict, Iterator, List, Literal, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import ValidationError

from .public_freshness import PublicationObservation, current_publication_observation
from .key_control import KeyControlError, KeyControlService
from .authority import AuthorityError, AuthorityService
from .sab_identity import (
    AgentIdentityV1,
    HIGH_IMPACT_LEVELS,
    INDEPENDENCE_GRADE_TIERS,
    MIN_INDEPENDENT_OPERATORS_FOR_STANDING,
    OperatorBacking,
    identity_operator_id,
    independence_grade,
    quorum_tier,
    subject_id_from_public_key,
    validate_witness_independence,
)


SEED_STATES = {
    "pending_seed",
    "challenge_window_open",
    "challenged",
    "corrected",
    "witnessed",
    "standing_active",
    "canon_candidate",
    "canon",
    "compost",
    "revoked",
    "expired",
}

FINAL_SEED_STATES = {"canon", "compost", "revoked", "expired"}

# Explicit transition matrix (SAB_STANDING_SEMANTICS_V0 §2.3(6)): final states
# are absorbing; membership-only checks allowed resurrection from compost.
SEED_TRANSITIONS: Dict[str, frozenset] = {
    "pending_seed": frozenset(
        {"pending_seed", "challenge_window_open", "challenged", "corrected", "witnessed", "compost", "expired"}
    ),
    "challenge_window_open": frozenset(
        {"challenge_window_open", "challenged", "corrected", "witnessed", "standing_active", "compost", "expired"}
    ),
    "challenged": frozenset(
        {
            "challenged",
            "corrected",
            "witnessed",
            "challenge_window_open",
            "standing_active",
            "revoked",
            "compost",
            "expired",
        }
    ),
    "corrected": frozenset(
        {"corrected", "challenged", "witnessed", "challenge_window_open", "standing_active", "compost", "expired"}
    ),
    "witnessed": frozenset({"witnessed", "challenged", "corrected", "standing_active", "compost", "expired"}),
    "standing_active": frozenset(
        {"standing_active", "challenged", "canon_candidate", "canon", "revoked", "expired", "compost"}
    ),
    "canon_candidate": frozenset(
        {"canon_candidate", "standing_active", "challenged", "canon", "revoked", "expired", "compost"}
    ),
    "canon": frozenset(),
    "compost": frozenset(),
    "revoked": frozenset(),
    "expired": frozenset(),
}

CHALLENGE_STATUSES = {"pending", "responded", "sustained", "rejected", "sustained_by_default", "lapsed"}
OPEN_CHALLENGE_STATUSES = {"pending", "responded"}
STANDING_STATUSES = {"provisional", "active", "challenged", "revoked", "expired", "canon", "compost", "superseded"}
WITNESS_EVENT_TYPES = {
    "submit",
    "gate_scored",
    "challenge",
    "response",
    "correction",
    "affirm",
    "refuse",
    "standing_issued",
    "revoked",
    "expired",
    "canon",
    "compost",
}

# These drive terminal/standing transitions and may only be produced by their
# dedicated endpoints or system paths, never by a bare witness-event post.
RESERVED_WITNESS_EVENT_TYPES = {"standing_issued", "revoked", "expired", "canon", "compost"}
WITNESSING_EVENT_TYPES = {"affirm", "refuse"}

CHALLENGE_RESPOND_WINDOW = timedelta(days=7)
CHALLENGE_PROSECUTE_WINDOW = timedelta(days=7)

# Historical actor signatures accepted uppercase and the six ASCII whitespace
# characters accepted by bytes.fromhex. Index their byte identity without
# changing old records, so new requests never scan unbounded signature history.
_SIGNATURE_IDENTITY_SQL = "signature"
for _ascii_space in (32, 9, 10, 13, 11, 12):
    _SIGNATURE_IDENTITY_SQL = f"replace({_SIGNATURE_IDENTITY_SQL}, char({_ascii_space}), '')"
_SIGNATURE_IDENTITY_SQL = f"lower({_SIGNATURE_IDENTITY_SQL})"


@dataclass(frozen=True)
class SabSeedingDeps:
    init_db: Callable[[], None]
    db: Callable[[], AbstractContextManager[sqlite3.Connection]]
    verify_agent_signature: Callable[[sqlite3.Connection, str, bytes, str], None]
    system_sign: Callable[[Dict[str, Any]], str]
    utc_now: Callable[[], str]
    invalidate_web_cache: Callable[[], None]
    read_only: bool = False
    publication_configured: bool = True
    read_observation: Optional[Callable[[], Optional[PublicationObservation]]] = None
    key_control: Optional[KeyControlService] = None
    authority: Optional[AuthorityService] = None


def _read_observation(deps: SabSeedingDeps) -> Optional[PublicationObservation]:
    """Reuse the request's single clock sample; never call mutation dependencies."""
    if not deps.read_only:
        return None
    observation = current_publication_observation()
    if observation is None and deps.read_observation is not None:
        observation = deps.read_observation()
    if observation is None:
        raise HTTPException(status_code=503, detail="Public publication observation is unavailable")
    return observation


def _publication_response(
    envelope: Dict[str, Any], observation: Optional[PublicationObservation], **basis: str
) -> Dict[str, Any]:
    """Attach provenance to an envelope without editing embedded signed originals."""
    if observation is None:
        return envelope
    return {**envelope, **basis, "publication_observation": observation.to_dict()}


@contextmanager
def _read_v1_db(deps: SabSeedingDeps) -> Iterator[sqlite3.Connection]:
    """Public reads observe an approved frozen source, without schema repair."""
    if deps.read_only and not deps.publication_configured:
        raise HTTPException(status_code=503, detail="No public snapshot is configured")
    with deps.db() as conn:
        yield conn


@contextmanager
def _mutation_v1_db(deps: SabSeedingDeps) -> Iterator[sqlite3.Connection]:
    """Serialize permission checks and effects; a rejected command rolls back."""
    if deps.read_only:
        raise HTTPException(status_code=403, detail="Public inspection does not accept commands")
    deps.init_db()
    with deps.db() as conn:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        try:
            _init_v1_tables(conn)
            yield conn
        except BaseException:
            conn.rollback()
            raise


def _require_authority(deps: SabSeedingDeps) -> AuthorityService:
    if deps.authority is None or not deps.authority.enabled:
        raise AuthorityError("authority_unavailable", 428, "Explicit issuer authority policy is required.")
    return deps.authority


def _authorize_actor(
    deps: SabSeedingDeps, conn: sqlite3.Connection, *, actor: str, action: str,
    seed_id: str, reference: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    service = _require_authority(deps)
    subject = _actor_subject(conn, actor)
    if reference is None:
        grant = service.authorize_actor(conn, subject_id=subject, action=action, target_seed_id=seed_id)
    else:
        grant = service.authorize(conn, reference, subject_id=subject, action=action, target_seed_id=seed_id)
    return {"lease_id": grant["lease_id"], "lease_sha256": grant["lease_sha256"], "action": action}


def _reject_unsigned_authority_selector(payload: Dict[str, Any]) -> None:
    if {"authority_lease", "authority_lease_id", "authority_lease_sha256", "lease_ref", "lease_id"} & set(payload):
        raise HTTPException(status_code=400, detail="This command resolves its covering grant; unsigned authority selectors are not accepted")


def _require_actor_signer(conn: sqlite3.Connection, actor: str, *payloads: Dict[str, Any]) -> str:
    actor_subject = _actor_subject(conn, actor)
    for payload in payloads:
        signer = _signature_signer(payload)
        if signer is not None and _actor_subject(conn, signer) != actor_subject:
            raise HTTPException(status_code=403, detail="signature signer must match the attributed actor")
    return actor_subject


async def _authority_body(request: Request) -> Dict[str, Any]:
    """Closed commands are validated by the service after bounded strict JSON decoding."""
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise AuthorityError("invalid_content_type", 415, "Authority commands require application/json.")
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > 65536:
            raise AuthorityError("authority_command_too_large", 413, "Authority commands may contain at most 65536 bytes.")
        content.extend(chunk)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("nonfinite number")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite number")
        return number

    try:
        payload = json.loads(content, object_pairs_hook=pairs, parse_constant=reject_constant,
                             parse_float=finite_float)
        if not isinstance(payload, dict):
            raise ValueError("object required")
    except (ValueError, UnicodeError, RecursionError):
        raise AuthorityError("invalid_json", 400, "Authority commands require a valid JSON object.") from None
    return payload


async def _key_control_body(request: Request) -> Dict[str, Any]:
    """Bound and strictly decode identity commands without reflecting their input."""
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise KeyControlError(
            "invalid_content_type", 415, "Identity commands require application/json."
        )
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > 16384:
            raise KeyControlError(
                "identity_command_too_large",
                413,
                "Identity commands may contain at most 16384 bytes.",
            )
        content.extend(chunk)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("non-JSON number")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite number")
        return number

    try:
        payload = json.loads(
            content,
            object_pairs_hook=pairs,
            parse_constant=invalid_constant,
            parse_float=finite_float,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise KeyControlError(
            "invalid_json", 400, "Identity commands require a valid JSON object."
        ) from None
    if not isinstance(payload, dict):
        raise KeyControlError("invalid_json", 400, "Identity commands require a valid JSON object.")
    return payload


def _authority_request_body(schema: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "requestBody": {
            "required": True,
            "description": (
                "Strict application/json, at most 65536 bytes; duplicate keys and nonfinite numbers are rejected. "
                "Schema validation checks shape only. The server separately verifies signatures, configured policy, "
                "current key control, exact resource/action permission, time and immutable grant history."
            ),
            "content": {"application/json": {"schema": schema}},
        }
    }


def _authority_challenge_request_schema() -> Dict[str, Any]:
    """Describe the extensible legacy packet without falsely claiming closure."""
    nonempty_string = {"type": "string", "minLength": 1}
    signature = {
        "anyOf": [
            nonempty_string,
            {
                "type": "object",
                "anyOf": [{"required": ["signature"]}, {"required": ["value"]}],
                "properties": {"signature": nonempty_string, "value": nonempty_string,
                               "signer": nonempty_string},
                "additionalProperties": True,
            },
        ],
        "description": "Ed25519 signature over the normal sab_challenge_submit message. A declared signer must resolve to the challenger.",
    }
    reference = {
        "type": "object",
        "anyOf": [{"required": ["lease_ref"]}, {"required": ["lease_id"]}],
        "properties": {name: nonempty_string for name in (
            "lease_ref", "lease_id", "scope", "expires_at", "revoker", "challenge_path"
        )},
        "additionalProperties": False,
        "description": "The challenger's own issued submit_challenge grant; every supplied declaration must match stored metadata.",
    }
    packet = {
        "type": "object",
        "required": ["challenge_id", "challenger_identity", "created_at", "authority_lease",
                     "authority_lease_id", "authority_lease_sha256"],
        "properties": {
            "schema": {"type": "string", "description": "Canonical packets use sab.challenge_packet.v1."},
            "challenge_id": nonempty_string,
            "challenger_identity": nonempty_string,
            "created_at": nonempty_string,
            "target_seed_id": {**nonempty_string, "description": "Must match the challenged grant's exact seed; defaults to that seed if omitted."},
            "target_claim_id": {**nonempty_string, "description": "Must match the existing seed claim; defaults to that claim if omitted."},
            "authority_lease": reference,
            "authority_lease_id": {"type": "string", "pattern": "^sab_lease_[A-Za-z0-9_.:-]{3,128}$",
                                   "description": "The authority basis being challenged; must equal the lease ID in the URL."},
            "authority_lease_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                                       "description": "Exact stored digest of the challenged lease and issuer signature."},
            "signature": signature,
        },
        "additionalProperties": True,
    }
    variants = [{"allOf": [packet, {"required": ["signature"]}]}]
    for wrapper in ("challenge_packet", "packet"):
        variants.append({
            "type": "object", "required": [wrapper],
            "properties": {wrapper: packet, "signature": signature},
            "anyOf": [{"required": ["signature"]}, {"properties": {wrapper: {"required": ["signature"]}}}],
            "additionalProperties": True,
        })
    return {
        "description": (
            "An extensible signed v1 challenge packet, directly or inside challenge_packet/packet. "
            "Additional packet fields remain accepted and are covered by the packet digest in the actor signature. "
            "This documents the current HTTP contract, not the stricter historical challenge document schema. "
            "The target seed must already exist. A challenge does not automatically revoke authority."
        ),
        "anyOf": variants,
    }


def create_sab_seeding_router(deps: SabSeedingDeps) -> APIRouter:
    if deps.read_only and deps.read_observation is None:
        raise ValueError("Public read-only routes require an explicit read_observation dependency")
    class AuthorityRoute(APIRoute):
        def get_route_handler(self):
            handler = super().get_route_handler()

            async def guarded(request: Request):
                # Reject public writes before FastAPI reads or validates a body.
                if deps.read_only and request.method not in {"GET", "HEAD", "OPTIONS"}:
                    return key_control_problem("public_readonly", "Public inspection does not accept commands.", 403)
                try:
                    return await handler(request)
                except AuthorityError as exc:
                    return key_control_problem(exc.code, exc.detail, exc.status)
            return guarded

    router = APIRouter(prefix="/api/v1", tags=["sab-seeding-v1"], route_class=AuthorityRoute)

    def key_control_problem(code: str, detail: str, status_code: int) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={
                "code": code,
                "detail": detail,
                "authority_effect": "none",
                "standing_effect": "none",
            },
            headers={"Cache-Control": "no-store"},
        )


    @router.post(
        "/agents/register",
        status_code=428,
        summary="Unsigned enrollment is unavailable",
        description="Use a scoped nonce from /api/v1/agents/challenge and sign it locally. Public inspection rejects all identity commands.",
    )
    async def register_agent_identity() -> JSONResponse:
        return key_control_problem(
            "key_control_required",
            "Request /api/v1/agents/challenge, sign its scoped message locally, then submit to /api/v1/agents/verify.",
            403 if deps.read_only else 428,
        )


    async def key_control_command(request: Request, operation: str) -> JSONResponse:
        if deps.read_only:
            return key_control_problem(
                "public_readonly", "Public inspection does not accept identity commands.", 403
            )
        if deps.key_control is None:
            return key_control_problem(
                "key_control_unavailable", "Key-control enrollment is not configured.", 503
            )
        try:
            payload = await _key_control_body(request)
            deps.init_db()
            with deps.db() as conn:
                _init_v1_tables(conn)
                result = getattr(deps.key_control, operation)(conn, payload)
            if operation == "verify":
                deps.invalidate_web_cache()
            return JSONResponse(
                result,
                status_code=201 if operation == "issue" else 200,
                headers={"Cache-Control": "no-store"},
            )
        except KeyControlError as exc:
            return key_control_problem(exc.code, exc.detail, exc.status)


    @router.post(
        "/agents/challenge",
        status_code=201,
        summary="Request a scoped key-control nonce",
        description="Local mode only. Request register, revoke, or dual-key rotate. Sign the returned message only after checking audience, action, key, metadata, and expiry. Key control grants no authority or standing. See /auth.md.",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "required": ["action", "registration"],
                                    "additionalProperties": False,
                                    "properties": {
                                        "action": {"const": "register"},
                                        "registration": {
                                            "type": "object",
                                            "description": "Public identity metadata with public_key and display_name; no private seed, status, timestamps, or evidence_refs.",
                                        },
                                    },
                                },
                                {
                                    "type": "object",
                                    "required": ["action", "subject_id"],
                                    "additionalProperties": False,
                                    "properties": {
                                        "action": {"const": "revoke"},
                                        "subject_id": {"type": "string"},
                                    },
                                },
                                {
                                    "type": "object",
                                    "required": ["action", "subject_id", "registration"],
                                    "additionalProperties": False,
                                    "properties": {
                                        "action": {"const": "rotate"},
                                        "subject_id": {"type": "string"},
                                        "registration": {
                                            "type": "object",
                                            "description": "Public successor identity metadata; requires a fresh key and signatures from both keys.",
                                        },
                                    },
                                },
                            ]
                        },
                        "example": {
                            "action": "register",
                            "registration": {
                                "display_name": "Example participant",
                                "public_key": "<64 hexadecimal characters>",
                            },
                        },
                    }
                },
            }
        },
    )
    async def agent_key_challenge(request: Request) -> JSONResponse:
        return await key_control_command(request, "issue")


    @router.post(
        "/agents/verify",
        summary="Consume a nonce and apply a signed key-control transition",
        description="Local mode only. Submit signatures over the stored canonical message. The nonce is single-use and expires within 120 seconds. Rotation requires both signatures. Successful enrollment does not grant authority or standing.",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["challenge_id", "signature"],
                            "additionalProperties": False,
                            "properties": {
                                "challenge_id": {
                                    "type": "string",
                                    "pattern": "^sab_kc_challenge_[0-9a-f]{32}$",
                                },
                                "signature": {"type": "string", "pattern": "^[0-9a-fA-F]{128}$"},
                                "successor_signature": {
                                    "type": "string",
                                    "pattern": "^[0-9a-fA-F]{128}$",
                                    "description": "Required only for rotation; the successor signs the exact same message.",
                                },
                            },
                        },
                    }
                },
            }
        },
    )
    async def agent_key_verify(request: Request) -> JSONResponse:
        return await key_control_command(request, "verify")

    def private_authority() -> AuthorityService:
        if deps.read_only:
            raise HTTPException(status_code=404, detail="Authority administration is unavailable on public inspection")
        if deps.authority is None:
            raise AuthorityError("authority_unavailable", 503, "Authority administration is unavailable.")
        return deps.authority

    @router.get("/authority/policy")
    async def authority_policy() -> JSONResponse:
        service = private_authority()
        return JSONResponse({"policy": service.policy, "policy_hash": service.policy_hash,
                             "authority_effect": "none", "standing_effect": "none"},
                            headers={"Cache-Control": "no-store"})

    @router.post(
        "/authority/leases", status_code=status.HTTP_201_CREATED,
        summary="Record an issuer-signed and witnessed authority grant",
        description="Local policy administration. Exact issuance retry returns 200; a new accepted grant returns 201. Public inspection rejects the command.",
        responses={200: {"description": "Exact previously accepted issuance; original receipt time retained"}},
        openapi_extra=_authority_request_body({
            "type": "object", "required": ["lease", "issuer_signature", "issuance_witness"],
            "properties": {
                "lease": {"$ref": "/schemas/sab.authority_lease.v2.schema.json"},
                "issuer_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$",
                                     "description": "Ed25519 over all canonical lease fields."},
                "issuance_witness": {"$ref": "/schemas/sab.authority_issuance_witness.v1.schema.json"},
            },
            "additionalProperties": False,
        }),
    )
    async def issue_authority(request: Request) -> JSONResponse:
        service = private_authority()
        payload = await _authority_body(request)
        with _mutation_v1_db(deps) as conn:
            result = service.issue(conn, payload)
        return JSONResponse(result, status_code=201 if result["created"] else 200,
                            headers={"Cache-Control": "no-store"})

    @router.get("/authority/leases/{lease_id}")
    async def get_authority(lease_id: str) -> JSONResponse:
        service = private_authority()
        with _read_v1_db(deps) as conn:
            result = service.get(conn, lease_id)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @router.post(
        "/authority/leases/{lease_id}/revoke",
        summary="Retire an issued grant using its designated revoker",
        description="The signed revocation must identify the exact lease and digest. Retirement does not erase signed history; exact retries retain the original receipt.",
        openapi_extra=_authority_request_body({
            "type": "object", "required": ["revocation", "signature"],
            "properties": {
                "revocation": {"$ref": "/schemas/sab.authority_revocation.v1.schema.json"},
                "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$",
                              "description": "Ed25519 over all canonical revocation fields."},
            },
            "additionalProperties": False,
        }),
    )
    async def revoke_authority(lease_id: str, request: Request) -> JSONResponse:
        service = private_authority()
        payload = await _authority_body(request)
        command = payload.get("revocation")
        if not isinstance(command, dict) or command.get("lease_id") != lease_id:
            raise AuthorityError("authority_target_mismatch", 400, "Revocation must target the lease in the URL.")
        with _mutation_v1_db(deps) as conn:
            result = service.revoke(conn, payload)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @router.post(
        "/authority/leases/{lease_id}/challenges", status_code=status.HTTP_201_CREATED,
        summary="Challenge an authority basis through its existing seed",
        description="Requires the challenger's own active submit_challenge grant. The challenged lease ID and digest must appear inside the signed packet. Issuance alone is not a seed or standing; the linked seed must exist.",
        openapi_extra=_authority_request_body(_authority_challenge_request_schema()),
    )
    async def challenge_authority(lease_id: str, request: Request) -> Dict[str, Any]:
        service = private_authority()
        payload = await _authority_body(request)
        packet = _extract_object(payload, "challenge_packet", "packet")
        with _read_v1_db(deps) as conn:
            grant = service.get(conn, lease_id)
            seed_id = grant["lease"]["target_seed_id"]
            if conn.execute("SELECT 1 FROM sab_seed_packets_v1 WHERE seed_id=?", (seed_id,)).fetchone() is None:
                raise HTTPException(status_code=409, detail="The linked seed must exist before its authority basis can be challenged")
            if (packet.get("authority_lease_id") != lease_id
                    or packet.get("authority_lease_sha256") != grant["lease_sha256"]):
                raise AuthorityError("authority_challenge_link_mismatch", 400,
                                     "The signed challenge must identify the exact authority lease and digest.")
        return await submit_challenge(seed_id, payload)

    @router.get("/authority/leases/{lease_id}/challenges")
    async def get_authority_challenges(lease_id: str) -> JSONResponse:
        service = private_authority()
        with _read_v1_db(deps) as conn:
            grant = service.get(conn, lease_id)
            rows = conn.execute(
                "SELECT * FROM sab_challenge_packets_v1 WHERE target_seed_id=? ORDER BY id DESC LIMIT 500",
                (grant["lease"]["target_seed_id"],),
            ).fetchall()
            items = []
            for row in rows:
                packet = json.loads(row["packet_json"])
                if (packet.get("authority_lease_id") == lease_id
                        and packet.get("authority_lease_sha256") == grant["lease_sha256"]):
                    items.append(_serialize_challenge(row))
            return JSONResponse({"lease_id": lease_id, "lease_sha256": grant["lease_sha256"],
                                 "items": items, "authority_effect": "none", "standing_effect": "none"},
                                headers={"Cache-Control": "no-store"})

    @router.get("/agents/me/home")
    async def agent_home(subject_id: str = Query(...)) -> Dict[str, Any]:
        with _read_v1_db(deps) as conn:
            agent = conn.execute(
                "SELECT id, name, public_key, created_at FROM web_agents WHERE id = ?",
                (subject_id,),
            ).fetchone()
            if agent is None:
                raise HTTPException(status_code=404, detail="agent not found")
            seed_rows = conn.execute(
                """
                SELECT seed_id, state, challenge_window_closes_at
                FROM sab_seed_packets_v1
                WHERE claimant_identity = ?
                ORDER BY id DESC
                LIMIT 25
                """,
                (subject_id,),
            ).fetchall()
            challenge_rows = conn.execute(
                """
                SELECT challenge_id, target_seed_id, status
                FROM sab_challenge_packets_v1
                WHERE challenger_identity = ? OR target_seed_id IN (
                    SELECT seed_id FROM sab_seed_packets_v1 WHERE claimant_identity = ?
                )
                ORDER BY id DESC
                LIMIT 25
                """,
                (subject_id, subject_id),
            ).fetchall()
            key_control = (
                deps.key_control.binding_status(conn, subject_id)
                if deps.key_control is not None else {"status": "unproven", "scope": "key_control_only"}
            )
            authority_grants = []
            if deps.authority is not None and not deps.read_only:
                try:
                    authority_grants = deps.authority.list_for_subject(conn, subject_id)
                except AuthorityError as exc:
                    # Old web-only IDs are observable history but cannot be grant subjects.
                    if exc.code != "invalid_authority_reference":
                        raise
            active_grants = [grant for grant in authority_grants if grant["status"] == "active"]
            recorded_identity = conn.execute(
                "SELECT identity_json FROM sab_agent_identities_v1 WHERE subject_id = ?", (subject_id,)
            ).fetchone()
            return {
                "schema": "sab.agent_home.v1",
                "subject_id": subject_id,
                "identity_status": key_control["status"],
                "identity": json.loads(recorded_identity["identity_json"]) if recorded_identity else None,
                "key_control": key_control,
                "authority_effect": "none",
                "standing_effect": "none",
                "agent": dict(agent),
                "active_authority_leases": active_grants,
                "authority_leases": authority_grants,
                "pending_seeds": [
                    {
                        "seed_id": str(row["seed_id"]),
                        "state": str(row["state"]),
                        "challenge_window_closes_at": row["challenge_window_closes_at"],
                    }
                    for row in seed_rows
                    if str(row["state"]) not in {"canon", "compost", "revoked", "expired"}
                ],
                "challenges_requiring_response": [
                    {
                        "challenge_id": str(row["challenge_id"]),
                        "target_seed_id": str(row["target_seed_id"]),
                        "status": str(row["status"]),
                    }
                    for row in challenge_rows
                    if str(row["status"]) == "pending"
                ],
                "witness_requests": [],
                "expiries": [],
                "recommended_next_action": (
                    "submit_seed_or_review_challenges" if key_control["status"] == "active" and active_grants
                    else "obtain_scoped_authority" if key_control["status"] == "active"
                    else "prove_key_control" if key_control["status"] == "unproven"
                    else "resolve_key_control"
                ),
            }

    @router.post("/seeds", status_code=status.HTTP_201_CREATED)
    async def submit_seed(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        with _mutation_v1_db(deps) as conn:
            seed_packet = _extract_object(payload, "seed_packet", "packet")
            signature_hex = _extract_signature(seed_packet, payload)
            packet_for_hash = _without_signature(seed_packet)

            seed_id = _required_str(packet_for_hash, "seed_id")
            claimant_identity = _claimant_identity(packet_for_hash, seed_packet)
            authority_reference = _object_value(packet_for_hash, "authority_lease")
            authority_lease_id = str(authority_reference.get("lease_ref") or authority_reference.get("lease_id") or "")
            if not authority_lease_id:
                raise HTTPException(status_code=400, detail="authority_lease lease_ref is required")
            created_at = _required_str(packet_for_hash, "created_at")
            _require_actor_signer(conn, claimant_identity, seed_packet, payload)

            seed_packet_hash = _hash_json(packet_for_hash)
            message = _seed_submit_message(
                seed_packet_hash=seed_packet_hash,
                claimant_identity=claimant_identity,
                authority_lease_id=authority_lease_id,
                created_at=created_at,
            )
            deps.verify_agent_signature(conn, claimant_identity, _canonical_bytes(message), signature_hex)
            authority = _authorize_actor(deps, conn, actor=claimant_identity, action="submit_seed",
                                         seed_id=seed_id, reference=authority_reference)
            _record_signature_use(conn, signature_hex, _hash_json(message), claimant_identity)

            if conn.execute("SELECT 1 FROM sab_seed_packets_v1 WHERE seed_id = ?", (seed_id,)).fetchone():
                raise HTTPException(status_code=409, detail="seed already exists")

            claim = _object_value(packet_for_hash, "claim")
            claim_id = str(claim.get("claim_id") or f"sab_claim_{_sha256_hex(str(claim.get('text', '')).encode())[:16]}")
            challenge_window_closes_at = _challenge_window_closes_at(packet_for_hash, created_at)
            spark_projection_id: Optional[int] = None
            if bool(payload.get("create_spark_projection", True)):
                spark_projection_id = _create_spark_projection(conn, packet_for_hash, claimant_identity, seed_id)

            now = deps.utc_now()
            conn.execute(
                """
                INSERT INTO sab_seed_packets_v1
                    (
                        seed_id, seed_type, title, claim_id, claimant_identity,
                        authority_lease_id, state, packet_json, packet_hash,
                        spark_projection_id, challenge_window_closes_at,
                        created_at, updated_at
                    )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    seed_id,
                    str(packet_for_hash.get("seed_type") or "claim"),
                    str(packet_for_hash.get("title") or seed_id),
                    claim_id,
                    claimant_identity,
                    authority_lease_id,
                    "pending_seed",
                    _json_dumps(seed_packet),
                    seed_packet_hash,
                    spark_projection_id,
                    challenge_window_closes_at,
                    created_at,
                    now,
                ),
            )
            witness = _record_seed_transition(
                deps,
                conn,
                seed_id=seed_id,
                actor_identity=claimant_identity,
                event_type="submit",
                to_state="pending_seed",
                payload={
                    "seed_packet_hash": seed_packet_hash,
                    "authority_lease_id": authority_lease_id,
                    "authority": authority,
                    "spark_projection_id": spark_projection_id,
                },
                signature_hex=signature_hex,
                update_state=False,
            )
            deps.invalidate_web_cache()
            return {
                "accepted": True,
                "seed_id": seed_id,
                "state": "pending_seed",
                "spark_projection_id": spark_projection_id,
                "challenge_window_closes_at": challenge_window_closes_at,
                "witness_head": witness["hash"],
                "next_actions": ["fetch_seed", "challenge_seed", "submit_witness_event"],
            }

    @router.get("/seeds/{seed_id}")
    async def get_seed(seed_id: str) -> Dict[str, Any]:
        publication = _read_observation(deps)
        with _read_v1_db(deps) as conn:
            _seed_row(conn, seed_id)
            row = _seed_row(conn, seed_id)
            return _publication_response(_serialize_seed(conn, row), publication, state_basis="stored")

    @router.get("/seeds/{seed_id}/chain")
    async def get_seed_chain(seed_id: str) -> Dict[str, Any]:
        publication = _read_observation(deps)
        with _read_v1_db(deps) as conn:
            _seed_row(conn, seed_id)
            return _publication_response(_seed_chain(conn, seed_id), publication)

    @router.get("/seeds/{seed_id:path}/dossier")
    async def get_claim_dossier(seed_id: str, download: bool = Query(default=False)) -> JSONResponse:
        from .claim_dossier import load_claim_dossier

        # Startup owns initialization. These reads must remain observations in
        # local mode too; reads never initialize or advance lifecycle state.
        publication = _read_observation(deps)
        with deps.db() as conn:
            dossier = load_claim_dossier(conn, seed_id, publication_observation=publication)
        if dossier is None:
            raise HTTPException(status_code=404, detail="seed not found", headers={"Cache-Control": "no-store"})
        headers = {"Cache-Control": "no-store"}
        if download:
            headers["Content-Disposition"] = 'attachment; filename="claim-dossier.json"'
        return JSONResponse(dossier, headers=headers)

    @router.get("/claims")
    async def get_claim_ledger(
        q: str = Query(default=""),
        state: str = Query(default=""),
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> JSONResponse:
        from .claim_dossier import list_claims

        publication = _read_observation(deps)
        with deps.db() as conn:
            ledger = list_claims(conn, q=q, state=state, limit=limit, offset=offset,
                                 publication_observation=publication)
        return JSONResponse(ledger, headers={"Cache-Control": "no-store"})

    @router.get("/claims/record")
    async def get_claim_record(
        kind: Literal["seed", "chain", "challenge", "standing", "witness_event", "dossier"] = Query(...),
        identifier: str = Query(..., min_length=1),
        download: bool = Query(default=False),
    ) -> JSONResponse:
        from .claim_dossier import load_claim_record

        publication = _read_observation(deps)
        with deps.db() as conn:
            record = load_claim_record(conn, kind, identifier, publication_observation=publication)
        if record is None:
            raise HTTPException(status_code=404, detail="record not found", headers={"Cache-Control": "no-store"})
        headers = {"Cache-Control": "no-store"}
        if download:
            headers["Content-Disposition"] = 'attachment; filename="claim-record.json"'
        return JSONResponse(record, headers=headers)

    @router.get("/seeds")
    async def list_seeds(
        state: Optional[str] = Query(default=None),
        status_filter: Optional[str] = Query(default=None, alias="status"),
        type_filter: Optional[str] = Query(default=None, alias="type"),
        claimant: Optional[str] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=500),
    ) -> Dict[str, Any]:
        publication = _read_observation(deps)
        if deps.read_only and not deps.publication_configured:
            return _publication_response({"items": [], "availability": "not_configured"}, publication,
                                         state_basis="stored")
        with _read_v1_db(deps) as conn:
            clauses: List[str] = []
            params: List[Any] = []
            wanted_state = state or status_filter
            if wanted_state:
                clauses.append("state = ?")
                params.append(wanted_state)
            if type_filter:
                clauses.append("seed_type = ?")
                params.append(type_filter)
            if claimant:
                clauses.append("claimant_identity = ?")
                params.append(claimant)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = conn.execute(
                f"""
                SELECT *
                FROM sab_seed_packets_v1
                {where}
                ORDER BY id DESC
                LIMIT ?
                """,  # nosec B608 - where only contains fixed clauses.
                (*params, limit),
            ).fetchall()
            return _publication_response(
                {"items": [_serialize_seed(conn, row, include_packet=False) for row in rows]},
                publication, state_basis="stored",
            )

    @router.post("/seeds/{seed_id}/advance")
    async def advance_seed_deadlines(seed_id: str, request: Request) -> Dict[str, Any]:
        _require_authority(deps)
        payload = await _authority_body(request)
        if set(payload) != {"actor_identity", "prev_hash", "created_at", "signature"}:
            raise HTTPException(status_code=400, detail="Advance commands require actor_identity, prev_hash, created_at, and signature only")
        with _mutation_v1_db(deps) as conn:
            _seed_row(conn, seed_id)
            actor = _required_str(payload, "actor_identity")
            head = _required_str(payload, "prev_hash")
            created_at = _required_str(payload, "created_at")
            if head != _latest_witness_hash(conn, seed_id):
                raise HTTPException(status_code=409, detail="prev_hash is stale")
            message = {"kind": "sab_seed_advance_deadlines", "seed_id": seed_id,
                       "actor_identity": actor, "prev_hash": head, "created_at": created_at}
            signature = _required_str(payload, "signature")
            deps.verify_agent_signature(conn, actor, _canonical_bytes(message), signature)
            authority = _authorize_actor(deps, conn, actor=actor, action="advance_deadlines", seed_id=seed_id)
            _record_signature_use(conn, signature, _hash_json(message), actor)
            last_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM sab_witness_events_v1").fetchone()[0]
            _sweep_challenge_deadlines(deps, conn, seed_id, authority=authority)
            for standing in conn.execute("SELECT * FROM sab_standing_leases_v1 WHERE subject_seed_id=? ORDER BY id", (seed_id,)).fetchall():
                _expire_standing_if_needed(deps, conn, standing, authority=authority)
            event = _append_witness_event(
                conn, event_type="gate_scored", actor_identity=actor, subject_type="seed",
                subject_id=seed_id, subject_seed_id=seed_id,
                payload={"kind": "advance_deadlines", "command": message}, signature_hex=signature,
                timestamp=deps.utc_now(), authority=authority,
            )
            generated = [row["event_id"] for row in conn.execute(
                "SELECT event_id FROM sab_witness_events_v1 WHERE subject_seed_id=? AND id>? ORDER BY id", (seed_id, last_id)
            ).fetchall()]
            deps.invalidate_web_cache()
            return {"seed_id": seed_id, "state": str(_seed_row(conn, seed_id)["state"]),
                    "generated_witness_ids": generated, "witness_head": event["hash"], "authority": authority,
                    "state_basis": "stored", "standing_effect": "existing_local_rules_only"}

    @router.post("/seeds/{seed_id}/correct")
    async def correct_seed(seed_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        _reject_unsigned_authority_selector(payload)
        with _mutation_v1_db(deps) as conn:
            row = _seed_row(conn, seed_id)
            actor_identity = _required_str(payload, "actor_identity")
            actor_subject = _actor_subject(conn, actor_identity)
            if str(row["claimant_identity"]) not in {actor_identity, actor_subject}:
                raise HTTPException(status_code=403, detail="only the claimant may correct the seed")
            created_at = _required_str(payload, "created_at")
            correction_payload = payload.get("correction") or payload.get("corrected_seed_packet") or {}
            correction_hash = _hash_json(correction_payload if isinstance(correction_payload, dict) else {"value": correction_payload})
            signature_hex = _required_str(payload, "signature")
            message = {
                "kind": "sab_seed_correct",
                "target_seed_id": seed_id,
                "actor_identity": actor_identity,
                "correction_sha256": correction_hash,
                "created_at": created_at,
            }
            _require_actor_signer(conn, actor_identity, payload)
            deps.verify_agent_signature(conn, actor_identity, _canonical_bytes(message), signature_hex)
            authority = _authorize_actor(deps, conn, actor=actor_identity, action="correct_seed",
                                         seed_id=seed_id)
            _record_signature_use(conn, signature_hex, _hash_json(message), actor_identity)
            witness = _record_seed_transition(
                deps,
                conn,
                seed_id=seed_id,
                actor_identity=actor_identity,
                event_type="correction",
                to_state="corrected",
                payload={"correction_hash": correction_hash, "correction": correction_payload, "authority": authority},
                signature_hex=signature_hex,
            )
            deps.invalidate_web_cache()
            return {"seed_id": seed_id, "state": "corrected", "witness_head": witness["hash"]}

    @router.post("/seeds/{seed_id}/withdraw")
    async def withdraw_seed(seed_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        _reject_unsigned_authority_selector(payload)
        with _mutation_v1_db(deps) as conn:
            row = _seed_row(conn, seed_id)
            actor_identity = _required_str(payload, "actor_identity")
            if actor_identity != str(row["claimant_identity"]):
                raise HTTPException(status_code=403, detail="only the claimant may withdraw the seed")
            created_at = _required_str(payload, "created_at")
            reason = str(payload.get("reason") or "")
            signature_hex = _required_str(payload, "signature")
            message = {
                "kind": "sab_seed_withdraw",
                "target_seed_id": seed_id,
                "actor_identity": actor_identity,
                "reason_sha256": _sha256_hex(reason.encode()),
                "created_at": created_at,
            }
            _require_actor_signer(conn, actor_identity, payload)
            deps.verify_agent_signature(conn, actor_identity, _canonical_bytes(message), signature_hex)
            authority = _authorize_actor(deps, conn, actor=actor_identity, action="withdraw_seed",
                                         seed_id=seed_id)
            _record_signature_use(conn, signature_hex, _hash_json(message), actor_identity)
            witness = _record_seed_transition(
                deps,
                conn,
                seed_id=seed_id,
                actor_identity=actor_identity,
                event_type="compost",
                to_state="compost",
                payload={"reason": reason, "withdrawn": True, "authority": authority},
                signature_hex=signature_hex,
            )
            deps.invalidate_web_cache()
            return {"seed_id": seed_id, "state": "compost", "witness_head": witness["hash"]}

    @router.post("/seeds/{seed_id}/challenges", status_code=status.HTTP_201_CREATED)
    async def submit_challenge(seed_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        with _mutation_v1_db(deps) as conn:
            seed = _seed_row(conn, seed_id)
            if str(seed["state"]) in FINAL_SEED_STATES:
                raise HTTPException(status_code=409, detail=f"seed is final in state {seed['state']}")
            _ensure_challenge_window_open(seed)
            challenge_packet = _extract_object(payload, "challenge_packet", "packet")
            packet_for_hash = _without_signature(challenge_packet)
            if str(packet_for_hash.get("target_seed_id") or seed_id) != seed_id:
                raise HTTPException(status_code=400, detail="challenge target_seed_id does not match URL")
            challenge_id = _required_str(packet_for_hash, "challenge_id")
            target_claim_id = str(packet_for_hash.get("target_claim_id") or seed["claim_id"])
            if target_claim_id != str(seed["claim_id"]):
                raise HTTPException(status_code=400, detail="challenge target_claim_id does not match seed claim")
            challenger_identity = _required_str(packet_for_hash, "challenger_identity")
            created_at = _required_str(packet_for_hash, "created_at")
            challenge_reference = _object_value(packet_for_hash, "authority_lease")

            signature_hex = _extract_signature(challenge_packet, payload)
            signature_signer = _require_actor_signer(conn, challenger_identity, challenge_packet, payload)
            challenge_packet_hash = _hash_json(packet_for_hash)
            message = _challenge_submit_message(
                target_seed_id=seed_id,
                target_claim_id=target_claim_id,
                challenge_packet_hash=challenge_packet_hash,
                challenger_identity=challenger_identity,
                created_at=created_at,
            )
            deps.verify_agent_signature(conn, signature_signer, _canonical_bytes(message), signature_hex)
            authority = _authorize_actor(deps, conn, actor=challenger_identity, action="submit_challenge",
                                         seed_id=seed_id, reference=challenge_reference)
            _sweep_challenge_deadlines(deps, conn, seed_id, authority=authority)
            seed = _seed_row(conn, seed_id)
            if str(seed["state"]) in FINAL_SEED_STATES:
                raise HTTPException(status_code=409, detail="seed is final")
            _record_signature_use(conn, signature_hex, _hash_json(message), signature_signer)
            if conn.execute(
                "SELECT 1 FROM sab_challenge_packets_v1 WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone():
                raise HTTPException(status_code=409, detail="challenge already exists")

            now = deps.utc_now()
            respond_by = _challenge_respond_by(packet_for_hash, created_at)
            conn.execute(
                """
                INSERT INTO sab_challenge_packets_v1
                    (
                        challenge_id, target_seed_id, target_claim_id, challenger_identity,
                        status, packet_json, packet_hash, response_json,
                        respond_by, prosecute_by, created_at, updated_at
                    )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    seed_id,
                    target_claim_id,
                    challenger_identity,
                    "pending",
                    _json_dumps(challenge_packet),
                    challenge_packet_hash,
                    None,
                    respond_by,
                    None,
                    created_at,
                    now,
                ),
            )
            witness = _record_seed_transition(
                deps,
                conn,
                seed_id=seed_id,
                actor_identity=challenger_identity,
                event_type="challenge",
                to_state="challenged",
                payload={"challenge_id": challenge_id, "challenge_packet_hash": challenge_packet_hash, "authority": authority},
                signature_hex=signature_hex,
            )
            challenge = _challenge_row(conn, challenge_id)
            deps.invalidate_web_cache()
            return {
                **_serialize_challenge(challenge),
                "state": "challenged",
                "seed_state": "challenged",
                "witness_head": witness["hash"],
            }

    @router.get("/challenges/{challenge_id}")
    async def get_challenge(challenge_id: str) -> Dict[str, Any]:
        publication = _read_observation(deps)
        with _read_v1_db(deps) as conn:
            return _publication_response(_serialize_challenge(_challenge_row(conn, challenge_id)),
                                         publication, status_basis="stored")

    @router.post("/challenges/{challenge_id}/respond", status_code=status.HTTP_201_CREATED)
    async def respond_to_challenge(challenge_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        return _resolve_challenge_action(deps, challenge_id, payload, action="respond", challenge_status="responded", seed_state="corrected")

    @router.post("/challenges/{challenge_id}/sustain", status_code=status.HTTP_201_CREATED)
    async def sustain_challenge(challenge_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        return _resolve_challenge_action(deps, challenge_id, payload, action="sustain", challenge_status="sustained", seed_state="compost")

    @router.post("/challenges/{challenge_id}/reject", status_code=status.HTTP_201_CREATED)
    async def reject_challenge(challenge_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        return _resolve_challenge_action(
            deps,
            challenge_id,
            payload,
            action="reject",
            challenge_status="rejected",
            seed_state="challenge_window_open",
        )

    @router.post("/witness-events", status_code=status.HTTP_201_CREATED)
    async def submit_witness_event(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        _reject_unsigned_authority_selector(payload)
        with _mutation_v1_db(deps) as conn:
            event_type = _required_str(payload, "event_type")
            if event_type not in WITNESS_EVENT_TYPES:
                raise HTTPException(status_code=400, detail="unsupported witness event_type")
            if event_type in RESERVED_WITNESS_EVENT_TYPES:
                raise HTTPException(
                    status_code=403,
                    detail=f"event_type {event_type} is reserved for its dedicated endpoint or system transitions",
                )
            actor_identity = _required_str(payload, "actor_identity")
            subject_type = _required_str(payload, "subject_type")
            subject_id = _required_str(payload, "subject_id")
            created_at = _required_str(payload, "created_at")
            event_payload = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
            signature_hex = _required_str(payload, "signature")
            subject_seed_id = _subject_seed_id(conn, subject_type, subject_id)
            if subject_seed_id is None:
                raise HTTPException(status_code=400, detail="Witness events require a specific existing seed, challenge, or standing subject")
            expected_prev_hash = _latest_witness_hash(conn, subject_seed_id or f"{subject_type}:{subject_id}")
            supplied_prev_hash = str(payload.get("prev_hash") or expected_prev_hash)
            if supplied_prev_hash != expected_prev_hash:
                raise HTTPException(status_code=409, detail="prev_hash is stale")
            target_state = _state_for_witness_event(event_type) if subject_type == "seed" else None
            seed = _seed_row(conn, subject_seed_id) if subject_seed_id else None
            if seed is not None and target_state:
                _ensure_seed_transition_allowed(str(seed["state"]), target_state)
            payload_hash = _hash_json(event_payload)
            message = _witness_event_message(
                event_type=event_type,
                subject_type=subject_type,
                subject_id=subject_id,
                payload_hash=payload_hash,
                prev_hash=expected_prev_hash,
                created_at=created_at,
            )
            _require_actor_signer(conn, actor_identity, payload)
            deps.verify_agent_signature(conn, actor_identity, _canonical_bytes(message), signature_hex)
            action = {"response": "respond_challenge", "correction": "correct_seed"}.get(event_type, "submit_witness_event")
            if event_type in {"response", "correction"} and seed is not None:
                if _actor_subject(conn, actor_identity) != _actor_subject(conn, str(seed["claimant_identity"])):
                    raise HTTPException(status_code=403, detail="Only the claimant may record a response or correction effect")
            authority = _authorize_actor(deps, conn, actor=actor_identity, action=action, seed_id=subject_seed_id)
            _record_signature_use(conn, signature_hex, _hash_json(message), actor_identity)
            independence: Optional[Dict[str, Any]] = None
            if seed is not None and event_type in WITNESSING_EVENT_TYPES:
                independence = _enforce_witness_policy(conn, seed=seed, actor_identity=actor_identity)
            event = _append_witness_event(
                conn,
                event_type=event_type,
                actor_identity=actor_identity,
                subject_type=subject_type,
                subject_id=subject_id,
                subject_seed_id=subject_seed_id,
                payload=event_payload,
                signature_hex=signature_hex,
                timestamp=created_at,
                expected_prev_hash=expected_prev_hash,
                authority=authority,
            )
            if subject_type == "seed" and subject_seed_id and target_state:
                transition_payload: Dict[str, Any] = {
                    "witness_event_id": event["event_id"],
                    "payload_hash": payload_hash,
                    "authority": authority,
                }
                if independence is not None:
                    transition_payload["independence"] = independence
                _record_seed_transition(
                    deps,
                    conn,
                    seed_id=subject_seed_id,
                    actor_identity=actor_identity,
                    event_type=event_type,
                    to_state=target_state,
                    payload=transition_payload,
                    signature_hex=signature_hex,
                    precreated_witness=event,
                )
            deps.invalidate_web_cache()
            return event

    @router.get("/witness-events/{event_id}")
    async def get_witness_event(event_id: str) -> Dict[str, Any]:
        publication = _read_observation(deps)
        with _read_v1_db(deps) as conn:
            row = conn.execute(
                "SELECT * FROM sab_witness_events_v1 WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="witness event not found")
            return _publication_response(_serialize_witness_event(row), publication)

    @router.get("/witness/chain")
    async def get_witness_chain(
        seed_id: Optional[str] = Query(default=None),
        subject_type: Optional[str] = Query(default=None),
        subject_id: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> Dict[str, Any]:
        publication = _read_observation(deps)
        with _read_v1_db(deps) as conn:
            rows = _witness_rows(conn, seed_id=seed_id, subject_type=subject_type, subject_id=subject_id, limit=limit)
            return _publication_response({
                "verified": None if deps.read_only and not rows else _verify_witness_rows(rows),
                "entries": [_serialize_witness_event(row) for row in rows],
            }, publication)

    @router.get("/witness/verify")
    async def verify_witness_chain(
        seed_id: Optional[str] = Query(default=None),
        subject_type: Optional[str] = Query(default=None),
        subject_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        publication = _read_observation(deps)
        with _read_v1_db(deps) as conn:
            rows = _witness_rows(conn, seed_id=seed_id, subject_type=subject_type, subject_id=subject_id, limit=10000)
            return _publication_response({
                "verified": None if deps.read_only and not rows else _verify_witness_rows(rows),
                "entry_count": len(rows),
                "head": str(rows[-1]["event_hash"]) if rows else "genesis",
            }, publication)

    @router.post("/standing/review", status_code=status.HTTP_201_CREATED)
    async def review_standing(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        if "standing_lease" not in payload and "lease" not in payload and "standing_id" not in payload:
            return key_control_problem(
                "signed_standing_review_required",
                "Standing review requires a signed standing lease and an active reviewer key binding.",
                428,
            )
        _reject_unsigned_authority_selector(payload)
        with _mutation_v1_db(deps) as conn:
            standing_lease = _extract_object(payload, "standing_lease", "lease")
            lease_for_hash = _without_signature(standing_lease)
            standing_id = _required_str(lease_for_hash, "standing_id")
            subject_seed_id = _required_str(lease_for_hash, "subject_seed_id")
            subject_claim_id = _required_str(lease_for_hash, "subject_claim_id")
            _seed_row(conn, subject_seed_id)
            seed = _seed_row(conn, subject_seed_id)
            if str(seed["claim_id"]) != subject_claim_id:
                raise HTTPException(status_code=400, detail="standing subject_claim_id does not match seed")
            _validate_standing_lease(lease_for_hash)
            _ensure_not_expired(_standing_expiry(lease_for_hash), "standing lease expired")
            reviewer_identity = str(payload.get("reviewer_identity") or lease_for_hash.get("issued_by") or "")
            if not reviewer_identity:
                raise HTTPException(status_code=400, detail="reviewer_identity is required")
            if str(lease_for_hash.get("issued_by") or "") != reviewer_identity:
                raise HTTPException(status_code=403, detail="standing issued_by must match the authenticated reviewer")
            _require_actor_signer(conn, reviewer_identity, standing_lease, payload)
            created_at = str(lease_for_hash.get("issued_at") or payload.get("created_at") or "")
            if not created_at:
                raise HTTPException(status_code=400, detail="issued_at is required")
            signature_hex = _extract_signature(standing_lease, payload)
            standing_lease_hash = _hash_json(lease_for_hash)
            message = {
                "kind": "sab_standing_review",
                "standing_lease_sha256": standing_lease_hash,
                "subject_seed_id": subject_seed_id,
                "reviewer_identity": reviewer_identity,
                "created_at": created_at,
            }
            deps.verify_agent_signature(conn, reviewer_identity, _canonical_bytes(message), signature_hex)
            authority = _authorize_actor(deps, conn, actor=reviewer_identity, action="request_standing_review",
                                         seed_id=subject_seed_id)
            _sweep_challenge_deadlines(deps, conn, subject_seed_id, authority=authority)
            seed = _seed_row(conn, subject_seed_id)
            if _pending_challenge_count(conn, subject_seed_id) > 0:
                raise HTTPException(status_code=409, detail="standing review requires resolved challenge path")
            if _challenge_count(conn, subject_seed_id) < 1:
                raise HTTPException(status_code=409, detail="standing review requires a challenge")
            if _seed_witness_count(conn, subject_seed_id) < 1:
                raise HTTPException(status_code=409, detail="standing review requires a witness event")
            _record_signature_use(conn, signature_hex, _hash_json(message), reviewer_identity)
            if conn.execute(
                "SELECT 1 FROM sab_standing_leases_v1 WHERE standing_id = ?",
                (standing_id,),
            ).fetchone():
                raise HTTPException(status_code=409, detail="standing already exists")
            issued_under = _independence_gate(conn, seed)
            issued_status = "active" if issued_under["tier"] in {"active", "canon"} else "provisional"
            now = deps.utc_now()
            conn.execute(
                """
                INSERT INTO sab_standing_leases_v1
                    (
                        standing_id, subject_seed_id, subject_claim_id, scope, purpose,
                        status, lease_json, lease_hash, expiry, revoker,
                        challenge_path, issued_by, issued_at, updated_at, issued_under_json
                    )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    standing_id,
                    subject_seed_id,
                    subject_claim_id,
                    str(lease_for_hash.get("scope") or ""),
                    str(lease_for_hash.get("purpose") or ""),
                    issued_status,
                    _json_dumps(standing_lease),
                    standing_lease_hash,
                    _standing_expiry(lease_for_hash),
                    str(lease_for_hash.get("revoker") or ""),
                    str(lease_for_hash.get("challenge_path") or ""),
                    reviewer_identity,
                    created_at,
                    now,
                    _json_dumps(issued_under),
                ),
            )
            event = _record_standing_event(
                deps,
                conn,
                standing_id=standing_id,
                actor_identity=reviewer_identity,
                event_type="standing_issued",
                to_status=issued_status,
                payload={"standing_lease_hash": standing_lease_hash, "issued_under": issued_under, "authority": authority},
                signature_hex=signature_hex,
            )
            _record_seed_transition(
                deps,
                conn,
                seed_id=subject_seed_id,
                actor_identity=reviewer_identity,
                event_type="standing_issued",
                to_state="standing_active",
                payload={"standing_id": standing_id, "standing_lease_hash": standing_lease_hash, "authority": authority},
                signature_hex=signature_hex,
                precreated_witness=event,
            )
            deps.invalidate_web_cache()
            return {**_serialize_standing(_standing_row(conn, standing_id)), "witness_head": event["hash"]}

    @router.get("/standing/{standing_id}")
    async def get_standing(standing_id: str) -> Dict[str, Any]:
        publication = _read_observation(deps)
        with _read_v1_db(deps) as conn:
            row = _standing_row(conn, standing_id)
            observation = _observe_standing(row, publication_observation=publication)
            return _publication_response(observation, publication)

    @router.get("/standing")
    async def list_standing(
        subject: Optional[str] = Query(default=None),
        status_filter: Optional[str] = Query(default=None, alias="status"),
        scope: Optional[str] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=500),
    ) -> Dict[str, Any]:
        publication = _read_observation(deps)
        if deps.read_only and not deps.publication_configured:
            return _publication_response({"items": [], "availability": "not_configured"}, publication)
        with _read_v1_db(deps) as conn:
            clauses: List[str] = []
            params: List[Any] = []
            observed_at = publication.observed_at if publication is not None else datetime.now(timezone.utc)
            if subject:
                clauses.append("subject_seed_id = ?")
                params.append(subject)
            if status_filter:
                # The same observer handles invalid timestamps and offsets in
                # list filtering and individual reads, before applying LIMIT.
                conn.create_function(
                    "sab_observed_standing_status",
                    2,
                    lambda stored, expiry: observe_standing_status(
                        stored, expiry, observed_at=observed_at, publication_observation=publication
                    )["status"],
                )
                clauses.append("sab_observed_standing_status(status, expiry) = ?")
                params.append(status_filter)
            if scope:
                clauses.append("scope = ?")
                params.append(scope)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = conn.execute(
                f"""
                SELECT *
                FROM sab_standing_leases_v1
                {where}
                ORDER BY id DESC
                LIMIT ?
                """,  # nosec B608 - where only contains fixed clauses.
                (*params, limit),
            ).fetchall()
            items = []
            for row in rows:
                observation = _observe_standing(row, include_lease=False, observed_at=observed_at,
                                                publication_observation=publication)
                items.append(observation)
            return _publication_response({"items": items}, publication)

    @router.post("/standing/{standing_id}/challenge")
    async def challenge_standing(standing_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        return _standing_action(deps, standing_id, payload, action="challenge", to_status="challenged", seed_state="challenged")

    @router.post("/standing/{standing_id}/revoke")
    async def revoke_standing(standing_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        return _standing_action(deps, standing_id, payload, action="revoke", to_status="revoked", seed_state="revoked")

    @router.post("/standing/{standing_id}/revalidate")
    async def revalidate_standing(standing_id: str, payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        for flag in ("promote_to_canon", "canon"):
            if flag in payload and not isinstance(payload[flag], bool):
                raise HTTPException(status_code=400, detail="Canon promotion flags must be booleans")
        if "promote_to_canon" in payload and "canon" in payload and payload["promote_to_canon"] != payload["canon"]:
            raise HTTPException(status_code=400, detail="Canon promotion flags conflict")
        promote_to_canon = payload.get("promote_to_canon", payload.get("canon", False))
        return _standing_action(
            deps,
            standing_id,
            payload,
            action="revalidate",
            to_status="canon" if promote_to_canon else "active",
            seed_state="canon" if promote_to_canon else "canon_candidate",
        )

    return router


def _init_v1_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_signature_index_v1 (
            signature TEXT PRIMARY KEY,
            message_hash TEXT NOT NULL,
            actor_identity TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sab_signature_identity_v1 "
        f"ON sab_signature_index_v1 ({_SIGNATURE_IDENTITY_SQL})"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_agent_identities_v1 (
            subject_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            controller TEXT NOT NULL,
            operator_id TEXT NOT NULL,
            operator_backing_json TEXT NOT NULL,
            identity_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_agent_identities_operator ON sab_agent_identities_v1(operator_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_authority_leases_v1 (
            lease_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            scope TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoker TEXT NOT NULL,
            challenge_path TEXT NOT NULL,
            lease_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_seed_packets_v1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seed_id TEXT NOT NULL UNIQUE,
            seed_type TEXT NOT NULL,
            title TEXT NOT NULL,
            claim_id TEXT NOT NULL,
            claimant_identity TEXT NOT NULL,
            authority_lease_id TEXT NOT NULL,
            state TEXT NOT NULL,
            packet_json TEXT NOT NULL,
            packet_hash TEXT NOT NULL,
            spark_projection_id INTEGER,
            challenge_window_closes_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_seed_packets_state ON sab_seed_packets_v1(state, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_seed_packets_claimant ON sab_seed_packets_v1(claimant_identity, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_seed_packets_claim ON sab_seed_packets_v1(claim_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_seed_events_v1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            seed_id TEXT NOT NULL,
            actor_identity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            from_state TEXT,
            to_state TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            witness_event_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_seed_events_seed ON sab_seed_events_v1(seed_id, id ASC)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_challenge_packets_v1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge_id TEXT NOT NULL UNIQUE,
            target_seed_id TEXT NOT NULL,
            target_claim_id TEXT NOT NULL,
            challenger_identity TEXT NOT NULL,
            status TEXT NOT NULL,
            packet_json TEXT NOT NULL,
            packet_hash TEXT NOT NULL,
            response_json TEXT,
            respond_by TEXT,
            prosecute_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_challenge_seed ON sab_challenge_packets_v1(target_seed_id, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_challenge_status ON sab_challenge_packets_v1(status, id DESC)")
    _ensure_v1_column(conn, "sab_challenge_packets_v1", "respond_by", "respond_by TEXT")
    _ensure_v1_column(conn, "sab_challenge_packets_v1", "prosecute_by", "prosecute_by TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_witness_events_v1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            chain_scope TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_identity TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            subject_seed_id TEXT,
            timestamp TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        )
        """
    )
    _ensure_v1_column(conn, "sab_witness_events_v1", "authority_json", "authority_json TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_witness_chain_scope ON sab_witness_events_v1(chain_scope, id ASC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_witness_subject ON sab_witness_events_v1(subject_type, subject_id, id ASC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_witness_seed ON sab_witness_events_v1(subject_seed_id, id ASC)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_standing_leases_v1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            standing_id TEXT NOT NULL UNIQUE,
            subject_seed_id TEXT NOT NULL,
            subject_claim_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            purpose TEXT NOT NULL,
            status TEXT NOT NULL,
            lease_json TEXT NOT NULL,
            lease_hash TEXT NOT NULL,
            expiry TEXT NOT NULL,
            revoker TEXT NOT NULL,
            challenge_path TEXT NOT NULL,
            issued_by TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            issued_under_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_standing_seed ON sab_standing_leases_v1(subject_seed_id, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_standing_status ON sab_standing_leases_v1(status, id DESC)")
    _ensure_v1_column(conn, "sab_standing_leases_v1", "issued_under_json", "issued_under_json TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sab_standing_events_v1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            standing_id TEXT NOT NULL,
            actor_identity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            witness_event_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sab_standing_events_standing ON sab_standing_events_v1(standing_id, id ASC)")


def _extract_object(payload: Dict[str, Any], *keys: str) -> Dict[str, Any]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    return payload


def _json_dumps(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return _json_dumps(payload).encode()


def _sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def _hash_json(payload: Any) -> str:
    if isinstance(payload, dict):
        return _sha256_hex(_canonical_bytes(payload))
    return _sha256_hex(_json_dumps(payload).encode())


def _without_signature(payload: Dict[str, Any]) -> Dict[str, Any]:
    stripped = json.loads(_json_dumps(payload))
    if isinstance(stripped, dict):
        stripped.pop("signature", None)
    return stripped


def _extract_signature(*payloads: Dict[str, Any]) -> str:
    for payload in payloads:
        signature = payload.get("signature")
        if isinstance(signature, dict):
            value = signature.get("signature") or signature.get("value")
        else:
            value = signature
        if isinstance(value, str) and value:
            return value
    raise HTTPException(status_code=400, detail="signature is required")


def _signature_signer(*payloads: Dict[str, Any]) -> Optional[str]:
    for payload in payloads:
        signature = payload.get("signature")
        if isinstance(signature, dict):
            signer = signature.get("signer")
            if isinstance(signer, str) and signer.strip():
                return signer.strip()
    return None


def _identity_ref_subject(conn: sqlite3.Connection, identity_ref: str) -> Optional[str]:
    if not identity_ref.startswith("sab_identity_"):
        return None
    suffix = identity_ref[len("sab_identity_") :]
    if not suffix:
        return None
    direct = conn.execute("SELECT id FROM web_agents WHERE id = ?", (suffix,)).fetchone()
    if direct is not None:
        return str(direct["id"])
    by_name = conn.execute(
        "SELECT id FROM web_agents WHERE name = ? ORDER BY created_at DESC LIMIT 1",
        (suffix,),
    ).fetchone()
    if by_name is not None:
        return str(by_name["id"])
    return None


def _ensure_v1_column(conn: sqlite3.Connection, table: str, column: str, column_def: str) -> None:
    columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")


def _actor_subject(conn: sqlite3.Connection, actor_identity: str) -> str:
    if actor_identity.startswith("sab_identity_"):
        resolved = _identity_ref_subject(conn, actor_identity)
        if resolved:
            return resolved
    return actor_identity


def _identity_model(conn: sqlite3.Connection, actor_identity: str) -> Optional[AgentIdentityV1]:
    subject = _actor_subject(conn, actor_identity)
    agent = conn.execute(
        "SELECT id, name, public_key FROM web_agents WHERE id = ?",
        (subject,),
    ).fetchone()
    if agent is None:
        return None
    controller = "unknown"
    backing: Dict[str, Any] = {}
    identity_row = conn.execute(
        "SELECT controller, operator_backing_json FROM sab_agent_identities_v1 WHERE subject_id = ?",
        (subject,),
    ).fetchone()
    if identity_row is not None:
        stored_controller = str(identity_row["controller"] or "unknown")
        if stored_controller in {"self", "operator", "org", "unknown"}:
            controller = stored_controller
        try:
            parsed = json.loads(str(identity_row["operator_backing_json"]))
            if isinstance(parsed, dict):
                backing = parsed
        except (TypeError, ValueError):
            backing = {}
    try:
        return AgentIdentityV1.from_public_key(
            display_name=str(agent["name"] or "sab-agent"),
            public_key=str(agent["public_key"]),
            controller=controller,
            operator_backing=OperatorBacking.model_validate(backing),
        )
    except (ValidationError, ValueError):
        # Grader failure mode: ungradable identities collapse to undisclosed.
        return None


def _system_operator_count(conn: sqlite3.Connection) -> int:
    rows = conn.execute("SELECT DISTINCT operator_id FROM sab_agent_identities_v1").fetchall()
    operators = {str(row["operator_id"]).strip().lower() for row in rows}
    return len({operator for operator in operators if operator and operator != "unknown"})


def _seed_witness_grades(conn: sqlite3.Connection, seed: sqlite3.Row) -> List[Dict[str, Any]]:
    claimant_model = _identity_model(conn, str(seed["claimant_identity"]))
    grades: List[Dict[str, Any]] = []
    rows = conn.execute(
        """
        SELECT DISTINCT actor_identity
        FROM sab_witness_events_v1
        WHERE subject_seed_id = ? AND event_type = 'affirm'
        """,
        (str(seed["seed_id"]),),
    ).fetchall()
    for row in rows:
        actor = str(row["actor_identity"])
        witness_model = _identity_model(conn, actor)
        if claimant_model is None or witness_model is None:
            grades.append({"witness_identity": actor, "grade": "undisclosed", "operator_id": "unknown"})
            continue
        grades.append(
            {
                "witness_identity": actor,
                "grade": independence_grade(witness_model, claimant_model),
                "operator_id": identity_operator_id(witness_model),
            }
        )
    return grades


def _independence_gate(conn: sqlite3.Connection, seed: sqlite3.Row) -> Dict[str, Any]:
    witnesses = _seed_witness_grades(conn, seed)
    system_operator_count = _system_operator_count(conn)
    tier = quorum_tier(
        witnesses=[(str(item["grade"]), str(item["operator_id"])) for item in witnesses],
        system_operator_count=system_operator_count,
    )
    distinct_operators = {
        str(item["operator_id"])
        for item in witnesses
        if str(item["operator_id"]).strip().lower() not in {"", "unknown"}
    }
    return {
        "tier": tier,
        "witnesses": witnesses,
        "distinct_operator_count": len(distinct_operators),
        "system_operator_count": system_operator_count,
        "operator_count_basis": "self_declared",
        "rehearsal_flag": "single_operator_rehearsal"
        if system_operator_count < MIN_INDEPENDENT_OPERATORS_FOR_STANDING
        else "multi_operator",
    }


def _enforce_witness_policy(
    conn: sqlite3.Connection,
    *,
    seed: sqlite3.Row,
    actor_identity: str,
) -> Dict[str, Any]:
    packet = json.loads(str(seed["packet_json"]))
    plan = packet.get("witness_plan") if isinstance(packet.get("witness_plan"), dict) else {}
    forbidden = {str(item).strip() for item in (plan.get("forbidden_witnesses") or []) if str(item).strip()}
    actor_subject = _actor_subject(conn, actor_identity)
    if forbidden & {actor_identity, actor_subject}:
        raise HTTPException(status_code=403, detail="witness is forbidden by the seed witness_plan")
    impact = str(plan.get("impact") or "low")
    claimant_model = _identity_model(conn, str(seed["claimant_identity"]))
    witness_model = _identity_model(conn, actor_subject)
    if claimant_model is None or witness_model is None:
        if impact.lower() in HIGH_IMPACT_LEVELS:
            raise HTTPException(status_code=403, detail="witness independence cannot be established; failing closed")
        return {"grade": "undisclosed", "impact": impact, "warnings": ["independence_ungradable"]}
    existing_models: List[AgentIdentityV1] = []
    seen: set = set()
    for row in conn.execute(
        """
        SELECT DISTINCT actor_identity
        FROM sab_witness_events_v1
        WHERE subject_seed_id = ? AND event_type = 'affirm'
        """,
        (str(seed["seed_id"]),),
    ).fetchall():
        prior = _identity_model(conn, str(row["actor_identity"]))
        if prior is not None and prior.subject_id not in seen:
            seen.add(prior.subject_id)
            existing_models.append(prior)
    decision = validate_witness_independence(
        claimant_identity=claimant_model,
        witness_identity=witness_model,
        impact=impact,
        existing_witness_identities=existing_models,
    )
    if not decision.ok:
        raise HTTPException(status_code=403, detail="witness independence rejected: " + "; ".join(decision.errors))
    return {
        "grade": independence_grade(witness_model, claimant_model),
        "impact": impact,
        "warnings": decision.warnings,
    }


def _adjudicator_independence(
    conn: sqlite3.Connection,
    *,
    adjudicator: str,
    claimant: str,
    challenger: str,
) -> Dict[str, Any]:
    system_operator_count = _system_operator_count(conn)
    if system_operator_count < MIN_INDEPENDENT_OPERATORS_FOR_STANDING:
        return {"independence": "single_operator_rehearsal", "system_operator_count": system_operator_count}
    adjudicator_model = _identity_model(conn, adjudicator)
    grades: Dict[str, str] = {}
    minimum = INDEPENDENCE_GRADE_TIERS["cross_operator_unverified"]
    for role, party in (("claimant", claimant), ("challenger", challenger)):
        party_model = _identity_model(conn, party)
        grade = "undisclosed"
        if adjudicator_model is not None and party_model is not None:
            grade = independence_grade(adjudicator_model, party_model)
        if INDEPENDENCE_GRADE_TIERS.get(grade, 1) < minimum:
            raise HTTPException(status_code=403, detail=f"adjudicator is not independent of the {role}")
        grades[f"vs_{role}"] = grade
    return {"independence": grades, "system_operator_count": system_operator_count}


def _seed_transition_allowed(from_state: str, to_state: str) -> bool:
    return to_state in SEED_TRANSITIONS.get(from_state, frozenset())


def _ensure_seed_transition_allowed(from_state: str, to_state: str) -> None:
    if _seed_transition_allowed(from_state, to_state):
        return
    if from_state in FINAL_SEED_STATES:
        raise HTTPException(status_code=409, detail=f"seed is final in state {from_state}")
    raise HTTPException(status_code=409, detail=f"seed transition {from_state} -> {to_state} is not allowed")


def _ensure_challenge_window_open(seed: sqlite3.Row) -> None:
    closes_at = seed["challenge_window_closes_at"]
    if not closes_at:
        return
    if _parse_datetime(str(closes_at)) <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=409,
            detail="challenge window is closed; late challenges require a challenge bond (not yet implemented)",
        )


def _challenge_respond_by(packet: Dict[str, Any], created_at: str) -> str:
    deadline = str(packet.get("deadline") or "").strip()
    if deadline:
        try:
            return _parse_datetime(deadline).isoformat()
        except HTTPException:
            pass
    return (_parse_datetime(created_at) + CHALLENGE_RESPOND_WINDOW).isoformat()


def _challenge_prosecute_by(packet: Dict[str, Any]) -> str:
    declared = str(packet.get("prosecute_by") or "").strip()
    if declared:
        try:
            return _parse_datetime(declared).isoformat()
        except HTTPException:
            pass
    return (datetime.now(timezone.utc) + CHALLENGE_PROSECUTE_WINDOW).isoformat()


def _sweep_challenge_deadlines(
    deps: SabSeedingDeps, conn: sqlite3.Connection, seed_id: str, *, authority: Dict[str, Any]
) -> None:
    now = deps.key_control.observe_time() if deps.key_control is not None else datetime.now(timezone.utc)
    rows = conn.execute(
        """
        SELECT challenge_id, status, respond_by, prosecute_by
        FROM sab_challenge_packets_v1
        WHERE target_seed_id = ? AND status IN ('pending', 'responded')
        """,
        (seed_id,),
    ).fetchall()
    for challenge in rows:
        challenge_id = str(challenge["challenge_id"])
        status_value = str(challenge["status"])
        if status_value == "pending":
            deadline_raw = challenge["respond_by"]
            if not deadline_raw:
                continue
            try:
                deadline = _parse_datetime(str(deadline_raw))
            except HTTPException:
                continue
            if deadline > now:
                continue
            conn.execute(
                """
                UPDATE sab_challenge_packets_v1
                SET status = 'sustained_by_default', updated_at = ?
                WHERE challenge_id = ?
                """,
                (deps.utc_now(), challenge_id),
            )
            seed = _seed_row(conn, seed_id)
            if _seed_transition_allowed(str(seed["state"]), "compost"):
                signature = deps.system_sign(
                    {
                        "kind": "sab_challenge_sustained_by_default",
                        "challenge_id": challenge_id,
                        "respond_by": str(deadline_raw),
                    }
                )
                _record_seed_transition(
                    deps,
                    conn,
                    seed_id=seed_id,
                    actor_identity="system",
                    event_type="compost",
                    to_state="compost",
                    payload={
                        "challenge_id": challenge_id,
                        "adjudication": "sustained_by_default",
                        "authority": authority,
                        "reason": "claimant did not respond before respond_by",
                        "respond_by": str(deadline_raw),
                    },
                    signature_hex=signature,
                )
        else:
            deadline_raw = challenge["prosecute_by"]
            if not deadline_raw:
                continue
            try:
                deadline = _parse_datetime(str(deadline_raw))
            except HTTPException:
                continue
            if deadline > now:
                continue
            conn.execute(
                """
                UPDATE sab_challenge_packets_v1
                SET status = 'lapsed', updated_at = ?
                WHERE challenge_id = ?
                """,
                (deps.utc_now(), challenge_id),
            )
            seed = _seed_row(conn, seed_id)
            current_state = str(seed["state"])
            if _seed_transition_allowed(current_state, current_state):
                signature = deps.system_sign(
                    {
                        "kind": "sab_challenge_lapsed",
                        "challenge_id": challenge_id,
                        "prosecute_by": str(deadline_raw),
                    }
                )
                _record_seed_transition(
                    deps,
                    conn,
                    seed_id=seed_id,
                    actor_identity="system",
                    event_type="challenge",
                    to_state=current_state,
                    payload={
                        "challenge_id": challenge_id,
                        "challenge_status": "lapsed",
                        "authority": authority,
                        "reason": "challenger did not prosecute before prosecute_by",
                        "prosecute_by": str(deadline_raw),
                    },
                    signature_hex=signature,
                )


def _verify_signature_with_fallback(
    deps: SabSeedingDeps,
    conn: sqlite3.Connection,
    actor_id: str,
    message: Dict[str, Any],
    signature_hex: str,
) -> bool:
    try:
        deps.verify_agent_signature(conn, actor_id, _canonical_bytes(message), signature_hex)
        return True
    except HTTPException:
        return False


def _required_str(payload: Dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=400, detail=f"{key} is required")
    return value if key == "signature" else value.strip()


def _object_value(payload: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail=f"{key} is required")
    return value


def _claimant_identity(packet: Dict[str, Any], signed_packet: Dict[str, Any]) -> str:
    claimant = packet.get("claimant_identity")
    if isinstance(claimant, dict):
        subject_id = claimant.get("subject_id")
        if isinstance(subject_id, str) and subject_id.strip():
            return subject_id.strip()
    signature = signed_packet.get("signature")
    if isinstance(signature, dict):
        signer = signature.get("signer")
        if isinstance(signer, str) and signer.strip():
            return signer.strip()
    raise HTTPException(status_code=400, detail="claimant_identity.subject_id is required")


def _parse_datetime(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid datetime: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ensure_not_expired(value: str, detail: str) -> None:
    if _parse_datetime(value) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail=detail)


def _challenge_window_closes_at(packet: Dict[str, Any], created_at: str) -> str:
    plan = packet.get("challenge_plan") if isinstance(packet.get("challenge_plan"), dict) else {}
    window = str(plan.get("challenge_window") or "P7D")
    start = _parse_datetime(created_at)
    duration = timedelta(days=7)
    compact = window.strip().upper()
    try:
        if compact.startswith("P") and compact.endswith("D"):
            duration = timedelta(days=int(compact[1:-1]))
        elif compact.endswith("D"):
            duration = timedelta(days=int(compact[:-1]))
        elif compact.endswith("H"):
            duration = timedelta(hours=int(compact[:-1].replace("PT", "")))
    except ValueError:
        duration = timedelta(days=7)
    return (start + duration).isoformat()


def _seed_submit_message(
    *,
    seed_packet_hash: str,
    claimant_identity: str,
    authority_lease_id: str,
    created_at: str,
) -> Dict[str, str]:
    return {
        "kind": "sab_seed_submit",
        "seed_packet_sha256": seed_packet_hash,
        "claimant_identity": claimant_identity,
        "authority_lease_id": authority_lease_id,
        "created_at": created_at,
    }


def _challenge_submit_message(
    *,
    target_seed_id: str,
    target_claim_id: str,
    challenge_packet_hash: str,
    challenger_identity: str,
    created_at: str,
) -> Dict[str, str]:
    return {
        "kind": "sab_challenge_submit",
        "target_seed_id": target_seed_id,
        "target_claim_id": target_claim_id,
        "challenge_packet_sha256": challenge_packet_hash,
        "challenger_identity": challenger_identity,
        "created_at": created_at,
    }


def _challenge_response_message(
    *,
    challenge_id: str,
    responder_identity: str,
    response_body: str,
) -> Dict[str, str]:
    return {
        "kind": "sab_challenge_response",
        "challenge_id": challenge_id,
        "responder_identity": responder_identity,
        "response_sha256": _sha256_hex(response_body.encode()),
    }


def _witness_event_message(
    *,
    event_type: str,
    subject_type: str,
    subject_id: str,
    payload_hash: str,
    prev_hash: str,
    created_at: str,
) -> Dict[str, str]:
    return {
        "kind": "sab_witness_event",
        "event_type": event_type,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "created_at": created_at,
    }


def _record_signature_use(conn: sqlite3.Connection, signature: str, message_hash: str, actor_identity: str) -> None:
    try:
        decoded = bytes.fromhex(signature)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Actor signatures require canonical Ed25519 hex") from None
    if len(decoded) != 64:
        raise HTTPException(status_code=400, detail="Actor signatures require canonical Ed25519 hex")
    canonical_signature = decoded.hex()
    row = conn.execute(
        f"SELECT 1 FROM sab_signature_index_v1 WHERE {_SIGNATURE_IDENTITY_SQL} = ? LIMIT 1",  # nosec B608 - fixed expression, parameterized signature.
        (canonical_signature,),
    ).fetchone()
    if row is not None:
        raise HTTPException(status_code=409, detail="signature already used; actor commands have one effect")
    if signature != canonical_signature:
        raise HTTPException(status_code=400, detail="New actor signatures require exactly 128 lowercase hex characters")
    conn.execute(
        """
        INSERT INTO sab_signature_index_v1 (signature, message_hash, actor_identity, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (canonical_signature, message_hash, actor_identity, datetime.now(timezone.utc).isoformat()),
    )


def _create_spark_projection(
    conn: sqlite3.Connection,
    packet: Dict[str, Any],
    claimant_identity: str,
    seed_id: str,
) -> int:
    claim = packet.get("claim") if isinstance(packet.get("claim"), dict) else {}
    content = str(claim.get("text") or packet.get("title") or seed_id)
    gate_scores = {
        "dimensions": {},
        "composite": 0.0,
        "rv_contraction": None,
        "rv_measurement_state": "not_evaluated",
        "rv_signal": {
            "signal_label": "not_evaluated",
            "warnings": ["v1_seed_projection_not_gate_scored"],
        },
    }
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO sparks
            (
                content, content_type, author_id, created_at, gate_scores, status,
                rv_contraction, composite_score, claim_packet_ref,
                artifact_refs_json, red_team_refs_json, witness_refs_json,
                lineage_root_id, parent_spark_id, sublation_status, founding_seed
            )
        VALUES (?, 'text', ?, ?, ?, 'spark', NULL, 0.0, ?, '[]', '[]', '[]', NULL, NULL, 'seed_projection', 0)
        """,
        (
            content,
            claimant_identity,
            datetime.now(timezone.utc).isoformat(),
            _json_dumps(gate_scores),
            seed_id,
        ),
    )
    return int(cursor.lastrowid)


def _seed_row(conn: sqlite3.Connection, seed_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM sab_seed_packets_v1 WHERE seed_id = ?", (seed_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="seed not found")
    return row


def _challenge_row(conn: sqlite3.Connection, challenge_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM sab_challenge_packets_v1 WHERE challenge_id = ?",
        (challenge_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="challenge not found")
    return row


def _standing_row(conn: sqlite3.Connection, standing_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM sab_standing_leases_v1 WHERE standing_id = ?",
        (standing_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="standing not found")
    return row


def _latest_witness_hash(conn: sqlite3.Connection, chain_scope: str) -> str:
    row = conn.execute(
        """
        SELECT event_hash
        FROM sab_witness_events_v1
        WHERE chain_scope = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (chain_scope,),
    ).fetchone()
    return str(row["event_hash"]) if row is not None else "genesis"


def _append_witness_event(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    actor_identity: str,
    subject_type: str,
    subject_id: str,
    subject_seed_id: Optional[str],
    payload: Dict[str, Any],
    signature_hex: str,
    timestamp: str,
    expected_prev_hash: Optional[str] = None,
    authority: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    chain_scope = subject_seed_id or f"{subject_type}:{subject_id}"
    prev_hash = expected_prev_hash if expected_prev_hash is not None else _latest_witness_hash(conn, chain_scope)
    event_id = f"sab_witness_{secrets.token_hex(12)}"
    payload_json = _json_dumps(payload)
    payload_hash = _sha256_hex(payload_json.encode())
    material = {
        "event_id": event_id,
        "chain_scope": chain_scope,
        "event_type": event_type,
        "actor_identity": actor_identity,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_seed_id": subject_seed_id,
        "timestamp": timestamp,
        "payload_hash": payload_hash,
        "payload_json": payload_json,
        "signature": signature_hex,
        "prev_hash": prev_hash,
    }
    if authority is not None:
        material["authority"] = authority
    event_hash = _hash_json(material)
    conn.execute(
        """
        INSERT INTO sab_witness_events_v1
            (
                event_id, chain_scope, event_type, actor_identity, subject_type,
                subject_id, subject_seed_id, timestamp, payload_hash,
                payload_json, signature, prev_hash, event_hash, authority_json
            )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            chain_scope,
            event_type,
            actor_identity,
            subject_type,
            subject_id,
            subject_seed_id,
            timestamp,
            payload_hash,
            payload_json,
            signature_hex,
            prev_hash,
            event_hash,
            _json_dumps(authority) if authority is not None else None,
        ),
    )
    return {
        "event_id": event_id,
        "event_type": event_type,
        "actor_identity": actor_identity,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_seed_id": subject_seed_id,
        "timestamp": timestamp,
        "payload_hash": payload_hash,
        "payload": payload,
        "signature": signature_hex,
        "prev_hash": prev_hash,
        "hash": event_hash,
        "event_hash": event_hash,
        **({"authority": authority} if authority is not None else {}),
    }


def _record_seed_transition(
    deps: SabSeedingDeps,
    conn: sqlite3.Connection,
    *,
    seed_id: str,
    actor_identity: str,
    event_type: str,
    to_state: str,
    payload: Dict[str, Any],
    signature_hex: str,
    update_state: bool = True,
    precreated_witness: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if to_state not in SEED_STATES:
        raise HTTPException(status_code=400, detail="unsupported seed state")
    row = _seed_row(conn, seed_id)
    from_state = str(row["state"])
    _ensure_seed_transition_allowed(from_state, to_state)
    transition_payload = {
        **payload,
        "from_state": from_state,
        "to_state": to_state,
    }
    witness = precreated_witness or _append_witness_event(
        conn,
        event_type=event_type,
        actor_identity=actor_identity,
        subject_type="seed",
        subject_id=seed_id,
        subject_seed_id=seed_id,
        payload=transition_payload,
        signature_hex=signature_hex,
        timestamp=deps.utc_now(),
    )
    seed_event_id = f"sab_seed_event_{secrets.token_hex(10)}"
    conn.execute(
        """
        INSERT INTO sab_seed_events_v1
            (
                event_id, seed_id, actor_identity, event_type, from_state,
                to_state, payload_json, witness_event_id, created_at
            )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            seed_event_id,
            seed_id,
            actor_identity,
            event_type,
            from_state,
            to_state,
            _json_dumps(transition_payload),
            witness["event_id"],
            deps.utc_now(),
        ),
    )
    if update_state and from_state != to_state:
        conn.execute(
            """
            UPDATE sab_seed_packets_v1
            SET state = ?, updated_at = ?
            WHERE seed_id = ?
            """,
            (to_state, deps.utc_now(), seed_id),
        )
        _update_spark_projection_state(conn, row["spark_projection_id"], to_state)
    return witness


def _record_standing_event(
    deps: SabSeedingDeps,
    conn: sqlite3.Connection,
    *,
    standing_id: str,
    actor_identity: str,
    event_type: str,
    to_status: str,
    payload: Dict[str, Any],
    signature_hex: str,
) -> Dict[str, Any]:
    if to_status not in STANDING_STATUSES:
        raise HTTPException(status_code=400, detail="unsupported standing status")
    row = _standing_row(conn, standing_id)
    from_status = str(row["status"])
    subject_seed_id = str(row["subject_seed_id"])
    event_payload = {
        **payload,
        "standing_id": standing_id,
        "from_status": from_status,
        "to_status": to_status,
    }
    witness = _append_witness_event(
        conn,
        event_type=event_type,
        actor_identity=actor_identity,
        subject_type="standing",
        subject_id=standing_id,
        subject_seed_id=subject_seed_id,
        payload=event_payload,
        signature_hex=signature_hex,
        timestamp=deps.utc_now(),
    )
    standing_event_id = f"sab_standing_event_{secrets.token_hex(10)}"
    conn.execute(
        """
        INSERT INTO sab_standing_events_v1
            (
                event_id, standing_id, actor_identity, event_type, from_status,
                to_status, payload_json, witness_event_id, created_at
            )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            standing_event_id,
            standing_id,
            actor_identity,
            event_type,
            from_status,
            to_status,
            _json_dumps(event_payload),
            witness["event_id"],
            deps.utc_now(),
        ),
    )
    if from_status != to_status:
        conn.execute(
            """
            UPDATE sab_standing_leases_v1
            SET status = ?, updated_at = ?
            WHERE standing_id = ?
            """,
            (to_status, deps.utc_now(), standing_id),
        )
    return witness


def _update_spark_projection_state(conn: sqlite3.Connection, spark_projection_id: Any, seed_state: str) -> None:
    if spark_projection_id is None:
        return
    if seed_state == "canon":
        spark_status = "canon"
    elif seed_state in {"compost", "revoked", "expired"}:
        spark_status = "compost"
    else:
        spark_status = "spark"
    conn.execute("UPDATE sparks SET status = ? WHERE id = ?", (spark_status, spark_projection_id))


def _serialize_seed(conn: sqlite3.Connection, row: sqlite3.Row, *, include_packet: bool = True) -> Dict[str, Any]:
    seed_id = str(row["seed_id"])
    head = _latest_witness_hash(conn, seed_id)
    item = {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "seed_type": str(row["seed_type"]),
        "title": str(row["title"]),
        "claim_id": str(row["claim_id"]),
        "claimant_identity": str(row["claimant_identity"]),
        "authority_lease_id": str(row["authority_lease_id"]),
        "state": str(row["state"]),
        "packet_hash": str(row["packet_hash"]),
        "spark_projection_id": row["spark_projection_id"],
        "challenge_window_closes_at": row["challenge_window_closes_at"],
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "witness_head": head,
    }
    if include_packet:
        item["seed_packet"] = json.loads(str(row["packet_json"]))
    return item


def _serialize_challenge(row: sqlite3.Row) -> Dict[str, Any]:
    response_raw = row["response_json"]
    return {
        "challenge_id": str(row["challenge_id"]),
        "target_seed_id": str(row["target_seed_id"]),
        "target_claim_id": str(row["target_claim_id"]),
        "challenger_identity": str(row["challenger_identity"]),
        "status": str(row["status"]),
        "packet_hash": str(row["packet_hash"]),
        "challenge_packet": json.loads(str(row["packet_json"])),
        "response": json.loads(str(response_raw)) if response_raw else None,
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def _serialize_witness_event(row: sqlite3.Row) -> Dict[str, Any]:
    authority = json.loads(row["authority_json"]) if "authority_json" in row.keys() and row["authority_json"] else None
    return {
        **({"authority": authority} if authority is not None else {}),
        "event_id": str(row["event_id"]),
        "event_type": str(row["event_type"]),
        "actor_identity": str(row["actor_identity"]),
        "subject_type": str(row["subject_type"]),
        "subject_id": str(row["subject_id"]),
        "subject_seed_id": row["subject_seed_id"],
        "timestamp": str(row["timestamp"]),
        "payload_hash": str(row["payload_hash"]),
        "payload": json.loads(str(row["payload_json"])),
        "signature": str(row["signature"]),
        "prev_hash": str(row["prev_hash"]),
        "hash": str(row["event_hash"]),
        "event_hash": str(row["event_hash"]),
    }


def observe_standing_status(
    stored_status: str,
    expiry: Any,
    *,
    observed_at: Optional[datetime] = None,
    publication_observation: Optional[PublicationObservation] = None,
) -> Dict[str, Any]:
    """Observe current lease status without granting authority or changing history.

    Canon records remain historical canon after expiry, but their lease cannot
    provide current reliance. Missing or malformed expiry never means active.
    """
    publication = publication_observation or current_publication_observation()
    if publication is not None:
        return publication.standing(stored_status, expiry)
    now = observed_at or datetime.now(timezone.utc)
    observation = {
        "status": stored_status,
        "stored_status": stored_status,
        "status_basis": "stored",
        "observed_at": now.isoformat(),
    }
    if stored_status in {"revoked", "expired", "compost", "superseded"}:
        return observation
    try:
        expires_at = _parse_datetime(str(expiry or ""))
    except (HTTPException, ValueError, OverflowError):
        observation["status"] = "unknown"
        observation["status_basis"] = "invalid_expiry"
        return observation
    if expires_at <= now:
        observation["status"] = "expired"
        observation["status_basis"] = "expiry_observation"
    return observation


def _observe_standing(
    row: sqlite3.Row,
    *,
    include_lease: bool = True,
    observed_at: Optional[datetime] = None,
    publication_observation: Optional[PublicationObservation] = None,
) -> Dict[str, Any]:
    """Project elapsed expiry without signing events or changing stored authority."""
    item = _serialize_standing(row, include_lease=include_lease)
    item.update(observe_standing_status(item["status"], row["expiry"], observed_at=observed_at,
                                       publication_observation=publication_observation))
    return item


def _serialize_standing(row: sqlite3.Row, *, include_lease: bool = True) -> Dict[str, Any]:
    item = {
        "standing_id": str(row["standing_id"]),
        "subject_seed_id": str(row["subject_seed_id"]),
        "subject_claim_id": str(row["subject_claim_id"]),
        "scope": str(row["scope"]),
        "purpose": str(row["purpose"]),
        "status": str(row["status"]),
        "lease_hash": str(row["lease_hash"]),
        "expiry": str(row["expiry"]),
        "revoker": str(row["revoker"]),
        "challenge_path": str(row["challenge_path"]),
        "issued_by": str(row["issued_by"]),
        "issued_at": str(row["issued_at"]),
        "updated_at": str(row["updated_at"]),
    }
    if "issued_under_json" in row.keys() and row["issued_under_json"]:
        item["issued_under"] = json.loads(str(row["issued_under_json"]))
    if include_lease:
        item["standing_lease"] = json.loads(str(row["lease_json"]))
    return item


def _seed_chain(conn: sqlite3.Connection, seed_id: str) -> Dict[str, Any]:
    rows = _witness_rows(conn, seed_id=seed_id, subject_type=None, subject_id=None, limit=10000)
    return {
        "seed_id": seed_id,
        "verified": _verify_witness_rows(rows),
        "head": str(rows[-1]["event_hash"]) if rows else "genesis",
        "entries": [_serialize_witness_event(row) for row in rows],
        "events": [_serialize_witness_event(row) for row in rows],
        "state_events": [
            dict(row)
            for row in conn.execute(
                """
                SELECT event_id, seed_id, actor_identity, event_type, from_state,
                       to_state, payload_json, witness_event_id, created_at
                FROM sab_seed_events_v1
                WHERE seed_id = ?
                ORDER BY id ASC
                """,
                (seed_id,),
            ).fetchall()
        ],
    }


def _witness_rows(
    conn: sqlite3.Connection,
    *,
    seed_id: Optional[str],
    subject_type: Optional[str],
    subject_id: Optional[str],
    limit: int,
) -> List[sqlite3.Row]:
    clauses: List[str] = []
    params: List[Any] = []
    if seed_id:
        clauses.append("subject_seed_id = ?")
        params.append(seed_id)
    if subject_type:
        clauses.append("subject_type = ?")
        params.append(subject_type)
    if subject_id:
        clauses.append("subject_id = ?")
        params.append(subject_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return conn.execute(
        f"""
        SELECT *
        FROM sab_witness_events_v1
        {where}
        ORDER BY chain_scope ASC, id ASC
        LIMIT ?
        """,  # nosec B608 - where only contains fixed clauses.
        (*params, limit),
    ).fetchall()


def _verify_witness_rows(rows: List[sqlite3.Row]) -> bool:
    heads: Dict[str, str] = {}
    for row in rows:
        chain_scope = str(row["chain_scope"])
        expected_prev = heads.get(chain_scope, "genesis")
        material = {
            "event_id": row["event_id"],
            "chain_scope": row["chain_scope"],
            "event_type": row["event_type"],
            "actor_identity": row["actor_identity"],
            "subject_type": row["subject_type"],
            "subject_id": row["subject_id"],
            "subject_seed_id": row["subject_seed_id"],
            "timestamp": row["timestamp"],
            "payload_hash": row["payload_hash"],
            "payload_json": row["payload_json"],
            "signature": row["signature"],
            "prev_hash": row["prev_hash"],
        }
        if "authority_json" in row.keys() and row["authority_json"]:
            material["authority"] = json.loads(row["authority_json"])
        if str(row["prev_hash"]) != expected_prev:
            return False
        if str(row["event_hash"]) != _hash_json(material):
            return False
        heads[chain_scope] = str(row["event_hash"])
    return True


def _subject_seed_id(conn: sqlite3.Connection, subject_type: str, subject_id: str) -> Optional[str]:
    if subject_type == "seed":
        _seed_row(conn, subject_id)
        return subject_id
    if subject_type == "challenge":
        return str(_challenge_row(conn, subject_id)["target_seed_id"])
    if subject_type == "standing":
        return str(_standing_row(conn, subject_id)["subject_seed_id"])
    if subject_type == "claim":
        row = conn.execute(
            "SELECT seed_id FROM sab_seed_packets_v1 WHERE claim_id = ? ORDER BY id DESC LIMIT 1",
            (subject_id,),
        ).fetchone()
        return str(row["seed_id"]) if row is not None else None
    if subject_type == "authority_lease":
        return None
    raise HTTPException(status_code=400, detail="unsupported subject_type")


def _state_for_witness_event(event_type: str) -> Optional[str]:
    return {
        "affirm": "witnessed",
        "refuse": "challenged",
        "response": "corrected",
        "correction": "corrected",
        "standing_issued": "standing_active",
        "revoked": "revoked",
        "expired": "expired",
        "canon": "canon",
        "compost": "compost",
    }.get(event_type)


def _resolve_challenge_action(
    deps: SabSeedingDeps,
    challenge_id: str,
    payload: Dict[str, Any],
    *,
    action: str,
    challenge_status: str,
    seed_state: str,
) -> Dict[str, Any]:
    _reject_unsigned_authority_selector(payload)
    with _mutation_v1_db(deps) as conn:
        challenge = _challenge_row(conn, challenge_id)
        seed_id = str(challenge["target_seed_id"])
        seed = _seed_row(conn, seed_id)
        current_status = str(challenge["status"])
        if current_status not in OPEN_CHALLENGE_STATUSES:
            raise HTTPException(status_code=409, detail=f"challenge is already {current_status}")
        actor_identity = str(
            payload.get("actor_identity")
            or payload.get("responder_identity")
            or payload.get("reviewer_identity")
            or ""
        ).strip()
        if not actor_identity:
            raise HTTPException(status_code=400, detail="actor_identity is required")
        actor_subject = _actor_subject(conn, actor_identity)
        claimant = str(seed["claimant_identity"])
        challenger = str(challenge["challenger_identity"])
        challenger_subject = _actor_subject(conn, challenger)
        actor_ids = {actor_identity, actor_subject}
        adjudication_meta: Optional[Dict[str, Any]] = None
        if action == "respond":
            if claimant not in actor_ids:
                raise HTTPException(status_code=403, detail="only the claimant may respond to the challenge")
        else:
            if actor_ids & {claimant, challenger, challenger_subject}:
                raise HTTPException(status_code=403, detail="adjudicator must be neither claimant nor challenger")
            adjudication_meta = _adjudicator_independence(
                conn,
                adjudicator=actor_subject,
                claimant=claimant,
                challenger=challenger_subject,
            )
        created_at = str(payload.get("created_at") or datetime.now(timezone.utc).isoformat()).strip()
        body = payload.get("response") if action == "respond" else payload.get("reason")
        if body is None and action == "respond":
            body = payload.get("correction")
        body_payload = body if isinstance(body, dict) else {"value": str(body or "")}
        signature_hex = _required_str(payload, "signature")
        signature_signer = _require_actor_signer(conn, actor_identity, payload)
        body_hash = _hash_json(body_payload)
        message = {
            "kind": f"sab_challenge_{action}",
            "challenge_id": challenge_id,
            "actor_identity": actor_identity,
            "payload_sha256": body_hash,
            "created_at": created_at,
        }
        if action != "respond":
            deps.verify_agent_signature(conn, signature_signer, _canonical_bytes(message), signature_hex)
        elif not _verify_signature_with_fallback(deps, conn, signature_signer, message, signature_hex):
            legacy_message = _challenge_response_message(
                challenge_id=challenge_id,
                responder_identity=actor_identity,
                response_body=str(body or ""),
            )
            deps.verify_agent_signature(conn, signature_signer, _canonical_bytes(legacy_message), signature_hex)
            message = legacy_message
        authority = _authorize_actor(
            deps, conn, actor=actor_identity,
            action="respond_challenge" if action == "respond" else "adjudicate_challenge", seed_id=seed_id,
        )
        _sweep_challenge_deadlines(deps, conn, seed_id, authority=authority)
        challenge = _challenge_row(conn, challenge_id)
        if str(challenge["status"]) not in OPEN_CHALLENGE_STATUSES:
            raise HTTPException(status_code=409, detail="challenge deadline requires explicit advancement before further action")
        _record_signature_use(conn, signature_hex, _hash_json(message), signature_signer)
        prosecute_by = challenge["prosecute_by"]
        if action == "respond" and not prosecute_by:
            if str(challenge["status"]) == "responded":
                raise HTTPException(status_code=409, detail="Responded challenge is missing its original prosecution deadline")
            prosecute_by = _challenge_prosecute_by(json.loads(str(challenge["packet_json"])))
        conn.execute(
            """
            UPDATE sab_challenge_packets_v1
            SET status = ?, response_json = ?, prosecute_by = ?, updated_at = ?
            WHERE challenge_id = ?
            """,
            (challenge_status, _json_dumps(body_payload), prosecute_by, deps.utc_now(), challenge_id),
        )
        transition_payload = {
            "challenge_id": challenge_id,
            "action": action,
            "payload_hash": body_hash,
            "payload": body_payload,
            "authority": authority,
        }
        if adjudication_meta is not None:
            transition_payload["adjudication"] = adjudication_meta
        witness = _record_seed_transition(
            deps,
            conn,
            seed_id=seed_id,
            actor_identity=actor_identity,
            event_type="response" if action == "respond" else ("compost" if action == "sustain" else "challenge"),
            to_state=seed_state,
            payload=transition_payload,
            signature_hex=signature_hex,
        )
        deps.invalidate_web_cache()
        return {
            "challenge_id": challenge_id,
            "challenge": _serialize_challenge(_challenge_row(conn, challenge_id)),
            "response_id": witness["event_id"],
            "state": seed_state,
            "seed_id": seed_id,
            "seed_state": seed_state,
            "witness_head": witness["hash"],
        }


def _challenge_count(conn: sqlite3.Connection, seed_id: str) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM sab_challenge_packets_v1 WHERE target_seed_id = ?",
            (seed_id,),
        ).fetchone()["c"]
    )


def _pending_challenge_count(conn: sqlite3.Connection, seed_id: str) -> int:
    return int(
        conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM sab_challenge_packets_v1
            WHERE target_seed_id = ? AND status IN ('pending', 'responded')
            """,
            (seed_id,),
        ).fetchone()["c"]
    )


def _seed_witness_count(conn: sqlite3.Connection, seed_id: str) -> int:
    return int(
        conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM sab_witness_events_v1
            WHERE subject_seed_id = ? AND event_type IN ('affirm', 'refuse', 'response', 'correction')
            """,
            (seed_id,),
        ).fetchone()["c"]
    )


def _validate_standing_lease(lease: Dict[str, Any]) -> None:
    for key in ("scope", "purpose", "revoker", "challenge_path"):
        if not str(lease.get(key) or "").strip():
            raise HTTPException(status_code=400, detail=f"standing lease {key} is required")
    if not _standing_expiry(lease):
        raise HTTPException(status_code=400, detail="standing lease expiry is required")


def _standing_expiry(lease: Dict[str, Any]) -> str:
    return str(lease.get("expiry") or lease.get("expires_at") or "").strip()


def _expire_standing_if_needed(
    deps: SabSeedingDeps,
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *, authority: Dict[str, Any],
) -> sqlite3.Row:
    status_value = str(row["status"])
    if status_value in {"revoked", "expired", "compost", "canon"}:
        return row
    now = deps.key_control.observe_time() if deps.key_control is not None else datetime.now(timezone.utc)
    if _parse_datetime(str(row["expiry"])) > now:
        return row
    signature = deps.system_sign(
        {
            "kind": "sab_standing_expired",
            "standing_id": str(row["standing_id"]),
            "expiry": str(row["expiry"]),
        }
    )
    event = _record_standing_event(
        deps,
        conn,
        standing_id=str(row["standing_id"]),
        actor_identity="system",
        event_type="expired",
        to_status="expired",
        payload={"expiry": str(row["expiry"]), "authority": authority},
        signature_hex=signature,
    )
    seed_row = _seed_row(conn, str(row["subject_seed_id"]))
    if _seed_transition_allowed(str(seed_row["state"]), "expired"):
        _record_seed_transition(
            deps,
            conn,
            seed_id=str(row["subject_seed_id"]),
            actor_identity="system",
            event_type="expired",
            to_state="expired",
            payload={"standing_id": str(row["standing_id"]), "authority": authority},
            signature_hex=signature,
            precreated_witness=event,
        )
    return _standing_row(conn, str(row["standing_id"]))


def _standing_action(
    deps: SabSeedingDeps,
    standing_id: str,
    payload: Dict[str, Any],
    *,
    action: str,
    to_status: str,
    seed_state: str,
) -> Dict[str, Any]:
    _reject_unsigned_authority_selector(payload)
    with _mutation_v1_db(deps) as conn:
        standing = _standing_row(conn, standing_id)
        current_status = str(standing["status"])
        if current_status == "revoked":
            raise HTTPException(status_code=409, detail="standing is revoked")
        if current_status == "expired":
            raise HTTPException(status_code=409, detail="standing is expired")
        actor_identity = _required_str(payload, "actor_identity")
        if action == "revoke":
            revoker = str(standing["revoker"])
            issued_by = str(standing["issued_by"])
            if actor_identity not in {revoker, issued_by}:
                raise HTTPException(status_code=403, detail="actor is not standing revoker")
        created_at = _required_str(payload, "created_at")
        evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
        reason = str(payload.get("reason") or "")
        action_payload = {"reason": reason, "evidence": evidence}
        signature_hex = _required_str(payload, "signature")
        message = {
            "kind": f"sab_standing_{action}",
            "standing_id": standing_id,
            "actor_identity": actor_identity,
            "payload_sha256": _hash_json(action_payload),
            "created_at": created_at,
        }
        if action == "revalidate" and to_status == "canon":
            message["promote_to_canon"] = True
        _require_actor_signer(conn, actor_identity, payload)
        deps.verify_agent_signature(conn, actor_identity, _canonical_bytes(message), signature_hex)
        authority = _authorize_actor(
            deps, conn, actor=actor_identity,
            action="canonize_standing" if action == "revalidate" and to_status == "canon" else f"{action}_standing",
            seed_id=str(standing["subject_seed_id"]),
        )
        if action == "revalidate" and _pending_challenge_count(conn, str(standing["subject_seed_id"])) > 0:
            raise HTTPException(status_code=409, detail="Standing revalidation requires a resolved challenge path")
        standing = _expire_standing_if_needed(deps, conn, standing, authority=authority)
        if str(standing["status"]) == "expired":
            raise HTTPException(status_code=409, detail="standing is expired")
        _record_signature_use(conn, signature_hex, _hash_json(message), actor_identity)
        event_payload: Dict[str, Any] = {**action_payload, "authority": authority}
        if action == "revalidate":
            seed = _seed_row(conn, str(standing["subject_seed_id"]))
            issued_under = _independence_gate(conn, seed)
            if to_status == "canon" and issued_under["tier"] != "canon":
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "canon requires a witness quorum of >=3 cross_operator_attested witnesses "
                        "from >=3 independent operators"
                    ),
                )
            if to_status == "active" and issued_under["tier"] not in {"active", "canon"}:
                to_status = "provisional"
                seed_state = "standing_active"
            event_payload["issued_under"] = issued_under
        event_type = {
            "challenge": "challenge",
            "revoke": "revoked",
            "revalidate": "canon" if to_status == "canon" else "standing_issued",
        }[action]
        event = _record_standing_event(
            deps,
            conn,
            standing_id=standing_id,
            actor_identity=actor_identity,
            event_type=event_type,
            to_status=to_status,
            payload=event_payload,
            signature_hex=signature_hex,
        )
        _record_seed_transition(
            deps,
            conn,
            seed_id=str(standing["subject_seed_id"]),
            actor_identity=actor_identity,
            event_type=event_type,
            to_state=seed_state,
            payload={"standing_id": standing_id, **action_payload, "authority": authority},
            signature_hex=signature_hex,
            precreated_witness=event,
        )
        deps.invalidate_web_cache()
        return {
            "standing": _serialize_standing(_standing_row(conn, standing_id)),
            "seed_id": str(standing["subject_seed_id"]),
            "seed_state": seed_state,
            "witness_head": event["hash"],
        }
