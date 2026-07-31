"""Agent-readable SAB MCP tool manifest.

This module defines the intended public MCP tool surface for SAB agent seeding
v1. It is a manifest only — a stub with respect to any runtime MCP surface:

- No MCP server in this repository binds, registers, or serves these tools
  (verified 2026-07-05: no server bootstrap in connectors/, no MCP entry point
  in pyproject.toml or package.json, no MCP config referencing this module).
- The `/api/v1` routes named below ARE live in-process (mounted via
  `agora/app.py` -> `agora/sab_seeding_api.py`) with one exception:
  `GET /api/v1/authority-leases/{lease_id}` (used by `sab.lease.validate`)
  does not exist in the router as of 2026-07-05.
- `returns` lists on mutation tools are the declared contract from
  docs/lanes/sab-agent-seeding-v1/MCP_A2A_PROFILE.md; the live routes observed
  on 2026-07-05 return `witness_head` but not a top-level `witness_event_id`
  (see dogfood receipts under
  docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood/).

Runtime handlers, once an MCP server exists, should bind these names to the
canonical `/api/v1` routes.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


SECRET_HANDLING_WARNING = (
    "Never pass SAB private keys, API keys, session tokens, cookies, identity "
    "tokens, or operator secrets as MCP tool arguments. Mutation tools require "
    "signatures produced by a local signer or approved key manager."
)

MCP_TOOL_NAMES = (
    "sab.seed.submit",
    "sab.seed.status",
    "sab.seed.fetch",
    "sab.challenge.submit",
    "sab.challenge.fetch",
    "sab.witness.fetch",
    "sab.standing.search",
    "sab.standing.fetch",
    "sab.lease.validate",
)

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "sab.seed.submit",
        "kind": "mutation",
        "method": "POST",
        "endpoint": "/api/v1/seeds",
        "description": "Submit a signed sab.seed_packet.v1 into pending_seed.",
        "requires_signature": True,
        "input_schema": {
            "type": "object",
            "required": ["seed_packet"],
            "properties": {
                "seed_packet": {"$ref": "/schemas/sab.seed_packet.v1.schema.json"},
                "signed_message": {"type": "object"},
            },
            "additionalProperties": False,
        },
        "returns": [
            "accepted",
            "seed_id",
            "state",
            "spark_projection_id",
            "challenge_window_closes_at",
            "witness_event_id",
            "witness_head",
            "next_actions",
        ],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.seed.status",
        "kind": "read",
        "method": "GET",
        "endpoint": "/api/v1/seeds/{seed_id}",
        "description": "Fetch seed state, challenge window, standing refs, and projection refs.",
        "requires_signature": False,
        "input_schema": {
            "type": "object",
            "required": ["seed_id"],
            "properties": {"seed_id": {"type": "string", "minLength": 3}},
            "additionalProperties": False,
        },
        "returns": ["seed_id", "state", "challenge_window_closes_at", "packet_hash", "witness_head"],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.seed.fetch",
        "kind": "read",
        "method": "GET",
        "endpoint": "/api/v1/seeds/{seed_id}",
        "description": (
            "Fetch the canonical seed packet (evidence_bundle is nested inside "
            "seed_packet, not top-level) plus state and witness head."
        ),
        "requires_signature": False,
        "input_schema": {
            "type": "object",
            "required": ["seed_id"],
            "properties": {
                "seed_id": {"type": "string", "minLength": 3},
                "include_chain": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
        "returns": ["seed_packet", "packet_hash", "state", "witness_head"],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.challenge.submit",
        "kind": "mutation",
        "method": "POST",
        "endpoint": "/api/v1/seeds/{seed_id}/challenges",
        "description": "Submit a signed challenge packet against a seed claim.",
        "requires_signature": True,
        "input_schema": {
            "type": "object",
            "required": ["target_seed_id", "challenge_packet"],
            "properties": {
                "target_seed_id": {"type": "string", "minLength": 3},
                "challenge_packet": {"type": "object"},
                "signed_message": {"type": "object"},
            },
            "additionalProperties": False,
        },
        "returns": ["challenge_id", "target_seed_id", "state", "witness_event_id", "witness_head"],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.challenge.fetch",
        "kind": "read",
        "method": "GET",
        "endpoint": "/api/v1/challenges/{challenge_id}",
        "description": "Fetch challenge packet, status, and the claimant response (if any).",
        "requires_signature": False,
        "input_schema": {
            "type": "object",
            "required": ["challenge_id"],
            "properties": {"challenge_id": {"type": "string", "minLength": 3}},
            "additionalProperties": False,
        },
        "returns": ["challenge_packet", "status", "response", "target_seed_id"],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.witness.fetch",
        "kind": "read",
        "method": "GET",
        "endpoint": "/api/v1/witness-events/{event_id}",
        "alternate_endpoint": "/api/v1/seeds/{seed_id}/chain",
        "description": (
            "Fetch one witness event (serialized event fields at top level) or a "
            "seed witness chain segment (events/entries, head, verified)."
        ),
        "requires_signature": False,
        "input_schema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string", "minLength": 3},
                "seed_id": {"type": "string", "minLength": 3},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "anyOf": [{"required": ["event_id"]}, {"required": ["seed_id"]}],
            "additionalProperties": False,
        },
        "returns": ["event_id", "event_hash", "events", "head", "verified"],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.standing.search",
        "kind": "read",
        "method": "GET",
        "endpoint": "/api/v1/standing",
        "description": "Search standing leases by subject seed, status, or exact scope string.",
        "requires_signature": False,
        "input_schema": {
            "type": "object",
            "properties": {
                "subject": {"type": "string"},
                "status": {"type": "string"},
                "scope": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "additionalProperties": False,
        },
        "returns": ["items"],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.standing.fetch",
        "kind": "read",
        "method": "GET",
        "endpoint": "/api/v1/standing/{standing_id}",
        "description": "Fetch a standing lease and its reliance boundaries.",
        "requires_signature": False,
        "input_schema": {
            "type": "object",
            "required": ["standing_id"],
            "properties": {"standing_id": {"type": "string", "minLength": 3}},
            "additionalProperties": False,
        },
        "returns": [
            "standing_id",
            "subject_seed_id",
            "subject_claim_id",
            "scope",
            "purpose",
            "status",
            "expiry",
            "revoker",
            "challenge_path",
            "standing_lease",
        ],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
    {
        "name": "sab.lease.validate",
        "kind": "read",
        "method": "GET",
        "endpoint": "/api/v1/authority-leases/{lease_id}",
        "description": (
            "Validate authority lease scope, expiry, revoker, challenge path, and status. "
            "PLANNED / stub target: this endpoint is NOT implemented in "
            "agora/sab_seeding_api.py as of 2026-07-05 — authority leases are stored "
            "(sab_authority_leases_v1) but expose no read route."
        ),
        "requires_signature": False,
        "input_schema": {
            "type": "object",
            "required": ["lease_id", "intended_action", "intended_scope"],
            "properties": {
                "lease_id": {"type": "string", "minLength": 3},
                "intended_action": {"type": "string", "minLength": 3},
                "intended_scope": {"type": "string", "minLength": 3},
            },
            "additionalProperties": False,
        },
        "returns": [
            "valid",
            "lease_id",
            "scope",
            "expires_at",
            "revoker",
            "challenge_path",
            "warnings",
        ],
        "secret_handling": SECRET_HANDLING_WARNING,
    },
]


def list_tools() -> list[dict[str, Any]]:
    """Return a copy of the SAB MCP tool manifest."""

    return deepcopy(MCP_TOOLS)


def get_tool(name: str) -> dict[str, Any]:
    """Return one SAB MCP tool manifest entry by name."""

    for tool in MCP_TOOLS:
        if tool["name"] == name:
            return deepcopy(tool)
    raise KeyError(f"unknown SAB MCP tool: {name}")


__all__ = [
    "MCP_TOOL_NAMES",
    "MCP_TOOLS",
    "SECRET_HANDLING_WARNING",
    "get_tool",
    "list_tools",
]
