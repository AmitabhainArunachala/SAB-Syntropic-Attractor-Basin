"""Local signing and bounded transport for explicitly configured SAB authority.

Offline validation produces a proposal, never permission. Every effect still
requires the server to evaluate the recorded grant in its mutation transaction.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import httpx
from nacl.signing import SigningKey

from .authority import (
    AuthorityError,
    canonical_bytes,
    hash_json,
    load_authority_policy,
    validate_policy,
    validate_envelope,
    validate_issuer_envelope,
    validate_lease,
    validate_revocation,
    validate_revocation_message,
    validate_witness_message,
)
from .key_control import canonical_origin
from .key_control_client import (
    KeyControlClientError,
    _read_registration_file,
    _request,
    load_signing_key,
)

LEASES_PATH = "/api/v1/authority/leases"
_LEASE_ID = re.compile(r"sab_lease_[A-Za-z0-9_.:-]{3,150}\Z")
_SIGNED_FIELDS = ("lease", "issuer_signature", "issuance_witness")


class AuthorityClientError(RuntimeError):
    """A diagnostic with no reflected document, signature or key material."""


def _fail(reason: str) -> None:
    raise AuthorityClientError(reason)


def _now(clock: Callable[[], datetime] | None) -> datetime:
    value = clock() if clock is not None else datetime.now(timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail("aware_local_clock_required")
    return value.astimezone(timezone.utc)


def _intent(lease: dict, *, subject_id: str, seed_id: str, actions: list[str]) -> None:
    if (
        lease["subject_id"] != subject_id
        or lease["target_seed_id"] != seed_id
        or len(actions) != len(set(actions))
        or set(lease["allowed_actions"]) != set(actions)
    ):
        _fail("lease_does_not_match_explicit_intent")


def sign_lease(
    lease: dict, policy: dict, signing_key: SigningKey, *, subject_id: str,
    seed_id: str, actions: list[str], utc_now: Callable[[], datetime] | None = None,
) -> dict:
    """Sign a caller-selected, fully validated draft for the exact intended act."""
    lease = validate_lease(lease, policy=policy, observed_at=_now(utc_now))
    _intent(lease, subject_id=subject_id, seed_id=seed_id, actions=actions)
    if signing_key.verify_key.encode().hex() != lease["issuer_public_key"]:
        _fail("local_key_is_not_the_pinned_issuer")
    return {
        "lease": lease,
        "issuer_signature": signing_key.sign(canonical_bytes(lease)).signature.hex(),
    }


def witness_lease(
    signed_lease: dict, policy: dict, signing_key: SigningKey, *, witness_id: str,
    subject_id: str, seed_id: str, actions: list[str],
    utc_now: Callable[[], datetime] | None = None,
) -> dict:
    observed = _now(utc_now)
    signed = validate_issuer_envelope(signed_lease, policy=policy, observed_at=observed)
    lease = signed["lease"]
    _intent(lease, subject_id=subject_id, seed_id=seed_id, actions=actions)
    witness = {
        "schema": "sab.authority_issuance_witness.v1",
        "event_id": "sab_authority_witness_" + secrets.token_hex(16),
        "audience": lease["audience"],
        "policy_hash": lease["policy_hash"],
        "lease_sha256": hash_json(signed),
        "witness_id": witness_id,
        "witness_public_key": signing_key.verify_key.encode().hex(),
        "observed_at": observed.isoformat(),
    }
    if not any(
        pin["subject_id"] == witness_id and pin["public_key"] == witness["witness_public_key"]
        for pin in policy["witnesses"]
    ) or witness_id in {lease["issuer_id"], lease["subject_id"]}:
        _fail("local_key_is_not_a_distinct_pinned_witness")
    witness = validate_witness_message(
        witness, issuer_envelope=signed, policy=policy, observed_at=observed
    )
    witness["signature"] = signing_key.sign(canonical_bytes(witness)).signature.hex()
    return validate_envelope(
        {**signed, "issuance_witness": witness}, policy=policy, observed_at=observed
    )


def _call(origin: str, path: str, payload: dict | None, transport) -> dict:
    origin = canonical_origin(origin)
    with httpx.Client(
        transport=transport, follow_redirects=False, trust_env=False,
        timeout=httpx.Timeout(10.0, connect=5.0),
    ) as client:
        return _request(client, origin, path, payload)


def _verified_observation(result: dict, policy: dict, *, origin: str, lease_id: str) -> dict:
    if not isinstance(result, dict) or any(name not in result for name in _SIGNED_FIELDS):
        _fail("invalid_lease_observation")
    signed = validate_envelope(
        {name: result[name] for name in _SIGNED_FIELDS}, policy=policy,
        audience=origin, check_freshness=False,
    )
    digest = hash_json({name: signed[name] for name in ("lease", "issuer_signature")})
    if (
        signed["lease"]["lease_id"] != lease_id
        or result.get("lease_id") != lease_id
        or result.get("lease_sha256") != digest
        or result.get("envelope_sha256") != hash_json(signed)
        or result.get("authority_effect") != "none"
        or result.get("standing_effect") != "none"
        or result.get("status") not in {"active", "revoked", "expired", "unavailable", "inactive"}
    ):
        _fail("lease_observation_does_not_match_signed_record")
    return {
        "schema": "sab.authority_client_observation.v1",
        **signed,
        "lease_id": lease_id,
        "lease_sha256": digest,
        "envelope_sha256": hash_json(signed),
        "signature_integrity": "valid_under_pinned_policy",
        "reported_status": result["status"],
        "current_permission": "evaluate_at_mutation",
        "authority_effect": "none",
        "standing_effect": "none",
    }


def issue(
    origin: str, envelope: dict, policy: dict, *, transport=None,
    utc_now: Callable[[], datetime] | None = None,
) -> dict:
    origin = canonical_origin(origin)
    signed = validate_envelope(
        envelope, policy=policy, audience=origin, observed_at=_now(utc_now)
    )
    result = _call(origin, LEASES_PATH, signed, transport)
    observed = _verified_observation(result, policy, origin=origin, lease_id=signed["lease"]["lease_id"])
    if any(observed[name] != signed[name] for name in _SIGNED_FIELDS):
        _fail("server_changed_submitted_lease")
    return observed


def inspect_lease(origin: str, lease_id: str, policy: dict, *, transport=None) -> dict:
    origin = canonical_origin(origin)
    if not isinstance(lease_id, str) or not _LEASE_ID.fullmatch(lease_id):
        _fail("invalid_lease_id")
    result = _call(origin, LEASES_PATH + "/" + lease_id, None, transport)
    return _verified_observation(result, policy, origin=origin, lease_id=lease_id)


def revoke(
    origin: str, envelope: dict, policy: dict, signing_key: SigningKey, *, reason: str,
    transport=None, utc_now: Callable[[], datetime] | None = None,
) -> dict:
    origin = canonical_origin(origin)
    observed = _now(utc_now)
    signed = validate_envelope(
        envelope, policy=policy, audience=origin, check_freshness=False
    )
    lease = signed["lease"]
    if signing_key.verify_key.encode().hex() != lease["revoker_public_key"]:
        _fail("local_key_is_not_the_designated_revoker")
    command = {
        "schema": "sab.authority_revocation.v1",
        "command_id": "sab_authority_revoke_" + secrets.token_hex(16),
        "audience": origin,
        "lease_id": lease["lease_id"],
        "lease_sha256": hash_json({name: signed[name] for name in ("lease", "issuer_signature")}),
        "revoker_id": lease["revoker_id"],
        "revoker_public_key": lease["revoker_public_key"],
        "reason": reason,
        "issued_at": observed.isoformat(),
        "expires_at": (observed + timedelta(seconds=120)).isoformat(),
    }
    command = validate_revocation_message(
        command, lease_envelope=signed, observed_at=observed
    )
    payload = {"revocation": command, "signature": signing_key.sign(canonical_bytes(command)).signature.hex()}
    payload = validate_revocation(payload, lease_envelope=signed, observed_at=observed)
    result = _call(origin, LEASES_PATH + "/" + lease["lease_id"] + "/revoke", payload, transport)
    # Validate the signed receipt without promoting the server's status to permission.
    if result.get("revocation") != payload["revocation"] or result.get("signature") != payload["signature"]:
        _fail("revocation_receipt_does_not_match_command")
    if result.get("authority_effect") != "none" or result.get("standing_effect") != "none":
        _fail("unexpected_revocation_effect_claim")
    return {
        "schema": "sab.authority_client_revocation.v1",
        **payload,
        "receipt_matched": True,
        "authority_effect": "none",
        "standing_effect": "none",
    }


def _write_new(path: Path, value: dict) -> None:
    raw = canonical_bytes(value) + b"\n"
    descriptor = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        _fail("output_requires_new_regular_path")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign and inspect scoped SAB authority; keys remain local.")
    commands = parser.add_subparsers(dest="command", required=True)
    digest_command = commands.add_parser("policy-digest", help="Validate and hash a locally reviewed policy; grants no permission.")
    digest_command.add_argument("--policy-file", type=Path, required=True)
    for name in ("sign-lease", "witness", "issue", "inspect", "revoke"):
        command = commands.add_parser(name)
        command.add_argument("--policy-file", type=Path, required=True)
        command.add_argument("--policy-sha256", required=True)
        if name in {"sign-lease", "witness", "revoke"}:
            command.add_argument("--key-file", type=Path, required=True)
        if name != "inspect":
            command.add_argument("--document", type=Path, required=True)
        if name in {"sign-lease", "witness"}:
            command.add_argument("--subject-id", required=True)
            command.add_argument("--seed-id", required=True)
            command.add_argument("--action", action="append", required=True)
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--origin", required=True)
        if name == "witness":
            command.add_argument("--witness-id", required=True)
        if name == "inspect":
            command.add_argument("--lease-id", required=True)
        if name == "revoke":
            command.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "policy-digest":
            policy = validate_policy(_read_registration_file(args.policy_file))
            result = {"schema": "sab.authority_policy_digest.v1", "policy_sha256": hash_json(policy),
                      "authority_effect": "none", "standing_effect": "none"}
            sys.stdout.write(canonical_bytes(result).decode("utf-8") + "\n")
            return 0
        policy = load_authority_policy(args.policy_file, args.policy_sha256)
        document = _read_registration_file(args.document) if args.command != "inspect" else None
        key = load_signing_key(args.key_file) if hasattr(args, "key_file") else None
        if args.command in {"sign-lease", "witness"}:
            intent = {"subject_id": args.subject_id, "seed_id": args.seed_id, "actions": args.action}
            result = (
                sign_lease(document, policy, key, **intent) if args.command == "sign-lease"
                else witness_lease(document, policy, key, witness_id=args.witness_id, **intent)
            )
            _write_new(args.output, result)
            result = {"schema": "sab.authority_proposal_written.v1", "proposal_sha256": hash_json(result),
                      "authority_effect": "none", "standing_effect": "none"}
        elif args.command == "issue":
            result = issue(args.origin, document, policy)
        elif args.command == "inspect":
            result = inspect_lease(args.origin, args.lease_id, policy)
        else:
            result = revoke(args.origin, document, policy, key, reason=args.reason)
        sys.stdout.write(canonical_bytes(result).decode("utf-8") + "\n")
        return 0
    except (AuthorityError, AuthorityClientError, KeyControlClientError, ValueError, OSError):
        # Never print nested validator errors or transport bodies: those may
        # contain material that a peer deliberately put in an error response.
        sys.stderr.write('{"error":"authority_operation_refused","authority_effect":"none","standing_effect":"none"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
