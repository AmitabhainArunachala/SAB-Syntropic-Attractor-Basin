"""Explicit local review/signing ceremony for scoped operator-control evidence.

Hashes identify bytes; signatures identify accountable reviewers. Neither this
client nor a saved observation establishes external facts or current eligibility.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx

from . import operator_control as core
from .key_control import canonical_origin
from .key_control_client import (
    KeyControlClientError, PROOF_PATTERN, _binding, _identity, _time,
    load_signing_key, read_home,
)

ASSESSMENTS_PATH = "/api/operator-control/assessments"
MAX_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * MAX_BYTES
MAX_RESPONSE_SECONDS = 20


class OperatorControlClientError(RuntimeError):
    """Fixed diagnostic without reflected documents, peer bodies or key material."""


def _fail(reason: str) -> None:
    raise OperatorControlClientError(reason)


def _summary(schema: str, **fields) -> dict:
    return {
        "schema": schema, **fields, "authority_effect": "none", "standing_effect": "none",
        "effective_reliance": "unestablished", "current_use_eligible": False,
        "currentness": "requires_live_scoped_registry_evaluation",
        "evidence_truth": "not_verified_by_client",
    }


def _canonical(value, *, limit=MAX_BYTES) -> bytes:
    def walk(item, depth=0):
        if depth > 16:
            _fail("document_depth_exceeded")
        if isinstance(item, str):
            item.encode("utf-8", errors="strict")
        elif item is None or isinstance(item, bool):
            pass
        elif type(item) is int and abs(item) <= 9007199254740991:
            pass
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    _fail("string_member_required")
                walk(key, depth + 1)
                walk(child, depth + 1)
        else:
            _fail("supported_canonical_json_required")

    try:
        walk(value)
        raw = core.canonical_json_bytes(value)
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        _fail("supported_canonical_json_required")
    if len(raw) > limit:
        _fail("document_too_large")
    return raw


def _parse(raw: bytes, *, limit=MAX_BYTES) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_json_member")
            result[key] = value
        return result

    def invalid_number(_value):
        _fail("integer_json_required")

    if not 0 < len(raw) <= limit:
        _fail("document_size_invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_float=invalid_number, parse_constant=invalid_number)
        if not isinstance(value, dict):
            _fail("json_object_required")
        _canonical(value, limit=limit)
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        _fail("invalid_json_document")


def read_document(path: Path, *, limit=MAX_BYTES) -> dict:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            _fail("bounded_regular_document_required")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(8192, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(raw) != before.st_size:
            _fail("document_changed_during_read")
        return _parse(bytes(raw), limit=limit)
    except OSError:
        _fail("document_unavailable_or_unsafe")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _now(clock: Callable[[], datetime] | None = None) -> datetime:
    value = clock() if clock is not None else datetime.now(timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail("aware_local_clock_required")
    return value.astimezone(timezone.utc)


def _digest_matches(document: dict, expected: str) -> None:
    if not isinstance(expected, str) or re.fullmatch(core.HEX, expected) is None or core.hash_json(document) != expected:
        _fail("document_does_not_match_explicit_digest")


def _key_matches(key, public_key: str) -> None:
    if key.verify_key.encode().hex() != public_key:
        _fail("local_key_does_not_match_explicit_actor")


def policy_digest(policy: dict) -> dict:
    policy = core.validate_policy(_parse(_canonical(policy)))
    return _summary("sab.operator_control_client_policy.v1", policy_id=policy["policy_id"],
                    policy_sha256=core.hash_json(policy), audience=policy["audience"],
                    not_before=policy["not_before"], expires_at=policy["expires_at"],
                    reviewers=policy["reviewers"], revokers=policy["revokers"])


def material_digest(document: dict) -> dict:
    raw = _canonical(document, limit=core.MAX_DOCUMENT_BYTES)
    if not isinstance(document, dict) or not document:
        _fail("nonempty_material_object_required")
    return _summary("sab.operator_control_client_material.v1", document_sha256=core.hash_json(document),
                    canonical_bytes=len(raw))


def inspect_document(document: dict, policy: dict) -> dict:
    document = _parse(_canonical(document))
    if set(document) == {"assessment", "reviews"}:
        signed = core.validate_envelope(document, policy=policy, check_freshness=False)
        assessment = signed["assessment"]
        integrity = "valid_under_pinned_policy"
        reviews = [{"reviewer_subject_id": r["reviewer_subject_id"], "review_sha256": core.hash_json(r),
                    "findings": r["findings"]} for r in signed["reviews"]]
    else:
        assessment = core.validate_assessment(document, policy=policy, check_freshness=False)
        integrity, reviews = "reviews_not_present", []
    return _summary(
        "sab.operator_control_client_inspection.v1", assessment_id=assessment["assessment_id"],
        assessment_sha256=core.hash_json(assessment), document_sha256=core.hash_json(document),
        policy_sha256=assessment["policy_sha256"], audience=assessment["audience"],
        seed_id=assessment["seed_id"], claim_sha256=assessment["claim_sha256"], purpose=assessment["purpose"],
        issued_at=assessment["issued_at"], expires_at=assessment["expires_at"],
        participants=assessment["participants"], replaces=assessment["replaces"],
        signature_integrity=integrity, reviews=reviews,
        materials=[{"evidence_id": e["evidence_id"], "category": e["category"],
                    "source_class": e["source_class"], "subject_ids": e["subject_ids"],
                    "document_sha256": e["document_sha256"], "artifact_sha256": core.hash_json(e),
                    "observed_at": e["observed_at"], "valid_until": e["valid_until"]}
                   for e in assessment["evidence"]],
    )


def sign_review(assessment: dict, review: dict, policy: dict, signing_key, *,
                assessment_sha256: str, reviewer_id: str, utc_now=None) -> dict:
    observed = _now(utc_now)
    assessment = core.validate_assessment(_parse(_canonical(assessment)), policy=policy, observed_at=observed)
    _digest_matches(assessment, assessment_sha256)
    message = core.validate_review_message(_parse(_canonical(review)), assessment=assessment,
                                           policy=policy, observed_at=observed)
    if message["reviewer_subject_id"] != reviewer_id:
        _fail("review_does_not_match_explicit_reviewer")
    _key_matches(signing_key, message["reviewer_public_key"])
    return {**message, "signature": signing_key.sign(_canonical(message)).signature.hex()}


def assemble(assessment: dict, reviews: list[dict], policy: dict) -> dict:
    envelope = _parse(_canonical({"assessment": assessment, "reviews": reviews}))
    return core.validate_envelope(envelope, policy=policy, check_freshness=False)


def _request(origin: str, path: str, payload: dict | None, transport) -> dict:
    origin = canonical_origin(origin)
    raw = _canonical(payload) if payload is not None else None
    deadline = time.monotonic() + MAX_RESPONSE_SECONDS
    try:
        with httpx.Client(transport=transport, follow_redirects=False, trust_env=False,
                          timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            with client.stream("POST" if raw is not None else "GET", origin + path, content=raw,
                               headers={"Content-Type": "application/json", "Accept": "application/json",
                                        "Accept-Encoding": "identity"}) as response:
                if time.monotonic() >= deadline:
                    _fail("response_time_budget_exceeded")
                if not 200 <= response.status_code < 300:
                    _fail("service_rejected_operation")
                if (response.headers.get("content-encoding", "identity").lower() != "identity"
                        or response.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json"):
                    _fail("plain_json_response_required")
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() >= deadline or len(chunks) + len(chunk) > MAX_RESPONSE_BYTES:
                        _fail("response_budget_exceeded")
                    chunks.extend(chunk)
                return _parse(bytes(chunks), limit=MAX_RESPONSE_BYTES)
    except httpx.HTTPError:
        _fail("transport_failed")


def _active_key(origin: str, subject_id: str, public_key: str, transport, observed: datetime) -> None:
    # Preflight only. The effect transaction must repeat this check against current state.
    home = read_home(origin, subject_id, transport=transport)
    identity = _identity(home.get("identity"))
    binding = home.get("key_control")
    if (home.get("schema") != "sab.agent_home.v1" or home.get("identity_status") != "active"
            or identity["subject_id"] != subject_id or identity["public_key"] != public_key
            or identity["revocation_status"] != "active" or not isinstance(binding, dict)
            or not isinstance(binding.get("proof_id"), str)
            or re.fullmatch(PROOF_PATTERN, binding["proof_id"]) is None
            or _time(binding.get("proved_at")) > observed):
        _fail("current_active_key_binding_required")
    _binding(binding, subject_id=subject_id, public_key=public_key, status="active",
             proof_id=binding["proof_id"], proved_at=binding["proved_at"])


def _observation(result: dict, policy: dict, *, origin: str, assessment_id: str, assessment_sha256: str) -> dict:
    if any(name not in result for name in ("assessment", "reviews")):
        _fail("signed_assessment_observation_required")
    signed = core.validate_envelope({name: result[name] for name in ("assessment", "reviews")},
                                    policy=policy, audience=origin, check_freshness=False)
    _digest_matches(signed["assessment"], assessment_sha256)
    if (signed["assessment"]["assessment_id"] != assessment_id or result.get("assessment_id") != assessment_id
            or result.get("assessment_sha256") != assessment_sha256
            or result.get("envelope_sha256") != core.hash_json(signed)
            or result.get("authority_effect") != "none" or result.get("standing_effect") != "none"):
        _fail("observation_does_not_match_signed_assessment")
    return {**inspect_document(signed, policy), "receipt_matched": True}


def issue(origin: str, envelope: dict, policy: dict, *, transport=None, utc_now=None) -> dict:
    origin, observed = canonical_origin(origin), _now(utc_now)
    signed = core.validate_envelope(_parse(_canonical(envelope)), policy=policy, audience=origin, observed_at=observed)
    participants = {p["subject_id"]: p["public_key"] for p in signed["assessment"]["participants"]}
    participants.update({r["reviewer_subject_id"]: r["reviewer_public_key"] for r in signed["reviews"]})
    for subject_id, public_key in sorted(participants.items()):
        _active_key(origin, subject_id, public_key, transport, observed)
    # A slow preflight cannot extend the signed proposal's lifetime.
    core.validate_envelope(signed, policy=policy, audience=origin, observed_at=_now(utc_now))
    result = _request(origin, ASSESSMENTS_PATH, signed, transport)
    if any(result.get(name) != signed[name] for name in ("assessment", "reviews")):
        _fail("server_changed_submitted_assessment")
    return _observation(result, policy, origin=origin, assessment_id=signed["assessment"]["assessment_id"],
                        assessment_sha256=core.hash_json(signed["assessment"]))


def get_assessment(origin: str, assessment_id: str, assessment_sha256: str, policy: dict, *, transport=None) -> dict:
    origin = canonical_origin(origin)
    if not isinstance(assessment_id, str) or re.fullmatch(core.ASSESSMENT_ID, assessment_id) is None:
        _fail("invalid_assessment_id")
    if not isinstance(assessment_sha256, str) or re.fullmatch(core.HEX, assessment_sha256) is None:
        _fail("invalid_assessment_digest")
    core.validate_policy(policy, audience=origin)
    result = _request(origin, ASSESSMENTS_PATH + "/" + assessment_id, None, transport)
    return _observation(result, policy, origin=origin, assessment_id=assessment_id, assessment_sha256=assessment_sha256)


def submit_action(action: str, origin: str, assessment: dict, message: dict, policy: dict, signing_key, *,
                  assessment_sha256: str, actor_id: str, transport=None, utc_now=None) -> dict:
    if action not in {"challenge", "revoke"}:
        _fail("unsupported_operator_control_action")
    origin, observed = canonical_origin(origin), _now(utc_now)
    assessment = core.validate_assessment(_parse(_canonical(assessment)), policy=policy,
                                          audience=origin, check_freshness=False)
    _digest_matches(assessment, assessment_sha256)
    kind, actor = ("challenge", "challenger") if action == "challenge" else ("revocation", "revoker")
    message = getattr(core, "validate_" + kind + "_message")(
        _parse(_canonical(message)), assessment=assessment, policy=policy, observed_at=observed)
    if message[actor + "_subject_id"] != actor_id or message["audience"] != origin:
        _fail("command_does_not_match_explicit_actor_or_origin")
    _key_matches(signing_key, message[actor + "_public_key"])
    _active_key(origin, actor_id, message[actor + "_public_key"], transport, observed)
    observed = _now(utc_now)
    getattr(core, "validate_" + kind + "_message")(
        message, assessment=assessment, policy=policy, observed_at=observed)
    payload = {kind: message, "signature": signing_key.sign(_canonical(message)).signature.hex()}
    payload = getattr(core, "validate_" + kind)(payload, assessment=assessment, policy=policy, observed_at=observed)
    result = _request(origin, ASSESSMENTS_PATH + "/" + assessment["assessment_id"] + "/" + action, payload, transport)
    if (any(result.get(name) != payload[name] for name in payload)
            or result.get("event_id") != message["challenge_id" if kind == "challenge" else "revocation_id"]
            or result.get("event_sha256") != core.hash_json(payload)
            or result.get("assessment_id") != assessment["assessment_id"]
            or result.get("assessment_sha256") != assessment_sha256
            or result.get("authority_effect") != "none" or result.get("standing_effect") != "none"):
        _fail("receipt_does_not_match_signed_command")
    return _summary("sab.operator_control_client_command.v1", action=action,
                    assessment_id=assessment["assessment_id"], assessment_sha256=assessment_sha256,
                    command_sha256=core.hash_json(payload), receipt_matched=True)


def _write_new(path: Path, document: dict) -> None:
    raw = _canonical(document) + b"\n"
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
    parser = argparse.ArgumentParser(description="Inspect and sign scoped operator-control evidence; no automatic trust or enrollment.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("policy-digest").add_argument("--policy-file", type=Path, required=True)
    commands.add_parser("material-digest").add_argument("--document", type=Path, required=True)
    for name in ("inspect", "sign-review", "assemble", "issue", "get", "challenge", "revoke"):
        command = commands.add_parser(name)
        command.add_argument("--policy-file", type=Path, required=True)
        command.add_argument("--policy-sha256", required=True)
        if name != "get" and name != "assemble":
            command.add_argument("--document", type=Path, required=True)
        if name in {"sign-review", "assemble", "challenge", "revoke"}:
            command.add_argument("--assessment-file", type=Path, required=True)
        if name in {"sign-review", "challenge", "revoke", "get"}:
            command.add_argument("--assessment-sha256", required=True)
        if name in {"sign-review", "challenge", "revoke"}:
            command.add_argument("--key-file", type=Path, required=True)
            command.add_argument("--actor-id", required=True)
        if name in {"sign-review", "assemble"}:
            command.add_argument("--output", type=Path, required=True)
        if name == "assemble":
            command.add_argument("--review-file", type=Path, action="append", required=True)
        if name in {"issue", "get", "challenge", "revoke"}:
            command.add_argument("--origin", required=True)
        if name == "get":
            command.add_argument("--assessment-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "policy-digest":
            result = policy_digest(read_document(args.policy_file))
        elif args.command == "material-digest":
            result = material_digest(read_document(args.document, limit=core.MAX_DOCUMENT_BYTES))
        else:
            policy = core.load_operator_policy(args.policy_file, args.policy_sha256)
            document = read_document(args.document) if hasattr(args, "document") else None
            assessment = read_document(args.assessment_file) if hasattr(args, "assessment_file") else None
            key = load_signing_key(args.key_file) if hasattr(args, "key_file") else None
            if args.command == "inspect":
                result = inspect_document(document, policy)
            elif args.command == "sign-review":
                result = sign_review(assessment, document, policy, key,
                                     assessment_sha256=args.assessment_sha256, reviewer_id=args.actor_id)
            elif args.command == "assemble":
                if len(args.review_file) != 2:
                    _fail("exactly_two_review_files_required")
                result = assemble(assessment, [read_document(p) for p in args.review_file], policy)
            elif args.command == "issue":
                result = issue(args.origin, document, policy)
            elif args.command == "get":
                result = get_assessment(args.origin, args.assessment_id, args.assessment_sha256, policy)
            else:
                result = submit_action(args.command, args.origin, assessment, document, policy, key,
                                       assessment_sha256=args.assessment_sha256, actor_id=args.actor_id)
            if args.command in {"sign-review", "assemble"}:
                _write_new(args.output, result)
                result = _summary("sab.operator_control_client_written.v1", document_sha256=core.hash_json(result))
        sys.stdout.write(_canonical(result).decode("utf-8") + "\n")
        return 0
    except (core.OperatorControlError, OperatorControlClientError, KeyControlClientError,
            ValueError, OSError, TypeError, UnicodeError, RecursionError):
        sys.stderr.write('{"error":"operator_control_operation_refused","authority_effect":"none","standing_effect":"none"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
