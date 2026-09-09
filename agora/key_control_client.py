"""Participant-held Ed25519 keys for SAB enrollment, revocation, and rotation.

Only public registration metadata and signatures cross the HTTP boundary. A
remote challenge is checked against the participant's intended operation before
either key signs it. The returned receipt proves key control only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlencode

import httpx
from nacl.signing import SigningKey

from .key_control import (
    CHALLENGE_ID_PATTERN,
    CHALLENGE_SCHEMA,
    MAX_CHALLENGE_TTL_SECONDS,
    MESSAGE_SCHEMA,
    NONCE_PATTERN,
    KeyControlError,
    SIGNATURE_ALGORITHM,
    VERIFY_PATH,
    canonical_json_bytes,
    canonical_origin,
    prepare_identity,
)
from .sab_identity import AgentIdentityV1, subject_id_from_public_key

CHALLENGE_PATH = "/api/v1/agents/challenge"
MAX_DOCUMENT_BYTES = 65536
MAX_REQUEST_BYTES = 16384
MAX_RESPONSE_SECONDS = 20
CLIENT_CLOCK_SKEW_SECONDS = 5
PROOF_PATTERN = r"sab_kc_proof_[0-9a-f]{32}"
_ENVELOPE_FIELDS = {
    "schema",
    "message",
    "canonicalization",
    "signature_algorithm",
    "authority_effect",
    "standing_effect",
}
_MESSAGE_FIELDS = {
    "schema",
    "action",
    "audience",
    "method",
    "path",
    "challenge_id",
    "nonce",
    "issued_at",
    "expires_at",
    "subject_id",
    "public_key",
    "proposed_identity",
    "proposed_identity_sha256",
}
_RESULT_FIELDS = {
    "schema",
    "action",
    "challenge_id",
    "proof_id",
    "verified_at",
    "identity",
    "binding",
    "previous_binding",
    "authority_effect",
    "standing_effect",
}
_BINDING_FIELDS = {
    "schema",
    "subject_id",
    "public_key",
    "status",
    "proof_id",
    "proved_at",
    "successor_subject_id",
    "scope",
    "authority_effect",
    "standing_effect",
}


class KeyControlClientError(RuntimeError):
    """Safe diagnostic: never embeds a request, response, signature, or key."""

    def __init__(self, reason: str, *, status_code: int | None = None):
        self.reason = reason
        self.status_code = status_code
        super().__init__(reason)


def _fail(reason: str) -> None:
    raise KeyControlClientError(reason)


def _object(value: Any, fields: set[str] | None = None) -> dict:
    if not isinstance(value, dict) or (fields is not None and set(value) != fields):
        _fail("unexpected_document_shape")
    return value


def _json_object(raw: bytes) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("non-JSON number")

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("non-finite JSON number")
        return result

    if len(raw) > MAX_DOCUMENT_BYTES:
        _fail("document_too_large")
    try:
        return _object(
            json.loads(
                raw,
                object_pairs_hook=pairs,
                parse_constant=invalid_constant,
                parse_float=finite_float,
            )
        )
    except (ValueError, UnicodeError, RecursionError):
        _fail("invalid_json_document")


def _time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError, OverflowError):
        _fail("invalid_utc_timestamp")


def _now(utc_now: Callable[[], datetime] | None) -> datetime:
    try:
        value = utc_now() if utc_now is not None else datetime.now(timezone.utc)
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("aware clock required")
        return value.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        _fail("local_clock_unavailable")


def _public_key(signing_key: SigningKey) -> str:
    if not isinstance(signing_key, SigningKey):
        _fail("participant_signing_key_required")
    return signing_key.verify_key.encode().hex()


def load_signing_key(path: str | Path) -> SigningKey:
    """Read a private, regular, single-link 0600 seed file without following it."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size not in (64, 65, 66)
        ):
            _fail("key_file_requires_owned_regular_0600_single_link")
        raw = os.read(descriptor, 67)
        if re.fullmatch(rb"[0-9a-fA-F]{64}(?:\r?\n)?", raw) is None:
            _fail("invalid_ed25519_seed_file")
        return SigningKey(bytes.fromhex(raw.decode("ascii").strip()))
    except OSError:
        _fail("key_file_unavailable_or_unsafe")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_registration_file(path: Path) -> dict:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DOCUMENT_BYTES:
            _fail("public_registration_file_requires_bounded_regular_file")
        return _json_object(os.read(descriptor, MAX_DOCUMENT_BYTES + 1))
    except OSError:
        _fail("public_registration_file_unavailable_or_unsafe")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def generate_key_file(path: str | Path) -> dict:
    """Create an exclusive participant key file; never replace an existing path."""
    descriptor = None
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        os.fchmod(descriptor, 0o600)
        signing_key = SigningKey.generate()
        raw = signing_key.encode().hex().encode("ascii") + b"\n"
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("key write failed")
            remaining = remaining[written:]
        os.fsync(descriptor)
        public_key = _public_key(signing_key)
        return {
            "schema": "sab.local_key_created.v1",
            "public_key": public_key,
            "subject_id": subject_id_from_public_key(public_key),
            "authority_effect": "none",
            "standing_effect": "none",
        }
    except FileExistsError:
        _fail("key_file_already_exists")
    except OSError:
        _fail("key_file_creation_failed")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _registration(registration: Mapping[str, Any], public_key: str) -> dict:
    if not isinstance(registration, Mapping):
        _fail("public_registration_object_required")
    data = dict(registration)
    if "public_key" in data and data["public_key"] != public_key:
        _fail("registration_key_does_not_match_local_key")
    data["public_key"] = public_key
    try:
        encoded = json.dumps(data, allow_nan=False).encode("utf-8")
        data = _json_object(encoded)
        # The same pure normalizer validates supported public metadata locally,
        # before any network request. This timestamp is not sent or signed.
        prepare_identity(data, created_at="2000-01-01T00:00:00+00:00")
    except (KeyControlError, TypeError, ValueError, RecursionError):
        _fail("invalid_public_registration")
    return data


def _identity(value: Any) -> dict:
    identity = _object(value)
    try:
        model = AgentIdentityV1.model_validate(identity)
        normalized = model.model_dump(mode="json", by_alias=True)
    except (TypeError, ValueError):
        _fail("invalid_identity_document")
    if set(identity) != set(normalized):
        _fail("incomplete_identity_document")
    _time(identity["created_at"])
    if not re.fullmatch(r"[0-9a-f]{64}", identity["public_key"]):
        _fail("noncanonical_identity_public_key")
    refs = identity["evidence_refs"]
    if (
        not isinstance(refs, list)
        or len(refs) > 32
        or any(not isinstance(ref, str) or not ref.strip() or len(ref) > 512 for ref in refs)
    ):
        _fail("invalid_identity_evidence_references")
    return identity


def _intended_identity(identity: dict, registration: dict, issued_at: str) -> None:
    try:
        expected = prepare_identity(registration, created_at=issued_at)
    except (KeyControlError, TypeError, ValueError):
        _fail("invalid_public_registration")
    # An existing identity keeps its original server-owned creation time and
    # bounded evidence references. All participant metadata must match exactly.
    for field in expected:
        if field not in {"created_at", "evidence_refs"} and identity.get(field) != expected[field]:
            _fail("challenge_changes_registration")
    if _time(identity["created_at"]) > _time(issued_at):
        _fail("identity_created_after_challenge")


def _challenge(
    envelope: dict,
    *,
    action: str,
    origin: str,
    subject_id: str,
    public_key: str,
    registration: dict | None,
    observed_at: datetime,
) -> dict:
    _object(envelope, _ENVELOPE_FIELDS)
    if (
        envelope["schema"] != CHALLENGE_SCHEMA
        or envelope["canonicalization"] != "json-sort-keys-compact-v1"
        or envelope["signature_algorithm"] != SIGNATURE_ALGORITHM
        or envelope["authority_effect"] != "none"
        or envelope["standing_effect"] != "none"
    ):
        _fail("unsupported_challenge_contract")
    message = _object(envelope["message"], _MESSAGE_FIELDS)
    expected = {
        "schema": MESSAGE_SCHEMA,
        "action": action,
        "audience": origin,
        "method": "POST",
        "path": VERIFY_PATH,
        "subject_id": subject_id,
        "public_key": public_key,
    }
    if any(message[key] != value for key, value in expected.items()):
        _fail("challenge_does_not_match_intent")
    for field, pattern in (("challenge_id", CHALLENGE_ID_PATTERN), ("nonce", NONCE_PATTERN)):
        if not isinstance(message[field], str) or re.fullmatch(pattern, message[field]) is None:
            _fail("invalid_challenge_identifier")
    issued = _time(message["issued_at"])
    expiry = _time(message["expires_at"])
    if not 0 < (expiry - issued).total_seconds() <= MAX_CHALLENGE_TTL_SECONDS:
        _fail("invalid_challenge_lifetime")
    if issued > observed_at + timedelta(seconds=CLIENT_CLOCK_SKEW_SECONDS):
        _fail("challenge_issued_in_future")
    if observed_at >= expiry:
        _fail("challenge_expired")
    if registration is None:
        if (
            message["proposed_identity"] is not None
            or message["proposed_identity_sha256"] is not None
        ):
            _fail("revocation_cannot_register_identity")
    else:
        identity = _identity(message["proposed_identity"])
        _intended_identity(identity, registration, message["issued_at"])
        digest = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        if message["proposed_identity_sha256"] != digest:
            _fail("proposed_identity_digest_mismatch")
    return message


def _binding(
    value: Any,
    *,
    subject_id: str,
    public_key: str,
    status: str,
    proof_id: str,
    proved_at: str,
    successor: str | None = None,
) -> dict:
    binding = _object(value, _BINDING_FIELDS)
    expected = {
        "schema": "sab.key_control_binding.v1",
        "subject_id": subject_id,
        "public_key": public_key,
        "status": status,
        "proof_id": proof_id,
        "proved_at": proved_at,
        "successor_subject_id": successor,
        "scope": "key_control_only",
        "authority_effect": "none",
        "standing_effect": "none",
    }
    if binding != expected:
        _fail("unexpected_key_control_binding")
    return binding


def _receipt(result: dict, message: dict) -> dict:
    _object(result, _RESULT_FIELDS)
    if (
        result["schema"] != "sab.key_control_result.v1"
        or result["action"] != message["action"]
        or result["challenge_id"] != message["challenge_id"]
        or result["authority_effect"] != "none"
        or result["standing_effect"] != "none"
        or not isinstance(result["proof_id"], str)
        or re.fullmatch(PROOF_PATTERN, result["proof_id"]) is None
    ):
        _fail("unexpected_key_control_receipt")
    verified_at = _time(result["verified_at"])
    if not _time(message["issued_at"]) <= verified_at < _time(message["expires_at"]):
        _fail("receipt_outside_challenge_lifetime")
    identity = _identity(result["identity"])
    action = message["action"]
    if action == "revoke":
        if (
            identity["subject_id"] != message["subject_id"]
            or identity["public_key"] != message["public_key"]
            or identity["revocation_status"] != "revoked"
        ):
            _fail("unexpected_revoked_identity")
    elif identity != message["proposed_identity"]:
        _fail("receipt_changes_signed_identity")
    _binding(
        result["binding"],
        subject_id=identity["subject_id"],
        public_key=identity["public_key"],
        status="revoked" if action == "revoke" else "active",
        proof_id=result["proof_id"],
        proved_at=result["verified_at"],
    )
    if action == "rotate":
        _binding(
            result["previous_binding"],
            subject_id=message["subject_id"],
            public_key=message["public_key"],
            status="superseded",
            proof_id=result["proof_id"],
            proved_at=result["verified_at"],
            successor=identity["subject_id"],
        )
    elif result["previous_binding"] is not None:
        _fail("unexpected_previous_binding")
    return result


def _request(client: httpx.Client, origin: str, path: str, payload: dict | None = None) -> dict:
    raw = canonical_json_bytes(payload) if payload is not None else None
    if raw is not None and len(raw) > MAX_REQUEST_BYTES:
        _fail("request_too_large")
    deadline = time.monotonic() + MAX_RESPONSE_SECONDS
    try:
        with client.stream(
            "POST" if payload is not None else "GET",
            origin + path,
            content=raw,
            follow_redirects=False,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
        ) as response:
            if time.monotonic() >= deadline:
                _fail("response_time_budget_exceeded")
            if 300 <= response.status_code < 400:
                _fail("redirect_refused")
            if not 200 <= response.status_code < 300:
                raise KeyControlClientError(
                    "service_rejected_operation", status_code=response.status_code
                )
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                _fail("encoded_response_refused")
            if (
                response.headers.get("content-type", "").split(";", 1)[0].strip()
                != "application/json"
            ):
                _fail("json_response_required")
            chunks = bytearray()
            # Check each transport chunk. Aggregating into fixed-size chunks
            # first would let a slow peer keep a read open by trickling bytes.
            # The HTTP read timeout bounds a blocked next chunk separately.
            for chunk in response.iter_bytes():
                if time.monotonic() >= deadline:
                    _fail("response_time_budget_exceeded")
                if len(chunks) + len(chunk) > MAX_DOCUMENT_BYTES:
                    _fail("response_too_large")
                chunks.extend(chunk)
            return _json_object(bytes(chunks))
    except httpx.HTTPError:
        _fail("transport_failed")


def _operate(
    origin: str,
    action: str,
    signing_key: SigningKey,
    *,
    subject_id: str | None = None,
    registration: Mapping[str, Any] | None = None,
    new_signing_key: SigningKey | None = None,
    transport: httpx.BaseTransport | None = None,
    utc_now: Callable[[], datetime] | None = None,
) -> dict:
    try:
        origin = canonical_origin(origin)
    except (TypeError, ValueError):
        _fail("https_or_loopback_origin_required")
    public_key = _public_key(signing_key)
    if action == "register":
        registration = _registration(registration, public_key)
        subject_id = registration.get("subject_id") or subject_id_from_public_key(public_key)
    elif action == "rotate":
        successor_key = _public_key(new_signing_key)
        if successor_key == public_key:
            _fail("rotation_requires_distinct_successor_key")
        registration = _registration(registration, successor_key)
    if (
        not isinstance(subject_id, str)
        or re.fullmatch(r"agent_[A-Za-z0-9_.:-]{2,154}", subject_id) is None
    ):
        _fail("valid_subject_id_required")
    payload = {"action": action}
    if action != "register":
        payload["subject_id"] = subject_id
    if registration is not None:
        payload["registration"] = registration
    with httpx.Client(
        transport=transport,
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(10.0),
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
    ) as client:
        envelope = _request(client, origin, CHALLENGE_PATH, payload)
        message = _challenge(
            envelope,
            action=action,
            origin=origin,
            subject_id=subject_id,
            public_key=public_key,
            registration=registration,
            observed_at=_now(utc_now),
        )
        signed_message = canonical_json_bytes(message)
        verification = {
            "challenge_id": message["challenge_id"],
            "signature": signing_key.sign(signed_message).signature.hex(),
        }
        if action == "rotate":
            verification["successor_signature"] = new_signing_key.sign(
                signed_message
            ).signature.hex()
        return _receipt(_request(client, origin, VERIFY_PATH, verification), message)


def enroll(
    origin: str, registration: Mapping[str, Any], signing_key: SigningKey, **options
) -> dict:
    """Enroll exact public metadata after proving control of the participant key."""
    return _operate(origin, "register", signing_key, registration=registration, **options)


def revoke(origin: str, subject_id: str, signing_key: SigningKey, **options) -> dict:
    """Revoke the current key binding using that participant-held key."""
    return _operate(origin, "revoke", signing_key, subject_id=subject_id, **options)


def rotate(
    origin: str,
    subject_id: str,
    registration: Mapping[str, Any],
    signing_key: SigningKey,
    new_signing_key: SigningKey,
    **options,
) -> dict:
    """Both old and new keys approve the same successor registration and challenge."""
    return _operate(
        origin,
        "rotate",
        signing_key,
        subject_id=subject_id,
        registration=registration,
        new_signing_key=new_signing_key,
        **options,
    )


def read_home(
    origin: str, subject_id: str, *, transport: httpx.BaseTransport | None = None
) -> dict:
    """Read the selected origin without redirects before deciding whether to enroll."""
    try:
        origin = canonical_origin(origin)
    except (TypeError, ValueError):
        _fail("https_or_loopback_origin_required")
    if (
        not isinstance(subject_id, str)
        or re.fullmatch(r"agent_[A-Za-z0-9_.:-]{2,154}", subject_id) is None
    ):
        _fail("valid_subject_id_required")
    with httpx.Client(
        transport=transport,
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(10.0),
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
    ) as client:
        return _request(
            client, origin, "/api/v1/agents/me/home?" + urlencode({"subject_id": subject_id})
        )


def active_binding_matches(
    home: Mapping[str, Any],
    registration: Mapping[str, Any],
    signing_key: SigningKey,
) -> bool:
    """Check a service home response before skipping repeated enrollment.

    This does not independently authenticate a server receipt or grant standing;
    callers must obtain the response from their selected service origin.
    """
    try:
        public_key = _public_key(signing_key)
        desired = _registration(registration, public_key)
        identity = _identity(home.get("identity"))
        _intended_identity(identity, desired, identity["created_at"])
        binding = _object(home.get("key_control"), _BINDING_FIELDS)
        if (
            identity["revocation_status"] != "active"
            or not isinstance(binding["proof_id"], str)
            or re.fullmatch(PROOF_PATTERN, binding["proof_id"]) is None
        ):
            return False
        _time(binding["proved_at"])
        _binding(
            binding,
            subject_id=identity["subject_id"],
            public_key=public_key,
            status="active",
            proof_id=binding["proof_id"],
            proved_at=binding["proved_at"],
        )
        return True
    except (KeyControlClientError, AttributeError, TypeError, ValueError):
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="Create a new exclusive 0600 local seed file")
    keygen.add_argument("--key-file", required=True, type=Path, help="Parent directory must exist")
    for name in ("enroll", "revoke", "rotate"):
        command = commands.add_parser(name)
        command.add_argument(
            "--origin", required=True, help="HTTPS service origin or loopback HTTP"
        )
        command.add_argument("--key-file", required=True, type=Path)
        if name in ("enroll", "rotate"):
            command.add_argument(
                "--registration", required=True, type=Path, help="Public metadata JSON"
            )
        if name in ("revoke", "rotate"):
            command.add_argument("--subject-id", required=True)
        if name == "rotate":
            command.add_argument("--new-key-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            result = generate_key_file(args.key_file)
        else:
            signing_key = load_signing_key(args.key_file)
            if args.command in ("enroll", "rotate"):
                registration = _read_registration_file(args.registration)
            if args.command == "enroll":
                result = enroll(args.origin, registration, signing_key)
            elif args.command == "revoke":
                result = revoke(args.origin, args.subject_id, signing_key)
            else:
                result = rotate(
                    args.origin,
                    args.subject_id,
                    registration,
                    signing_key,
                    load_signing_key(args.new_key_file),
                )
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except KeyControlClientError as exc:
        error = {"error": exc.reason}
        if exc.status_code is not None:
            error["http_status"] = exc.status_code
        print(json.dumps(error, sort_keys=True), file=sys.stderr)
        return 1
    except OSError:
        print('{"error": "public_registration_file_unavailable"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
