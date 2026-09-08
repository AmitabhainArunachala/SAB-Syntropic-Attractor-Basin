"""Explicitly provisioned, signed and witnessed local SAB permissions.

A key-control proof is not a grant. A grant is usable only while its exact
stored signatures, configured policy, active key bindings, resource, action,
guarded local time and revocation history all agree. Read observations and
cryptographic validation helpers never confer authority by themselves.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .key_control import KeyControlError, KeyControlService, canonical_origin
from .sab_identity import canonical_json_bytes, verify_ed25519_signature

POLICY_SCHEMA = "sab.authority_policy.v1"
LEASE_SCHEMA = "sab.authority_lease.v2"
WITNESS_SCHEMA = "sab.authority_issuance_witness.v1"
REVOCATION_SCHEMA = "sab.authority_revocation.v1"
MAX_POLICY_BYTES = 65536
MAX_ENVELOPE_BYTES = 65536
MAX_STORED_GRANTS = 10000
MAX_STORED_EVENTS = 20000
MAX_GRANTS_PER_SUBJECT = 100
MAX_FRESHNESS_SECONDS = 120
MAX_LEASE_TTL_SECONDS = 31 * 24 * 60 * 60
ACTION_VOCABULARY = frozenset({
    "submit_seed", "correct_seed", "withdraw_seed", "submit_challenge",
    "respond_challenge", "adjudicate_challenge", "submit_witness_event",
    "request_standing_review", "challenge_standing", "revoke_standing",
    "revalidate_standing", "canonize_standing", "advance_deadlines", "challenge_authority",
})
SUBJECT_PATTERN = r"agent_[A-Za-z0-9_.:-]{2,154}"
LEASE_ID_PATTERN = r"sab_lease_[A-Za-z0-9_.:-]{3,128}"
SEED_ID_PATTERN = r"sab_seed_[A-Za-z0-9_.:-]{3,128}"
EVENT_ID_PATTERN = r"sab_[A-Za-z0-9_.:-]{3,150}"
HEX_KEY_PATTERN = r"[0-9a-f]{64}"
HEX_SIGNATURE_PATTERN = r"[0-9a-f]{128}"
UTC_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)"
_POLICY_FIELDS = frozenset({
    "schema", "audience", "policy_id", "not_before", "expires_at", "issuers", "witnesses", "revokers",
})
_PIN_FIELDS = frozenset({"subject_id", "public_key"})
_ISSUER_FIELDS = _PIN_FIELDS | {
    "allowed_actions", "allowed_seed_ids", "all_seeds", "max_ttl_seconds", "revoker_ids",
}
_LEASE_FIELDS = frozenset({
    "schema", "lease_id", "audience", "policy_hash", "subject_id", "subject_public_key",
    "issuer_id", "issuer_public_key", "target_seed_id", "purpose", "scope", "allowed_actions",
    "forbidden_actions", "allowed_reliance", "forbidden_reliance", "issued_at", "expires_at",
    "revoker_id", "revoker_public_key", "challenge_path", "evidence_refs",
})
_WITNESS_FIELDS = frozenset({
    "schema", "event_id", "audience", "policy_hash", "lease_sha256", "witness_id",
    "witness_public_key", "observed_at", "signature",
})
_REVOCATION_FIELDS = frozenset({
    "schema", "command_id", "audience", "lease_id", "lease_sha256", "revoker_id",
    "revoker_public_key", "reason", "issued_at", "expires_at",
})
_REFERENCE_FIELDS = frozenset({
    "lease_ref", "lease_id", "scope", "expires_at", "revoker", "challenge_path",
})
_TABLES = ("sab_authority_grants_v2", "sab_authority_events_v2")


class AuthorityError(Exception):
    """A bounded HTTP-safe error; no caller bytes appear in its text."""

    def __init__(self, code: str, status: int, detail: str):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


def _invalid(kind: str = "lease") -> AuthorityError:
    return AuthorityError(f"invalid_authority_{kind}", 400, "Authority request fields are invalid.")


def _inconsistent() -> AuthorityError:
    return AuthorityError("authority_inconsistent", 409, "The recorded grant and signed history do not agree.")


def _conflict() -> AuthorityError:
    return AuthorityError("authority_conflict", 409, "An immutable authority identifier already has different content.")


def _required() -> AuthorityError:
    return AuthorityError("authority_required", 428, "An explicitly issued grant covering this action and seed is required.")


def canonical_bytes(value: Any) -> bytes:
    """Canonical signing bytes; callers must separately validate the contract."""
    return canonical_json_bytes(value)


def hash_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _strict_json(raw: str | bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field.")
            result[key] = value
        return result

    def invalid_number(value):
        raise ValueError("Only finite JSON values are allowed.")

    # Every numeric field in this protocol is an integer. Reject decimal JSON
    # before parsing, including overflowing exponents, instead of coercing it.
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_number, parse_float=invalid_number)


def _copy_input(value: Any, *, limit: int, kind: str) -> dict[str, Any]:
    try:
        encoded = canonical_bytes(value)
        if len(encoded) > limit:
            raise ValueError("Oversized JSON.")
        copied = _strict_json(encoded)
        if not isinstance(copied, dict):
            raise ValueError("An object is required.")
        return copied
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError) as exc:
        raise _invalid(kind) from exc


def _closed(value: Any, fields: frozenset[str] | set[str], kind: str) -> None:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise _invalid(kind)


def _match(value: Any, pattern: str, kind: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise _invalid(kind)
    return value


def _text(value: Any, kind: str, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise _invalid(kind)
    return value


def _strings(value: Any, kind: str, *, minimum: int = 0, maximum: int = 64, item_limit: int = 512,
             pattern: str | None = None, vocabulary: frozenset[str] | None = None) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise _invalid(kind)
    for item in value:
        _text(item, kind, item_limit)
        if pattern is not None:
            _match(item, pattern, kind)
        if vocabulary is not None and item not in vocabulary:
            raise _invalid(kind)
    if len(set(value)) != len(value):
        raise _invalid(kind)
    return value


def _utc(value: Any, kind: str) -> datetime:
    _match(value, UTC_PATTERN, kind)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() != timedelta(0):
            raise ValueError("UTC is required.")
        return parsed
    except (ValueError, TypeError, OverflowError) as exc:
        raise _invalid(kind) from exc


def _observation(value: datetime | str | None, kind: str) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, str):
        return _utc(value, kind)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise _invalid(kind)
    return value


def _audience(value: Any, expected: str | None, kind: str) -> str:
    try:
        if not isinstance(value, str) or canonical_origin(value) != value:
            raise ValueError("Canonical origin required.")
        if expected is not None and value != expected:
            raise ValueError("Audience mismatch.")
        return value
    except (ValueError, TypeError) as exc:
        raise _invalid(kind) from exc


def validate_policy(policy: Any, audience: str | None = None) -> dict[str, Any]:
    """Validate pinned local configuration, without claiming it is authoritative."""
    value = _copy_input(policy, limit=MAX_POLICY_BYTES, kind="policy")
    _closed(value, _POLICY_FIELDS, "policy")
    if value["schema"] != POLICY_SCHEMA:
        raise _invalid("policy")
    _audience(value["audience"], audience, "policy")
    _match(value["policy_id"], EVENT_ID_PATTERN, "policy")
    if _utc(value["not_before"], "policy") >= _utc(value["expires_at"], "policy"):
        raise _invalid("policy")
    pins: dict[str, str] = {}
    key_subjects: dict[str, str] = {}
    role_subjects: dict[str, set[str]] = {}
    for role in ("issuers", "witnesses", "revokers"):
        entries = value[role]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
            raise _invalid("policy")
        subjects: set[str] = set()
        for entry in entries:
            _closed(entry, _ISSUER_FIELDS if role == "issuers" else _PIN_FIELDS, "policy")
            subject = _match(entry["subject_id"], SUBJECT_PATTERN, "policy")
            key = _match(entry["public_key"], HEX_KEY_PATTERN, "policy")
            if subject in subjects or pins.get(subject, key) != key or key_subjects.get(key, subject) != subject:
                raise _invalid("policy")
            subjects.add(subject)
            pins[subject] = key
            key_subjects[key] = subject
            if role == "issuers":
                _strings(entry["allowed_actions"], "policy", minimum=1, vocabulary=ACTION_VOCABULARY)
                if type(entry["all_seeds"]) is not bool:
                    raise _invalid("policy")
                _strings(entry["allowed_seed_ids"], "policy", minimum=0 if entry["all_seeds"] else 1,
                         maximum=0 if entry["all_seeds"] else 256, pattern=SEED_ID_PATTERN)
                if type(entry["max_ttl_seconds"]) is not int or not 1 <= entry["max_ttl_seconds"] <= MAX_LEASE_TTL_SECONDS:
                    raise _invalid("policy")
                _strings(entry["revoker_ids"], "policy", minimum=1, maximum=32, pattern=SUBJECT_PATTERN)
        role_subjects[role] = subjects
    if role_subjects["issuers"] & role_subjects["witnesses"]:
        raise _invalid("policy")
    for issuer in value["issuers"]:
        if not set(issuer["revoker_ids"]) <= role_subjects["revokers"]:
            raise _invalid("policy")
    return value


def load_authority_policy(path: str | os.PathLike[str] | None, expected_sha256: str | None) -> dict[str, Any] | None:
    """Read an explicit owned policy file and verify its out-of-band digest."""
    if path is None and expected_sha256 is None:
        return None
    if path is None or expected_sha256 is None:
        raise ValueError("Authority policy path and canonical SHA256 must both be configured.")
    fd = None
    try:
        _match(expected_sha256, HEX_KEY_PATTERN, "policy")
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("Safe policy file opening is unavailable.")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_mode & 0o022:
            raise ValueError("Unsafe policy file.")
        if not 1 <= before.st_size <= MAX_POLICY_BYTES:
            raise ValueError("Invalid policy size.")
        raw = bytearray()
        while len(raw) <= MAX_POLICY_BYTES:
            part = os.read(fd, min(8192, MAX_POLICY_BYTES + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(fd)
        if len(raw) > MAX_POLICY_BYTES or (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode
        ):
            raise ValueError("Policy changed during observation.")
        policy = validate_policy(_strict_json(bytes(raw)))
        if hash_json(policy) != expected_sha256:
            raise ValueError("Policy digest mismatch.")
        return policy
    except (OSError, ValueError, TypeError, AuthorityError, RecursionError, UnicodeError) as exc:
        raise ValueError("Authority policy must be an owned regular protected file with its exact canonical SHA256.") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _pin(policy: dict[str, Any], role: str, subject_id: str, key: str, kind: str) -> dict[str, Any]:
    for pin in policy[role]:
        if pin["subject_id"] == subject_id and pin["public_key"] == key:
            return pin
    raise AuthorityError("authority_policy_denied", 403, "The signed grant is outside the configured issuer policy.")


def validate_lease(lease: Any, *, policy: Any, audience: str | None = None,
                   observed_at: datetime | str | None = None, check_freshness: bool = True) -> dict[str, Any]:
    """Validate lease metadata and root bounds; this does not verify a signature."""
    policy = validate_policy(policy, audience)
    value = _copy_input(lease, limit=MAX_ENVELOPE_BYTES, kind="lease")
    _closed(value, _LEASE_FIELDS, "lease")
    if value["schema"] != LEASE_SCHEMA or value["policy_hash"] != hash_json(policy):
        raise _invalid()
    _audience(value["audience"], policy["audience"], "lease")
    _match(value["lease_id"], LEASE_ID_PATTERN, "lease")
    _match(value["target_seed_id"], SEED_ID_PATTERN, "lease")
    for role in ("subject", "issuer", "revoker"):
        _match(value[f"{role}_id"], SUBJECT_PATTERN, "lease")
        _match(value[f"{role}_public_key"], HEX_KEY_PATTERN, "lease")
    if value["subject_id"] == value["issuer_id"] or value["subject_public_key"] == value["issuer_public_key"]:
        raise _invalid()
    issuer = _pin(policy, "issuers", value["issuer_id"], value["issuer_public_key"], "lease")
    _pin(policy, "revokers", value["revoker_id"], value["revoker_public_key"], "lease")
    if value["revoker_id"] not in issuer["revoker_ids"]:
        raise _invalid()
    _text(value["purpose"], "lease", 512)
    _text(value["scope"], "lease", 2048)
    allowed = _strings(value["allowed_actions"], "lease", minimum=1, vocabulary=ACTION_VOCABULARY)
    forbidden = _strings(value["forbidden_actions"], "lease", vocabulary=ACTION_VOCABULARY)
    if set(allowed) & set(forbidden) or not set(allowed) <= set(issuer["allowed_actions"]):
        raise _invalid()
    if not issuer["all_seeds"] and value["target_seed_id"] not in issuer["allowed_seed_ids"]:
        raise AuthorityError("authority_policy_denied", 403, "The signed grant is outside the configured issuer policy.")
    _strings(value["allowed_reliance"], "lease", maximum=0)
    _strings(value["forbidden_reliance"], "lease")
    _strings(value["evidence_refs"], "lease")
    if value["challenge_path"] != f"/api/v1/authority/leases/{value['lease_id']}/challenges":
        raise _invalid()
    issued = _utc(value["issued_at"], "lease")
    expires = _utc(value["expires_at"], "lease")
    if not (
        _utc(policy["not_before"], "policy") <= issued < expires <= _utc(policy["expires_at"], "policy")
        and (expires - issued).total_seconds() <= issuer["max_ttl_seconds"]
    ):
        raise _invalid()
    if check_freshness:
        now = _observation(observed_at, "lease")
        if not issued <= now < expires or (now - issued).total_seconds() > MAX_FRESHNESS_SECONDS:
            raise AuthorityError("authority_issuance_stale", 410, "The issuance interval is not current.")
    return value


def validate_issuer_envelope(payload: Any, *, policy: Any, audience: str | None = None,
                             observed_at: datetime | str | None = None,
                             check_freshness: bool = True) -> dict[str, Any]:
    """Check an issuer's actual signature; the result is not a grant of authority."""
    value = _copy_input(payload, limit=MAX_ENVELOPE_BYTES, kind="lease")
    _closed(value, {"lease", "issuer_signature"}, "lease")
    lease = validate_lease(value["lease"], policy=policy, audience=audience,
                           observed_at=observed_at, check_freshness=check_freshness)
    _match(value["issuer_signature"], HEX_SIGNATURE_PATTERN, "lease")
    if not verify_ed25519_signature(lease["issuer_public_key"], canonical_bytes(lease), value["issuer_signature"]):
        raise AuthorityError("authority_signature_invalid", 403, "An authority signature does not verify.")
    return value


def validate_envelope(payload: Any, *, policy: Any, audience: str | None = None,
                       observed_at: datetime | str | None = None,
                       check_freshness: bool = True) -> dict[str, Any]:
    """Validate both signatures and signed metadata, without querying authority."""
    value = _copy_input(payload, limit=MAX_ENVELOPE_BYTES, kind="lease")
    _closed(value, {"lease", "issuer_signature", "issuance_witness"}, "lease")
    policy = validate_policy(policy, audience)
    issuer_envelope = validate_issuer_envelope(
        {"lease": value["lease"], "issuer_signature": value["issuer_signature"]}, policy=policy,
        audience=audience, observed_at=observed_at, check_freshness=check_freshness,
    )
    witness = value["issuance_witness"]
    _closed(witness, _WITNESS_FIELDS, "witness")
    _match(witness["signature"], HEX_SIGNATURE_PATTERN, "witness")
    unsigned = validate_witness_message(
        {key: item for key, item in witness.items() if key != "signature"},
        issuer_envelope=issuer_envelope, policy=policy, audience=audience,
        observed_at=observed_at, check_freshness=check_freshness,
    )
    if not verify_ed25519_signature(witness["witness_public_key"], canonical_bytes(unsigned), witness["signature"]):
        raise AuthorityError("authority_signature_invalid", 403, "An authority signature does not verify.")
    return value


def validate_witness_message(witness_without_signature: Any, *, issuer_envelope: Any, policy: Any,
                              audience: str | None = None, observed_at: datetime | str | None = None,
                              check_freshness: bool = True) -> dict[str, Any]:
    """Validate exact issuance observation metadata before a witness signs it."""
    policy = validate_policy(policy, audience)
    issuer_envelope = validate_issuer_envelope(issuer_envelope, policy=policy, audience=audience,
                                               observed_at=observed_at, check_freshness=check_freshness)
    lease = issuer_envelope["lease"]
    witness = _copy_input(witness_without_signature, limit=MAX_ENVELOPE_BYTES, kind="witness")
    _closed(witness, _WITNESS_FIELDS - {"signature"}, "witness")
    if witness["schema"] != WITNESS_SCHEMA or witness["policy_hash"] != lease["policy_hash"]:
        raise _invalid("witness")
    _audience(witness["audience"], lease["audience"], "witness")
    _match(witness["event_id"], EVENT_ID_PATTERN, "witness")
    _match(witness["witness_id"], SUBJECT_PATTERN, "witness")
    _match(witness["witness_public_key"], HEX_KEY_PATTERN, "witness")
    if witness["lease_sha256"] != hash_json(issuer_envelope):
        raise _invalid("witness")
    _pin(policy, "witnesses", witness["witness_id"], witness["witness_public_key"], "witness")
    if (
        witness["witness_id"] in {lease["subject_id"], lease["issuer_id"]}
        or witness["witness_public_key"] in {lease["subject_public_key"], lease["issuer_public_key"]}
    ):
        raise _invalid("witness")
    observed = _utc(witness["observed_at"], "witness")
    if not _utc(lease["issued_at"], "lease") <= observed < _utc(lease["expires_at"], "lease"):
        raise _invalid("witness")
    if check_freshness:
        now = _observation(observed_at, "witness")
        if observed > now or (now - observed).total_seconds() > MAX_FRESHNESS_SECONDS:
            raise AuthorityError("authority_issuance_stale", 410, "The issuance interval is not current.")
    return witness


def validate_revocation(payload: Any, *, lease_envelope: dict[str, Any],
                          observed_at: datetime | str | None = None,
                          check_freshness: bool = True) -> dict[str, Any]:
    """Validate a revocation signature against already validated immutable grant bytes."""
    value = _copy_input(payload, limit=MAX_ENVELOPE_BYTES, kind="revocation")
    _closed(value, {"revocation", "signature"}, "revocation")
    command = validate_revocation_message(value["revocation"], lease_envelope=lease_envelope,
                                           observed_at=observed_at, check_freshness=check_freshness)
    _match(value["signature"], HEX_SIGNATURE_PATTERN, "revocation")
    if not verify_ed25519_signature(command["revoker_public_key"], canonical_bytes(command), value["signature"]):
        raise AuthorityError("authority_signature_invalid", 403, "An authority signature does not verify.")
    return value


def validate_revocation_message(revocation: Any, *, lease_envelope: dict[str, Any],
                                 observed_at: datetime | str | None = None,
                                 check_freshness: bool = True) -> dict[str, Any]:
    """Validate a designated retirement command before its key holder signs it."""
    command = _copy_input(revocation, limit=MAX_ENVELOPE_BYTES, kind="revocation")
    _closed(command, _REVOCATION_FIELDS, "revocation")
    lease = lease_envelope["lease"]
    if command["schema"] != REVOCATION_SCHEMA:
        raise _invalid("revocation")
    _match(command["command_id"], EVENT_ID_PATTERN, "revocation")
    if any(command[key] != lease[key] for key in ("audience", "lease_id", "revoker_id", "revoker_public_key")):
        raise _invalid("revocation")
    if command["lease_sha256"] != hash_json({"lease": lease, "issuer_signature": lease_envelope["issuer_signature"]}):
        raise _invalid("revocation")
    _text(command["reason"], "revocation", 2048)
    issued = _utc(command["issued_at"], "revocation")
    expires = _utc(command["expires_at"], "revocation")
    if not 0 < (expires - issued).total_seconds() <= MAX_FRESHNESS_SECONDS:
        raise _invalid("revocation")
    if check_freshness and not issued <= _observation(observed_at, "revocation") < expires:
        raise AuthorityError("authority_revocation_stale", 410, "The revocation interval is not current.")
    return command


def lease_reference(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return declarative packet metadata, not a transferable capability."""
    lease = envelope["lease"]
    return {"lease_ref": lease["lease_id"], "scope": lease["scope"], "expires_at": lease["expires_at"],
            "revoker": lease["revoker_id"], "challenge_path": lease["challenge_path"]}


def init_authority_tables(conn: sqlite3.Connection) -> None:
    """Add private v2 storage without rewriting v1 declarations or their history."""
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_authority_grants_v2 (
        lease_id TEXT PRIMARY KEY, subject_id TEXT NOT NULL, target_seed_id TEXT NOT NULL,
        issuer_id TEXT NOT NULL, witness_id TEXT NOT NULL, revoker_id TEXT NOT NULL,
        policy_hash TEXT NOT NULL, policy_json TEXT NOT NULL,
        lease_sha256 TEXT NOT NULL, envelope_json TEXT NOT NULL, envelope_sha256 TEXT NOT NULL,
        accepted_at TEXT NOT NULL, issuance_event_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK(status IN ('active','revoked')),
        revocation_command_id TEXT UNIQUE
    )""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_sab_authority_grants_subject
        ON sab_authority_grants_v2(subject_id,lease_id)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_authority_events_v2 (
        event_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK(event_type IN ('issuance','revocation')),
        lease_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
        observed_at TEXT NOT NULL, previous_event_sha256 TEXT, event_sha256 TEXT NOT NULL
    )""")
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_sab_authority_event_coverage
        ON sab_authority_events_v2(lease_id,event_type)""")


def _one(conn: sqlite3.Connection, query: str, values: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    cursor = conn.execute(query, values)
    row = cursor.fetchone()
    return None if row is None else dict(zip((field[0] for field in cursor.description), row))


def _rows(conn: sqlite3.Connection, query: str, values: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    cursor = conn.execute(query, values)
    names = [field[0] for field in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _has_tables(conn: sqlite3.Connection) -> bool:
    count = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (?,?)", _TABLES).fetchone()[0]
    if count == 1:
        raise _inconsistent()
    return count == 2


def _storage_error() -> AuthorityError:
    return AuthorityError("authority_storage_unavailable", 503, "Local authority storage is unavailable.")


@contextmanager
def _transaction(conn: sqlite3.Connection, *, write: bool) -> Iterator[None]:
    owned = not conn.in_transaction
    savepoint = not owned and write
    try:
        if owned:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        elif savepoint:
            conn.execute("SAVEPOINT sab_authority_service")
            # A caller may have opened a deferred transaction. Acquire SQLite's
            # reserved writer lock before consulting the shared clock lock.
            if _has_tables(conn):
                conn.execute("UPDATE sab_authority_grants_v2 SET lease_id=lease_id WHERE 0")
        yield
        if owned:
            conn.commit()
        elif savepoint:
            conn.execute("RELEASE SAVEPOINT sab_authority_service")
    except BaseException as exc:
        if owned:
            conn.rollback()
        elif savepoint:
            try:
                conn.execute("ROLLBACK TO SAVEPOINT sab_authority_service")
                conn.execute("RELEASE SAVEPOINT sab_authority_service")
            except sqlite3.Error:
                pass
        if isinstance(exc, sqlite3.Error):
            raise _storage_error() from exc
        raise


def _event_digest(row: dict[str, Any]) -> str:
    return hash_json({"schema": "sab.authority_storage_event.v1", **{
        key: row[key] for key in ("event_id", "lease_id", "event_type", "lease_sha256",
                                 "payload_sha256", "observed_at", "previous_event_sha256")
    }})


def _insert_event(conn: sqlite3.Connection, *, event_id: str, lease_id: str, event_type: str,
                  lease_sha256: str, payload: dict[str, Any], observed_at: str,
                  previous_event_sha256: str | None = None) -> dict[str, Any]:
    row = {"event_id": event_id, "lease_id": lease_id, "event_type": event_type,
           "lease_sha256": lease_sha256, "payload_json": canonical_bytes(payload).decode(),
           "payload_sha256": hash_json(payload), "observed_at": observed_at,
           "previous_event_sha256": previous_event_sha256}
    row["event_sha256"] = _event_digest(row)
    conn.execute("""INSERT INTO sab_authority_events_v2
        (event_id,lease_id,event_type,lease_sha256,payload_json,payload_sha256,observed_at,previous_event_sha256,event_sha256)
        VALUES (?,?,?,?,?,?,?,?,?)""", tuple(row.values()))
    return row


class AuthorityService:
    """One explicit local policy evaluator. No policy means no implicit issuer."""

    init_authority_tables = staticmethod(init_authority_tables)

    def __init__(self, policy: dict[str, Any] | None, key_control: KeyControlService):
        self.key_control = key_control
        self.audience = key_control.audience
        self._policy_bytes = None if policy is None else canonical_bytes(validate_policy(policy, self.audience))

    @property
    def policy(self) -> dict[str, Any] | None:
        return None if self._policy_bytes is None else _strict_json(self._policy_bytes)

    @property
    def policy_hash(self) -> str | None:
        return None if self._policy_bytes is None else hashlib.sha256(self._policy_bytes).hexdigest()

    @property
    def enabled(self) -> bool:
        return self._policy_bytes is not None

    def _now(self) -> datetime:
        try:
            return self.key_control.observe_time()
        except KeyControlError as exc:
            raise AuthorityError("authority_clock_uncertain", 503, "Local clock uncertainty prevents authority evaluation.") from exc

    def _active_key(self, conn: sqlite3.Connection, subject: str, key: str) -> None:
        try:
            if self.key_control.require_active_binding(conn, subject) != key:
                raise _inconsistent()
        except KeyControlError as exc:
            raise AuthorityError("authority_key_inactive", 403, "A required authority key lacks a current consistent control proof.") from exc

    def _current(self, conn: sqlite3.Connection, record: dict[str, Any], now: datetime) -> None:
        lease = record["envelope"]["lease"]
        witness = record["envelope"]["issuance_witness"]
        if record["row"]["status"] == "revoked":
            raise AuthorityError("authority_revoked", 403, "This issued grant has been revoked.")
        if not self.enabled:
            raise _required()
        if lease["policy_hash"] != self.policy_hash:
            raise AuthorityError("authority_policy_changed", 403, "The issued grant is not covered by the current configured policy.")
        policy = self.policy
        if not _utc(policy["not_before"], "policy") <= now < _utc(policy["expires_at"], "policy"):
            raise AuthorityError("authority_policy_expired", 410, "The configured authority policy is outside its validity interval.")
        if not _utc(lease["issued_at"], "lease") <= now < _utc(lease["expires_at"], "lease"):
            raise AuthorityError("authority_expired", 410, "The issued grant is outside its validity interval.")
        self._active_key(conn, lease["subject_id"], lease["subject_public_key"])
        self._active_key(conn, lease["issuer_id"], lease["issuer_public_key"])
        self._active_key(conn, witness["witness_id"], witness["witness_public_key"])
        self._active_key(conn, lease["revoker_id"], lease["revoker_public_key"])

    def _stored(self, conn: sqlite3.Connection, lease_id: str) -> dict[str, Any]:
        if not _has_tables(conn):
            raise AuthorityError("authority_unknown", 404, "No issued grant exists for this identifier.")
        row = _one(conn, "SELECT * FROM sab_authority_grants_v2 WHERE lease_id=?", (lease_id,))
        if row is None:
            raise AuthorityError("authority_unknown", 404, "No issued grant exists for this identifier.")
        try:
            if len(row["envelope_json"]) > MAX_ENVELOPE_BYTES or len(row["policy_json"]) > MAX_POLICY_BYTES:
                raise _inconsistent()
            policy = validate_policy(_strict_json(row["policy_json"]), self.audience)
            envelope = validate_envelope(_strict_json(row["envelope_json"]), policy=policy,
                                         audience=self.audience, observed_at=row["accepted_at"])
            lease, witness = envelope["lease"], envelope["issuance_witness"]
            digest = hash_json({"lease": lease, "issuer_signature": envelope["issuer_signature"]})
            expected = {
                "lease_id": lease["lease_id"], "subject_id": lease["subject_id"],
                "target_seed_id": lease["target_seed_id"], "issuer_id": lease["issuer_id"],
                "witness_id": witness["witness_id"], "revoker_id": lease["revoker_id"],
                "policy_hash": hash_json(policy), "policy_json": canonical_bytes(policy).decode(),
                "lease_sha256": digest, "envelope_json": canonical_bytes(envelope).decode(),
                "envelope_sha256": hash_json(envelope), "issuance_event_id": witness["event_id"],
            }
            if any(row[key] != value for key, value in expected.items()) or row["lease_id"] != lease_id:
                raise _inconsistent()
            events = _rows(conn, "SELECT * FROM sab_authority_events_v2 WHERE lease_id=? ORDER BY event_type LIMIT 3", (lease_id,))
            if len(events) not in {1, 2}:
                raise _inconsistent()
            by_type = {event["event_type"]: event for event in events}
            if len(by_type) != len(events) or "issuance" not in by_type:
                raise _inconsistent()
            for event in events:
                if len(event["payload_json"]) > MAX_ENVELOPE_BYTES:
                    raise _inconsistent()
                payload = _strict_json(event["payload_json"])
                if (
                    event["payload_json"] != canonical_bytes(payload).decode()
                    or event["payload_sha256"] != hash_json(payload)
                    or event["event_sha256"] != _event_digest(event)
                    or event["lease_sha256"] != digest
                ):
                    raise _inconsistent()
            issued_event = by_type["issuance"]
            if (
                issued_event["event_id"] != witness["event_id"]
                or issued_event["payload_json"] != row["envelope_json"]
                or issued_event["observed_at"] != row["accepted_at"]
                or issued_event["previous_event_sha256"] is not None
            ):
                raise _inconsistent()
            if row["status"] == "active":
                if len(events) != 1 or row["revocation_command_id"] is not None:
                    raise _inconsistent()
            elif row["status"] == "revoked":
                revoked_event = by_type.get("revocation")
                if revoked_event is None:
                    raise _inconsistent()
                revocation = validate_revocation(_strict_json(revoked_event["payload_json"]),
                                                 lease_envelope=envelope, observed_at=revoked_event["observed_at"])
                if (
                    revoked_event["event_id"] != row["revocation_command_id"]
                    or revoked_event["event_id"] != revocation["revocation"]["command_id"]
                    or revoked_event["previous_event_sha256"] != issued_event["event_sha256"]
                    or _utc(revoked_event["observed_at"], "revocation") < _utc(row["accepted_at"], "lease")
                ):
                    raise _inconsistent()
            else:
                raise _inconsistent()
            return {"row": row, "envelope": envelope, "events": by_type}
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, AuthorityError) as exc:
            raise _inconsistent() from exc

    def _read_envelope(self, conn: sqlite3.Connection, record: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        error = None
        try:
            now = now or self._now()
            self._current(conn, record, now)
        except AuthorityError as exc:
            error = exc
        status = "active" if error is None else {
            "authority_revoked": "revoked", "authority_expired": "expired", "authority_policy_expired": "expired",
            "authority_clock_uncertain": "unavailable",
        }.get(error.code, "inactive")
        result = {
            "schema": "sab.authority_observation.v1", **record["envelope"],
            "lease_id": record["row"]["lease_id"], "lease_sha256": record["row"]["lease_sha256"],
            "envelope_sha256": record["row"]["envelope_sha256"], "status": status,
            "issued_receipt_at": record["row"]["accepted_at"], "observed_at": now.isoformat() if now else None,
            "authority_effect": "none",
            "standing_effect": "none", "reliance_effect": "none",
        }
        if error is not None:
            result.update(reason_code=error.code, detail=error.detail)
        return result

    @staticmethod
    def _request_fields(subject_id: str, action: str, target_seed_id: str) -> None:
        _match(subject_id, SUBJECT_PATTERN, "reference")
        _match(target_seed_id, SEED_ID_PATTERN, "reference")
        if not isinstance(action, str) or action not in ACTION_VOCABULARY:
            raise _invalid("reference")

    def _authorize_record(self, conn: sqlite3.Connection, record: dict[str, Any], *,
                          subject_id: str, action: str, target_seed_id: str, now: datetime) -> dict[str, Any]:
        self._current(conn, record, now)
        lease = record["envelope"]["lease"]
        if (
            lease["subject_id"] != subject_id or lease["target_seed_id"] != target_seed_id
            or action not in lease["allowed_actions"] or action in lease["forbidden_actions"]
        ):
            raise AuthorityError("authority_scope_denied", 403, "The issued grant does not cover this actor, action and exact seed.")
        return self._read_envelope(conn, record, now=now)

    def authorize(self, conn: sqlite3.Connection, reference: Any, *,
                  subject_id: str, action: str, target_seed_id: str) -> dict[str, Any]:
        self._request_fields(subject_id, action, target_seed_id)
        reference = _copy_input(reference, limit=8192, kind="reference")
        if set(reference) - _REFERENCE_FIELDS or not ({"lease_ref", "lease_id"} & set(reference)):
            raise _invalid("reference")
        lease_id = reference.get("lease_ref", reference.get("lease_id"))
        _match(lease_id, LEASE_ID_PATTERN, "reference")
        if any(reference[key] != lease_id for key in ("lease_ref", "lease_id") if key in reference):
            raise _invalid("reference")
        with _transaction(conn, write=True):
            record = self._stored(conn, lease_id)
            declaration = lease_reference(record["envelope"])
            if any(reference[key] != declaration[key] for key in reference if key not in {"lease_id", "lease_ref"}):
                raise AuthorityError("authority_reference_mismatch", 409, "The declared lease metadata differs from the issued grant.")
            return self._authorize_record(conn, record, subject_id=subject_id, action=action,
                                           target_seed_id=target_seed_id, now=self._now())

    def authorize_actor(self, conn: sqlite3.Connection, *, subject_id: str,
                        action: str, target_seed_id: str) -> dict[str, Any]:
        self._request_fields(subject_id, action, target_seed_id)
        with _transaction(conn, write=True):
            if not _has_tables(conn) or not self.enabled:
                raise _required()
            rows = _rows(conn, "SELECT lease_id FROM sab_authority_grants_v2 WHERE subject_id=? ORDER BY lease_id LIMIT ?",
                         (subject_id, MAX_GRANTS_PER_SUBJECT + 1))
            if len(rows) > MAX_GRANTS_PER_SUBJECT:
                raise _inconsistent()
            now = self._now()
            for row in rows:
                record = self._stored(conn, row["lease_id"])
                try:
                    return self._authorize_record(conn, record, subject_id=subject_id, action=action,
                                                   target_seed_id=target_seed_id, now=now)
                except AuthorityError as exc:
                    if exc.status >= 500 or exc.code == "authority_inconsistent":
                        raise
            raise _required()

    def get(self, conn: sqlite3.Connection, lease_id: str) -> dict[str, Any]:
        _match(lease_id, LEASE_ID_PATTERN, "reference")
        with _transaction(conn, write=False):
            return self._read_envelope(conn, self._stored(conn, lease_id))

    def list_for_subject(self, conn: sqlite3.Connection, subject_id: str) -> list[dict[str, Any]]:
        _match(subject_id, SUBJECT_PATTERN, "reference")
        with _transaction(conn, write=False):
            if not _has_tables(conn):
                return []
            rows = _rows(conn, "SELECT lease_id FROM sab_authority_grants_v2 WHERE subject_id=? ORDER BY lease_id LIMIT ?",
                         (subject_id, MAX_GRANTS_PER_SUBJECT + 1))
            if len(rows) > MAX_GRANTS_PER_SUBJECT:
                raise _inconsistent()
            return [self._read_envelope(conn, self._stored(conn, row["lease_id"])) for row in rows]

    def issue(self, conn: sqlite3.Connection, payload: Any) -> dict[str, Any]:
        payload = _copy_input(payload, limit=MAX_ENVELOPE_BYTES, kind="lease")
        _closed(payload, {"lease", "issuer_signature", "issuance_witness"}, "lease")
        if not isinstance(payload["lease"], dict):
            raise _invalid()
        lease_id = _match(payload["lease"].get("lease_id"), LEASE_ID_PATTERN, "lease")
        with _transaction(conn, write=True):
            tables_exist = _has_tables(conn)
            if tables_exist and _one(conn, "SELECT lease_id FROM sab_authority_grants_v2 WHERE lease_id=?", (lease_id,)):
                record = self._stored(conn, lease_id)
                if canonical_bytes(payload).decode() != record["row"]["envelope_json"]:
                    raise _conflict()
                return {**self._read_envelope(conn, record), "created": False}
            if not self.enabled:
                raise _required()
            # DDL only occurs inside the successful command transaction. Any
            # validation failure rolls it back, including a first request.
            init_authority_tables(conn)
            now = self._now()
            envelope = validate_envelope(payload, policy=self.policy, audience=self.audience, observed_at=now)
            lease, witness = envelope["lease"], envelope["issuance_witness"]
            for subject, key in (
                (lease["subject_id"], lease["subject_public_key"]), (lease["issuer_id"], lease["issuer_public_key"]),
                (witness["witness_id"], witness["witness_public_key"]), (lease["revoker_id"], lease["revoker_public_key"]),
            ):
                self._active_key(conn, subject, key)
            if _one(conn, "SELECT event_id FROM sab_authority_events_v2 WHERE event_id=?", (witness["event_id"],)):
                raise _conflict()
            if _one(conn, "SELECT name FROM sqlite_master WHERE type='table' AND name='sab_authority_leases_v1'"):
                legacy = _one(conn, "SELECT subject_id,lease_json FROM sab_authority_leases_v1 WHERE lease_id=?", (lease_id,))
                if legacy and (legacy["subject_id"] != lease["subject_id"] or legacy["lease_json"] != canonical_bytes(lease).decode()):
                    raise _conflict()
            grants = conn.execute("SELECT count(*) FROM sab_authority_grants_v2").fetchone()[0]
            subject_grants = conn.execute("SELECT count(*) FROM sab_authority_grants_v2 WHERE subject_id=?", (lease["subject_id"],)).fetchone()[0]
            events = conn.execute("SELECT count(*) FROM sab_authority_events_v2").fetchone()[0]
            active = conn.execute("SELECT count(*) FROM sab_authority_grants_v2 WHERE status='active'").fetchone()[0]
            if grants >= MAX_STORED_GRANTS or subject_grants >= MAX_GRANTS_PER_SUBJECT or events + active + 2 > MAX_STORED_EVENTS:
                raise AuthorityError("authority_capacity", 503, "Local authority history is at its admission limit; retirement capacity is reserved.")
            digest = hash_json({"lease": lease, "issuer_signature": envelope["issuer_signature"]})
            accepted = now.isoformat()
            conn.execute("""INSERT INTO sab_authority_grants_v2
                (lease_id,subject_id,target_seed_id,issuer_id,witness_id,revoker_id,policy_hash,policy_json,
                 lease_sha256,envelope_json,envelope_sha256,accepted_at,issuance_event_id,status,revocation_command_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'active',NULL)""", (
                lease_id, lease["subject_id"], lease["target_seed_id"], lease["issuer_id"], witness["witness_id"],
                lease["revoker_id"], self.policy_hash, self._policy_bytes.decode(), digest,
                canonical_bytes(envelope).decode(), hash_json(envelope), accepted, witness["event_id"],
            ))
            _insert_event(conn, event_id=witness["event_id"], lease_id=lease_id, event_type="issuance",
                          lease_sha256=digest, payload=envelope, observed_at=accepted)
            return {**self._read_envelope(conn, self._stored(conn, lease_id), now=now), "created": True}

    @staticmethod
    def _revocation_receipt(record: dict[str, Any], *, created: bool) -> dict[str, Any]:
        event = record["events"]["revocation"]
        return {"schema": "sab.authority_revocation_receipt.v1", **_strict_json(event["payload_json"]),
                "lease_id": record["row"]["lease_id"], "lease_sha256": record["row"]["lease_sha256"],
                "event_sha256": event["event_sha256"], "revoked_at": event["observed_at"],
                "status": "revoked", "created": created, "authority_effect": "none",
                "standing_effect": "none", "reliance_effect": "none"}

    def revoke(self, conn: sqlite3.Connection, payload: Any) -> dict[str, Any]:
        payload = _copy_input(payload, limit=MAX_ENVELOPE_BYTES, kind="revocation")
        _closed(payload, {"revocation", "signature"}, "revocation")
        command = payload["revocation"]
        _closed(command, _REVOCATION_FIELDS, "revocation")
        lease_id = _match(command["lease_id"], LEASE_ID_PATTERN, "revocation")
        command_id = _match(command["command_id"], EVENT_ID_PATTERN, "revocation")
        with _transaction(conn, write=True):
            record = self._stored(conn, lease_id)
            prior = _one(conn, "SELECT * FROM sab_authority_events_v2 WHERE event_id=?", (command_id,))
            if prior is not None:
                if prior["event_type"] != "revocation" or prior["lease_id"] != lease_id or prior["payload_json"] != canonical_bytes(payload).decode():
                    raise _conflict()
                if record["row"]["status"] != "revoked" or record["row"]["revocation_command_id"] != command_id:
                    raise _inconsistent()
                return self._revocation_receipt(record, created=False)
            if record["row"]["status"] == "revoked":
                raise _conflict()
            now = self._now()
            validate_revocation(payload, lease_envelope=record["envelope"], observed_at=now)
            self._active_key(conn, command["revoker_id"], command["revoker_public_key"])
            if conn.execute("SELECT count(*) FROM sab_authority_events_v2").fetchone()[0] >= MAX_STORED_EVENTS:
                raise AuthorityError("authority_capacity", 503, "Local signed authority history has reached its storage limit.")
            _insert_event(conn, event_id=command_id, lease_id=lease_id, event_type="revocation",
                          lease_sha256=record["row"]["lease_sha256"], payload=payload, observed_at=now.isoformat(),
                          previous_event_sha256=record["events"]["issuance"]["event_sha256"])
            conn.execute("UPDATE sab_authority_grants_v2 SET status='revoked',revocation_command_id=? WHERE lease_id=?",
                         (command_id, lease_id))
            return self._revocation_receipt(self._stored(conn, lease_id), created=True)
