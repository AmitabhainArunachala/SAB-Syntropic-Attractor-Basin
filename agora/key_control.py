"""Signed control of a local SAB identity key, without any authority transfer.

This service is one local process backed by one SQLite database. A challenge is
usable only in the process that issued it. Consumed proof records survive a
restart, but pending challenges do not. Local UTC is guarded with monotonic
elapsed time; neither clock is an authenticated source of civil time.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from .sab_identity import (
    AgentIdentityV1,
    SIGNATURE_CANONICALIZATION,
    canonical_json_bytes,
    subject_id_from_public_key,
    verify_ed25519_signature,
)

CHALLENGE_SCHEMA = "sab.key_control_challenge.v1"
MESSAGE_SCHEMA = "sab.key_control_message.v1"
RESULT_SCHEMA = "sab.key_control_result.v1"
BINDING_SCHEMA = "sab.key_control_binding.v1"
SIGNATURE_ALGORITHM = "ed25519"
VERIFY_PATH = "/api/v1/agents/verify"
MAX_CHALLENGE_TTL_SECONDS = 120
MAX_CLOCK_SKEW_SECONDS = 5
CHALLENGE_ID_PATTERN = r"sab_kc_challenge_[0-9a-f]{32}"
NONCE_PATTERN = r"[0-9a-f]{64}"
PROOF_ID_PATTERN = r"sab_kc_proof_[0-9a-f]{32}"
MAX_PENDING_PER_SUBJECT = 4
MAX_PENDING_CHALLENGES = 512
MAX_STORED_RECORDS = 10000
_MAX_REGISTRATION_BYTES = 32768
_REGISTRATION_FIELDS = frozenset(
    {
        "public_key",
        "display_name",
        "name",
        "subject_id",
        "identity_ref",
        "identity_rail",
        "controller",
        "operator_backing",
        "external_attestations",
        "schema",
    }
)
_MESSAGE_FIELDS = frozenset(
    {
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
)
_SECRET_FIELDS = frozenset(
    {
        "privatekey",
        "signingkey",
        "secretkey",
        "secret",
        "apikey",
        "password",
        "passphrase",
        "token",
        "accesstoken",
        "refreshtoken",
        "clientsecret",
        "seed",
        "seedphrase",
        "mnemonic",
        "authorization",
        "credential",
        "credentials",
    }
)


class KeyControlError(Exception):
    """An HTTP-safe error whose text never reflects caller-supplied content."""

    def __init__(self, code: str, status: int, detail: str):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


def _invalid_registration() -> KeyControlError:
    return KeyControlError("invalid_registration", 400, "Registration fields are invalid.")


def _conflict() -> KeyControlError:
    return KeyControlError(
        "identity_conflict", 409, "An existing identity binding or its metadata conflicts."
    )


def _inconsistent() -> KeyControlError:
    return KeyControlError(
        "key_control_inconsistent", 409, "The recorded identity and its control proof do not agree."
    )


def _unavailable() -> KeyControlError:
    return KeyControlError(
        "challenge_unavailable", 409, "The challenge is unknown, consumed, or from another process."
    )


def canonical_origin(value: str) -> str:
    """Normalize a configured HTTPS origin or explicit loopback HTTP origin.

    No request headers, DNS resolution, or network observations participate.
    """
    error = ValueError("Identity audience must be an HTTPS origin or loopback HTTP origin.")
    if not isinstance(value, str) or not value or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise error
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or "?" in value
            or "#" in value
            or "\\" in value
            or "%" in parsed.netloc
        ):
            raise error
        hostname = parsed.hostname
        port = parsed.port
        if not hostname or (port is not None and not 1 <= port <= 65535):
            raise error
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            if len(hostname) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in hostname.split(".")
            ):
                raise error
            host = hostname.lower()
            loopback = host == "localhost"
        else:
            host = address.compressed
            loopback = address.is_loopback
            if address.version == 6:
                host = f"[{host}]"
        if parsed.scheme == "http" and not loopback:
            raise error
        default_port = 443 if parsed.scheme == "https" else 80
        suffix = f":{port}" if port is not None and port != default_port else ""
        return f"{parsed.scheme}://{host}{suffix}"
    except (ValueError, TypeError) as exc:
        raise error from exc


def _utc(value: Any) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware UTC observation is required.")
    return value.astimezone(timezone.utc)


def _finite(value: Any) -> float:
    if type(value) not in {int, float}:
        raise ValueError("A finite monotonic observation is required.")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("A finite monotonic observation is required.")
    return result


def _json_input(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [1000]
    budget[0] -= 1
    if depth > 12 or budget[0] < 0:
        raise _invalid_registration()
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or re.sub(r"[^a-z0-9]", "", key.lower()) in _SECRET_FIELDS:
                raise _invalid_registration()
            _json_input(item, depth=depth + 1, budget=budget)
    elif isinstance(value, list):
        for item in value:
            _json_input(item, depth=depth + 1, budget=budget)
    elif value is None or type(value) in {str, bool, int}:
        if isinstance(value, str) and len(value) > _MAX_REGISTRATION_BYTES:
            raise _invalid_registration()
    elif type(value) is float and math.isfinite(value):
        return
    else:
        raise _invalid_registration()


def prepare_identity(registration: Mapping[str, Any], created_at: datetime | str) -> dict[str, Any]:
    """Normalize supported registration fields without reading or writing state.

    Declared legacy agent aliases can be represented here. The service permits
    them only when both pre-existing identity projections already agree.
    """
    if not isinstance(registration, dict) or set(registration) - _REGISTRATION_FIELDS:
        raise _invalid_registration()
    _json_input(registration)
    if "schema" in registration and registration["schema"] != "sab.agent_identity.v1":
        raise _invalid_registration()
    try:
        if len(canonical_json_bytes(registration)) > _MAX_REGISTRATION_BYTES:
            raise _invalid_registration()
        public_key = registration.get("public_key")
        if not isinstance(public_key, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", public_key):
            raise _invalid_registration()
        public_key = public_key.lower()
        canonical_subject = subject_id_from_public_key(public_key)
        subject = registration.get("subject_id", canonical_subject)
        if not isinstance(subject, str) or not re.fullmatch(
            r"agent_[A-Za-z0-9_.:-]{2,154}", subject.strip()
        ):
            raise _invalid_registration()
        subject = subject.strip()
        display_name = registration.get("display_name", registration.get("name", "sab-agent"))
        if not isinstance(display_name, str) or not display_name.strip():
            raise _invalid_registration()
        if (
            "name" in registration
            and "display_name" in registration
            and (
                not isinstance(registration["name"], str)
                or registration["name"].strip() != display_name.strip()
            )
        ):
            raise _invalid_registration()
        backing = registration.get("operator_backing", {})
        attestations = registration.get("external_attestations", [])
        if not isinstance(backing, dict) or not isinstance(attestations, list):
            raise _invalid_registration()
        identity = {
            "schema": "sab.agent_identity.v1",
            "subject_id": subject,
            "identity_ref": registration.get("identity_ref", f"sab_identity_{subject}"),
            "display_name": display_name.strip(),
            "identity_rail": registration.get("identity_rail", "ed25519"),
            "public_key": public_key,
            "controller": registration.get("controller", "unknown"),
            "operator_backing": backing,
            "external_attestations": attestations,
            "created_at": _utc(created_at),
            "revocation_status": "active",
            "evidence_refs": [f"web_agents:{subject}"],
        }
        return AgentIdentityV1.model_validate(identity).model_dump(mode="json", by_alias=True)
    except (ValidationError, ValueError, TypeError, OverflowError) as exc:
        raise _invalid_registration() from exc


def init_key_control_tables(conn: sqlite3.Connection) -> None:
    """Create only private control tables. Public identity schemas are untouched."""
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_key_control_challenges_v1 (
            challenge_id TEXT PRIMARY KEY,
            instance_epoch TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('register','revoke','rotate')),
            message_json TEXT NOT NULL,
            message_sha256 TEXT NOT NULL,
            issued_monotonic REAL NOT NULL,
            expires_monotonic REAL NOT NULL
        )""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_sab_key_control_pending_subject
           ON sab_key_control_challenges_v1(subject_id)""")
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_sab_key_control_pending_revocation
           ON sab_key_control_challenges_v1(subject_id,instance_epoch) WHERE action='revoke'""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_key_control_proofs_v1 (
            proof_id TEXT PRIMARY KEY,
            challenge_id TEXT NOT NULL UNIQUE,
            message_json TEXT NOT NULL,
            message_sha256 TEXT NOT NULL,
            signature TEXT NOT NULL,
            successor_signature TEXT,
            verified_at TEXT NOT NULL
        )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_key_control_bindings_v1 (
            subject_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK(status IN ('active','revoked','superseded')),
            proof_id TEXT NOT NULL,
            identity_sha256 TEXT NOT NULL,
            proved_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            successor_subject_id TEXT,
            transition_proof_id TEXT
        )""")


def _one(conn: sqlite3.Connection, query: str, values: tuple[Any, ...]) -> dict[str, Any] | None:
    cursor = conn.execute(query, values)
    row = cursor.fetchone()
    return None if row is None else dict(zip((item[0] for item in cursor.description), row))


def _rows(conn: sqlite3.Connection, query: str, values: tuple[Any, ...]) -> list[dict[str, Any]]:
    cursor = conn.execute(query, values)
    names = [item[0] for item in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _has_control_tables(conn: sqlite3.Connection) -> bool:
    return conn.execute("""SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN
           ('sab_key_control_challenges_v1','sab_key_control_proofs_v1',
            'sab_key_control_bindings_v1')""").fetchone()[0] == 3


def _hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _recorded_identity(
    conn: sqlite3.Connection, subject: str, public_key: str
) -> dict[str, Any] | None:
    web_rows = _rows(
        conn, "SELECT * FROM web_agents WHERE id=? OR lower(public_key)=?", (subject, public_key)
    )
    identity_rows = _rows(
        conn,
        "SELECT * FROM sab_agent_identities_v1 WHERE subject_id=? OR lower(public_key)=?",
        (subject, public_key),
    )
    for row in web_rows:
        if row["id"] != subject or str(row["public_key"]).lower() != public_key:
            raise _conflict()
    for row in identity_rows:
        if row["subject_id"] != subject or str(row["public_key"]).lower() != public_key:
            raise _conflict()
    if not web_rows and not identity_rows:
        return None
    if len(web_rows) != 1 or len(identity_rows) != 1:
        raise KeyControlError(
            "authenticated_migration_required",
            409,
            "Partial legacy identity records require an authenticated migration.",
        )
    row = identity_rows[0]
    try:
        raw = json.loads(row["identity_json"])
        identity = AgentIdentityV1.model_validate(raw).model_dump(mode="json", by_alias=True)
        # Canonical identity JSON is the immutable binding. Do not silently repair
        # a projection or drop unknown fields when proving an existing identity.
        if identity != raw:
            raise _inconsistent()
        if (
            identity["subject_id"] != subject
            or identity["public_key"] != public_key
            or web_rows[0]["name"] != identity["display_name"]
            or row["display_name"] != identity["display_name"]
            or row["controller"] != identity["controller"]
            or row["operator_id"] != identity["operator_backing"]["operator_id"]
            or json.loads(row["operator_backing_json"]) != identity["operator_backing"]
        ):
            raise _inconsistent()
    except (ValueError, TypeError, KeyError, ValidationError) as exc:
        raise _inconsistent() from exc
    return identity


@contextmanager
def _transaction(conn: sqlite3.Connection) -> Iterator[None]:
    if conn.in_transaction:
        raise KeyControlError(
            "storage_transaction_active",
            503,
            "Key control requires a dedicated database transaction.",
        )
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        raise KeyControlError(
            "key_control_storage_unavailable", 503, "Local key-control storage is unavailable."
        ) from exc
    try:
        yield
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        raise KeyControlError(
            "key_control_storage_unavailable", 503, "Local key-control storage is unavailable."
        ) from exc
    except BaseException:
        conn.rollback()
        raise


class KeyControlService:
    """One local challenge issuer and verifier, never a source of standing."""

    init_key_control_tables = staticmethod(init_key_control_tables)

    def __init__(
        self,
        audience: str,
        *,
        utc_now: Callable[[], datetime | str] | None = None,
        monotonic: Callable[[], float] | None = None,
        ttl_seconds: int = MAX_CHALLENGE_TTL_SECONDS,
    ):
        self.audience = canonical_origin(audience)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_CHALLENGE_TTL_SECONDS:
            raise ValueError("Challenge lifetime must be an integer from 1 through 120 seconds.")
        self.ttl_seconds = ttl_seconds
        self._utc_now = utc_now or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic or time.monotonic
        try:
            self._boot_utc = _utc(self._utc_now())
            self._boot_monotonic = _finite(self._monotonic())
        except Exception as exc:
            raise ValueError("Initial key-control clock observations must be valid.") from exc
        self._last_utc = self._boot_utc
        self._last_monotonic = self._boot_monotonic
        self._effective_utc = self._boot_utc
        self._clock_uncertain = False
        self._epoch = secrets.token_hex(32)
        self._lock = RLock()

    def _now(self) -> tuple[datetime, float]:
        if not self._clock_uncertain:
            try:
                wall = _utc(self._utc_now())
                mono = _finite(self._monotonic())
                expected = self._boot_utc + timedelta(seconds=mono - self._boot_monotonic)
                if (
                    mono < self._last_monotonic
                    or wall < self._last_utc
                    or abs((wall - expected).total_seconds()) > MAX_CLOCK_SKEW_SECONDS
                ):
                    raise ValueError("Clock observations disagree.")
                self._last_utc = wall
                self._last_monotonic = mono
                self._effective_utc = max(self._effective_utc, wall, expected)
            except Exception:
                self._clock_uncertain = True
        if self._clock_uncertain:
            raise KeyControlError(
                "clock_uncertain",
                503,
                "Local clock uncertainty prevents key-control challenge issuance or verification.",
            )
        return self._effective_utc, self._last_monotonic

    def observe_time(self) -> datetime:
        """Return guarded local UTC without creating a key-control challenge.

        Callers performing a database mutation must acquire their SQLite write
        transaction before this lock. The observation is local clock evidence,
        not authenticated UTC and not a permission to act.
        """
        with self._lock:
            return self._now()[0]

    @staticmethod
    def _subject(payload: Mapping[str, Any]) -> str:
        value = payload.get("subject_id")
        if not isinstance(value, str) or not re.fullmatch(r"agent_[A-Za-z0-9_.:-]{2,154}", value):
            raise KeyControlError("invalid_request", 400, "Key-control request fields are invalid.")
        return value

    @staticmethod
    def _capacity(conn: sqlite3.Connection) -> tuple[int, int, int]:
        counts = conn.execute("""SELECT (SELECT count(*) FROM sab_key_control_challenges_v1)
               + (SELECT count(*) FROM sab_key_control_proofs_v1)
               + (SELECT count(*) FROM sab_key_control_bindings_v1),
               (SELECT count(*) FROM sab_key_control_challenges_v1),
               (SELECT count(*) FROM sab_key_control_bindings_v1 WHERE status='active')
               - (SELECT count(*) FROM sab_key_control_challenges_v1 c JOIN
                  sab_key_control_bindings_v1 b ON c.subject_id=b.subject_id
                  WHERE c.action='revoke' AND b.status='active')""").fetchone()
        # One future row and pending slot for each active identity without an
        # outstanding revocation challenge. That challenge already occupies its
        # reserve; its eventual proof replaces the same row.
        return int(counts[0]), int(counts[1]), int(counts[2])

    @staticmethod
    def _capacity_error() -> KeyControlError:
        return KeyControlError(
            "key_control_capacity", 429, "The local key-control storage or pending quota is full."
        )

    def _registration_candidate(
        self,
        conn: sqlite3.Connection,
        proposed: dict[str, Any],
        *,
        successor: bool = False,
    ) -> dict[str, Any]:
        subject, key = proposed["subject_id"], proposed["public_key"]
        existing = _recorded_identity(conn, subject, key)
        binding = _one(
            conn,
            "SELECT * FROM sab_key_control_bindings_v1 WHERE subject_id=? OR public_key=?",
            (subject, key),
        )
        if successor and (existing is not None or binding is not None):
            raise _conflict()
        if binding is not None:
            if binding["subject_id"] != subject or binding["public_key"] != key:
                raise _conflict()
            if binding["status"] != "active":
                raise KeyControlError(
                    "key_control_inactive", 403, "The identity key has been retired."
                )
            self.require_active_binding(conn, subject)
        if existing is None:
            if binding is not None:
                raise _inconsistent()
            if subject != subject_id_from_public_key(key):
                raise KeyControlError(
                    "canonical_identity_required",
                    400,
                    "New identities require the subject derived from their public key.",
                )
            return proposed
        if existing["revocation_status"] != "active":
            raise KeyControlError("key_control_inactive", 403, "The identity key has been retired.")
        comparable = set(proposed) - {"created_at", "evidence_refs"}
        if any(existing.get(field) != proposed[field] for field in comparable):
            raise _conflict()
        return existing

    def issue(self, conn: sqlite3.Connection, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise KeyControlError("invalid_request", 400, "Key-control request fields are invalid.")
        action = payload.get("action")
        fields = {
            "register": {"action", "registration"},
            "revoke": {"action", "subject_id"},
            "rotate": {"action", "subject_id", "registration"},
        }
        if not isinstance(action, str) or action not in fields or set(payload) != fields[action]:
            raise KeyControlError("invalid_request", 400, "Key-control request fields are invalid.")
        with _transaction(conn), self._lock:
            now, mono = self._now()
            init_key_control_tables(conn)
            if action == "register":
                proposed = self._registration_candidate(
                    conn, prepare_identity(payload["registration"], now)
                )
                subject, key = proposed["subject_id"], proposed["public_key"]
            else:
                subject = self._subject(payload)
                key = self.require_active_binding(conn, subject)
                proposed = None
                if action == "rotate":
                    proposed = self._registration_candidate(
                        conn, prepare_identity(payload["registration"], now), successor=True
                    )
            # Pending records from prior processes or elapsed challenges carry no
            # durable proof. Purge only those rows, never consumed proof history.
            conn.execute(
                "DELETE FROM sab_key_control_challenges_v1 WHERE instance_epoch<>? OR expires_monotonic<=?",
                (self._epoch, mono),
            )
            conn.execute("""DELETE FROM sab_key_control_challenges_v1 WHERE subject_id IN
                   (SELECT subject_id FROM sab_key_control_bindings_v1 WHERE status<>'active')""")
            if action == "revoke":
                existing_revoke = _one(
                    conn,
                    """SELECT * FROM sab_key_control_challenges_v1
                          WHERE subject_id=? AND instance_epoch=? AND action='revoke'""",
                    (subject, self._epoch),
                )
                if existing_revoke is not None:
                    return self._envelope(self._message(existing_revoke))
            stored, pending, reserved = self._capacity(conn)
            per_subject = conn.execute(
                "SELECT count(*) FROM sab_key_control_challenges_v1 WHERE subject_id=?", (subject,)
            ).fetchone()[0]
            new_subject = (
                action == "register"
                and _one(
                    conn,
                    "SELECT subject_id FROM sab_key_control_bindings_v1 WHERE subject_id=?",
                    (subject,),
                )
                is None
            )
            admission_rows = 1 + (2 if new_subject else 1 if action == "rotate" else 0)
            if action == "revoke":
                # Revocation consumes its pre-reserved allowance and bypasses
                # per-subject challenge saturation. Repeated issuance reuses the
                # live challenge instead of invalidating a signer's response.
                allowed = stored + 1 <= MAX_STORED_RECORDS and pending + 1 <= MAX_PENDING_CHALLENGES
            else:
                allowed = (
                    per_subject < MAX_PENDING_PER_SUBJECT
                    and stored + reserved + admission_rows <= MAX_STORED_RECORDS
                    and pending + reserved + 1 + int(new_subject) <= MAX_PENDING_CHALLENGES
                )
            if not allowed:
                raise self._capacity_error()
            challenge_id = "sab_kc_challenge_" + secrets.token_hex(16)
            message = {
                "schema": MESSAGE_SCHEMA,
                "action": action,
                "audience": self.audience,
                "method": "POST",
                "path": VERIFY_PATH,
                "challenge_id": challenge_id,
                "nonce": secrets.token_hex(32),
                "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=self.ttl_seconds)).isoformat(),
                "subject_id": subject,
                "public_key": key,
                "proposed_identity": proposed,
                "proposed_identity_sha256": _hash(proposed) if proposed is not None else None,
            }
            message_bytes = canonical_json_bytes(message)
            conn.execute(
                """INSERT INTO sab_key_control_challenges_v1
                   (challenge_id,instance_epoch,subject_id,action,message_json,message_sha256,
                    issued_monotonic,expires_monotonic) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    challenge_id,
                    self._epoch,
                    subject,
                    action,
                    message_bytes.decode(),
                    hashlib.sha256(message_bytes).hexdigest(),
                    mono,
                    mono + self.ttl_seconds,
                ),
            )
        return self._envelope(message)

    @staticmethod
    def _envelope(message: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": CHALLENGE_SCHEMA,
            "message": message,
            "canonicalization": SIGNATURE_CANONICALIZATION,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "authority_effect": "none",
            "standing_effect": "none",
        }

    @staticmethod
    def _message(row: dict[str, Any]) -> dict[str, Any]:
        try:
            message = json.loads(row["message_json"])
            if (
                not isinstance(message, dict)
                or set(message) != _MESSAGE_FIELDS
                or canonical_json_bytes(message).decode() != row["message_json"]
                or _hash(message) != row["message_sha256"]
                or message["schema"] != MESSAGE_SCHEMA
                or message["action"] not in {"register", "revoke", "rotate"}
                or message["method"] != "POST"
                or message["path"] != VERIFY_PATH
                or canonical_origin(message["audience"]) != message["audience"]
                or not isinstance(message["subject_id"], str)
                or not re.fullmatch(r"agent_[A-Za-z0-9_.:-]{2,154}", message["subject_id"])
                or not isinstance(message["public_key"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", message["public_key"])
                or not re.fullmatch(CHALLENGE_ID_PATTERN, message["challenge_id"])
                or not re.fullmatch(NONCE_PATTERN, message["nonce"])
            ):
                raise _inconsistent()
            issued, expires = _utc(message["issued_at"]), _utc(message["expires_at"])
            if not 0 < (expires - issued).total_seconds() <= MAX_CHALLENGE_TTL_SECONDS:
                raise _inconsistent()
            proposed = message["proposed_identity"]
            if message["action"] == "revoke":
                if proposed is not None or message["proposed_identity_sha256"] is not None:
                    raise _inconsistent()
            elif (
                not isinstance(proposed, dict)
                or AgentIdentityV1.model_validate(proposed).model_dump(mode="json", by_alias=True)
                != proposed
                or proposed["revocation_status"] != "active"
                or _hash(proposed) != message["proposed_identity_sha256"]
            ):
                raise _inconsistent()
            if message["action"] == "register" and (
                proposed["subject_id"] != message["subject_id"]
                or proposed["public_key"] != message["public_key"]
            ):
                raise _inconsistent()
            return message
        except (ValueError, TypeError, KeyError, ValidationError) as exc:
            raise _inconsistent() from exc

    @staticmethod
    def _verify_signatures(
        message: dict[str, Any], signature: str, successor_signature: str | None
    ) -> bool:
        if (
            not isinstance(signature, str)
            or not re.fullmatch(r"[0-9a-fA-F]{128}", signature)
            or (
                successor_signature is not None
                and (
                    not isinstance(successor_signature, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{128}", successor_signature)
                )
            )
        ):
            return False
        encoded = canonical_json_bytes(message)
        if not verify_ed25519_signature(message["public_key"], encoded, signature):
            return False
        if message["action"] == "rotate":
            return successor_signature is not None and verify_ed25519_signature(
                message["proposed_identity"]["public_key"], encoded, successor_signature
            )
        return successor_signature is None

    @staticmethod
    def _insert_identity(conn: sqlite3.Connection, identity: dict[str, Any]) -> None:
        subject, key = identity["subject_id"], identity["public_key"]
        if _recorded_identity(conn, subject, key) is not None:
            return
        conn.execute(
            """INSERT INTO web_agents
               (id,name,public_key,created_at,witness_count,witness_accuracy) VALUES (?,?,?,?,0,0.0)""",
            (subject, identity["display_name"], key, identity["created_at"]),
        )
        conn.execute(
            """INSERT INTO sab_agent_identities_v1
               (subject_id,display_name,public_key,controller,operator_id,operator_backing_json,
                identity_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                subject,
                identity["display_name"],
                key,
                identity["controller"],
                identity["operator_backing"]["operator_id"],
                canonical_json_bytes(identity["operator_backing"]).decode(),
                canonical_json_bytes(identity).decode(),
                identity["created_at"],
                identity["created_at"],
            ),
        )

    def verify(self, conn: sqlite3.Connection, payload: Mapping[str, Any]) -> dict[str, Any]:
        if (
            not isinstance(payload, dict)
            or set(payload)
            not in (
                {"challenge_id", "signature"},
                {"challenge_id", "signature", "successor_signature"},
            )
            or not isinstance(payload.get("challenge_id"), str)
            or not re.fullmatch(CHALLENGE_ID_PATTERN, payload["challenge_id"])
            or any(
                not isinstance(payload.get(field), str)
                or not re.fullmatch(r"[0-9a-fA-F]{128}", payload[field])
                for field in {"signature", "successor_signature"}.intersection(payload)
            )
        ):
            raise KeyControlError(
                "invalid_proof", 400, "Proof fields or signature encoding are invalid."
            )
        with _transaction(conn), self._lock:
            now, mono = self._now()
            init_key_control_tables(conn)
            row = _one(
                conn,
                "SELECT * FROM sab_key_control_challenges_v1 WHERE challenge_id=?",
                (payload["challenge_id"],),
            )
            if row is None or row["instance_epoch"] != self._epoch:
                raise _unavailable()
            message = self._message(row)
            if (
                message["audience"] != self.audience
                or message["challenge_id"] != row["challenge_id"]
                or message["subject_id"] != row["subject_id"]
                or message["action"] != row["action"]
                # Reproduce issuance's floating-point addition exactly. The
                # inverse subtraction can round to a value adjacent to the TTL.
                or _finite(row["expires_monotonic"])
                != _finite(row["issued_monotonic"]) + self.ttl_seconds
            ):
                raise _inconsistent()
            self._check_expiry(message, row, now, mono)
            signature = payload["signature"].lower()
            successor_signature = payload.get("successor_signature")
            if successor_signature is not None:
                successor_signature = successor_signature.lower()
            if not self._verify_signatures(message, signature, successor_signature):
                raise KeyControlError(
                    "invalid_signature", 401, "The required key-control signatures did not verify."
                )
            action = message["action"]
            proposed = message["proposed_identity"]
            if action == "register":
                candidate = self._registration_candidate(conn, proposed)
                if candidate != proposed:
                    raise _conflict()
                resulting_identity = proposed
            else:
                key = self.require_active_binding(conn, message["subject_id"])
                if key != message["public_key"]:
                    raise _inconsistent()
                if action == "rotate":
                    self._registration_candidate(conn, proposed, successor=True)
                    resulting_identity = proposed
                else:
                    resulting_identity = _recorded_identity(conn, message["subject_id"], key)
                    resulting_identity["revocation_status"] = "revoked"
            now, mono = self._now()
            self._check_expiry(message, row, now, mono)
            new_binding = action == "rotate" or (
                action == "register"
                and _one(
                    conn,
                    "SELECT subject_id FROM sab_key_control_bindings_v1 WHERE subject_id=?",
                    (message["subject_id"],),
                )
                is None
            )
            # Consuming one pending row and adding one durable proof is neutral;
            # a new binding costs one additional stored row.
            stored, pending, reserved = self._capacity(conn)
            new_active = action == "register" and new_binding
            if stored + reserved + int(new_binding) + int(new_active) > MAX_STORED_RECORDS:
                raise self._capacity_error()
            proof_id = "sab_kc_proof_" + secrets.token_hex(16)
            verified_at = now.isoformat()
            conn.execute(
                """INSERT INTO sab_key_control_proofs_v1
                   (proof_id,challenge_id,message_json,message_sha256,signature,successor_signature,verified_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    proof_id,
                    row["challenge_id"],
                    row["message_json"],
                    row["message_sha256"],
                    signature,
                    successor_signature,
                    verified_at,
                ),
            )
            if action in {"register", "rotate"}:
                self._insert_identity(conn, resulting_identity)
                conn.execute(
                    """INSERT INTO sab_key_control_bindings_v1
                       (subject_id,public_key,status,proof_id,identity_sha256,proved_at,updated_at)
                       VALUES (?,?,'active',?,?,?,?)
                       ON CONFLICT(subject_id) DO UPDATE SET proof_id=excluded.proof_id,
                       identity_sha256=excluded.identity_sha256,proved_at=excluded.proved_at,
                       updated_at=excluded.updated_at""",
                    (
                        resulting_identity["subject_id"],
                        resulting_identity["public_key"],
                        proof_id,
                        _hash(resulting_identity),
                        verified_at,
                        verified_at,
                    ),
                )
            if action in {"revoke", "rotate"}:
                retired = _recorded_identity(conn, message["subject_id"], message["public_key"])
                retired["revocation_status"] = "revoked" if action == "revoke" else "superseded"
                successor = resulting_identity["subject_id"] if action == "rotate" else None
                conn.execute(
                    "UPDATE sab_agent_identities_v1 SET identity_json=?,updated_at=? WHERE subject_id=?",
                    (canonical_json_bytes(retired).decode(), verified_at, message["subject_id"]),
                )
                conn.execute(
                    """UPDATE sab_key_control_bindings_v1 SET status=?,updated_at=?,
                       successor_subject_id=?,transition_proof_id=? WHERE subject_id=?""",
                    (
                        retired["revocation_status"],
                        verified_at,
                        successor,
                        proof_id,
                        message["subject_id"],
                    ),
                )
            consumed = conn.execute(
                "DELETE FROM sab_key_control_challenges_v1 WHERE challenge_id=? AND instance_epoch=?",
                (row["challenge_id"], self._epoch),
            ).rowcount
            if consumed != 1:
                raise _unavailable()
            if action in {"revoke", "rotate"}:
                conn.execute(
                    "DELETE FROM sab_key_control_challenges_v1 WHERE subject_id=?",
                    (message["subject_id"],),
                )
            result = {
                "schema": RESULT_SCHEMA,
                "action": action,
                "challenge_id": row["challenge_id"],
                "proof_id": proof_id,
                "verified_at": verified_at,
                "identity": resulting_identity,
                "binding": self.binding_status(conn, resulting_identity["subject_id"]),
                "previous_binding": (
                    self.binding_status(conn, message["subject_id"]) if action == "rotate" else None
                ),
                "authority_effect": "none",
                "standing_effect": "none",
            }
        return result

    @staticmethod
    def _check_expiry(
        message: dict[str, Any], row: dict[str, Any], now: datetime, mono: float
    ) -> None:
        if mono >= _finite(row["expires_monotonic"]) or now >= _utc(message["expires_at"]):
            raise KeyControlError("challenge_expired", 410, "The challenge lifetime has elapsed.")
        if mono < _finite(row["issued_monotonic"]) or now < _utc(message["issued_at"]):
            raise _inconsistent()

    def _active_record(self, conn: sqlite3.Connection, subject_id: str) -> dict[str, Any] | None:
        if not _has_control_tables(conn):
            return None
        binding = _one(
            conn, "SELECT * FROM sab_key_control_bindings_v1 WHERE subject_id=?", (subject_id,)
        )
        if binding is None or binding["status"] != "active":
            return binding
        try:
            identity = _recorded_identity(conn, subject_id, binding["public_key"])
            proof = _one(
                conn,
                "SELECT * FROM sab_key_control_proofs_v1 WHERE proof_id=?",
                (binding["proof_id"],),
            )
            if (
                identity is None
                or identity["revocation_status"] != "active"
                or _hash(identity) != binding["identity_sha256"]
                or proof is None
            ):
                raise _inconsistent()
            message = self._message(proof)
            if (
                message["audience"] != self.audience
                or message["action"] not in {"register", "rotate"}
                or message["proposed_identity"] != identity
                or message["challenge_id"] != proof["challenge_id"]
                or binding["proved_at"] != proof["verified_at"]
                or not _utc(message["issued_at"])
                <= _utc(proof["verified_at"])
                < _utc(message["expires_at"])
                or not self._verify_signatures(
                    message, proof["signature"], proof["successor_signature"]
                )
            ):
                raise _inconsistent()
        except KeyControlError as exc:
            raise _inconsistent() from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise _inconsistent() from exc
        return binding

    def require_active_binding(self, conn: sqlite3.Connection, subject_id: str) -> str:
        """Return the exact proven active public key; perform no schema repair."""
        binding = self._active_record(conn, subject_id)
        if binding is None:
            raise KeyControlError(
                "key_control_unproven",
                428,
                "A signed enrollment proof is required for this identity.",
            )
        if binding["status"] != "active":
            raise KeyControlError("key_control_inactive", 403, "The identity key has been retired.")
        return str(binding["public_key"])

    def binding_status(self, conn: sqlite3.Connection, subject_id: str) -> dict[str, Any]:
        """Observe a private current binding without promoting any authority."""
        inconsistent = False
        try:
            binding = self._active_record(conn, subject_id)
        except KeyControlError:
            binding = None
            inconsistent = True
        return {
            "schema": BINDING_SCHEMA,
            "subject_id": subject_id,
            "public_key": binding["public_key"] if binding else None,
            "status": (
                binding["status"] if binding else "inconsistent" if inconsistent else "unproven"
            ),
            "proof_id": (
                (binding["transition_proof_id"] or binding["proof_id"]) if binding else None
            ),
            "proved_at": (
                (binding["updated_at"] if binding["transition_proof_id"] else binding["proved_at"])
                if binding
                else None
            ),
            "successor_subject_id": binding["successor_subject_id"] if binding else None,
            "scope": "key_control_only",
            "authority_effect": "none",
            "standing_effect": "none",
        }
