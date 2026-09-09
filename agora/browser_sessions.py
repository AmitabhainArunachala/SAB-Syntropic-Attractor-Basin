"""Browser authentication from a fresh signature by an already proved key.

Sessions carry display context, never command authority or a participant signing
key. Only bearer-token hashes and authenticated proof history are durable. The
shared clock guard is local to one process, not authenticated civil time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any

from .key_control import KeyControlError, KeyControlService
from .sab_identity import SIGNATURE_CANONICALIZATION, canonical_json_bytes, verify_ed25519_signature

MESSAGE_SCHEMA = "sab.browser_session_message.v1"
CHALLENGE_SCHEMA = "sab.browser_session_challenge.v1"
SESSION_SCHEMA = "sab.browser_session.v1"
VERIFY_PATH = "/api/v1/browser/session/verify"
CHALLENGE_TTL_SECONDS = 120
SESSION_TTL_SECONDS = 6 * 60 * 60
MAX_PENDING_CHALLENGES = 512
MAX_PENDING_PER_SUBJECT = 4
MAX_SESSION_RECORDS = 10000
MAX_ACTIVE_SESSIONS_PER_SUBJECT = 16
SUBJECT_PATTERN = r"agent_[A-Za-z0-9_.:-]{2,154}"
CHALLENGE_ID_PATTERN = r"sab_browser_challenge_[0-9a-f]{32}"
CSRF_PURPOSE = b"sab.browser_session.csrf.v1"
_TOKEN_PATTERN = r"[A-Za-z0-9_-]{43}"
_HEX_PATTERN = r"[0-9a-f]{64}"
_UTC_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)"
_MESSAGE_FIELDS = frozenset({
    "schema", "action", "audience", "method", "path", "challenge_id", "nonce",
    "subject_id", "public_key", "issued_at", "expires_at",
})
_RECORD_FIELDS = frozenset({
    "schema", "token_sha256", "subject_id", "public_key", "challenge_id", "instance_epoch",
    "created_at", "expires_at", "created_monotonic", "expires_monotonic", "message", "signature",
})
_TABLES = ("sab_browser_session_challenges_v1", "sab_browser_sessions_v1", "sab_browser_session_revocations_v1")


class BrowserSessionError(Exception):
    """A fixed HTTP-safe error that never includes cookies or caller content."""

    def __init__(self, code: str, status: int, detail: str):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


def _invalid() -> BrowserSessionError:
    return BrowserSessionError("invalid_browser_session_request", 400, "Browser session request fields are invalid.")


def _inconsistent() -> BrowserSessionError:
    return BrowserSessionError("browser_session_inconsistent", 409, "The recorded browser proof and session do not agree.")


def _unavailable() -> BrowserSessionError:
    return BrowserSessionError("browser_session_challenge_unavailable", 409, "The browser challenge is unknown, consumed, or from another process.")


def _storage() -> BrowserSessionError:
    return BrowserSessionError("browser_session_storage_unavailable", 503, "Local browser session storage is unavailable.")


def _capacity() -> BrowserSessionError:
    return BrowserSessionError("browser_session_capacity", 429, "The local browser session admission limit has been reached.")


def _clock_error() -> BrowserSessionError:
    return BrowserSessionError("browser_session_clock_uncertain", 503, "Local clock uncertainty prevents browser authentication.")


def _match(value: Any, pattern: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise _invalid()
    return value


def _closed(value: Any, fields: frozenset[str] | set[str]) -> None:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise _invalid()


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _json(value: str) -> Any:
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("Duplicate JSON fields.")
            result[key] = item
        return result

    def constant(value):
        raise ValueError("Nonfinite JSON value.")

    if not isinstance(value, str) or len(value) > 8192:
        raise _inconsistent()
    parsed = json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
    if canonical_json_bytes(parsed).decode() != value:
        raise _inconsistent()
    return parsed


def _utc(value: Any) -> datetime:
    try:
        _match(value, _UTC_PATTERN)
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError) as exc:
        raise _inconsistent() from exc


def _finite(value: Any) -> float:
    try:
        if type(value) not in {int, float} or not math.isfinite(value):
            raise _inconsistent()
        return float(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise _inconsistent() from exc


def _token(value: Any) -> str | None:
    if not isinstance(value, str) or re.fullmatch(_TOKEN_PATTERN, value) is None:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        return None
    return value if len(decoded) == 32 and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() == value else None


def csrf_token_for(token: str) -> str:
    """Derive browser CSRF context without storing a second secret."""
    if _token(token) is None:
        raise _invalid()
    return hmac.new(token.encode("ascii"), CSRF_PURPOSE, hashlib.sha256).hexdigest()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def init_browser_session_tables(conn: sqlite3.Connection) -> None:
    """Create private session storage; never called by a session read."""
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_browser_session_challenges_v1 (
        challenge_id TEXT PRIMARY KEY, subject_id TEXT NOT NULL, instance_epoch TEXT NOT NULL,
        message_json TEXT NOT NULL, message_sha256 TEXT NOT NULL,
        issued_monotonic REAL NOT NULL, expires_monotonic REAL NOT NULL, record_sha256 TEXT NOT NULL
    )""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_sab_browser_pending_subject
        ON sab_browser_session_challenges_v1(subject_id)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_browser_sessions_v1 (
        token_sha256 TEXT PRIMARY KEY, subject_id TEXT NOT NULL, public_key TEXT NOT NULL,
        challenge_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active','revoked')),
        record_json TEXT NOT NULL, record_sha256 TEXT NOT NULL
    )""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_sab_browser_sessions_subject
        ON sab_browser_sessions_v1(subject_id,status,expires_at)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_browser_session_revocations_v1 (
        token_sha256 TEXT PRIMARY KEY, event_json TEXT NOT NULL, event_sha256 TEXT NOT NULL,
        cookie_proof TEXT NOT NULL
    )""")


def _one(conn: sqlite3.Connection, query: str, values: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    cursor = conn.execute(query, values)
    row = cursor.fetchone()
    return None if row is None else dict(zip((field[0] for field in cursor.description), row))


def _has_tables(conn: sqlite3.Connection) -> bool:
    count = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (?,?,?)", _TABLES).fetchone()[0]
    if count not in {0, 3}:
        raise _inconsistent()
    return count == 3


@contextmanager
def _transaction(conn: sqlite3.Connection, *, write: bool) -> Iterator[None]:
    owned = not conn.in_transaction
    savepoint = not owned and write
    try:
        if owned:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        elif savepoint:
            conn.execute("SAVEPOINT sab_browser_session_service")
            if _has_tables(conn):
                conn.execute("UPDATE sab_browser_sessions_v1 SET token_sha256=token_sha256 WHERE 0")
        yield
        if owned:
            conn.commit()
        elif savepoint:
            conn.execute("RELEASE SAVEPOINT sab_browser_session_service")
    except BaseException as exc:
        if owned:
            conn.rollback()
        elif savepoint:
            try:
                conn.execute("ROLLBACK TO SAVEPOINT sab_browser_session_service")
                conn.execute("RELEASE SAVEPOINT sab_browser_session_service")
            except sqlite3.Error:
                pass
        if isinstance(exc, sqlite3.Error):
            raise _storage() from exc
        raise


def _message(value: Any) -> dict[str, Any]:
    _closed(value, _MESSAGE_FIELDS)
    if (value["schema"] != MESSAGE_SCHEMA or value["action"] != "open_session"
            or value["method"] != "POST" or value["path"] != VERIFY_PATH):
        raise _inconsistent()
    _match(value["challenge_id"], CHALLENGE_ID_PATTERN)
    _match(value["subject_id"], SUBJECT_PATTERN)
    _match(value["public_key"], _HEX_PATTERN)
    _match(value["nonce"], _HEX_PATTERN)
    if not 0 < (_utc(value["expires_at"]) - _utc(value["issued_at"])).total_seconds() <= CHALLENGE_TTL_SECONDS:
        raise _inconsistent()
    return value


def _pending_hash(row: dict[str, Any]) -> str:
    return _hash({key: row[key] for key in (
        "challenge_id", "subject_id", "instance_epoch", "message_json", "message_sha256",
        "issued_monotonic", "expires_monotonic",
    )})


class BrowserSessionService:
    """One process's login nonce issuer and durable token-hash session reader."""

    init_browser_session_tables = staticmethod(init_browser_session_tables)

    def __init__(self, key_control: KeyControlService, *, monotonic: Callable[[], float] | None = None,
                 challenge_ttl_seconds: int = CHALLENGE_TTL_SECONDS):
        if type(challenge_ttl_seconds) is not int or not 1 <= challenge_ttl_seconds <= CHALLENGE_TTL_SECONDS:
            raise ValueError("Browser challenge lifetime must be an integer from 1 through 120 seconds.")
        self.key_control = key_control
        self.audience = key_control.audience
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self._monotonic = monotonic or time.monotonic
        self._epoch = secrets.token_hex(32)
        self._lock = RLock()
        self._clock_uncertain = False
        try:
            self._last_monotonic = _finite(self._monotonic())
        except Exception as exc:
            raise ValueError("Initial browser monotonic observation must be finite.") from exc

    def _now(self) -> tuple[datetime, float]:
        with self._lock:
            if self._clock_uncertain:
                raise _clock_error()
            try:
                now = self.key_control.observe_time()
                mono = _finite(self._monotonic())
                if mono < self._last_monotonic:
                    raise ValueError("Browser monotonic clock moved backward.")
                self._last_monotonic = mono
                return now, mono
            except Exception as exc:
                self._clock_uncertain = True
                raise _clock_error() from exc

    def _active_key(self, conn: sqlite3.Connection, subject: str, public_key: str | None = None) -> tuple[str, str]:
        try:
            key = self.key_control.require_active_binding(conn, subject)
            if public_key is not None and key != public_key:
                raise _inconsistent()
            # The control service has already checked both identity projections,
            # including legacy hexadecimal case. Read only its validated name.
            row = _one(conn, "SELECT name FROM web_agents WHERE id=?", (subject,))
            if row is None or not isinstance(row["name"], str) or not row["name"] or len(row["name"]) > 120:
                raise _inconsistent()
            return key, row["name"]
        except KeyControlError as exc:
            raise BrowserSessionError("browser_session_key_unavailable", exc.status,
                                      "Current control of the enrolled identity key is required.") from exc

    def _pending(self, row: dict[str, Any]) -> dict[str, Any]:
        try:
            message = _message(_json(row["message_json"]))
            duration = (_utc(message["expires_at"]) - _utc(message["issued_at"])).total_seconds()
            if (
                message["audience"] != self.audience or row["challenge_id"] != message["challenge_id"]
                or row["subject_id"] != message["subject_id"] or row["message_sha256"] != _hash(message)
                or row["record_sha256"] != _pending_hash(row)
                or _finite(row["expires_monotonic"]) != _finite(row["issued_monotonic"]) + duration
            ):
                raise _inconsistent()
            _match(row["instance_epoch"], _HEX_PATTERN)
            return message
        except (ValueError, TypeError, KeyError, BrowserSessionError) as exc:
            raise _inconsistent() from exc

    def issue(self, conn: sqlite3.Connection, payload: Any) -> dict[str, Any]:
        _closed(payload, {"subject_id"})
        subject = _match(payload["subject_id"], SUBJECT_PATTERN)
        with _transaction(conn, write=True):
            init_browser_session_tables(conn)
            now, mono = self._now()
            public_key, _ = self._active_key(conn, subject)
            # Pending nonces are not accepted proof history. Old-process and
            # elapsed nonces can be discarded only inside an explicit write.
            conn.execute("DELETE FROM sab_browser_session_challenges_v1 WHERE instance_epoch<>? OR expires_monotonic<=?",
                         (self._epoch, mono))
            total = conn.execute("SELECT count(*) FROM sab_browser_session_challenges_v1").fetchone()[0]
            per_subject = conn.execute("SELECT count(*) FROM sab_browser_session_challenges_v1 WHERE subject_id=?", (subject,)).fetchone()[0]
            sessions = conn.execute("SELECT count(*) FROM sab_browser_sessions_v1").fetchone()[0]
            if total >= MAX_PENDING_CHALLENGES or per_subject >= MAX_PENDING_PER_SUBJECT or sessions >= MAX_SESSION_RECORDS:
                raise _capacity()
            challenge_id = "sab_browser_challenge_" + secrets.token_hex(16)
            message = {
                "schema": MESSAGE_SCHEMA, "action": "open_session", "audience": self.audience,
                "method": "POST", "path": VERIFY_PATH, "challenge_id": challenge_id, "nonce": secrets.token_hex(32),
                "subject_id": subject, "public_key": public_key, "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=self.challenge_ttl_seconds)).isoformat(),
            }
            row = {"challenge_id": challenge_id, "subject_id": subject, "instance_epoch": self._epoch,
                   "message_json": canonical_json_bytes(message).decode(), "message_sha256": _hash(message),
                   "issued_monotonic": mono, "expires_monotonic": mono + self.challenge_ttl_seconds}
            row["record_sha256"] = _pending_hash(row)
            conn.execute("""INSERT INTO sab_browser_session_challenges_v1
                (challenge_id,subject_id,instance_epoch,message_json,message_sha256,issued_monotonic,expires_monotonic,record_sha256)
                VALUES (?,?,?,?,?,?,?,?)""", tuple(row.values()))
            return {"schema": CHALLENGE_SCHEMA, "message": message, "signature_algorithm": "ed25519",
                    "canonicalization": SIGNATURE_CANONICALIZATION, "authority_effect": "none", "standing_effect": "none"}

    def _stored(self, conn: sqlite3.Connection, token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        digest = _token_hash(token)
        row = _one(conn, "SELECT * FROM sab_browser_sessions_v1 WHERE token_sha256=?", (digest,))
        if row is None:
            return None
        try:
            record = _json(row["record_json"])
            _closed(record, _RECORD_FIELDS)
            if record["schema"] != "sab.browser_session_record.v1" or row["record_sha256"] != _hash(record):
                raise _inconsistent()
            for field in ("token_sha256", "subject_id", "public_key", "challenge_id", "created_at", "expires_at"):
                if row[field] != record[field]:
                    raise _inconsistent()
            if record["token_sha256"] != digest:
                raise _inconsistent()
            _match(record["instance_epoch"], _HEX_PATTERN)
            message = _message(record["message"])
            signature = _match(record["signature"], r"[0-9a-f]{128}")
            created, expires = _utc(record["created_at"]), _utc(record["expires_at"])
            if (
                message["audience"] != self.audience or message["subject_id"] != record["subject_id"]
                or message["public_key"] != record["public_key"] or message["challenge_id"] != record["challenge_id"]
                or not _utc(message["issued_at"]) <= created < _utc(message["expires_at"])
                or expires != created + timedelta(seconds=SESSION_TTL_SECONDS)
                or _finite(record["expires_monotonic"]) != _finite(record["created_monotonic"]) + SESSION_TTL_SECONDS
                or not verify_ed25519_signature(record["public_key"], canonical_json_bytes(message), signature)
            ):
                raise _inconsistent()
            retirement = _one(conn, "SELECT * FROM sab_browser_session_revocations_v1 WHERE token_sha256=?", (digest,))
            if row["status"] == "active":
                if retirement is not None:
                    raise _inconsistent()
            elif row["status"] == "revoked":
                if retirement is None:
                    raise _inconsistent()
                event = _json(retirement["event_json"])
                _closed(event, {"schema", "token_sha256", "session_record_sha256", "revoked_at", "clock_status"})
                proof = hmac.new(token.encode("ascii"), canonical_json_bytes(event), hashlib.sha256).hexdigest()
                if (
                    event["schema"] != "sab.browser_session_revocation.v1" or event["token_sha256"] != digest
                    or event["session_record_sha256"] != row["record_sha256"]
                    or retirement["event_sha256"] != _hash(event)
                    or not hmac.compare_digest(retirement["cookie_proof"], proof)
                ):
                    raise _inconsistent()
                if event["clock_status"] == "observed":
                    if _utc(event["revoked_at"]) < created:
                        raise _inconsistent()
                elif event["clock_status"] != "uncertain" or event["revoked_at"] is not None:
                    raise _inconsistent()
            else:
                raise _inconsistent()
            return row, record
        except (ValueError, TypeError, KeyError, BrowserSessionError) as exc:
            raise _inconsistent() from exc

    @staticmethod
    def _observation(record: dict[str, Any], name: str, token: str) -> dict[str, Any]:
        return {"schema": SESSION_SCHEMA, "subject_id": record["subject_id"], "public_key": record["public_key"],
                "display_name": name, "created_at": record["created_at"], "expires_at": record["expires_at"],
                "csrf_token": csrf_token_for(token), "authority_effect": "none", "standing_effect": "none"}

    def verify(self, conn: sqlite3.Connection, payload: Any) -> dict[str, Any]:
        _closed(payload, {"challenge_id", "signature"})
        challenge_id = _match(payload["challenge_id"], CHALLENGE_ID_PATTERN)
        signature = _match(payload["signature"], r"[0-9a-f]{128}")
        with _transaction(conn, write=True):
            if not _has_tables(conn):
                raise _unavailable()
            row = _one(conn, "SELECT * FROM sab_browser_session_challenges_v1 WHERE challenge_id=?", (challenge_id,))
            if row is None or row["instance_epoch"] != self._epoch:
                raise _unavailable()
            message = self._pending(row)
            now, mono = self._now()
            if now >= _utc(message["expires_at"]) or mono >= _finite(row["expires_monotonic"]):
                raise BrowserSessionError("browser_session_challenge_expired", 410, "The browser challenge lifetime has elapsed.")
            if now < _utc(message["issued_at"]) or mono < _finite(row["issued_monotonic"]):
                raise _inconsistent()
            _, name = self._active_key(conn, message["subject_id"], message["public_key"])
            if not verify_ed25519_signature(message["public_key"], canonical_json_bytes(message), signature):
                raise BrowserSessionError("browser_session_signature_invalid", 403, "The browser key-control signature does not verify.")
            if _one(conn, "SELECT token_sha256 FROM sab_browser_sessions_v1 WHERE challenge_id=?", (challenge_id,)):
                raise _unavailable()
            total = conn.execute("SELECT count(*) FROM sab_browser_sessions_v1").fetchone()[0]
            active = conn.execute("SELECT expires_at FROM sab_browser_sessions_v1 WHERE subject_id=? AND status='active'",
                                  (message["subject_id"],)).fetchall()
            if total >= MAX_SESSION_RECORDS or sum(_utc(item[0]) > now for item in active) >= MAX_ACTIVE_SESSIONS_PER_SUBJECT:
                raise _capacity()
            token = secrets.token_urlsafe(32)
            digest = _token_hash(token)
            record = {"schema": "sab.browser_session_record.v1", "token_sha256": digest,
                      "subject_id": message["subject_id"], "public_key": message["public_key"],
                      "challenge_id": challenge_id, "instance_epoch": self._epoch,
                      "created_at": now.isoformat(), "expires_at": (now + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat(),
                      "created_monotonic": mono, "expires_monotonic": mono + SESSION_TTL_SECONDS,
                      "message": message, "signature": signature}
            conn.execute("""INSERT INTO sab_browser_sessions_v1
                (token_sha256,subject_id,public_key,challenge_id,created_at,expires_at,status,record_json,record_sha256)
                VALUES (?,?,?,?,?,?,'active',?,?)""", (
                digest, record["subject_id"], record["public_key"], challenge_id, record["created_at"], record["expires_at"],
                canonical_json_bytes(record).decode(), _hash(record),
            ))
            if conn.execute("DELETE FROM sab_browser_session_challenges_v1 WHERE challenge_id=? AND instance_epoch=?",
                            (challenge_id, self._epoch)).rowcount != 1:
                raise _unavailable()
            return {**self._observation(record, name, token), "_session_token": token}

    def read(self, conn: sqlite3.Connection, token: Any) -> dict[str, Any] | None:
        """Observe an authenticated cookie without renewal, mutation or repair."""
        if _token(token) is None:
            return None
        try:
            with _transaction(conn, write=False):
                if not _has_tables(conn):
                    return None
                stored = self._stored(conn, token)
                if stored is None:
                    return None
                row, record = stored
                if row["status"] != "active":
                    return None
                now, mono = self._now()
                if not _utc(record["created_at"]) <= now < _utc(record["expires_at"]):
                    return None
                if record["instance_epoch"] == self._epoch and not (
                    _finite(record["created_monotonic"]) <= mono < _finite(record["expires_monotonic"])
                ):
                    return None
                _, name = self._active_key(conn, record["subject_id"], record["public_key"])
                return self._observation(record, name, token)
        except (BrowserSessionError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
            return None

    def logout(self, conn: sqlite3.Connection, token: Any, csrf: Any) -> dict[str, Any]:
        if (_token(token) is None or not isinstance(csrf, str) or re.fullmatch(_HEX_PATTERN, csrf) is None
                or not hmac.compare_digest(csrf_token_for(token), csrf)):
            raise BrowserSessionError("browser_session_csrf_invalid", 403, "A matching browser session CSRF token is required.")
        result = {"schema": "sab.browser_session_logout.v1", "signed_out": True,
                  "authority_effect": "none", "standing_effect": "none"}
        with _transaction(conn, write=True):
            if not _has_tables(conn):
                return result
            stored = self._stored(conn, token)
            if stored is None or stored[0]["status"] == "revoked":
                return result
            row, record = stored
            try:
                now, _ = self._now()
                if now < _utc(record["created_at"]):
                    raise _clock_error()
                stamp, clock_status = now.isoformat(), "observed"
            except BrowserSessionError:
                # Closing a known cookie needs no time-based permission. A
                # clock failure cannot force a user to retain a live session.
                stamp, clock_status = None, "uncertain"
            event = {"schema": "sab.browser_session_revocation.v1", "token_sha256": row["token_sha256"],
                     "session_record_sha256": row["record_sha256"], "revoked_at": stamp, "clock_status": clock_status}
            proof = hmac.new(token.encode("ascii"), canonical_json_bytes(event), hashlib.sha256).hexdigest()
            conn.execute("""INSERT INTO sab_browser_session_revocations_v1
                (token_sha256,event_json,event_sha256,cookie_proof) VALUES (?,?,?,?)""", (
                row["token_sha256"], canonical_json_bytes(event).decode(), _hash(event), proof,
            ))
            conn.execute("UPDATE sab_browser_sessions_v1 SET status='revoked' WHERE token_sha256=?", (row["token_sha256"],))
            return result
