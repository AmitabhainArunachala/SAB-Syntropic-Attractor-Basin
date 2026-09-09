"""Browser session proofs use real synthetic keys and isolated SQLite storage."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import math
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event

import pytest
from nacl.signing import SigningKey

from agora import browser_sessions as bs
from agora.key_control import KeyControlService
from agora.sab_identity import canonical_json_bytes, subject_id_from_public_key

ORIGIN = "https://participant.example.test"
NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.wall = NOW
        self.mono = 100.1

    def advance(self, seconds):
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


def connect(path=":memory:"):
    conn = sqlite3.connect(path, timeout=5)
    conn.execute("""CREATE TABLE IF NOT EXISTS web_agents (
        id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,witness_count INTEGER DEFAULT 0,witness_accuracy REAL DEFAULT 0.0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_agent_identities_v1 (
        subject_id TEXT PRIMARY KEY,display_name TEXT NOT NULL,public_key TEXT NOT NULL,
        controller TEXT NOT NULL,operator_id TEXT NOT NULL,operator_backing_json TEXT NOT NULL,
        identity_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)""")
    conn.commit()
    return conn


class Rig:
    def __init__(self, conn):
        self.conn = conn
        self.clock = Clock()
        self.key = SigningKey(bytes([84]) * 32)
        self.other_key = SigningKey(bytes([85]) * 32)
        self.public = self.key.verify_key.encode().hex()
        self.subject = subject_id_from_public_key(self.public)
        self.control = self.new_control()
        self.service = self.new_service()
        challenge = self.control.issue(self.conn, {"action": "register", "registration": {
            "display_name": "Synthetic browser participant", "public_key": self.public,
        }})
        self.enrollment_signature = self.key.sign(canonical_json_bytes(challenge["message"])).signature.hex()
        self.control.verify(self.conn, {"challenge_id": challenge["message"]["challenge_id"],
                                        "signature": self.enrollment_signature})

    def new_control(self, origin=ORIGIN):
        return KeyControlService(origin, utc_now=lambda: self.clock.wall, monotonic=lambda: self.clock.mono)

    def new_service(self, control=None, **kwargs):
        return bs.BrowserSessionService(control or self.control, monotonic=lambda: self.clock.mono, **kwargs)

    def issue(self):
        return self.service.issue(self.conn, {"subject_id": self.subject})

    def signed(self, challenge=None, key=None):
        challenge = challenge or self.issue()
        return {"challenge_id": challenge["message"]["challenge_id"],
                "signature": (key or self.key).sign(canonical_json_bytes(challenge["message"])).signature.hex()}

    def login(self):
        return self.service.verify(self.conn, self.signed())

    def retire(self, *, rotate=False):
        payload = {"action": "rotate" if rotate else "revoke", "subject_id": self.subject}
        if rotate:
            payload["registration"] = {"display_name": "Synthetic successor", "public_key": self.other_key.verify_key.encode().hex()}
        challenge = self.control.issue(self.conn, payload)
        proof = {"challenge_id": challenge["message"]["challenge_id"],
                 "signature": self.key.sign(canonical_json_bytes(challenge["message"])).signature.hex()}
        if rotate:
            proof["successor_signature"] = self.other_key.sign(canonical_json_bytes(challenge["message"])).signature.hex()
        return self.control.verify(self.conn, proof)


@pytest.fixture
def rig():
    conn = connect()
    yield Rig(conn)
    conn.close()


def snapshot(conn):
    return tuple(conn.iterdump())


def denied(rig, operation, code=None):
    before = snapshot(rig.conn)
    transaction = rig.conn.in_transaction
    with pytest.raises(bs.BrowserSessionError) as result:
        operation()
    if code is not None:
        assert result.value.code == code
    assert snapshot(rig.conn) == before
    assert rig.conn.in_transaction == transaction
    return result.value


def read_none(rig, token):
    before = snapshot(rig.conn)
    assert rig.service.read(rig.conn, token) is None
    assert snapshot(rig.conn) == before


def test_exact_challenge_contract_uses_current_proved_key(rig):
    before = snapshot(rig.conn)
    challenge = rig.issue()
    assert set(challenge) == {"schema", "message", "signature_algorithm", "canonicalization", "authority_effect", "standing_effect"}
    assert challenge["schema"] == "sab.browser_session_challenge.v1"
    assert challenge["signature_algorithm"] == "ed25519"
    assert challenge["canonicalization"] == "json-sort-keys-compact-v1"
    assert challenge["authority_effect"] == challenge["standing_effect"] == "none"
    message = challenge["message"]
    assert set(message) == {"schema", "action", "audience", "method", "path", "challenge_id", "nonce",
                            "subject_id", "public_key", "issued_at", "expires_at"}
    assert message["schema"] == "sab.browser_session_message.v1" and message["action"] == "open_session"
    assert message["audience"] == ORIGIN and message["method"] == "POST" and message["path"] == bs.VERIFY_PATH
    assert message["subject_id"] == rig.subject and message["public_key"] == rig.public
    assert len(bytes.fromhex(message["nonce"])) == 32
    assert datetime.fromisoformat(message["expires_at"]) - datetime.fromisoformat(message["issued_at"]) == timedelta(seconds=120)
    assert snapshot(rig.conn) != before
    assert rig.conn.execute("SELECT count(*) FROM sab_browser_sessions_v1").fetchone()[0] == 0


def test_login_stores_only_cookie_hash_and_returns_no_authority(rig):
    result = rig.login()
    token = result["_session_token"]
    assert len(base64.urlsafe_b64decode(token + "=")) == 32
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert result["subject_id"] == rig.subject and result["public_key"] == rig.public
    assert result["display_name"] == "Synthetic browser participant"
    assert datetime.fromisoformat(result["expires_at"]) - datetime.fromisoformat(result["created_at"]) == timedelta(hours=6)
    data = "\n".join(snapshot(rig.conn))
    assert token not in data, "Raw cookie was persisted"
    assert result["csrf_token"] not in data, "Derived CSRF was needlessly persisted"
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    assert rig.conn.execute("SELECT token_sha256 FROM sab_browser_sessions_v1").fetchone()[0] == digest
    before = snapshot(rig.conn)
    public = rig.service.read(rig.conn, token)
    assert public is not None and "_session_token" not in public
    assert set(public) == {"schema", "subject_id", "public_key", "display_name", "created_at", "expires_at", "csrf_token",
                           "authority_effect", "standing_effect"}
    assert snapshot(rig.conn) == before
    assert rig.conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'sab_authority_%'").fetchall() == []


def test_session_reads_do_not_renew_absolute_expiry(rig):
    session = rig.login()
    token = session["_session_token"]
    before = snapshot(rig.conn)
    for seconds in (1, 599, 10000, 10999):
        rig.clock.advance(seconds)
        public = rig.service.read(rig.conn, token)
        assert public is not None and public["expires_at"] == session["expires_at"]
    assert snapshot(rig.conn) == before
    rig.clock.advance(1)
    read_none(rig, token)


def test_enrollment_signature_does_not_open_browser_session(rig):
    challenge = rig.issue()
    denied(rig, lambda: rig.service.verify(rig.conn, {"challenge_id": challenge["message"]["challenge_id"],
                                                    "signature": rig.enrollment_signature}), "browser_session_signature_invalid")


def test_replay_is_one_use_and_does_not_return_or_mint_another_cookie(rig):
    proof = rig.signed()
    rig.service.verify(rig.conn, proof)
    denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_challenge_unavailable")
    assert rig.conn.execute("SELECT count(*) FROM sab_browser_sessions_v1").fetchone()[0] == 1


def test_restart_invalidates_pending_challenge_but_preserves_accepted_session(rig):
    session = rig.login()
    proof = rig.signed()
    rig.clock.advance(20)
    rig.service = rig.new_service(rig.new_control())
    denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_challenge_unavailable")
    before = snapshot(rig.conn)
    assert rig.service.read(rig.conn, session["_session_token"]) is not None
    assert snapshot(rig.conn) == before
    rig.issue()
    assert rig.conn.execute("SELECT count(*) FROM sab_browser_session_challenges_v1").fetchone()[0] == 1


@pytest.mark.parametrize("payload", [None, [], {}, {"subject_id": None}, {"subject_id": "unknown"},
                                     {"subject_id": "agent_unknown", "private_key": "NEVER_REFLECT_SYNTHETIC"}])
def test_invalid_issue_is_closed_and_has_no_schema_effect(rig, payload):
    error = denied(rig, lambda: rig.service.issue(rig.conn, payload), "invalid_browser_session_request")
    assert "NEVER_REFLECT_SYNTHETIC" not in str(error)
    assert rig.conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'sab_browser_%'").fetchall() == []


@pytest.mark.parametrize("payload", [None, [], {}, {"challenge_id": "no", "signature": "0" * 128},
                                     {"challenge_id": "sab_browser_challenge_" + "a" * 32, "signature": "A" * 128},
                                     {"challenge_id": "sab_browser_challenge_" + "a" * 32, "signature": "0" * 128,
                                      "authority": "NEVER_REFLECT_SYNTHETIC"}])
def test_invalid_verify_is_closed_and_has_no_schema_effect(rig, payload):
    denied(rig, lambda: rig.service.verify(rig.conn, payload), "invalid_browser_session_request")
    assert rig.conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'sab_browser_%'").fetchall() == []


@pytest.mark.parametrize("token", [None, False, [], {}, "", "x" * 10000, "../cookie", "a" * 43 + "=", "a" * 43])
def test_invalid_or_unknown_cookie_read_never_creates_schema(rig, token):
    read_none(rig, token)
    assert rig.conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'sab_browser_%'").fetchall() == []


def test_unknown_well_formed_cookie_read_and_logout_have_no_schema_effect(rig):
    token = base64.urlsafe_b64encode(bytes([51]) * 32).rstrip(b"=").decode()
    read_none(rig, token)
    before = snapshot(rig.conn)
    assert rig.service.logout(rig.conn, token, bs.csrf_token_for(token))["signed_out"]
    assert snapshot(rig.conn) == before


def test_unproved_subject_does_not_receive_login_nonce(rig):
    subject = subject_id_from_public_key(rig.other_key.verify_key.encode().hex())
    denied(rig, lambda: rig.service.issue(rig.conn, {"subject_id": subject}), "browser_session_key_unavailable")


@pytest.mark.parametrize("rotate", [False, True])
def test_retirement_invalidates_issue_pending_proof_and_accepted_session(rig, rotate):
    session = rig.login()
    proof = rig.signed()
    rig.retire(rotate=rotate)
    denied(rig, lambda: rig.issue(), "browser_session_key_unavailable")
    denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_key_unavailable")
    read_none(rig, session["_session_token"])
    assert rig.service.logout(rig.conn, session["_session_token"], session["csrf_token"])["signed_out"]


def test_wrong_key_signature_is_rejected_without_consuming_nonce(rig):
    challenge = rig.issue()
    denied(rig, lambda: rig.service.verify(rig.conn, rig.signed(challenge, rig.other_key)), "browser_session_signature_invalid")
    assert rig.service.verify(rig.conn, rig.signed(challenge))["subject_id"] == rig.subject


@pytest.mark.parametrize("field,value", [("audience", "https://wrong.example.test"), ("path", "/api/v1/agents/verify"),
                                        ("method", "GET"), ("action", "register"), ("nonce", "0" * 64),
                                        ("subject_id", "agent_different")])
def test_signature_over_different_intent_does_not_verify(rig, field, value):
    challenge = rig.issue()
    forged = copy.deepcopy(challenge)
    forged["message"][field] = value
    denied(rig, lambda: rig.service.verify(rig.conn, rig.signed(forged)), "browser_session_signature_invalid")


@pytest.mark.parametrize("delta", [120, 121])
def test_inclusive_nonce_expiry(rig, delta):
    proof = rig.signed()
    rig.clock.advance(delta)
    denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_challenge_expired")


@pytest.mark.parametrize("origin", [63.01, 100.1, 120.001, 200.01])
def test_fractional_monotonic_origins_preserve_original_deadlines(rig, origin):
    rig.clock.mono = origin
    rig.control = rig.new_control()
    rig.service = rig.new_service()
    session = rig.login()
    assert rig.service.read(rig.conn, session["_session_token"]) is not None


@pytest.mark.parametrize("failure", ["wall_forward", "wall_backward", "monotonic_backward", "monotonic_nan"])
def test_clock_failure_latches_and_reads_do_not_authenticate(rig, failure):
    session = rig.login()
    if failure == "wall_forward":
        rig.clock.wall += timedelta(seconds=6)
    elif failure == "wall_backward":
        rig.clock.wall -= timedelta(seconds=1)
    elif failure == "monotonic_backward":
        rig.clock.mono -= 1
    else:
        rig.clock.mono = float("nan")
    read_none(rig, session["_session_token"])
    rig.clock.wall = NOW
    rig.clock.mono = 100.1
    denied(rig, lambda: rig.issue(), "browser_session_clock_uncertain")
    read_none(rig, session["_session_token"])
    assert rig.service.logout(rig.conn, session["_session_token"], session["csrf_token"])["signed_out"]
    event = json.loads(rig.conn.execute("SELECT event_json FROM sab_browser_session_revocations_v1").fetchone()[0])
    assert event["clock_status"] == "uncertain" and event["revoked_at"] is None


def test_utc_guard_blocks_expiry_even_if_wall_clock_lags_monotonic(rig):
    session = rig.login()
    rig.clock.advance(bs.SESSION_TTL_SECONDS - 3)
    rig.clock.mono += 3
    read_none(rig, session["_session_token"])


def test_restarted_clock_before_session_creation_does_not_authenticate(rig):
    session = rig.login()
    rig.clock.wall -= timedelta(seconds=1)
    rig.service = rig.new_service(rig.new_control())
    read_none(rig, session["_session_token"])


def test_a_different_configured_audience_cannot_use_the_cookie(rig):
    session = rig.login()
    rig.service = rig.new_service(rig.new_control("https://different.example.test"))
    read_none(rig, session["_session_token"])


def test_csrf_derivation_is_exact_and_logout_only_retires_one_cookie(rig):
    first, second = rig.login(), rig.login()
    token = first["_session_token"]
    expected = hmac.new(token.encode("ascii"), b"sab.browser_session.csrf.v1", hashlib.sha256).hexdigest()
    assert first["csrf_token"] == expected
    denied(rig, lambda: rig.service.logout(rig.conn, token, second["csrf_token"]), "browser_session_csrf_invalid")
    before = rig.conn.execute("SELECT record_json FROM sab_browser_sessions_v1 ORDER BY token_sha256").fetchall()
    assert rig.service.logout(rig.conn, token, expected)["signed_out"]
    read_none(rig, token)
    assert rig.service.read(rig.conn, second["_session_token"]) is not None
    assert rig.conn.execute("SELECT record_json FROM sab_browser_sessions_v1 ORDER BY token_sha256").fetchall() == before
    after = snapshot(rig.conn)
    rig.service.logout(rig.conn, token, expected)
    assert snapshot(rig.conn) == after
    rig.service = rig.new_service(rig.new_control())
    read_none(rig, token)


@pytest.mark.parametrize("csrf", [None, [], {}, "", "0" * 64, "A" * 64, "x" * 10000])
def test_bad_csrf_never_changes_session(rig, csrf):
    session = rig.login()
    denied(rig, lambda: rig.service.logout(rig.conn, session["_session_token"], csrf), "browser_session_csrf_invalid")


@pytest.mark.parametrize("column,value", [("subject_id", "agent_other"), ("public_key", "0" * 64),
                                         ("created_at", "2099-01-01T00:00:00Z"), ("expires_at", "2099-01-01T00:00:00Z"),
                                         ("record_json", "{}"), ("record_sha256", "0" * 64),
                                         ("challenge_id", "sab_browser_challenge_" + "0" * 32), ("status", "revoked")])
def test_session_reads_revalidate_columns_and_proof_history_without_repair(rig, column, value):
    session = rig.login()
    rig.conn.execute(f"UPDATE sab_browser_sessions_v1 SET {column}=?", (value,))
    rig.conn.commit()
    read_none(rig, session["_session_token"])


@pytest.mark.parametrize("column,value", [("message_json", "{}"), ("message_sha256", "0" * 64),
                                         ("subject_id", "agent_other"), ("record_sha256", "0" * 64),
                                         ("expires_monotonic", 999999.0)])
def test_pending_record_tampering_is_denied_without_consumption(rig, column, value):
    proof = rig.signed()
    rig.conn.execute(f"UPDATE sab_browser_session_challenges_v1 SET {column}=?", (value,))
    rig.conn.commit()
    denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_inconsistent")


def test_rewriting_unsigned_record_hash_does_not_replace_real_signature(rig):
    session = rig.login()
    row = rig.conn.execute("SELECT record_json FROM sab_browser_sessions_v1").fetchone()
    record = json.loads(row[0])
    record["message"]["nonce"] = "f" * 64
    rig.conn.execute("UPDATE sab_browser_sessions_v1 SET record_json=?,record_sha256=?",
                     (canonical_json_bytes(record).decode(), bs._hash(record)))
    rig.conn.commit()
    read_none(rig, session["_session_token"])


@pytest.mark.parametrize("corrupt", ["reset_status", "remove_event", "bad_cookie_proof"])
def test_logout_state_cannot_be_independently_reset_to_resurrect_session(rig, corrupt):
    session = rig.login()
    rig.service.logout(rig.conn, session["_session_token"], session["csrf_token"])
    if corrupt == "reset_status":
        rig.conn.execute("UPDATE sab_browser_sessions_v1 SET status='active'")
    elif corrupt == "remove_event":
        rig.conn.execute("DELETE FROM sab_browser_session_revocations_v1")
    else:
        rig.conn.execute("UPDATE sab_browser_session_revocations_v1 SET cookie_proof=?", ("0" * 64,))
    rig.conn.commit()
    read_none(rig, session["_session_token"])


def test_bounded_pending_admission_and_elapsed_cleanup(rig, monkeypatch):
    monkeypatch.setattr(bs, "MAX_PENDING_PER_SUBJECT", 2)
    rig.issue()
    rig.issue()
    denied(rig, lambda: rig.issue(), "browser_session_capacity")
    rig.clock.advance(120)
    rig.issue()
    assert rig.conn.execute("SELECT count(*) FROM sab_browser_session_challenges_v1").fetchone()[0] == 1


def test_bounded_sessions_preserve_logout_capacity_and_never_evict_live_cookie(rig, monkeypatch):
    monkeypatch.setattr(bs, "MAX_SESSION_RECORDS", 2)
    first, second = rig.login(), rig.login()
    denied(rig, lambda: rig.issue(), "browser_session_capacity")
    assert rig.service.read(rig.conn, first["_session_token"]) is not None
    assert rig.service.read(rig.conn, second["_session_token"]) is not None
    rig.service.logout(rig.conn, first["_session_token"], first["csrf_token"])
    rig.service.logout(rig.conn, second["_session_token"], second["csrf_token"])
    assert rig.conn.execute("SELECT count(*) FROM sab_browser_sessions_v1").fetchone()[0] == 2
    assert rig.conn.execute("SELECT count(*) FROM sab_browser_session_revocations_v1").fetchone()[0] == 2


def test_active_subject_limit_can_be_released_only_by_logout_or_expiry(rig, monkeypatch):
    monkeypatch.setattr(bs, "MAX_ACTIVE_SESSIONS_PER_SUBJECT", 1)
    session = rig.login()
    proof = rig.signed()
    denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_capacity")
    rig.service.logout(rig.conn, session["_session_token"], session["csrf_token"])
    assert rig.service.verify(rig.conn, proof)["subject_id"] == rig.subject


def test_verification_insertion_failure_rolls_back_and_preserves_nonce(rig):
    proof = rig.signed()
    rig.conn.execute("""CREATE TRIGGER synthetic_insert_failure BEFORE INSERT ON sab_browser_sessions_v1
        BEGIN SELECT RAISE(ABORT,'NEVER_REFLECT_SYNTHETIC'); END""")
    rig.conn.commit()
    error = denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_storage_unavailable")
    assert "NEVER_REFLECT_SYNTHETIC" not in str(error)
    rig.conn.execute("DROP TRIGGER synthetic_insert_failure")
    rig.conn.commit()
    assert rig.service.verify(rig.conn, proof)["subject_id"] == rig.subject


def test_logout_insertion_failure_does_not_revoke_or_erase_proof(rig):
    session = rig.login()
    rig.conn.execute("""CREATE TRIGGER synthetic_logout_failure BEFORE INSERT ON sab_browser_session_revocations_v1
        BEGIN SELECT RAISE(ABORT,'synthetic failure'); END""")
    rig.conn.commit()
    denied(rig, lambda: rig.service.logout(rig.conn, session["_session_token"], session["csrf_token"]),
           "browser_session_storage_unavailable")
    assert rig.service.read(rig.conn, session["_session_token"]) is not None


def test_caller_transaction_keeps_ownership_of_session_commit(rig):
    proof = rig.signed()
    rig.conn.execute("BEGIN IMMEDIATE")
    session = rig.service.verify(rig.conn, proof)
    assert rig.conn.in_transaction
    rig.conn.rollback()
    read_none(rig, session["_session_token"])
    assert rig.service.verify(rig.conn, proof)["subject_id"] == rig.subject


def test_read_is_compatible_with_read_only_sqlite(tmp_path):
    path = tmp_path / "sessions.sqlite3"
    conn = connect(path)
    rig = Rig(conn)
    session = rig.login()
    conn.close()
    before = path.read_bytes()
    readonly = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        assert rig.service.read(readonly, session["_session_token"]) is not None
    finally:
        readonly.close()
    assert path.read_bytes() == before


def test_two_real_connections_cannot_consume_same_browser_proof(tmp_path):
    path = tmp_path / "race.sqlite3"
    conn = connect(path)
    rig = Rig(conn)
    proof = rig.signed()
    barrier = Barrier(2)

    def consume():
        worker_conn = sqlite3.connect(path, timeout=5)
        try:
            barrier.wait(timeout=5)
            try:
                rig.service.verify(worker_conn, proof)
                return "accepted"
            except bs.BrowserSessionError as exc:
                return exc.code
        finally:
            worker_conn.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))
        assert sorted(results) == ["accepted", "browser_session_challenge_unavailable"]
        assert conn.execute("SELECT count(*) FROM sab_browser_sessions_v1").fetchone()[0] == 1
    finally:
        conn.close()


def test_held_retirement_transaction_serializes_before_browser_verification(tmp_path, monkeypatch):
    path = tmp_path / "retirement-race.sqlite3"
    conn = connect(path)
    rig = Rig(conn)
    proof = rig.signed()
    acquired, release, attempting, verifier_done = Event(), Event(), Event(), Event()
    challenge = rig.control.issue(conn, {"action": "revoke", "subject_id": rig.subject})
    observe = rig.control._now

    def hold_inside_real_retirement():
        # Key-control verification calls this only after its BEGIN IMMEDIATE.
        acquired.set()
        assert release.wait(5)
        return observe()

    monkeypatch.setattr(rig.control, "_now", hold_inside_real_retirement)

    def retire():
        worker_conn = sqlite3.connect(path, timeout=5)
        try:
            return rig.control.verify(worker_conn, {
                "challenge_id": challenge["message"]["challenge_id"],
                "signature": rig.key.sign(canonical_json_bytes(challenge["message"])).signature.hex(),
            })
        finally:
            worker_conn.close()

    def verify():
        worker_conn = sqlite3.connect(path, timeout=5)
        try:
            attempting.set()
            try:
                rig.service.verify(worker_conn, proof)
                return "accepted"
            except bs.BrowserSessionError as exc:
                return exc.code
        finally:
            verifier_done.set()
            worker_conn.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            retirement_result = pool.submit(retire)
            assert acquired.wait(5)
            verification_result = pool.submit(verify)
            assert attempting.wait(5)
            assert not verifier_done.wait(0.1)
            release.set()
            assert retirement_result.result(timeout=5)["binding"]["status"] == "revoked"
            assert verification_result.result(timeout=5) == "browser_session_key_unavailable"
        assert conn.execute("SELECT count(*) FROM sab_browser_sessions_v1").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM sab_browser_session_challenges_v1").fetchone()[0] == 1
    finally:
        release.set()
        conn.close()


@pytest.mark.parametrize("ttl", [0, 121, True, 1.5])
def test_constructor_rejects_invalid_challenge_lifetimes(rig, ttl):
    with pytest.raises(ValueError):
        rig.new_service(challenge_ttl_seconds=ttl)


def test_current_process_monotonic_deadline_tampering_is_detected(rig):
    proof = rig.signed()
    row = bs._one(rig.conn, "SELECT * FROM sab_browser_session_challenges_v1")
    row["expires_monotonic"] = math.nextafter(row["expires_monotonic"], math.inf)
    row["record_sha256"] = bs._pending_hash(row)
    rig.conn.execute("UPDATE sab_browser_session_challenges_v1 SET expires_monotonic=?,record_sha256=?",
                     (row["expires_monotonic"], row["record_sha256"]))
    rig.conn.commit()
    denied(rig, lambda: rig.service.verify(rig.conn, proof), "browser_session_inconsistent")
