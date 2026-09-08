"""Adversarial local identity-control lifecycle tests, with actual signatures."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event

import pytest
from nacl.signing import SigningKey

from agora import key_control as kc
from agora.sab_identity import canonical_json_bytes, subject_id_from_public_key
from agora.sab_seeding_api import _init_v1_tables

NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
ORIGIN = "https://agents.example.test"


class Clock:
    def __init__(self):
        self.wall = NOW
        self.mono = 1000.0

    def utc(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, seconds):
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def service(clock):
    return kc.KeyControlService(ORIGIN, utc_now=clock.utc, monotonic=clock.monotonic)


def connect(path=":memory:"):
    conn = sqlite3.connect(path, timeout=10)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS web_agents (
           id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key TEXT NOT NULL UNIQUE,
           created_at TEXT NOT NULL,witness_count INTEGER DEFAULT 0,witness_accuracy REAL DEFAULT 0.0)"""
    )
    _init_v1_tables(conn)
    conn.commit()
    return conn


@pytest.fixture
def conn():
    with connect() as value:
        yield value
    value.close()


def key(number=1):
    return SigningKey(bytes([number]) * 32)


def registration(signing_key=None, **extra):
    signing_key = signing_key or key()
    return {
        "display_name": "Control test agent",
        "public_key": signing_key.verify_key.encode().hex(),
        **extra,
    }


def sign(challenge, signing_key=None, *, successor=None, message=None):
    signing_key = signing_key or key()
    encoded = canonical_json_bytes(message or challenge["message"])
    result = {
        "challenge_id": challenge["message"]["challenge_id"],
        "signature": signing_key.sign(encoded).signature.hex(),
    }
    if successor is not None:
        result["successor_signature"] = successor.sign(encoded).signature.hex()
    return result


def enroll(service, conn, signing_key=None, **extra):
    challenge = service.issue(
        conn, {"action": "register", "registration": registration(signing_key, **extra)}
    )
    return service.verify(conn, sign(challenge, signing_key))


def snapshot(conn):
    return tuple(conn.iterdump())


def assert_failure(code, operation, conn):
    before = snapshot(conn)
    with pytest.raises(kc.KeyControlError) as error:
        operation()
    assert error.value.code == code
    assert snapshot(conn) == before
    assert not conn.in_transaction
    return error.value


def legacy_identity(conn, identity, *, web_only=False):
    conn.execute(
        "INSERT INTO web_agents VALUES (?,?,?,?,7,0.75)",
        (
            identity["subject_id"],
            identity["display_name"],
            identity["public_key"],
            identity["created_at"],
        ),
    )
    if not web_only:
        conn.execute(
            "INSERT INTO sab_agent_identities_v1 VALUES (?,?,?,?,?,?,?,?,?)",
            (
                identity["subject_id"],
                identity["display_name"],
                identity["public_key"],
                identity["controller"],
                identity["operator_backing"]["operator_id"],
                json.dumps(identity["operator_backing"]),
                json.dumps(identity),
                identity["created_at"],
                identity["created_at"],
            ),
        )
    conn.commit()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://agents.example.test", ORIGIN),
        ("https://AGENTS.example.test:443/", ORIGIN),
        ("https://agents.example.test:8443", ORIGIN + ":8443"),
        ("http://127.0.0.1:8000/", "http://127.0.0.1:8000"),
        ("http://127.42.1.5", "http://127.42.1.5"),
        ("http://localhost:80", "http://localhost"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("https://[2001:db8::1]:443", "https://[2001:db8::1]"),
    ],
)
def test_audience_is_configured_origin(raw, expected):
    assert kc.canonical_origin(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "http://agents.example.test",
        "http://192.168.0.1",
        "http://0.0.0.0",
        "http://127.0.0.1.evil.test",
        "http://localhost.evil.test",
        "ftp://localhost",
        "https://example.test/path",
        "https://example.test?x=1",
        "https://example.test?",
        "https://example.test#fragment",
        "https://example.test#",
        "https://user@example.test",
        "https://user:password@example.test",
        "https://example.test:0",
        "https://example.test:65536",
        "https://exam%70le.test",
        " https://example.test",
        "https://example.test\n",
        "https://example.test\\@evil.test",
        "https://-bad.example",
        "https://bad..example",
        "https://example.test.",
        "https://éxample.test",
        "http://127.1",
        "//localhost",
        "",
    ],
)
def test_audience_rejects_unsafe_or_non_origin_input(raw):
    with pytest.raises(ValueError):
        kc.canonical_origin(raw)


@pytest.mark.parametrize("ttl", [0, 121, -1, True, 1.5, "120"])
def test_challenge_lifetime_is_bounded(ttl):
    with pytest.raises(ValueError):
        kc.KeyControlService(ORIGIN, ttl_seconds=ttl)


def test_prepare_identity_normalizes_supported_registration():
    payload = registration(name="Agent name", display_name=" Agent name ")
    payload["public_key"] = payload["public_key"].upper()
    identity = kc.prepare_identity(payload, NOW)
    assert identity["public_key"] == payload["public_key"].lower()
    assert identity["subject_id"] == subject_id_from_public_key(identity["public_key"])
    assert identity["display_name"] == "Agent name"
    assert identity["revocation_status"] == "active"
    assert identity["operator_backing"]["backing_count_attestation"] == "unchecked"
    assert identity["evidence_refs"] == ["web_agents:" + identity["subject_id"]]
    assert "created_at" not in payload


@pytest.mark.parametrize(
    "change",
    [
        {"private_key": "do-not-reflect"},
        {"created_at": NOW.isoformat()},
        {"schema": "other.identity.v1"},
        {"revocation_status": "active"},
        {"evidence_refs": []},
        {"unexpected": 1},
        {"operator_backing": {"private_key": "do-not-reflect"}},
        {"operator_backing": {"operator_id": {"secret": "do-not-reflect"}}},
        {"external_attestations": [{"public_claims": {"access_token": "do-not-reflect"}}]},
        {"external_attestations": "wrong"},
        {"operator_backing": []},
        {"display_name": 123},
        {"display_name": ""},
        {"display_name": "x", "name": "y"},
        {"public_key": "z" * 64},
        {"public_key": "00" * 64},
        {"subject_id": "not-an-agent"},
        {"subject_id": "agent_ed25519_" + "f" * 32},
        {"external_attestations": [{"public_claims": {"x": float("nan")}}]},
    ],
)
def test_prepare_identity_rejects_unknown_private_and_invalid_fields(change):
    with pytest.raises(kc.KeyControlError) as error:
        kc.prepare_identity(registration(**change), NOW)
    assert error.value.code == "invalid_registration"
    assert "do-not-reflect" not in str(error.value)


def test_prepare_identity_requires_aware_server_timestamp():
    with pytest.raises(kc.KeyControlError):
        kc.prepare_identity(registration(), NOW.replace(tzinfo=None))


def test_reading_unproven_binding_creates_no_tables(service, conn):
    before = snapshot(conn)
    subject = subject_id_from_public_key(registration()["public_key"])
    assert service.binding_status(conn, subject)["status"] == "unproven"
    with pytest.raises(kc.KeyControlError) as error:
        service.require_active_binding(conn, subject)
    assert error.value.status == 428
    assert snapshot(conn) == before


def test_challenge_has_bound_purpose_and_no_identity_side_effect(service, conn):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    message = challenge["message"]
    assert set(challenge) == {
        "schema",
        "message",
        "canonicalization",
        "signature_algorithm",
        "authority_effect",
        "standing_effect",
    }
    assert message["audience"] == ORIGIN
    assert message["method"] == "POST" and message["path"] == "/api/v1/agents/verify"
    assert message["schema"] == "sab.key_control_message.v1"
    assert (
        message["proposed_identity_sha256"]
        == hashlib.sha256(canonical_json_bytes(message["proposed_identity"])).hexdigest()
    )
    assert (
        datetime.fromisoformat(message["expires_at"]) - datetime.fromisoformat(message["issued_at"])
    ).total_seconds() == 120
    assert challenge["authority_effect"] == challenge["standing_effect"] == "none"
    assert conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM sab_agent_identities_v1").fetchone()[0] == 0
    assert "instance_epoch" not in json.dumps(challenge)


def test_enrollment_is_single_use_durable_and_authority_free(service, conn, clock):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    proof = sign(challenge)
    result = service.verify(conn, proof)
    subject = result["identity"]["subject_id"]
    assert result["binding"]["status"] == "active"
    assert result["binding"]["scope"] == "key_control_only"
    assert result["previous_binding"] is None
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert service.require_active_binding(conn, subject) == registration()["public_key"]
    assert conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 1
    assert conn.execute("SELECT count(*) FROM sab_key_control_challenges_v1").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM sab_authority_leases_v1").fetchone()[0] == 0
    assert_failure("challenge_unavailable", lambda: service.verify(conn, proof), conn)
    restarted = kc.KeyControlService(ORIGIN, utc_now=clock.utc, monotonic=clock.monotonic)
    assert restarted.require_active_binding(conn, subject) == registration()["public_key"]
    assert restarted.binding_status(conn, subject) == result["binding"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("audience", "https://evil.example"),
        ("action", "revoke"),
        ("method", "GET"),
        ("path", "/api/v1/seeds/submit"),
        ("nonce", "a" * 64),
        ("challenge_id", "sab_kc_challenge_" + "b" * 32),
        ("subject_id", "agent_other"),
        ("public_key", "f" * 64),
        ("issued_at", "2026-09-09T11:59:59+00:00"),
        ("expires_at", "2026-09-09T13:00:00+00:00"),
        ("proposed_identity_sha256", "0" * 64),
    ],
)
def test_signing_modified_purpose_or_binding_fails_without_writes(service, conn, field, value):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    modified = copy.deepcopy(challenge["message"])
    modified[field] = value
    assert_failure(
        "invalid_signature", lambda: service.verify(conn, sign(challenge, message=modified)), conn
    )


def test_signing_modified_identity_does_not_authorize_original(service, conn):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    modified = copy.deepcopy(challenge["message"])
    modified["proposed_identity"]["controller"] = "self"
    assert_failure(
        "invalid_signature", lambda: service.verify(conn, sign(challenge, message=modified)), conn
    )


def test_wrong_private_key_has_no_writes_and_does_not_consume_nonce(service, conn):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    assert_failure("invalid_signature", lambda: service.verify(conn, sign(challenge, key(2))), conn)
    assert service.verify(conn, sign(challenge))["binding"]["status"] == "active"


@pytest.mark.parametrize(
    "change",
    [
        {"signature": "x" * 128},
        {"signature": "00" * 63},
        {"signature": None},
        {"signature": 100},
        {"challenge_id": "bad"},
        {"message": {"audience": "evil"}},
        {"private_key": "do-not-reflect"},
        {"successor_signature": "malformed"},
    ],
)
def test_malformed_or_extra_proof_fields_have_no_writes(service, conn, change):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    payload = {**sign(challenge), **change}
    assert_failure("invalid_proof", lambda: service.verify(conn, payload), conn)


def test_uppercase_hex_signature_is_equivalent(service, conn):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    payload = sign(challenge)
    payload["signature"] = payload["signature"].upper()
    assert service.verify(conn, payload)["binding"]["status"] == "active"


@pytest.mark.parametrize("elapsed,accepted", [(119.999999, True), (120, False), (121, False)])
def test_expiry_is_inclusive(service, conn, clock, elapsed, accepted):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    clock.advance(elapsed)
    if accepted:
        assert service.verify(conn, sign(challenge))["binding"]["status"] == "active"
    else:
        assert_failure("challenge_expired", lambda: service.verify(conn, sign(challenge)), conn)


def test_monotonic_expiry_cannot_be_extended_by_slow_utc(service, conn, clock):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    clock.mono += 120
    clock.wall += timedelta(seconds=116)
    assert_failure("challenge_expired", lambda: service.verify(conn, sign(challenge)), conn)


@pytest.mark.parametrize("mutation", ["wall_back", "wall_forward", "mono_back", "nan", "utc_naive"])
def test_clock_uncertainty_is_sticky_and_performs_no_writes(service, conn, clock, mutation):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    if mutation == "wall_back":
        clock.wall -= timedelta(microseconds=1)
    elif mutation == "wall_forward":
        clock.wall += timedelta(seconds=6)
    elif mutation == "mono_back":
        clock.mono -= 0.01
    elif mutation == "nan":
        clock.mono = float("nan")
    else:
        clock.wall = clock.wall.replace(tzinfo=None)
    assert_failure("clock_uncertain", lambda: service.verify(conn, sign(challenge)), conn)
    clock.wall, clock.mono = NOW, 1000
    assert_failure("clock_uncertain", lambda: service.verify(conn, sign(challenge)), conn)
    assert_failure(
        "clock_uncertain",
        lambda: service.issue(conn, {"action": "register", "registration": registration(key(2))}),
        conn,
    )


def test_failed_clock_callbacks_latch_uncertainty(conn, clock):
    service = kc.KeyControlService(ORIGIN, utc_now=clock.utc, monotonic=clock.monotonic)
    challenge = service.issue(conn, {"action": "register", "registration": registration()})

    def failed():
        raise RuntimeError("private diagnostic must not escape")

    service._utc_now = failed
    error = assert_failure("clock_uncertain", lambda: service.verify(conn, sign(challenge)), conn)
    assert "private diagnostic" not in error.detail


def test_restart_rejects_pending_and_preserves_consumed_proofs(service, conn, clock):
    old = enroll(service, conn)
    pending = service.issue(conn, {"action": "register", "registration": registration(key(2))})
    restarted = kc.KeyControlService(ORIGIN, utc_now=clock.utc, monotonic=clock.monotonic)
    assert_failure(
        "challenge_unavailable", lambda: restarted.verify(conn, sign(pending, key(2))), conn
    )
    assert (
        restarted.require_active_binding(conn, old["identity"]["subject_id"])
        == registration()["public_key"]
    )
    enroll(restarted, conn, key(2))
    assert conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 2
    assert_failure(
        "challenge_unavailable", lambda: service.verify(conn, sign(pending, key(2))), conn
    )


def test_concurrent_nonce_consumption_succeeds_exactly_once(service, tmp_path):
    path = tmp_path / "concurrent.sqlite"
    with connect(path) as conn:
        challenge = service.issue(conn, {"action": "register", "registration": registration()})
    barrier = Barrier(2)

    def run():
        conn = sqlite3.connect(path, timeout=10)
        barrier.wait()
        try:
            return service.verify(conn, sign(challenge))["binding"]["status"]
        except kc.KeyControlError as exc:
            return exc.code
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: run(), range(2)))
    assert sorted(results) == ["active", "challenge_unavailable"]
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 1


def test_existing_exact_named_identity_gets_proof_without_rewriting_history(service, conn):
    payload = registration(
        subject_id="agent_named_fixture",
        controller="operator",
        operator_backing={"operator_id": "recorded-operator"},
    )
    identity = kc.prepare_identity(payload, NOW - timedelta(days=30))
    identity["evidence_refs"].append("historical:existing")
    legacy_identity(conn, identity)
    before = tuple(conn.execute("SELECT * FROM web_agents")), tuple(
        conn.execute("SELECT * FROM sab_agent_identities_v1")
    )
    challenge = service.issue(conn, {"action": "register", "registration": payload})
    assert challenge["message"]["proposed_identity"] == identity
    result = service.verify(conn, sign(challenge))
    after = tuple(conn.execute("SELECT * FROM web_agents")), tuple(
        conn.execute("SELECT * FROM sab_agent_identities_v1")
    )
    assert before == after
    assert result["identity"] == identity
    assert service.require_active_binding(conn, identity["subject_id"]) == identity["public_key"]


def test_new_named_alias_requires_existing_complete_binding(service, conn):
    assert_failure(
        "canonical_identity_required",
        lambda: service.issue(
            conn,
            {"action": "register", "registration": registration(subject_id="agent_named_fixture")},
        ),
        conn,
    )


def test_partial_legacy_identity_requires_migration(service, conn):
    identity = kc.prepare_identity(registration(), NOW)
    legacy_identity(conn, identity, web_only=True)
    assert_failure(
        "authenticated_migration_required",
        lambda: service.issue(conn, {"action": "register", "registration": registration()}),
        conn,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"display_name": "replacement"},
        {"controller": "operator"},
        {"operator_backing": {"operator_id": "other"}},
        {"identity_ref": "sab_identity_replaced"},
    ],
)
def test_even_correct_key_cannot_rewrite_enrolled_metadata(service, conn, change):
    enroll(service, conn)
    assert_failure(
        "identity_conflict",
        lambda: service.issue(conn, {"action": "register", "registration": registration(**change)}),
        conn,
    )


def test_existing_registration_retry_preserves_identity_and_adds_proof(service, conn, clock):
    first = enroll(service, conn)
    clock.advance(1)
    second = enroll(service, conn)
    assert first["identity"] == second["identity"]
    assert first["proof_id"] != second["proof_id"]
    assert conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 2
    assert conn.execute("SELECT count(*) FROM sab_key_control_bindings_v1").fetchone()[0] == 1


def test_takeover_of_existing_subject_or_key_is_rejected(service, conn):
    enroll(service, conn)
    assert_failure(
        "identity_conflict",
        lambda: service.issue(
            conn, {"action": "register", "registration": registration(subject_id="agent_another")}
        ),
        conn,
    )


def test_identity_changed_between_issue_and_verify_conflicts_without_overwrite(service, conn):
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    different = kc.prepare_identity(registration(display_name="first durable writer"), NOW)
    legacy_identity(conn, different)
    assert_failure("identity_conflict", lambda: service.verify(conn, sign(challenge)), conn)


def test_proof_failure_rolls_back_schema_and_commit_trigger_failure_rolls_back_all(service, conn):
    payload = {"challenge_id": "sab_kc_challenge_" + "a" * 32, "signature": "00" * 64}
    assert_failure("challenge_unavailable", lambda: service.verify(conn, payload), conn)
    challenge = service.issue(conn, {"action": "register", "registration": registration()})
    conn.execute("""CREATE TRIGGER reject_binding BEFORE INSERT ON sab_key_control_bindings_v1
           BEGIN SELECT RAISE(ABORT, 'injected test failure'); END""")
    conn.commit()
    before = snapshot(conn)
    with pytest.raises(kc.KeyControlError) as error:
        service.verify(conn, sign(challenge))
    assert error.value.code == "key_control_storage_unavailable"
    assert "injected test failure" not in error.value.detail
    assert snapshot(conn) == before
    assert conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 0


def test_no_implicit_commit_of_callers_existing_transaction(service, conn):
    conn.execute("INSERT INTO web_agents VALUES ('agent_other','other','00','now',0,0)")
    with pytest.raises(kc.KeyControlError) as error:
        service.issue(conn, {"action": "register", "registration": registration()})
    assert error.value.code == "storage_transaction_active"
    assert conn.in_transaction
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 0


def test_revocation_requires_active_proof_and_prevents_reactivation(service, conn):
    subject = subject_id_from_public_key(registration()["public_key"])
    assert_failure(
        "key_control_unproven",
        lambda: service.issue(conn, {"action": "revoke", "subject_id": subject}),
        conn,
    )
    old = enroll(service, conn)
    pending = service.issue(conn, {"action": "register", "registration": registration()})
    challenge = service.issue(conn, {"action": "revoke", "subject_id": subject})
    assert challenge["message"]["proposed_identity"] is None
    assert challenge["message"]["proposed_identity_sha256"] is None
    result = service.verify(conn, sign(challenge))
    assert result["binding"]["status"] == "revoked"
    assert result["binding"]["proof_id"] == result["proof_id"]
    assert result["identity"] == {**old["identity"], "revocation_status": "revoked"}
    assert_failure(
        "key_control_inactive", lambda: service.require_active_binding(conn, subject), conn
    )
    assert_failure(
        "key_control_inactive",
        lambda: service.issue(conn, {"action": "register", "registration": registration()}),
        conn,
    )
    assert_failure("challenge_unavailable", lambda: service.verify(conn, sign(pending)), conn)
    assert conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 1


def test_rotation_requires_both_keys_and_transfers_no_authority_or_history(service, conn):
    first = enroll(service, conn)
    subject = first["identity"]["subject_id"]
    conn.execute(
        "UPDATE web_agents SET witness_count=7,witness_accuracy=0.8 WHERE id=?", (subject,)
    )
    conn.commit()
    challenge = service.issue(
        conn, {"action": "rotate", "subject_id": subject, "registration": registration(key(2))}
    )
    assert challenge["message"]["public_key"] == registration()["public_key"]
    assert (
        challenge["message"]["proposed_identity"]["public_key"]
        == registration(key(2))["public_key"]
    )
    assert_failure("invalid_signature", lambda: service.verify(conn, sign(challenge)), conn)
    assert_failure(
        "invalid_signature", lambda: service.verify(conn, sign(challenge, successor=key(3))), conn
    )
    assert_failure(
        "invalid_signature",
        lambda: service.verify(conn, sign(challenge, key(3), successor=key(2))),
        conn,
    )
    result = service.verify(conn, sign(challenge, successor=key(2)))
    successor_subject = result["identity"]["subject_id"]
    assert result["binding"]["status"] == "active"
    assert result["previous_binding"]["status"] == "superseded"
    assert result["previous_binding"]["proof_id"] == result["proof_id"]
    assert result["previous_binding"]["successor_subject_id"] == successor_subject
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert (
        service.require_active_binding(conn, successor_subject)
        == registration(key(2))["public_key"]
    )
    assert_failure(
        "key_control_inactive", lambda: service.require_active_binding(conn, subject), conn
    )
    assert conn.execute(
        "SELECT witness_count,witness_accuracy FROM web_agents WHERE id=?", (subject,)
    ).fetchone() == (7, 0.8)
    assert conn.execute(
        "SELECT witness_count,witness_accuracy FROM web_agents WHERE id=?", (successor_subject,)
    ).fetchone() == (0, 0.0)
    old_identity = json.loads(
        conn.execute(
            "SELECT identity_json FROM sab_agent_identities_v1 WHERE subject_id=?", (subject,)
        ).fetchone()[0]
    )
    assert old_identity == {**first["identity"], "revocation_status": "superseded"}
    assert conn.execute("SELECT count(*) FROM sab_authority_leases_v1").fetchone()[0] == 0


def test_rotation_existing_successor_conflicts_even_with_both_keys(service, conn):
    first = enroll(service, conn)
    enroll(service, conn, key(2))
    assert_failure(
        "identity_conflict",
        lambda: service.issue(
            conn,
            {
                "action": "rotate",
                "subject_id": first["identity"]["subject_id"],
                "registration": registration(key(2)),
            },
        ),
        conn,
    )


def test_rotation_to_same_key_conflicts(service, conn):
    first = enroll(service, conn)
    assert_failure(
        "identity_conflict",
        lambda: service.issue(
            conn,
            {
                "action": "rotate",
                "subject_id": first["identity"]["subject_id"],
                "registration": registration(),
            },
        ),
        conn,
    )


def test_successor_registration_race_rolls_back_rotation(service, conn):
    first = enroll(service, conn)
    challenge = service.issue(
        conn,
        {
            "action": "rotate",
            "subject_id": first["identity"]["subject_id"],
            "registration": registration(key(2)),
        },
    )
    enroll(service, conn, key(2))
    assert_failure(
        "identity_conflict", lambda: service.verify(conn, sign(challenge, successor=key(2))), conn
    )
    assert service.binding_status(conn, first["identity"]["subject_id"])["status"] == "active"


@pytest.mark.parametrize(
    "corruption",
    ["public_key", "metadata", "web_name", "missing_proof", "signature", "proof_audience"],
)
def test_active_binding_checks_exact_record_and_durable_signed_proof(service, conn, corruption):
    first = enroll(service, conn)
    subject = first["identity"]["subject_id"]
    if corruption == "public_key":
        conn.execute(
            "UPDATE sab_key_control_bindings_v1 SET public_key=?",
            (registration(key(2))["public_key"],),
        )
    elif corruption == "metadata":
        identity = copy.deepcopy(first["identity"])
        identity["display_name"] = "tampered"
        conn.execute("UPDATE sab_agent_identities_v1 SET identity_json=?", (json.dumps(identity),))
    elif corruption == "web_name":
        conn.execute("UPDATE web_agents SET name='tampered'")
    elif corruption == "missing_proof":
        conn.execute("DELETE FROM sab_key_control_proofs_v1")
    elif corruption == "signature":
        conn.execute("UPDATE sab_key_control_proofs_v1 SET signature=?", ("00" * 64,))
    else:
        row = conn.execute("SELECT message_json FROM sab_key_control_proofs_v1").fetchone()
        message = json.loads(row[0])
        message["audience"] = "https://other.example"
        encoded = canonical_json_bytes(message)
        signature = key().sign(encoded).signature.hex()
        conn.execute(
            "UPDATE sab_key_control_proofs_v1 SET message_json=?,message_sha256=?,signature=?",
            (encoded.decode(), hashlib.sha256(encoded).hexdigest(), signature),
        )
    conn.commit()
    assert service.binding_status(conn, subject)["status"] == "inconsistent"
    assert_failure(
        "key_control_inconsistent", lambda: service.require_active_binding(conn, subject), conn
    )


def test_origin_change_does_not_reinterpret_an_old_proof(service, conn, clock):
    first = enroll(service, conn)
    other = kc.KeyControlService(
        "https://other.example", utc_now=clock.utc, monotonic=clock.monotonic
    )
    assert other.binding_status(conn, first["identity"]["subject_id"])["status"] == "inconsistent"


def test_pending_challenges_are_unpredictable_and_subject_bounded(service, conn, clock):
    challenges = [
        service.issue(conn, {"action": "register", "registration": registration()})
        for _ in range(kc.MAX_PENDING_PER_SUBJECT)
    ]
    assert len({c["message"]["nonce"] for c in challenges}) == kc.MAX_PENDING_PER_SUBJECT
    assert len({c["message"]["challenge_id"] for c in challenges}) == kc.MAX_PENDING_PER_SUBJECT
    assert_failure(
        "key_control_capacity",
        lambda: service.issue(conn, {"action": "register", "registration": registration()}),
        conn,
    )
    clock.advance(120)
    fresh = service.issue(conn, {"action": "register", "registration": registration()})
    assert fresh["message"]["challenge_id"] not in {
        c["message"]["challenge_id"] for c in challenges
    }
    assert conn.execute("SELECT count(*) FROM sab_key_control_challenges_v1").fetchone()[0] == 1


def test_storage_saturation_preserves_revocation_and_all_proofs(service, conn, monkeypatch):
    monkeypatch.setattr(kc, "MAX_STORED_RECORDS", 8)
    monkeypatch.setattr(kc, "MAX_PENDING_CHALLENGES", 6)
    first = enroll(service, conn)
    subject = first["identity"]["subject_id"]
    # Re-proving this existing binding grows durable history but may never use
    # the allowance needed for its terminal revocation.
    for _ in range(4):
        enroll(service, conn)
    original_proofs = tuple(
        conn.execute("SELECT proof_id FROM sab_key_control_proofs_v1 ORDER BY proof_id")
    )
    assert len(original_proofs) == 5
    assert_failure(
        "key_control_capacity",
        lambda: service.issue(conn, {"action": "register", "registration": registration(key(2))}),
        conn,
    )
    # One ordinary challenge can occupy the last unreserved row.
    service.issue(conn, {"action": "register", "registration": registration()})
    assert_failure(
        "key_control_capacity",
        lambda: service.issue(conn, {"action": "register", "registration": registration()}),
        conn,
    )
    challenge = service.issue(conn, {"action": "revoke", "subject_id": subject})
    repeated = service.issue(conn, {"action": "revoke", "subject_id": subject})
    assert challenge == repeated
    assert service.verify(conn, sign(challenge))["binding"]["status"] == "revoked"
    remaining = set(conn.execute("SELECT proof_id FROM sab_key_control_proofs_v1"))
    assert set(original_proofs).issubset(remaining)
    assert len(remaining) == 6
    assert kc.KeyControlService._capacity(conn)[0] <= 8


def test_pending_saturation_does_not_block_revoke(service, conn, monkeypatch):
    monkeypatch.setattr(kc, "MAX_PENDING_PER_SUBJECT", 1)
    monkeypatch.setattr(kc, "MAX_PENDING_CHALLENGES", 2)
    first = enroll(service, conn)
    subject = first["identity"]["subject_id"]
    service.issue(conn, {"action": "register", "registration": registration()})
    assert_failure(
        "key_control_capacity",
        lambda: service.issue(conn, {"action": "register", "registration": registration()}),
        conn,
    )
    challenge = service.issue(conn, {"action": "revoke", "subject_id": subject})
    assert conn.execute("SELECT count(*) FROM sab_key_control_challenges_v1").fetchone()[0] == 2
    assert service.verify(conn, sign(challenge))["binding"]["status"] == "revoked"


def test_new_admission_rejects_before_spending_revocation_reserve(service, conn, monkeypatch):
    monkeypatch.setattr(kc, "MAX_STORED_RECORDS", 4)
    first = enroll(service, conn)
    assert_failure(
        "key_control_capacity",
        lambda: service.issue(conn, {"action": "register", "registration": registration(key(2))}),
        conn,
    )
    challenge = service.issue(
        conn, {"action": "revoke", "subject_id": first["identity"]["subject_id"]}
    )
    assert service.verify(conn, sign(challenge))["binding"]["status"] == "revoked"


def test_const_identity_schema_is_supported():
    assert kc.prepare_identity(
        registration(schema="sab.agent_identity.v1"), NOW
    ) == kc.prepare_identity(registration(), NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("public_key", 123),
        ("public_key", "z" * 64),
        ("subject_id", []),
        ("audience", "http://public.example"),
        ("issued_at", "invalid"),
        ("proposed_identity", {}),
    ],
)
def test_corrupt_durable_message_fails_closed_without_exception_leak(service, conn, field, value):
    first = enroll(service, conn)
    row = conn.execute("SELECT message_json FROM sab_key_control_proofs_v1").fetchone()
    message = json.loads(row[0])
    message[field] = value
    encoded = canonical_json_bytes(message)
    conn.execute(
        "UPDATE sab_key_control_proofs_v1 SET message_json=?,message_sha256=?",
        (encoded.decode(), hashlib.sha256(encoded).hexdigest()),
    )
    conn.commit()
    assert service.binding_status(conn, first["identity"]["subject_id"])["status"] == "inconsistent"
    assert_failure(
        "key_control_inconsistent",
        lambda: service.require_active_binding(conn, first["identity"]["subject_id"]),
        conn,
    )


def test_v1_transaction_and_control_mutation_use_consistent_lock_order(service, tmp_path):
    path = tmp_path / "ordered.sqlite"
    with connect(path) as initial:
        first = enroll(service, initial)
    attempting_begin = Event()

    class TrackedConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql == "BEGIN IMMEDIATE":
                attempting_begin.set()
            return super().execute(sql, *args, **kwargs)

    held = sqlite3.connect(path, timeout=5, check_same_thread=False)
    held.execute("BEGIN IMMEDIATE")

    def issue_while_v1_is_writing():
        separate = sqlite3.connect(path, timeout=5, factory=TrackedConnection)
        try:
            return service.issue(
                separate, {"action": "register", "registration": registration(key(2))}
            )
        finally:
            separate.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            pending = executor.submit(issue_while_v1_is_writing)
            assert attempting_begin.wait(2)
            gated = executor.submit(
                service.require_active_binding, held, first["identity"]["subject_id"]
            )
            try:
                assert gated.result(timeout=1) == registration()["public_key"]
            finally:
                held.rollback()
            assert pending.result(timeout=2)["schema"] == kc.CHALLENGE_SCHEMA
    finally:
        held.rollback()
        held.close()


def test_locked_storage_reports_stable_error_without_partial_writes(service, tmp_path):
    path = tmp_path / "locked.sqlite"
    with connect(path):
        pass
    holder = sqlite3.connect(path)
    separate = sqlite3.connect(path, timeout=0.01)
    try:
        holder.execute("BEGIN IMMEDIATE")
        with pytest.raises(kc.KeyControlError) as error:
            service.issue(separate, {"action": "register", "registration": registration()})
        assert error.value.code == "key_control_storage_unavailable"
        assert error.value.status == 503
        assert not separate.in_transaction
        assert "locked" not in error.value.detail
        holder.rollback()
        assert conn_count(separate, "web_agents") == 0
        assert (
            separate.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'sab_key_control_%'"
            ).fetchall()
            == []
        )
    finally:
        holder.rollback()
        holder.close()
        separate.close()


def conn_count(conn, table):
    assert table == "web_agents"
    return conn.execute("SELECT count(*) FROM web_agents").fetchone()[0]
