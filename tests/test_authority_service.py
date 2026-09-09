"""Real Ed25519 and isolated SQLite evidence for issued local permissions."""

from __future__ import annotations

import copy
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event

import pytest
from nacl.signing import SigningKey

from agora import authority as au
from agora.key_control import KeyControlService
from agora.sab_identity import subject_id_from_public_key

NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
ORIGIN = "https://authority.example.test"
SEED = "sab_seed_authority_service"


class Clock:
    def __init__(self):
        self.wall = NOW
        self.mono = 100.5

    def advance(self, seconds):
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


def connect(path=":memory:"):
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS web_agents (
        id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,witness_count INTEGER DEFAULT 0,witness_accuracy REAL DEFAULT 0.0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_agent_identities_v1 (
        subject_id TEXT PRIMARY KEY,display_name TEXT NOT NULL,public_key TEXT NOT NULL,
        controller TEXT NOT NULL,operator_id TEXT NOT NULL,operator_backing_json TEXT NOT NULL,
        identity_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)""")
    conn.commit()
    return conn


def sign(key, message):
    return key.sign(au.canonical_bytes(message)).signature.hex()


class Rig:
    def __init__(self, conn):
        self.conn = conn
        self.clock = Clock()
        self.keys = {name: SigningKey(bytes([index]) * 32) for index, name in enumerate(
            ("subject", "issuer", "witness", "revoker", "other"), start=31)}
        self.control = self.new_control()
        for name, key in self.keys.items():
            challenge = self.control.issue(conn, {"action": "register", "registration": {
                "public_key": self.public(name), "display_name": f"Synthetic {name}",
            }})
            self.control.verify(conn, {"challenge_id": challenge["message"]["challenge_id"],
                                       "signature": sign(key, challenge["message"])})
        self.policy = {
            "schema": au.POLICY_SCHEMA, "audience": ORIGIN, "policy_id": "sab_policy_synthetic_authority",
            "not_before": (NOW - timedelta(days=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=10)).isoformat(),
            "issuers": [{"subject_id": self.subject("issuer"), "public_key": self.public("issuer"),
                         "allowed_actions": sorted(au.ACTION_VOCABULARY), "allowed_seed_ids": [SEED],
                         "all_seeds": False, "max_ttl_seconds": 86400, "revoker_ids": [self.subject("revoker")]}],
            "witnesses": [{"subject_id": self.subject("witness"), "public_key": self.public("witness")}],
            "revokers": [{"subject_id": self.subject("revoker"), "public_key": self.public("revoker")}],
        }
        self.service = au.AuthorityService(self.policy, self.control)

    def new_control(self):
        return KeyControlService(ORIGIN, utc_now=lambda: self.clock.wall, monotonic=lambda: self.clock.mono)

    def public(self, name):
        return self.keys[name].verify_key.encode().hex()

    def subject(self, name):
        return subject_id_from_public_key(self.public(name))

    def envelope(self, suffix="one", *, lease_changes=None, witness_changes=None, policy=None):
        policy = policy or self.policy
        now = self.clock.wall
        lease_id = f"sab_lease_authority_{suffix}"
        lease = {
            "schema": au.LEASE_SCHEMA, "lease_id": lease_id, "audience": ORIGIN,
            "policy_hash": au.hash_json(policy), "subject_id": self.subject("subject"),
            "subject_public_key": self.public("subject"), "issuer_id": self.subject("issuer"),
            "issuer_public_key": self.public("issuer"), "target_seed_id": SEED,
            "purpose": "Synthetic permission for one resource", "scope": "Exact seed; no derived standing",
            "allowed_actions": ["submit_seed", "submit_challenge"], "forbidden_actions": [],
            "allowed_reliance": [], "forbidden_reliance": ["truth", "independent_operator"],
            "issued_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
            "revoker_id": self.subject("revoker"), "revoker_public_key": self.public("revoker"),
            "challenge_path": f"/api/v1/authority/leases/{lease_id}/challenges", "evidence_refs": ["test:synthetic"],
        }
        lease.update(lease_changes or {})
        issuer_signature = sign(self.keys["issuer"], lease)
        witness = {"schema": au.WITNESS_SCHEMA, "event_id": f"sab_authority_witness_{suffix}",
                   "audience": ORIGIN, "policy_hash": au.hash_json(policy),
                   "lease_sha256": au.hash_json({"lease": lease, "issuer_signature": issuer_signature}),
                   "witness_id": self.subject("witness"), "witness_public_key": self.public("witness"),
                   "observed_at": now.isoformat()}
        witness.update(witness_changes or {})
        witness["signature"] = sign(self.keys["witness"], witness)
        return {"lease": lease, "issuer_signature": issuer_signature, "issuance_witness": witness}

    def issue(self, *args, **kwargs):
        return self.service.issue(self.conn, self.envelope(*args, **kwargs))

    def authorize(self, reference=None, **overrides):
        fields = {"subject_id": self.subject("subject"), "action": "submit_seed", "target_seed_id": SEED}
        fields.update(overrides)
        return self.service.authorize(self.conn, reference or {"lease_ref": "sab_lease_authority_one"}, **fields)

    def retirement(self, envelope, *, suffix="one", changes=None):
        now = self.clock.wall
        lease = envelope["lease"]
        command = {"schema": au.REVOCATION_SCHEMA, "command_id": f"sab_authority_revoke_{suffix}",
                   "audience": ORIGIN, "lease_id": lease["lease_id"],
                   "lease_sha256": au.hash_json({"lease": lease, "issuer_signature": envelope["issuer_signature"]}),
                   "revoker_id": self.subject("revoker"), "revoker_public_key": self.public("revoker"),
                   "reason": "End synthetic permission", "issued_at": now.isoformat(),
                   "expires_at": (now + timedelta(seconds=90)).isoformat()}
        command.update(changes or {})
        return {"revocation": command, "signature": sign(self.keys["revoker"], command)}

    def retire_key(self, name):
        challenge = self.control.issue(self.conn, {"action": "revoke", "subject_id": self.subject(name)})
        return self.control.verify(self.conn, {"challenge_id": challenge["message"]["challenge_id"],
                                               "signature": sign(self.keys[name], challenge["message"])})


@pytest.fixture
def rig():
    conn = connect()
    yield Rig(conn)
    conn.close()


def snapshot(conn):
    return tuple(conn.iterdump())


def denied(rig, operation, code=None):
    before = snapshot(rig.conn)
    was_active = rig.conn.in_transaction
    with pytest.raises(au.AuthorityError) as result:
        operation()
    if code:
        assert result.value.code == code
    assert snapshot(rig.conn) == before
    assert rig.conn.in_transaction == was_active
    return result.value


def test_real_issue_use_observation_and_exact_retry(rig):
    payload = rig.envelope()
    issued = rig.service.issue(rig.conn, payload)
    assert issued["created"] is True and issued["status"] == "active"
    assert {key: issued[key] for key in payload} == payload
    assert issued["lease_sha256"] == au.hash_json({"lease": payload["lease"], "issuer_signature": payload["issuer_signature"]})
    assert issued["envelope_sha256"] == au.hash_json(payload)
    assert issued["authority_effect"] == issued["standing_effect"] == issued["reliance_effect"] == "none"
    before = snapshot(rig.conn)
    assert rig.authorize(au.lease_reference(issued))["status"] == "active"
    assert rig.service.get(rig.conn, issued["lease_id"])["lease"] == payload["lease"]
    assert rig.service.list_for_subject(rig.conn, rig.subject("subject"))[0]["lease_id"] == issued["lease_id"]
    assert rig.service.issue(rig.conn, payload) == {**issued, "created": False}
    assert snapshot(rig.conn) == before


def test_policy_is_explicit_defensive_copy_and_exact_audience(rig):
    original_hash = rig.service.policy_hash
    rig.policy["issuers"][0]["all_seeds"] = True
    returned = rig.service.policy
    returned["audience"] = "https://wrong.example.test"
    assert rig.service.policy_hash == original_hash
    assert rig.service.policy["audience"] == ORIGIN
    wrong = copy.deepcopy(rig.service.policy)
    wrong["audience"] = "https://wrong.example.test"
    with pytest.raises(au.AuthorityError):
        au.AuthorityService(wrong, rig.control)


def test_missing_policy_never_creates_implicit_issuer_or_tables(rig):
    rig.service = au.AuthorityService(None, rig.control)
    assert rig.service.policy is rig.service.policy_hash is None
    assert not rig.service.enabled
    denied(rig, lambda: rig.service.issue(rig.conn, rig.envelope()), "authority_required")
    denied(rig, lambda: rig.authorize(), "authority_unknown")
    before = snapshot(rig.conn)
    assert rig.service.list_for_subject(rig.conn, rig.subject("subject")) == []
    denied(rig, lambda: rig.service.get(rig.conn, "sab_lease_unknown"), "authority_unknown")
    assert snapshot(rig.conn) == before
    assert rig.conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'sab_authority_%'").fetchall() == []


@pytest.mark.parametrize("change", [
    lambda p: p.update(secret="NEVER_REFLECT_SYNTHETIC"),
    lambda p: p.update(schema="sab.authority_policy.v2"),
    lambda p: p.update(audience=ORIGIN + "/"),
    lambda p: p.update(not_before=123),
    lambda p: p.update(not_before="2026-09-09T00:00:00"),
    lambda p: p.update(not_before="2026-09-09T09:00:00+09:00"),
    lambda p: p.update(expires_at=p["not_before"]),
    lambda p: p.update(issuers=[]),
    lambda p: p.update(witnesses=p["witnesses"] * 33),
    lambda p: p["issuers"][0].update(max_ttl_seconds=True),
    lambda p: p["issuers"][0].update(max_ttl_seconds=31 * 86400 + 1),
    lambda p: p["issuers"][0].update(max_ttl_seconds=1.5),
    lambda p: p["issuers"][0].update(all_seeds=1),
    lambda p: p["issuers"][0].update(all_seeds=True),
    lambda p: p["issuers"][0].update(allowed_seed_ids=[]),
    lambda p: p["issuers"][0].update(allowed_seed_ids=["sab_seed_*"]),
    lambda p: p["issuers"][0].update(allowed_actions=["*"]),
    lambda p: p["issuers"][0].update(allowed_actions=["submit_seed", "submit_seed"]),
    lambda p: p["issuers"][0].update(revoker_ids=["agent_unknown"]),
    lambda p: p["issuers"][0].update(private_key="NEVER_REFLECT_SYNTHETIC"),
    lambda p: p["witnesses"][0].update(subject_id=p["issuers"][0]["subject_id"], public_key=p["issuers"][0]["public_key"]),
    lambda p: p["witnesses"][0].update(public_key=p["issuers"][0]["public_key"]),
    lambda p: p["revokers"][0].update(subject_id=p["issuers"][0]["subject_id"]),
])
def test_closed_policy_and_role_collision_checks(rig, change):
    policy = copy.deepcopy(rig.policy)
    change(policy)
    with pytest.raises(au.AuthorityError) as error:
        au.validate_policy(policy)
    assert "NEVER_REFLECT_SYNTHETIC" not in str(error.value)


def test_explicit_all_seed_root_still_has_exact_child_seed(rig):
    policy = copy.deepcopy(rig.policy)
    policy["issuers"][0].update(all_seeds=True, allowed_seed_ids=[])
    rig.service = au.AuthorityService(policy, rig.control)
    value = rig.envelope(policy=policy, lease_changes={"target_seed_id": "sab_seed_another"})
    rig.service.issue(rig.conn, value)
    assert rig.authorize(target_seed_id="sab_seed_another")["status"] == "active"
    denied(rig, lambda: rig.authorize(), "authority_scope_denied")


def test_issuer_may_be_designated_revoker(rig):
    policy = copy.deepcopy(rig.policy)
    policy["revokers"] = [{"subject_id": rig.subject("issuer"), "public_key": rig.public("issuer")}]
    policy["issuers"][0]["revoker_ids"] = [rig.subject("issuer")]
    service = au.AuthorityService(policy, rig.control)
    envelope = rig.envelope(policy=policy, lease_changes={"revoker_id": rig.subject("issuer"),
                                                        "revoker_public_key": rig.public("issuer")})
    assert service.issue(rig.conn, envelope)["status"] == "active"


@pytest.mark.parametrize("field,value", [
    ("schema", "sab.authority_lease.v1"), ("lease_id", "sab_lease_../bad"),
    ("audience", "https://elsewhere.example.test"), ("policy_hash", "0" * 64),
    ("subject_public_key", "A" * 64), ("target_seed_id", "sab_seed_*") ,
    ("target_seed_id", "sab_seed_other"), ("scope", " "), ("purpose", "x\ny"),
    ("allowed_actions", []), ("allowed_actions", ["submit_seed", "submit_seed"]),
    ("allowed_actions", ["invented_action"]), ("forbidden_actions", ["submit_seed"]),
    ("allowed_reliance", ["truth"]), ("forbidden_reliance", ["x"] * 65),
    ("evidence_refs", ["x"] * 65), ("challenge_path", "https://elsewhere.example.test/challenge"),
    ("issued_at", 0), ("expires_at", "2026-09-09T13:00:00"), ("scope", "x" * 2049),
    ("token", "NEVER_REFLECT_SYNTHETIC"), ("expires_at", "2026-09-10T12:00:00.000001+00:00"),
])
def test_signed_but_invalid_child_cannot_acquire_authority(rig, field, value):
    error = denied(rig, lambda: rig.service.issue(rig.conn, rig.envelope(lease_changes={field: value})))
    assert "NEVER_REFLECT_SYNTHETIC" not in str(error)


@pytest.mark.parametrize("path", [
    ("lease", "scope"), ("lease", "allowed_actions"), ("lease", "subject_id"),
    ("issuance_witness", "observed_at"), ("issuance_witness", "event_id"),
])
def test_tampering_after_signing_rejected_atomically(rig, path):
    value = rig.envelope()
    container, field = path
    value[container][field] = ["correct_seed"] if field == "allowed_actions" else (
        rig.subject("other") if field == "subject_id" else
        (NOW - timedelta(seconds=1)).isoformat() if field == "observed_at" else "sab_changed_content")
    denied(rig, lambda: rig.service.issue(rig.conn, value))


@pytest.mark.parametrize("mutation", [
    lambda r, p: p.update(issuer_signature="00" * 64),
    lambda r, p: p["issuance_witness"].update(signature="00" * 64),
    lambda r, p: p.pop("issuer_signature"),
    lambda r, p: p.pop("issuance_witness"),
    lambda r, p: p["issuance_witness"].update(private_key="NEVER_REFLECT_SYNTHETIC"),
    lambda r, p: p["issuance_witness"].update(witness_id=r.subject("other"), witness_public_key=r.public("other")),
    lambda r, p: p["lease"].update(issuer_id=r.subject("other"), issuer_public_key=r.public("other")),
    lambda r, p: p["lease"].update(subject_id=r.subject("issuer"), subject_public_key=r.public("issuer")),
    lambda r, p: p["lease"].update(subject_id=r.subject("witness"), subject_public_key=r.public("witness")),
])
def test_missing_forged_or_same_actor_signatures_never_grant(rig, mutation):
    payload = rig.envelope()
    mutation(rig, payload)
    denied(rig, lambda: rig.service.issue(rig.conn, payload))


@pytest.mark.parametrize("role", ["subject", "issuer", "witness", "revoker"])
def test_retired_required_key_blocks_new_issuance(rig, role):
    rig.retire_key(role)
    denied(rig, lambda: rig.issue(), "authority_key_inactive")


@pytest.mark.parametrize("role", ["subject", "issuer", "witness", "revoker"])
def test_retired_required_key_disables_existing_grant_use(rig, role):
    issued = rig.issue()
    rig.retire_key(role)
    denied(rig, lambda: rig.authorize(), "authority_key_inactive")
    assert rig.service.get(rig.conn, issued["lease_id"])["status"] == "inactive"


@pytest.mark.parametrize("seconds", [-1, 121, 3600])
def test_issuance_has_current_short_acceptance_interval(rig, seconds):
    payload = rig.envelope()
    rig.clock.advance(seconds)
    if seconds < 0:
        code = "authority_clock_uncertain"
    else:
        code = "authority_issuance_stale"
    denied(rig, lambda: rig.service.issue(rig.conn, payload), code)


def test_issuance_120_second_boundary_and_inclusive_expiry(rig):
    payload = rig.envelope()
    rig.clock.advance(120)
    issued = rig.service.issue(rig.conn, payload)
    rig.clock.advance(3480)
    denied(rig, lambda: rig.authorize(), "authority_expired")
    assert rig.service.get(rig.conn, issued["lease_id"])["status"] == "expired"
    before = snapshot(rig.conn)
    duplicate = rig.service.issue(rig.conn, payload)
    assert duplicate["created"] is False and duplicate["status"] == "expired"
    assert duplicate["issued_receipt_at"] == issued["issued_receipt_at"]
    assert snapshot(rig.conn) == before


def test_future_lease_and_witness_times_are_not_accepted(rig):
    future = (NOW + timedelta(seconds=1)).isoformat()
    denied(rig, lambda: rig.service.issue(rig.conn, rig.envelope(lease_changes={"issued_at": future})))
    denied(rig, lambda: rig.service.issue(rig.conn, rig.envelope(witness_changes={"observed_at": future})))


@pytest.mark.parametrize("change", ["wall_forward", "wall_backward", "mono_backward", "mono_nonfinite"])
def test_clock_uncertainty_latches_and_never_returns_active(rig, change):
    issued = rig.issue()
    if change == "wall_forward":
        rig.clock.wall += timedelta(seconds=6)
    elif change == "wall_backward":
        rig.clock.wall -= timedelta(seconds=1)
    elif change == "mono_backward":
        rig.clock.mono -= 1
    else:
        rig.clock.mono = float("nan")
    denied(rig, lambda: rig.authorize(), "authority_clock_uncertain")
    rig.clock.wall = NOW
    rig.clock.mono = 100.5
    denied(rig, lambda: rig.authorize(), "authority_clock_uncertain")
    assert rig.service.get(rig.conn, issued["lease_id"])["status"] == "unavailable"


def test_guarded_clock_uses_effective_time_not_lagging_wall(rig):
    rig.issue(lease_changes={"expires_at": (NOW + timedelta(seconds=3)).isoformat()})
    rig.clock.mono += 3
    assert rig.control.observe_time() == NOW + timedelta(seconds=3)
    denied(rig, lambda: rig.authorize(), "authority_expired")


def test_offline_validators_inspect_expired_bytes_without_authorizing(rig):
    payload = rig.envelope()
    historical = NOW + timedelta(days=90)
    assert au.validate_envelope(payload, policy=rig.policy, observed_at=historical, check_freshness=False) == payload
    with pytest.raises(au.AuthorityError):
        au.validate_envelope(payload, policy=rig.policy, observed_at=historical)
    retirement = rig.retirement(payload)
    assert au.validate_revocation(retirement, lease_envelope=payload, observed_at=historical, check_freshness=False) == retirement
    assert rig.service.list_for_subject(rig.conn, rig.subject("subject")) == []


def test_unsigned_helpers_validate_before_caller_signs(rig):
    envelope = rig.envelope()
    issuer = {key: envelope[key] for key in ("lease", "issuer_signature")}
    unsigned_witness = {key: value for key, value in envelope["issuance_witness"].items() if key != "signature"}
    assert au.validate_witness_message(unsigned_witness, issuer_envelope=issuer, policy=rig.policy, observed_at=NOW) == unsigned_witness
    command = rig.retirement(envelope)["revocation"]
    assert au.validate_revocation_message(command, lease_envelope=envelope, observed_at=NOW) == command
    command["lease_sha256"] = "0" * 64
    with pytest.raises(au.AuthorityError):
        au.validate_revocation_message(command, lease_envelope=envelope, observed_at=NOW)
    unsigned_witness["witness_public_key"] = rig.public("subject")
    with pytest.raises(au.AuthorityError):
        au.validate_witness_message(unsigned_witness, issuer_envelope=issuer, policy=rig.policy, observed_at=NOW)


@pytest.mark.parametrize("override", [
    {"subject_id": "agent_wrong_subject"}, {"target_seed_id": "sab_seed_other"},
    {"action": "canonize_standing"}, {"action": "invented_action"},
])
def test_every_use_requires_exact_subject_action_and_seed(rig, override):
    rig.issue()
    denied(rig, lambda: rig.authorize(**override))


@pytest.mark.parametrize("reference", [
    {"lease_ref": "sab_lease_authority_one", "scope": "x"},
    {"lease_ref": "sab_lease_authority_one", "expires_at": "2026-09-09T13:00:00Z"},
    {"lease_ref": "sab_lease_authority_one", "revoker": "agent_other"},
    {"lease_ref": "sab_lease_authority_one", "challenge_path": "/other"},
    {"lease_ref": "sab_lease_authority_one", "lease_id": "sab_lease_other"},
    {"lease_ref": "sab_lease_authority_one", "allowed_actions": ["canonize_standing"]},
    {"scope": "invented"},
])
def test_reference_is_exact_declaration_not_arbitrary_grant(rig, reference):
    rig.issue()
    denied(rig, lambda: rig.authorize(reference))


def test_lease_id_alias_supported_without_broadening_metadata(rig):
    rig.issue()
    assert rig.authorize({"lease_id": "sab_lease_authority_one"})["status"] == "active"


def test_immutable_lease_and_witness_identifier_conflicts(rig):
    payload = rig.envelope()
    rig.service.issue(rig.conn, payload)
    denied(rig, lambda: rig.issue(lease_changes={"scope": "Changed scope"}), "authority_conflict")
    denied(rig, lambda: rig.issue("two", witness_changes={"event_id": payload["issuance_witness"]["event_id"]}), "authority_conflict")


def test_historical_v1_collision_is_preserved_and_never_reinterpreted(rig):
    rig.conn.execute("CREATE TABLE sab_authority_leases_v1 (lease_id TEXT PRIMARY KEY,subject_id TEXT,lease_json TEXT)")
    rig.conn.execute("INSERT INTO sab_authority_leases_v1 VALUES (?,?,?)", (
        "sab_lease_authority_one", rig.subject("other"), '{"schema":"sab.authority_lease.v1"}'))
    rig.conn.commit()
    denied(rig, lambda: rig.authorize(), "authority_unknown")
    denied(rig, lambda: rig.issue(), "authority_conflict")


def test_policy_change_disables_use_without_overwriting_original_bytes(rig):
    issued = rig.issue()
    before = snapshot(rig.conn)
    policy = copy.deepcopy(rig.policy)
    policy["policy_id"] = "sab_policy_new_generation"
    rig.service = au.AuthorityService(policy, rig.control)
    denied(rig, lambda: rig.authorize(), "authority_policy_changed")
    assert rig.service.get(rig.conn, issued["lease_id"])["reason_code"] == "authority_policy_changed"
    assert snapshot(rig.conn) == before


def test_revocation_exact_retry_restart_and_no_resurrection(rig):
    payload = rig.envelope()
    issued = rig.service.issue(rig.conn, payload)
    command = rig.retirement(issued)
    receipt = rig.service.revoke(rig.conn, command)
    assert receipt["created"] and receipt["status"] == "revoked"
    assert receipt["revocation"] == command["revocation"] and receipt["signature"] == command["signature"]
    before = snapshot(rig.conn)
    rig.clock.advance(1000)
    rig.service = au.AuthorityService(rig.policy, rig.new_control())
    assert rig.service.revoke(rig.conn, command) == {**receipt, "created": False}
    assert rig.service.issue(rig.conn, payload)["status"] == "revoked"
    denied(rig, lambda: rig.authorize(), "authority_revoked")
    denied(rig, lambda: rig.service.revoke(rig.conn, rig.retirement(issued, suffix="different")), "authority_conflict")
    assert snapshot(rig.conn) == before


def test_retirement_survives_expiry_policy_removal_and_subject_issuer_witness_retirement(rig):
    issued = rig.issue()
    for actor in ("subject", "issuer", "witness"):
        rig.retire_key(actor)
    rig.clock.advance(11 * 86400)
    rig.service = au.AuthorityService(None, rig.new_control())
    assert rig.service.get(rig.conn, issued["lease_id"])["status"] == "inactive"
    receipt = rig.service.revoke(rig.conn, rig.retirement(issued))
    assert receipt["status"] == "revoked"


@pytest.mark.parametrize("field,value", [
    ("lease_sha256", "0" * 64), ("revoker_id", "agent_unknown"),
    ("revoker_public_key", "0" * 64), ("audience", "https://wrong.example.test"),
    ("reason", ""), ("reason", "x" * 2049), ("private_key", "NEVER_REFLECT_SYNTHETIC"),
    ("expires_at", "2026-09-09T12:02:00.000001+00:00"),
    ("issued_at", "2026-09-09T12:00:01+00:00"),
])
def test_invalid_signed_retirement_is_atomic(rig, field, value):
    issued = rig.issue()
    denied(rig, lambda: rig.service.revoke(rig.conn, rig.retirement(issued, changes={field: value})))
    assert rig.authorize()["status"] == "active"


def test_retirement_requires_active_designated_revoker_and_real_signature(rig):
    issued = rig.issue()
    command = rig.retirement(issued)
    command["signature"] = sign(rig.keys["subject"], command["revocation"])
    denied(rig, lambda: rig.service.revoke(rig.conn, command), "authority_signature_invalid")
    command = rig.retirement(issued)
    rig.retire_key("revoker")
    denied(rig, lambda: rig.service.revoke(rig.conn, command), "authority_key_inactive")


def test_retirement_inclusive_expiry_and_conflicting_command_replay(rig):
    issued = rig.issue()
    command = rig.retirement(issued)
    rig.clock.advance(90)
    denied(rig, lambda: rig.service.revoke(rig.conn, command), "authority_revocation_stale")
    fresh = rig.retirement(issued)
    rig.service.revoke(rig.conn, fresh)
    changed = rig.retirement(issued, changes={"reason": "Different command bytes"})
    denied(rig, lambda: rig.service.revoke(rig.conn, changed), "authority_conflict")


@pytest.mark.parametrize("table,column,value", [
    ("sab_authority_grants_v2", "subject_id", "agent_wrong"),
    ("sab_authority_grants_v2", "target_seed_id", "sab_seed_wrong"),
    ("sab_authority_grants_v2", "issuer_id", "agent_wrong"),
    ("sab_authority_grants_v2", "witness_id", "agent_wrong"),
    ("sab_authority_grants_v2", "revoker_id", "agent_wrong"),
    ("sab_authority_grants_v2", "lease_sha256", "0" * 64),
    ("sab_authority_grants_v2", "envelope_sha256", "0" * 64),
    ("sab_authority_grants_v2", "policy_hash", "0" * 64),
    ("sab_authority_grants_v2", "policy_json", "{}"),
    ("sab_authority_grants_v2", "envelope_json", "{}"),
    ("sab_authority_grants_v2", "accepted_at", "2026-09-09T12:00:01+00:00"),
    ("sab_authority_grants_v2", "issuance_event_id", "sab_event_other"),
    ("sab_authority_grants_v2", "status", "revoked"),
    ("sab_authority_events_v2", "payload_sha256", "0" * 64),
    ("sab_authority_events_v2", "event_sha256", "0" * 64),
    ("sab_authority_events_v2", "previous_event_sha256", "0" * 64),
    ("sab_authority_events_v2", "payload_json", "{}"),
    ("sab_authority_events_v2", "observed_at", "2026-09-09T12:00:01+00:00"),
])
def test_use_revalidates_stored_bytes_columns_and_history(rig, table, column, value):
    rig.issue()
    # Controlled corruption of previously genuine data; never a positive proof.
    rig.conn.execute(f"UPDATE {table} SET {column}=?", (value,))
    rig.conn.commit()
    denied(rig, lambda: rig.authorize(), "authority_inconsistent")
    denied(rig, lambda: rig.service.get(rig.conn, "sab_lease_authority_one"), "authority_inconsistent")


@pytest.mark.parametrize("corrupt", ["delete_issue", "delete_revoke", "reset_status", "change_revocation"])
def test_missing_event_or_reset_status_cannot_resurrect_grant(rig, corrupt):
    issued = rig.issue()
    rig.service.revoke(rig.conn, rig.retirement(issued))
    if corrupt == "delete_issue":
        rig.conn.execute("DELETE FROM sab_authority_events_v2 WHERE event_type='issuance'")
    elif corrupt == "delete_revoke":
        rig.conn.execute("DELETE FROM sab_authority_events_v2 WHERE event_type='revocation'")
    elif corrupt == "reset_status":
        rig.conn.execute("UPDATE sab_authority_grants_v2 SET status='active',revocation_command_id=NULL")
    else:
        rig.conn.execute("UPDATE sab_authority_events_v2 SET payload_json='{}' WHERE event_type='revocation'")
    rig.conn.commit()
    denied(rig, lambda: rig.authorize(), "authority_inconsistent")


@pytest.mark.parametrize("layer", ["issuer", "witness"])
def test_rewritten_unsigned_digests_do_not_replace_signature_verification(rig, layer):
    payload = rig.envelope()
    rig.service.issue(rig.conn, payload)
    if layer == "issuer":
        payload["lease"]["scope"] = "Altered stored scope after authentic issuance"
        witness = payload["issuance_witness"]
        witness["lease_sha256"] = au.hash_json({"lease": payload["lease"], "issuer_signature": payload["issuer_signature"]})
        witness["signature"] = sign(rig.keys["witness"], {key: value for key, value in witness.items() if key != "signature"})
    else:
        payload["issuance_witness"]["event_id"] = "sab_authority_witness_rewritten"
    encoded = au.canonical_bytes(payload).decode()
    lease_digest = au.hash_json({"lease": payload["lease"], "issuer_signature": payload["issuer_signature"]})
    rig.conn.execute("UPDATE sab_authority_grants_v2 SET envelope_json=?,envelope_sha256=?,lease_sha256=?,issuance_event_id=?",
                     (encoded, au.hash_json(payload), lease_digest, payload["issuance_witness"]["event_id"]))
    event = au._one(rig.conn, "SELECT * FROM sab_authority_events_v2")
    event.update(payload_json=encoded, payload_sha256=au.hash_json(payload), lease_sha256=lease_digest,
                 event_id=payload["issuance_witness"]["event_id"])
    rig.conn.execute("UPDATE sab_authority_events_v2 SET payload_json=?,payload_sha256=?,lease_sha256=?,event_sha256=?,event_id=?",
                     (encoded, au.hash_json(payload), lease_digest, au._event_digest(event), event["event_id"]))
    rig.conn.commit()
    denied(rig, lambda: rig.authorize(), "authority_inconsistent")


@pytest.mark.parametrize("role", ["subject", "issuer", "witness", "revoker"])
def test_valid_signatures_from_unenrolled_key_do_not_supply_control_proof(rig, role):
    rig.keys[role] = SigningKey(bytes([80]) * 32)
    if role in {"issuer", "witness", "revoker"}:
        plural = {"issuer": "issuers", "witness": "witnesses", "revoker": "revokers"}[role]
        rig.policy[plural][0].update(subject_id=rig.subject(role), public_key=rig.public(role))
    if role == "revoker":
        rig.policy["issuers"][0]["revoker_ids"] = [rig.subject("revoker")]
    rig.service = au.AuthorityService(rig.policy, rig.control)
    denied(rig, lambda: rig.issue(), "authority_key_inactive")


def test_caller_transaction_is_not_committed_and_failure_preserves_caller_work(rig):
    rig.issue()
    rig.conn.execute("CREATE TABLE synthetic_effect (value TEXT)")
    rig.conn.commit()
    rig.conn.execute("BEGIN IMMEDIATE")
    rig.conn.execute("INSERT INTO synthetic_effect VALUES ('caller uncommitted')")
    assert rig.authorize()["status"] == "active"
    assert rig.conn.in_transaction
    denied(rig, lambda: rig.authorize(action="canonize_standing"), "authority_scope_denied")
    assert rig.conn.execute("SELECT value FROM synthetic_effect").fetchall() == [("caller uncommitted",)]
    rig.conn.rollback()
    assert rig.conn.execute("SELECT value FROM synthetic_effect").fetchall() == []


def test_issue_and_revoke_rollback_with_caller_transaction(rig):
    rig.conn.execute("BEGIN IMMEDIATE")
    issued = rig.issue()
    assert rig.conn.in_transaction
    rig.conn.rollback()
    denied(rig, lambda: rig.authorize(), "authority_unknown")
    issued = rig.issue()
    rig.conn.execute("BEGIN IMMEDIATE")
    rig.service.revoke(rig.conn, rig.retirement(issued))
    rig.conn.rollback()
    assert rig.authorize()["status"] == "active"


def test_event_insert_failure_rolls_back_grant_and_hides_sql_error(rig):
    au.init_authority_tables(rig.conn)
    rig.conn.execute("""CREATE TRIGGER synthetic_fail_event BEFORE INSERT ON sab_authority_events_v2
        BEGIN SELECT RAISE(ABORT,'NEVER_REFLECT_SYNTHETIC'); END""")
    rig.conn.commit()
    error = denied(rig, lambda: rig.issue(), "authority_storage_unavailable")
    assert "NEVER_REFLECT_SYNTHETIC" not in str(error)


def test_get_and_list_work_on_read_only_sqlite_connection(tmp_path):
    path = tmp_path / "authority.sqlite3"
    conn = connect(path)
    rig = Rig(conn)
    issued = rig.issue()
    conn.close()
    before = path.read_bytes()
    readonly = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        assert rig.service.get(readonly, issued["lease_id"])["status"] == "active"
        assert rig.service.list_for_subject(readonly, rig.subject("subject"))[0]["lease_id"] == issued["lease_id"]
    finally:
        readonly.close()
    assert path.read_bytes() == before


def test_actor_resolver_is_deterministic_current_and_exact(rig):
    rig.issue("zzz")
    rig.issue("aaa", lease_changes={"allowed_actions": ["submit_challenge"]})
    rig.issue("bbb")
    selected = rig.service.authorize_actor(rig.conn, subject_id=rig.subject("subject"), action="submit_seed", target_seed_id=SEED)
    assert selected["lease_id"] == "sab_lease_authority_bbb"
    rig.service.revoke(rig.conn, rig.retirement(selected))
    selected = rig.service.authorize_actor(rig.conn, subject_id=rig.subject("subject"), action="submit_seed", target_seed_id=SEED)
    assert selected["lease_id"] == "sab_lease_authority_zzz"
    denied(rig, lambda: rig.service.authorize_actor(rig.conn, subject_id=rig.subject("subject"),
                                                   action="submit_seed", target_seed_id="sab_seed_other"), "authority_required")


def test_admission_reserves_retirement_capacity_without_erasing_history(rig, monkeypatch):
    monkeypatch.setattr(au, "MAX_STORED_EVENTS", 4)
    one, two = rig.issue("one"), rig.issue("two")
    denied(rig, lambda: rig.issue("three"), "authority_capacity")
    rig.service.revoke(rig.conn, rig.retirement(one, suffix="one"))
    rig.service.revoke(rig.conn, rig.retirement(two, suffix="two"))
    assert rig.conn.execute("SELECT count(*) FROM sab_authority_events_v2").fetchone()[0] == 4
    denied(rig, lambda: rig.issue("three"), "authority_capacity")


def test_subject_lookup_bound_is_an_admission_bound(rig, monkeypatch):
    monkeypatch.setattr(au, "MAX_GRANTS_PER_SUBJECT", 2)
    rig.issue("one")
    rig.issue("two")
    denied(rig, lambda: rig.issue("three"), "authority_capacity")
    assert len(rig.service.list_for_subject(rig.conn, rig.subject("subject"))) == 2


def test_policy_loader_digest_is_canonical_not_file_whitespace(rig, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(rig.policy, indent=2))
    path.chmod(0o600)
    assert au.load_authority_policy(path, au.hash_json(rig.policy)) == rig.policy
    assert au.load_authority_policy(None, None) is None
    for configured_path, digest in ((None, au.hash_json(rig.policy)), (path, None), (path, "0" * 64)):
        with pytest.raises(ValueError):
            au.load_authority_policy(configured_path, digest)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "writable", "directory", "oversized", "duplicate", "nonfinite", "secret", "wrong_owner"])
def test_policy_loader_rejects_unsafe_files_and_json_without_reflection(rig, tmp_path, monkeypatch, kind):
    path = tmp_path / "policy.json"
    path.write_bytes(au.canonical_bytes(rig.policy))
    path.chmod(0o600)
    if kind == "symlink":
        link = tmp_path / "policy-link.json"
        link.symlink_to(path)
        path = link
    elif kind == "fifo":
        path = tmp_path / "policy.fifo"
        os.mkfifo(path, 0o600)
    elif kind == "writable":
        path.chmod(0o620)
    elif kind == "directory":
        path = tmp_path
    elif kind == "oversized":
        path.write_text(" " * (au.MAX_POLICY_BYTES + 1))
    elif kind == "duplicate":
        path.write_text('{"schema":"one","schema":"two"}')
    elif kind == "nonfinite":
        path.write_text('{"value":1e999}')
    elif kind == "secret":
        path.write_text('{"private_key":"NEVER_REFLECT_SYNTHETIC"}')
    elif kind == "wrong_owner":
        monkeypatch.setattr(au.os, "geteuid", lambda: -1)
    with pytest.raises(ValueError) as error:
        au.load_authority_policy(path, au.hash_json(rig.policy))
    assert "NEVER_REFLECT_SYNTHETIC" not in str(error.value)


def test_revocation_serializes_after_authorized_effect_on_same_db(tmp_path):
    path = tmp_path / "authority.sqlite3"
    initial = connect(path)
    rig = Rig(initial)
    issued = rig.issue()
    initial.execute("CREATE TABLE synthetic_effect (value TEXT)")
    initial.commit()
    approved, release, revoker_entered, retired = Event(), Event(), Event(), Event()

    def writer():
        conn = sqlite3.connect(path, timeout=5)
        try:
            conn.execute("BEGIN IMMEDIATE")
            rig.service.authorize(conn, {"lease_ref": issued["lease_id"]}, subject_id=rig.subject("subject"),
                                  action="submit_seed", target_seed_id=SEED)
            approved.set()
            assert release.wait(5)
            conn.execute("INSERT INTO synthetic_effect VALUES ('authorized before retirement')")
            conn.commit()
        finally:
            conn.close()

    def revoker():
        conn = sqlite3.connect(path, timeout=5)
        try:
            revoker_entered.set()
            result = rig.service.revoke(conn, rig.retirement(issued))
            retired.set()
            return result
        finally:
            conn.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            write_result = pool.submit(writer)
            assert approved.wait(5)
            revoke_result = pool.submit(revoker)
            assert revoker_entered.wait(5)
            assert not retired.wait(0.1)
            release.set()
            write_result.result(timeout=5)
            assert revoke_result.result(timeout=5)["status"] == "revoked"
        assert initial.execute("SELECT value FROM synthetic_effect").fetchall() == [("authorized before retirement",)]
        denied(rig, lambda: rig.authorize(), "authority_revoked")
    finally:
        release.set()
        initial.close()


def test_new_node_schemas_validate_real_signed_protocol(rig):
    import jsonschema

    root = Path(__file__).resolve().parents[1] / "nodes" / "schemas"
    envelope = rig.envelope()
    samples = (rig.policy, envelope["lease"], envelope["issuance_witness"], rig.retirement(envelope)["revocation"])
    for sample in samples:
        schema = json.loads((root / f"{sample['schema']}.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(sample, schema, format_checker=jsonschema.FormatChecker())
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({**sample, "private_key": "synthetic"}, schema)
