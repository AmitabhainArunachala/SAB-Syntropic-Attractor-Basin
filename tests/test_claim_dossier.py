from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agora.claim_dossier import list_claims, load_claim_dossier
from agora.sab_seeding_api import (
    SabSeedingDeps,
    _append_witness_event,
    _hash_json,
    _init_v1_tables,
    _without_signature,
    create_sab_seeding_router,
)

NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
STAMP = "2026-09-01T00:00:00+00:00"
FUTURE = "2026-10-01T00:00:00+00:00"
PAST = "2026-09-02T00:00:00+00:00"
SEED = "sab_seed_dossier"


def _insert(conn, table, values):
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values()))


def _packet(seed_id=SEED, text="Exact claim.\nSecond line — unchanged."):
    return {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "title": "A bounded claim",
        "claim": {
            "claim_id": "sab_claim_shared",
            "text": text,
            "scope": "Local test only.",
            "decision_context": "Decide whether to run a local experiment.",
        },
        "claimant_identity": {"subject_id": "agent_claimant"},
        "operator_backing": {
            "operator_ref": "claimed_operator",
            "disclosure": "One disclosed operator.",
        },
        "authority_lease": {
            "lease_ref": "sab_authority_submission",
            "scope": "submit one seed",
            "expires_at": FUTURE,
        },
        "evidence_bundle": [
            {
                "ref": "https://example.invalid/evidence",
                "digest": "sha256:" + "a" * 64,
                "notes": "Submitted note; no content fetch.",
                "kind": "test",
            }
        ],
        "signature": {"signature": "deliberately-not-verified"},
        "created_at": STAMP,
    }


def _seed(conn, seed_id=SEED, *, packet=None, state="standing_active", title="A bounded claim"):
    packet = _packet(seed_id) if packet is None else packet
    _insert(
        conn,
        "sab_seed_packets_v1",
        {
            "seed_id": seed_id,
            "seed_type": "claim",
            "title": title,
            "claim_id": "sab_claim_shared",
            "claimant_identity": "agent_claimant",
            "authority_lease_id": "sab_authority_submission",
            "state": state,
            "packet_json": json.dumps(packet, ensure_ascii=False),
            "packet_hash": _hash_json(_without_signature(packet)),
            "spark_projection_id": None,
            "challenge_window_closes_at": PAST,
            "created_at": STAMP,
            "updated_at": STAMP,
        },
    )
    return packet


def _challenge(
    conn, status="pending", *, challenge_id="sab_challenge_dossier", seed_id=SEED, response=None
):
    packet = {
        "challenge_id": challenge_id,
        "target_seed_id": seed_id,
        "target_claim_id": "sab_claim_shared",
        "challenger_identity": "agent_challenger",
        "quoted_claim_fragment": "Exact claim.",
        "proposed_falsification_or_narrowing": "Narrow the scope.",
        "evidence": [{"ref": "test://counterexample", "notes": "No digest disclosed."}],
    }
    _insert(
        conn,
        "sab_challenge_packets_v1",
        {
            "challenge_id": challenge_id,
            "target_seed_id": seed_id,
            "target_claim_id": "sab_claim_shared",
            "challenger_identity": "agent_challenger",
            "status": status,
            "packet_json": json.dumps(packet),
            "packet_hash": _hash_json(packet),
            "response_json": json.dumps(response) if response else None,
            "respond_by": PAST,
            "prosecute_by": PAST,
            "created_at": STAMP,
            "updated_at": STAMP,
        },
    )
    return packet


def _standing(
    conn, *, standing_id="sab_standing_dossier", status="active", expiry=FUTURE, seed_id=SEED
):
    lease = {
        "standing_id": standing_id,
        "subject_seed_id": seed_id,
        "subject_claim_id": "sab_claim_shared",
        "scope": "Only reproduce the local experiment.",
        "purpose": "Local assessment.",
        "allowed_reliance": ["Use as one input to a local test."],
        "forbidden_reliance": ["Deployment", "Medical decisions"],
        "allowed_actions": ["read"],
        "forbidden_actions": ["publish"],
        "expiry": expiry,
        "status": "active",
        "issued_by": "agent_witness",
        "signature": {"signature": "unverified"},
    }
    _insert(
        conn,
        "sab_standing_leases_v1",
        {
            "standing_id": standing_id,
            "subject_seed_id": seed_id,
            "subject_claim_id": "sab_claim_shared",
            "scope": lease["scope"],
            "purpose": lease["purpose"],
            "status": status,
            "lease_json": json.dumps(lease),
            "lease_hash": _hash_json(_without_signature(lease)),
            "expiry": expiry,
            "revoker": "agent_revoker",
            "challenge_path": f"/api/v1/standing/{standing_id}/challenge",
            "issued_by": "agent_witness",
            "issued_at": STAMP,
            "updated_at": STAMP,
            "issued_under_json": json.dumps(
                {"operator_count_basis": "self_declared", "distinct_operator_count": 3}
            ),
        },
    )
    return lease


def _event(conn, event_type="submit", *, actor="agent_claimant", payload=None):
    return _append_witness_event(
        conn,
        event_type=event_type,
        actor_identity=actor,
        subject_type="seed",
        subject_id=SEED,
        subject_seed_id=SEED,
        payload=payload or {"recorded": True},
        signature_hex="not-a-verified-signature",
        timestamp=STAMP,
    )


def _check(dossier, check_id):
    return next(item for item in dossier["checks"] if item["id"] == check_id)


def _inspection_app(conn):
    from agora.public_freshness import FreshnessPolicy, PublicationFreshnessObserver

    path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
    # This is an explicitly synthetic clock/source descriptor for route tests,
    # not a production publication or evidence of current standing.
    observer = PublicationFreshnessObserver(
        {"configured": True, "observed_at": NOW.isoformat(),
         "manifest_sha256": "0" * 64, "fixture": "synthetic dossier route source"},
        FreshnessPolicy(), utc_now=lambda: NOW, monotonic=lambda: 0.0,
    )

    @contextmanager
    def database():
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def forbidden(*args, **kwargs):
        pytest.fail("inspection called a lifecycle or initialization dependency")

    app = FastAPI()
    app.include_router(
        create_sab_seeding_router(
            SabSeedingDeps(
                init_db=forbidden,
                db=database,
                verify_agent_signature=forbidden,
                system_sign=forbidden,
                utc_now=forbidden,
                invalidate_web_cache=forbidden,
                read_only=True,
                read_observation=observer.observe,
            )
        )
    )
    return app


@pytest.fixture
def conn(tmp_path):
    connection = sqlite3.connect(tmp_path / "dossier.db")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode = WAL")
    _init_v1_tables(connection)
    connection.commit()
    yield connection
    connection.close()


def test_dossier_preserves_exact_submission_and_does_not_infer_truth_or_permission(conn):
    packet = _seed(conn)
    lease = _standing(conn)
    _event(conn)
    _event(conn, "affirm", actor="agent_witness")
    conn.commit()

    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)

    assert dossier["schema"] == "sab.claim_dossier.v1"
    assert dossier["original_packet"] == packet
    assert dossier["claim"]["submitted"] == packet["claim"]
    for field in ("text", "scope", "decision_context"):
        assert dossier["claim"][field] == packet["claim"][field]
    assert dossier["identity"]["claim_id"] == "sab_claim_shared"
    assert dossier["identity"]["packet_hash"] == _hash_json(_without_signature(packet))
    assert dossier["evidence"]["items"][0]["submitted"] == packet["evidence_bundle"][0]
    assert dossier["standing"]["items"][0]["standing_lease"] == lease
    for field in (
        "allowed_reliance",
        "forbidden_reliance",
        "allowed_actions",
        "forbidden_actions",
        "expiry",
        "scope",
    ):
        assert dossier["standing"]["items"][0][field] == lease[field]
    assert _check(dossier, "packet_digest")["state"] == "passed"
    assert _check(dossier, "event_hashes_and_links")["state"] == "passed"
    assert _check(dossier, "witness_payload_digests")["state"] == "passed"
    for check in (
        "signatures",
        "evidence_bytes",
        "operator_independence",
        "authority_policy",
        "schema_validation",
    ):
        assert _check(dossier, check)["state"] == "not_checked"
    assert dossier["reliance"]["status"] == "unestablished"
    assert dossier["authority_effect"] == dossier["standing_effect"] == "none"
    assert "verified" not in dossier and "trusted" not in dossier and "true" not in dossier


@pytest.mark.parametrize("tamper", ["packet", "hash"])
def test_packet_or_stored_hash_tampering_fails_only_the_named_digest_check(conn, tamper):
    packet = _seed(conn)
    if tamper == "packet":
        packet["claim"]["text"] = "Changed after submission."
        conn.execute("UPDATE sab_seed_packets_v1 SET packet_json = ?", (json.dumps(packet),))
    else:
        conn.execute("UPDATE sab_seed_packets_v1 SET packet_hash = ?", ("0" * 64,))
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert _check(dossier, "packet_digest")["state"] == "failed"
    assert dossier["reliance"]["status"] == "unestablished"
    assert any("check failed" in reason for reason in dossier["reliance"]["reasons"])


def test_signature_changes_are_not_misrepresented_as_signature_verification(conn):
    packet = _seed(conn)
    packet["signature"] = {"signature": "a different arbitrary string"}
    conn.execute("UPDATE sab_seed_packets_v1 SET packet_json = ?", (json.dumps(packet),))
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert _check(dossier, "packet_digest")["state"] == "passed"
    assert _check(dossier, "signatures")["state"] == "not_checked"


def test_changed_packet_with_recomputed_digest_is_compared_to_submit_event(conn):
    packet = _seed(conn)
    _event(conn, payload={"seed_packet_hash": _hash_json(_without_signature(packet))})
    packet["claim"]["text"] = "A different claim after submission."
    conn.execute(
        "UPDATE sab_seed_packets_v1 SET packet_json = ?, packet_hash = ?",
        (json.dumps(packet), _hash_json(_without_signature(packet))),
    )
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert _check(dossier, "packet_digest")["state"] == "passed"
    assert _check(dossier, "submission_packet_binding")["state"] == "failed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("payload_json", '{"changed":true}'),
        ("prev_hash", "unrelated-head"),
        ("event_hash", "wrong"),
    ],
)
def test_witness_hash_or_chain_tampering_is_reported(conn, field, value):
    _seed(conn)
    event = _event(conn)
    conn.execute(
        f"UPDATE sab_witness_events_v1 SET {field} = ? WHERE event_id = ?",
        (value, event["event_id"]),
    )
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert _check(dossier, "event_hashes_and_links")["state"] == "failed"


def test_payload_digest_is_checked_separately_from_self_consistent_event_hash(conn):
    _seed(conn)
    _event(conn)
    conn.execute("UPDATE sab_witness_events_v1 SET payload_hash = ?", ("0" * 64,))
    row = dict(conn.execute("SELECT * FROM sab_witness_events_v1").fetchone())
    material = {key: value for key, value in row.items() if key not in {"id", "event_hash"}}
    conn.execute("UPDATE sab_witness_events_v1 SET event_hash = ?", (_hash_json(material),))
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert _check(dossier, "event_hashes_and_links")["state"] == "passed"
    assert _check(dossier, "witness_payload_digests")["state"] == "failed"


@pytest.mark.parametrize(
    "status,expiry,observed,basis",
    [
        ("active", PAST, "expired", "expiry_observation"),
        ("canon", PAST, "expired", "expiry_observation"),
        ("active", "invalid", "unknown", "invalid_expiry"),
        ("active", "", "unknown", "invalid_expiry"),
        ("revoked", FUTURE, "revoked", "stored"),
        ("provisional", FUTURE, "provisional", "stored"),
        ("active", FUTURE, "active", "stored"),
    ],
)
def test_standing_uses_shared_expiry_observation_without_promoting_permission(
    conn, status, expiry, observed, basis
):
    _seed(conn)
    _standing(conn, status=status, expiry=expiry)
    conn.commit()
    before = tuple(conn.iterdump())
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    item = dossier["standing"]["items"][0]
    assert (item["stored_status"], item["status"], item["status_basis"]) == (
        status,
        observed,
        basis,
    )
    assert item["observed_at"] == NOW.isoformat()
    assert item["reliance_status"] == "unestablished"
    assert tuple(conn.iterdump()) == before


def test_all_scoped_standing_records_are_kept_and_missing_reliance_is_unknown(conn):
    _seed(conn)
    _standing(conn, standing_id="sab_standing_old", status="expired", expiry=PAST)
    _standing(conn, standing_id="sab_standing_current")
    conn.execute(
        "UPDATE sab_standing_leases_v1 SET lease_json = '{}' WHERE standing_id = 'sab_standing_current'"
    )
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert [lease["standing_id"] for lease in dossier["standing"]["items"]] == [
        "sab_standing_current",
        "sab_standing_old",
    ]
    current = dossier["standing"]["items"][0]
    assert current["allowed_reliance"] is None and current["forbidden_reliance"] is None
    assert current["allowed_actions"] is None
    assert _check(dossier, "standing_lease_digests")["state"] == "failed"
    assert any("allowed_reliance" in item for item in dossier["missing_data"])


def test_pending_and_responded_remain_unresolved_after_both_deadlines(conn):
    _seed(conn)
    _challenge(conn, "pending", challenge_id="sab_challenge_pending")
    _challenge(
        conn,
        "responded",
        challenge_id="sab_challenge_responded",
        response={"response": "Recorded answer."},
    )
    _challenge(conn, "rejected", challenge_id="sab_challenge_rejected")
    conn.commit()
    before = tuple(conn.iterdump())
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    items = dossier["challenges"]["items"]
    assert dossier["challenges"]["unresolved_count"] == 2
    assert [item["unresolved"] for item in items] == [True, True, False]
    assert items[1]["status"] == "responded"
    assert items[1]["response"] == {"response": "Recorded answer."}
    assert all(
        item["respond_deadline"]["elapsed"] and item["prosecute_deadline"]["elapsed"]
        for item in items
    )
    assert list_claims(conn)["items"][0]["unresolved_challenge_count"] == 2
    assert tuple(conn.iterdump()) == before


def test_unknown_challenge_status_is_not_counted_as_resolved(conn):
    _seed(conn)
    _challenge(conn, "open_unknown")
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    challenge = dossier["challenges"]["items"][0]
    assert challenge["status"] == "open_unknown"
    assert challenge["unresolved"] is None
    assert challenge["resolution_state"] == "unknown"
    assert dossier["challenges"]["unknown_status_count"] == 1
    assert dossier["challenges"]["resolution_complete"] is False
    assert dossier["challenges"]["unresolved_count_basis"] == "known_open_records"
    assert list_claims(conn)["items"][0]["unknown_challenge_status_count"] == 1
    assert any("resolution is unknown" in item for item in dossier["missing_data"])


def test_unknown_standing_status_is_preserved_as_raw_and_observed_unknown(conn):
    _seed(conn)
    _standing(conn, status="unrecognized_active")
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    standing = dossier["standing"]["items"][0]
    assert standing["stored_status"] == "unrecognized_active"
    assert standing["status"] == "unknown"
    assert standing["status_basis"] == "invalid_stored_status"


def test_correction_payload_is_history_and_does_not_replace_claim(conn):
    packet = _seed(conn)
    correction = {"text": "Proposed new wording.", "scope": "Narrower scope."}
    payload = {
        "correction_hash": _hash_json(correction),
        "correction": correction,
        "from_state": "challenged",
        "to_state": "corrected",
    }
    event = _event(conn, "correction", payload=payload)
    _insert(
        conn,
        "sab_seed_events_v1",
        {
            "event_id": "sab_seed_event_correct",
            "seed_id": SEED,
            "actor_identity": "agent_claimant",
            "event_type": "correction",
            "from_state": "challenged",
            "to_state": "corrected",
            "payload_json": json.dumps(payload),
            "witness_event_id": event["event_id"],
            "created_at": STAMP,
        },
    )
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert len(dossier["corrections"]["items"]) == 1
    assert dossier["corrections"]["items"][0]["payload"] == payload
    assert dossier["corrections"]["items"][0]["correction"] == correction
    assert dossier["claim"]["text"] == packet["claim"]["text"]
    assert dossier["claim"]["current_corrected_text"] is None
    assert dossier["original_packet"] == packet
    assert _check(dossier, "correction_payload_digests")["state"] == "passed"


def test_missing_fields_and_empty_chain_do_not_synthesize_evidence_or_claim_text(conn):
    packet = {"seed_id": SEED, "claim": {"statement": "Historical text under another field."}}
    _seed(conn, packet=packet)
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert dossier["claim"]["text"] is None
    assert dossier["claim"]["submitted"]["statement"] == packet["claim"]["statement"]
    assert dossier["evidence"]["availability"] == "missing"
    assert dossier["witness"]["head"] is None
    assert dossier["witness"]["events"] == []
    assert _check(dossier, "event_hashes_and_links")["state"] == "not_checked"
    assert dossier["standing"]["items"] == []
    assert any("No scoped standing lease" in reason for reason in dossier["reliance"]["reasons"])


def test_malformed_claim_fields_are_preserved_in_submission_and_safe_for_display(conn):
    packet = _packet()
    packet["claim"].update(text={"unexpected": "object"}, scope=["array"], decision_context=42)
    _seed(conn, packet=packet)
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert dossier["claim"]["submitted"] == packet["claim"]
    assert all(dossier["claim"][field] is None for field in ("text", "scope", "decision_context"))
    assert list_claims(conn)["items"][0]["text"] is None


@pytest.mark.parametrize("raw", ["{bad json", "[]", "null", '{"claim":NaN}', '{"claim":1e999}'])
def test_malformed_historical_packet_is_exposed_without_crashing(conn, raw):
    _seed(conn)
    conn.execute("UPDATE sab_seed_packets_v1 SET packet_json = ?", (raw,))
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert dossier["original_packet_json"] == raw
    assert dossier["claim"]["text"] is None
    assert _check(dossier, "packet_json")["state"] == "failed"
    assert _check(dossier, "packet_digest")["state"] == "not_checked"
    json.dumps(dossier, allow_nan=False)
    assert list_claims(conn)["total"] == 1


def test_malformed_historical_event_response_lease_and_disclosure_are_retained(conn):
    _seed(conn)
    _challenge(conn, "responded")
    _standing(conn)
    event = _event(conn, "correction")
    conn.execute("UPDATE sab_challenge_packets_v1 SET packet_json = '[]', response_json = '{bad'")
    conn.execute("UPDATE sab_standing_leases_v1 SET lease_json = '[1]', issued_under_json = 'bad'")
    conn.execute(
        "UPDATE sab_witness_events_v1 SET payload_json = ?", ('"scalar correction history"',)
    )
    _insert(
        conn,
        "sab_agent_identities_v1",
        {
            "subject_id": "agent_claimant",
            "display_name": "Claimant",
            "public_key": "key",
            "controller": "operator",
            "operator_id": "disclosed_operator",
            "operator_backing_json": "broken",
            "identity_json": "[1]",
            "created_at": STAMP,
            "updated_at": STAMP,
        },
    )
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert dossier["challenges"]["items"][0]["response_json"] == "{bad"
    assert dossier["challenges"]["items"][0]["response"] is None
    assert dossier["standing"]["items"][0]["standing_lease"] == [1]
    assert dossier["standing"]["items"][0]["issued_under_json"] == "bad"
    assert dossier["corrections"]["items"][0]["event_id"] == event["event_id"]
    assert dossier["corrections"]["items"][0]["payload"] == "scalar correction history"
    assert dossier["operators"]["independence_status"] == "unknown"
    assert dossier["missing_data"]


def test_distinct_registered_keys_and_operator_strings_never_establish_independence(conn):
    _seed(conn)
    _standing(conn)
    for index in range(3):
        actor = f"agent_witness_{index}"
        _event(conn, "affirm", actor=actor)
        backing = {"operator_id": f"operator_{index}", "backing_count_attestation": "verified"}
        _insert(
            conn,
            "sab_agent_identities_v1",
            {
                "subject_id": actor,
                "display_name": actor,
                "public_key": f"distinct-key-{index}",
                "controller": "operator",
                "operator_id": backing["operator_id"],
                "operator_backing_json": json.dumps(backing),
                "identity_json": json.dumps({"subject_id": actor, "operator_backing": backing}),
                "created_at": STAMP,
                "updated_at": STAMP,
            },
        )
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    operators = dossier["operators"]
    assert (
        len(
            [
                item
                for item in operators["disclosures"]
                if item["source"] == "sab_agent_identities_v1"
            ]
        )
        == 3
    )
    assert operators["independently_verified"] == []
    assert operators["independently_verified_count"] is None
    assert operators["independence_status"] == "unknown"
    assert operators["check"]["state"] == "not_checked"
    assert dossier["reliance"]["status"] == "unestablished"


def test_display_name_reuse_does_not_rebind_a_historical_operator(conn):
    _seed(conn)
    _event(conn, "affirm", actor="sab_identity_shared")
    conn.execute("CREATE TABLE web_agents (id TEXT, name TEXT, public_key TEXT, created_at TEXT)")
    for subject, operator, created in [
        ("agent_original", "original_operator", STAMP),
        ("agent_later", "later_operator", FUTURE),
    ]:
        _insert(
            conn,
            "web_agents",
            {"id": subject, "name": "shared", "public_key": subject, "created_at": created},
        )
        _insert(
            conn,
            "sab_agent_identities_v1",
            {
                "subject_id": subject,
                "display_name": "shared",
                "public_key": subject,
                "controller": "operator",
                "operator_id": operator,
                "operator_backing_json": json.dumps({"operator_id": operator}),
                "identity_json": json.dumps({"subject_id": subject}),
                "created_at": created,
                "updated_at": created,
            },
        )
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    alias = [
        item
        for item in dossier["operators"]["disclosures"]
        if item["actor_identity"] == "sab_identity_shared"
    ]
    assert len(alias) == 1
    assert alias[0]["source"] == "missing"
    assert alias[0]["operator_id"] is None


def test_unknown_seed_and_missing_tables_are_read_only(conn):
    before = tuple(conn.iterdump())
    assert load_claim_dossier(conn, "missing") is None
    assert tuple(conn.iterdump()) == before
    with sqlite3.connect(":memory:") as empty:
        assert load_claim_dossier(empty, SEED) is None
        assert list_claims(empty)["availability"] == "missing"
        assert empty.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0


def test_missing_optional_tables_are_disclosed(conn):
    _seed(conn)
    conn.execute("DROP TABLE sab_witness_events_v1")
    conn.execute("DROP TABLE sab_standing_leases_v1")
    conn.commit()
    before = tuple(conn.iterdump())
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert dossier["witness"]["availability"] == "missing"
    assert dossier["standing"]["availability"] == "missing"
    assert _check(dossier, "event_hashes_and_links")["state"] == "not_checked"
    assert tuple(conn.iterdump()) == before


def test_reads_work_with_plain_rows_and_query_only_and_preserve_caller_transaction(conn):
    _seed(conn)
    _challenge(conn, "responded")
    _standing(conn, expiry=PAST)
    conn.commit()
    before = tuple(conn.iterdump())
    conn.row_factory = None
    conn.execute("PRAGMA query_only = ON")
    trace = []
    conn.set_trace_callback(trace.append)
    assert load_claim_dossier(conn, SEED, observed_at=NOW)["claim"]["text"]
    assert conn.in_transaction is False
    assert trace.count("BEGIN") == trace.count("ROLLBACK") == 1
    assert list_claims(conn)["total"] == 1
    conn.execute("BEGIN")
    assert load_claim_dossier(conn, SEED, observed_at=NOW)
    assert conn.in_transaction is True
    conn.rollback()
    assert tuple(conn.iterdump()) == before


def test_dossier_uses_one_snapshot_while_another_connection_commits(conn):
    _seed(conn)
    conn.commit()
    db_path = conn.execute("PRAGMA database_list").fetchone()[2]
    writer = sqlite3.connect(db_path)
    wrote = False

    def interleave(sql):
        nonlocal wrote
        if not wrote and sql.startswith("SELECT * FROM sab_challenge_packets_v1"):
            wrote = True
            _challenge(writer, "pending")
            writer.execute("UPDATE sab_seed_packets_v1 SET state = 'challenged'")
            writer.commit()

    conn.set_trace_callback(interleave)
    try:
        dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    finally:
        conn.set_trace_callback(None)
        writer.close()
    assert wrote
    assert dossier["seed"]["stored_state"] == "standing_active"
    assert dossier["challenges"]["unresolved_count"] == 0
    assert load_claim_dossier(conn, SEED, observed_at=NOW)["challenges"]["unresolved_count"] == 1


def test_ledger_count_and_page_share_a_snapshot(conn):
    _seed(conn)
    conn.commit()
    writer = sqlite3.connect(conn.execute("PRAGMA database_list").fetchone()[2])
    wrote = False

    def interleave(sql):
        nonlocal wrote
        if not wrote and sql.startswith("SELECT * FROM sab_seed_packets_v1"):
            wrote = True
            _seed(writer, "sab_seed_later")
            writer.commit()

    conn.set_trace_callback(interleave)
    try:
        ledger = list_claims(conn)
    finally:
        conn.set_trace_callback(None)
        writer.close()
    assert wrote
    assert ledger["total"] == len(ledger["items"]) == 1
    assert ledger["items"][0]["seed_id"] == SEED
    assert list_claims(conn)["total"] == 2


def test_ledger_filtering_pagination_literal_search_and_repeated_claim_id(conn):
    for index in range(5):
        _seed(
            conn,
            f"sab_seed_{index}",
            state="challenged" if index % 2 else "pending_seed",
            title=f"Title {index}",
        )
    _seed(conn, "sab_seed_literal", title="100%_match")
    conn.commit()
    ledger = list_claims(conn, state="pending_seed", limit=2)
    assert ledger["total"] == 3
    assert [row["seed_id"] for row in ledger["items"]] == ["sab_seed_4", "sab_seed_2"]
    assert ledger["has_more"] is True
    second = list_claims(conn, state="pending_seed", limit=2, offset=2)
    assert [row["seed_id"] for row in second["items"]] == ["sab_seed_0"]
    assert second["has_more"] is False
    assert list_claims(conn, q="local EXPERIMENT")["total"] == 6
    assert list_claims(conn, q="%_")["total"] == 1
    assert list_claims(conn, q="' OR 1=1 --")["total"] == 0
    assert list_claims(conn, q="sab_claim_shared")["total"] == 6
    assert list_claims(conn, state="unknown")["items"] == []
    assert list_claims(conn, offset=999)["items"] == []


def test_dossier_does_not_truncate_long_claims_evidence_or_chain(conn):
    packet = _packet(text="Long exact claim.\n" * 1500)
    packet["evidence_bundle"] = [
        {"ref": f"test://evidence/{index}", "notes": "Preserve all notes " * 50}
        for index in range(120)
    ]
    _seed(conn, packet=packet)
    # The older chain endpoint stops at 10,000. A dossier must expose the
    # entire stored history, including the event after that boundary.
    for index in range(10_001):
        _event(conn, "affirm", payload={"index": index})
    dossier = load_claim_dossier(conn, SEED, observed_at=NOW)
    assert dossier["claim"]["text"] == packet["claim"]["text"]
    assert len(dossier["evidence"]["items"]) == 120
    assert len(dossier["witness"]["events"]) == dossier["witness"]["total_count"] == 10_001
    assert dossier["witness"]["events"][-1]["payload"]["index"] == 10_000
    assert dossier["witness"]["complete"] is True


def test_ledger_searches_decoded_unicode_and_multiline_claim_text(conn):
    packet = _packet(text="条件を確認する。\nStraße, CAFÉ.")
    _seed(conn, packet=packet)
    # The live writer uses ensure_ascii=True, so raw JSON alone cannot match
    # a Japanese text query or Unicode case folding.
    conn.execute(
        "UPDATE sab_seed_packets_v1 SET packet_json = ?", (json.dumps(packet, ensure_ascii=True),)
    )
    assert list_claims(conn, q="条件")["total"] == 1
    assert list_claims(conn, q="STRASSE")["total"] == 1
    assert list_claims(conn, q="café")["total"] == 1
    assert list_claims(conn, q="。\nStraße")["total"] == 1


def test_generated_dossier_matches_public_schema(conn):
    jsonschema = pytest.importorskip("jsonschema")
    _seed(conn)
    _challenge(conn, "responded")
    _standing(conn, expiry="invalid")
    _event(conn)
    schema_path = (
        Path(__file__).resolve().parents[1] / "nodes/schemas/sab.claim_dossier.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(load_claim_dossier(conn, SEED, observed_at=NOW))


def test_derived_links_percent_encode_identifiers(conn):
    seed_id = "sab_seed_spaces ?#&%/"
    _seed(conn, seed_id)
    dossier = load_claim_dossier(conn, seed_id, observed_at=NOW)
    assert parse_qs(urlsplit(dossier["links"]["seed"]).query) == {
        "kind": ["seed"],
        "identifier": [seed_id],
    }
    assert parse_qs(urlsplit(dossier["links"]["download"]).query) == {
        "kind": ["dossier"],
        "identifier": [seed_id],
        "download": ["true"],
    }


@pytest.mark.parametrize(
    "seed_id",
    [
        SEED,
        "seed/path",
        "seed/chain",
        "seed/dossier",
        "odd %#?/with space",
        "seed\\backslash",
        ".",
        "..",
        "日本語",
        "seed\nline",
    ],
)
def test_api_generated_links_round_trip_exact_awkward_identifiers(conn, seed_id):
    _seed(conn, seed_id)
    challenge_id = "challenge/%#? with space\nline"
    standing_id = "standing/%#? with space\nline"
    _challenge(conn, seed_id=seed_id, challenge_id=challenge_id)
    _standing(conn, seed_id=seed_id, standing_id=standing_id)
    _append_witness_event(
        conn,
        event_type="affirm",
        actor_identity="agent_witness",
        subject_type="seed",
        subject_id=seed_id,
        subject_seed_id=seed_id,
        payload={"recorded": True},
        signature_hex="unchecked",
        timestamp=STAMP,
    )
    conn.commit()
    before = tuple(conn.iterdump())
    with TestClient(_inspection_app(conn)) as client:
        ledger = client.get("/api/v1/claims").json()
        dossier_response = client.get(ledger["items"][0]["links"]["dossier"])
        assert dossier_response.status_code == 200, dossier_response.text
        dossier = dossier_response.json()
        assert dossier["identity"]["seed_id"] == seed_id
        for key in ("seed", "chain", "download", "verify"):
            response = client.get(dossier["links"][key])
            assert response.status_code == 200, (key, response.text)
            if key == "seed":
                assert response.json()["seed_id"] == seed_id
            if key == "download":
                assert response.headers["content-disposition"].startswith("attachment;")
                assert response.json()["identity"]["seed_id"] == seed_id
        challenge = client.get(dossier["links"]["challenges"][0])
        assert challenge.status_code == 200, challenge.text
        assert challenge.json()["challenge_id"] == challenge_id
        standing = client.get(dossier["links"]["standing"][0])
        assert standing.status_code == 200, standing.text
        assert standing.json()["standing_id"] == standing_id
        event = client.get(dossier["witness"]["events"][0]["links"]["event"])
        assert event.status_code == 200, event.text
        assert event.json()["subject_seed_id"] == seed_id
        if "/" in seed_id and "\n" not in seed_id:
            direct = client.get("/api/v1/seeds/" + quote(seed_id, safe="") + "/dossier")
            assert direct.status_code == 200
            assert direct.json()["identity"]["seed_id"] == seed_id
    assert tuple(conn.iterdump()) == before


def test_lone_unicode_surrogate_retains_escaped_packet_and_renders_api_records(conn):
    packet = _seed(conn)
    packet["claim"]["text"] = "unreadable \ud800"
    raw = json.dumps(packet)
    conn.execute("UPDATE sab_seed_packets_v1 SET packet_json = ?", (raw,))
    conn.commit()
    with TestClient(_inspection_app(conn)) as client:
        ledger = client.get("/api/v1/claims")
        assert ledger.status_code == 200
        assert ledger.json()["items"][0]["text"] is None
        response = client.get(f"/api/v1/seeds/{SEED}/dossier")
        assert response.status_code == 200
        dossier = response.json()
        assert dossier["original_packet_json"] == raw
        assert dossier["original_packet"] is None
        assert any("non-scalar Unicode" in entry for entry in dossier["missing_data"])
        original = client.get(dossier["links"]["seed"])
        assert original.status_code == 200
        assert original.json()["packet_json"] == raw


def test_malformed_historical_record_links_remain_dereferenceable(conn):
    _seed(conn)
    _challenge(conn)
    _standing(conn)
    _event(conn)
    conn.execute("UPDATE sab_challenge_packets_v1 SET packet_json = 'bad'")
    conn.execute("UPDATE sab_standing_leases_v1 SET issued_under_json = 'bad'")
    conn.execute("UPDATE sab_witness_events_v1 SET payload_json = 'bad'")
    conn.commit()
    with TestClient(_inspection_app(conn)) as client:
        dossier = client.get(f"/api/v1/seeds/{SEED}/dossier").json()
        for link in [
            dossier["links"]["chain"],
            *dossier["links"]["challenges"],
            *dossier["links"]["standing"],
            dossier["witness"]["events"][0]["links"]["event"],
        ]:
            response = client.get(link)
            assert response.status_code == 200, response.text


def test_api_dossier_and_ledger_never_initialize_or_mutate_even_in_local_mode(conn):
    _seed(conn)
    _challenge(conn, "responded")
    _standing(conn, expiry=PAST)
    conn.commit()
    db_path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
    before = tuple(conn.iterdump())

    @contextmanager
    def database():
        connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
        try:
            yield connection
        finally:
            connection.close()

    def forbidden(*args, **kwargs):
        pytest.fail("dossier read called a mutation/lifecycle dependency")

    app = FastAPI()
    app.include_router(
        create_sab_seeding_router(
            SabSeedingDeps(
                init_db=forbidden,
                db=database,
                verify_agent_signature=forbidden,
                system_sign=forbidden,
                utc_now=forbidden,
                invalidate_web_cache=forbidden,
                read_only=False,
            )
        )
    )
    with TestClient(app) as client:
        response = client.get(f"/api/v1/seeds/{SEED}/dossier")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        dossier = response.json()
        assert dossier["challenges"]["unresolved_count"] == 1
        assert dossier["standing"]["items"][0]["status"] == "expired"
        download = client.get(f"/api/v1/seeds/{SEED}/dossier?download=true")
        assert download.status_code == 200
        assert (
            download.headers["content-disposition"] == 'attachment; filename="claim-dossier.json"'
        )
        missing = client.get("/api/v1/seeds/unknown/dossier")
        assert missing.status_code == 404
        assert missing.headers["cache-control"] == "no-store"
        ledger = client.get("/api/v1/claims?state=standing_active&limit=1&offset=0")
        assert ledger.status_code == 200
        assert ledger.headers["cache-control"] == "no-store"
        assert ledger.json()["total"] == 1
        assert client.get("/api/v1/claims?limit=101").status_code == 422
    assert tuple(conn.iterdump()) == before
