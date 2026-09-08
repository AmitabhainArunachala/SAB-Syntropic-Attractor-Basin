from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import agora.public_snapshot as ps
from agora.claim_dossier import list_claims, load_claim_dossier
from agora.sab_seeding_api import (
    _append_witness_event,
    _hash_json,
    _init_v1_tables,
    _without_signature,
)

STAMP = "2026-09-09T00:00:00+00:00"
SEED = "sab_seed_public_snapshot"


def _insert(conn, table, values):
    conn.execute(
        f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})",
        tuple(values.values()),
    )


def _seed(conn, seed_id=SEED):
    packet = {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "privacy_class": "public",
        "claim": {
            "claim_id": "sab_claim_snapshot",
            "text": "Exact public claim.\n条件を確認する。",
            "scope": "A local test",
            "decision_context": "Whether to reproduce one test",
        },
        "claimant_identity": {"subject_id": "agent_claimant"},
        "evidence_bundle": [
            {
                "ref": "https://example.invalid/public-evidence",
                "digest": "a" * 64,
                "notes": "Public test reference.",
            }
        ],
        "signature": {"signature": "public-signature-bytes"},
        "created_at": STAMP,
    }
    _insert(
        conn,
        "sab_seed_packets_v1",
        {
            "seed_id": seed_id,
            "seed_type": "claim",
            "title": "A public test",
            "claim_id": "sab_claim_snapshot",
            "claimant_identity": "agent_claimant",
            "authority_lease_id": "submit_lease",
            "state": "standing_active",
            "packet_json": json.dumps(packet, indent=2),
            "packet_hash": _hash_json(_without_signature(packet)),
            "spark_projection_id": None,
            "challenge_window_closes_at": "2026-09-02T00:00:00Z",
            "created_at": STAMP,
            "updated_at": STAMP,
        },
    )
    return packet


def _event(conn, kind, actor, payload, *, subject_type="seed", subject_id=SEED):
    return _append_witness_event(
        conn,
        event_type=kind,
        actor_identity=actor,
        subject_type=subject_type,
        subject_id=subject_id,
        subject_seed_id=SEED,
        payload=payload,
        signature_hex="exact-public-witness-signature",
        timestamp=STAMP,
    )


@pytest.fixture
def source(tmp_path):
    path = tmp_path.resolve() / "source.sqlite3"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    _init_v1_tables(conn)
    packet = _seed(conn)
    submit_payload = {
        "seed_packet_hash": _hash_json(_without_signature(packet)),
        "from_state": "pending_seed",
        "to_state": "pending_seed",
    }
    submit = _event(conn, "submit", "agent_claimant", submit_payload)
    _insert(
        conn,
        "sab_seed_events_v1",
        {
            "event_id": "seed_event_submit",
            "seed_id": SEED,
            "actor_identity": "agent_claimant",
            "event_type": "submit",
            "from_state": "pending_seed",
            "to_state": "pending_seed",
            "payload_json": json.dumps(submit_payload),
            "witness_event_id": submit["event_id"],
            "created_at": STAMP,
        },
    )
    for status in ("pending", "responded"):
        challenge_id = "challenge_" + status
        challenge = {
            "challenge_id": challenge_id,
            "target_seed_id": SEED,
            "target_claim_id": "sab_claim_snapshot",
            "evidence": [{"ref": "https://example.invalid/counterexample"}],
            "quoted_claim_fragment": "Exact public claim.",
        }
        _insert(
            conn,
            "sab_challenge_packets_v1",
            {
                "challenge_id": challenge_id,
                "target_seed_id": SEED,
                "target_claim_id": "sab_claim_snapshot",
                "challenger_identity": "agent_challenger",
                "status": status,
                "packet_json": json.dumps(challenge),
                "packet_hash": _hash_json(challenge),
                "response_json": (
                    json.dumps({"response": "Recorded answer"}) if status == "responded" else None
                ),
                "respond_by": STAMP,
                "prosecute_by": STAMP,
                "created_at": STAMP,
                "updated_at": STAMP,
            },
        )
        _event(
            conn,
            "challenge",
            "agent_challenger",
            {"challenge_id": challenge_id},
            subject_type="challenge",
            subject_id=challenge_id,
        )
    correction = {"text": "A proposed narrowing; original stays unchanged."}
    correction_payload = {"correction": correction, "correction_hash": _hash_json(correction)}
    correction_event = _event(conn, "correction", "agent_claimant", correction_payload)
    _insert(
        conn,
        "sab_seed_events_v1",
        {
            "event_id": "seed_event_correction",
            "seed_id": SEED,
            "actor_identity": "agent_claimant",
            "event_type": "correction",
            "from_state": "challenged",
            "to_state": "corrected",
            "payload_json": json.dumps(correction_payload),
            "witness_event_id": correction_event["event_id"],
            "created_at": STAMP,
        },
    )
    lease = {
        "standing_id": "standing_snapshot",
        "subject_seed_id": SEED,
        "subject_claim_id": "sab_claim_snapshot",
        "scope": "Only reproduce one test",
        "purpose": "Public local evaluation",
        "allowed_reliance": ["One input to a test"],
        "forbidden_reliance": ["Production deployment"],
        "expiry": "2027-01-01T00:00:00Z",
        "signature": {"signature": "exact-standing-signature"},
    }
    _insert(
        conn,
        "sab_standing_leases_v1",
        {
            "standing_id": "standing_snapshot",
            "subject_seed_id": SEED,
            "subject_claim_id": "sab_claim_snapshot",
            "scope": lease["scope"],
            "purpose": lease["purpose"],
            "status": "active",
            "lease_json": json.dumps(lease, indent=1),
            "lease_hash": _hash_json(_without_signature(lease)),
            "expiry": lease["expiry"],
            "revoker": "agent_witness",
            "challenge_path": "/public/challenge",
            "issued_by": "agent_witness",
            "issued_at": STAMP,
            "updated_at": STAMP,
            "issued_under_json": json.dumps({"operator_count_basis": "self_declared"}),
        },
    )
    standing_payload = {
        "standing_id": "standing_snapshot",
        "standing_lease_hash": _hash_json(_without_signature(lease)),
    }
    issued = _event(
        conn,
        "standing_issued",
        "agent_witness",
        standing_payload,
        subject_type="standing",
        subject_id="standing_snapshot",
    )
    _insert(
        conn,
        "sab_standing_events_v1",
        {
            "event_id": "standing_event",
            "standing_id": "standing_snapshot",
            "actor_identity": "agent_witness",
            "event_type": "standing_issued",
            "from_status": "provisional",
            "to_status": "active",
            "payload_json": json.dumps(standing_payload),
            "witness_event_id": issued["event_id"],
            "created_at": STAMP,
        },
    )
    for actor in ("agent_claimant", "agent_challenger", "agent_witness"):
        identity = {
            "subject_id": actor,
            "public_key": "public-key-" + actor,
            "operator_backing": {"operator_id": "disclosed_operator"},
        }
        _insert(
            conn,
            "sab_agent_identities_v1",
            {
                "subject_id": actor,
                "display_name": actor,
                "public_key": identity["public_key"],
                "controller": "operator",
                "operator_id": "disclosed_operator",
                "operator_backing_json": json.dumps(identity["operator_backing"]),
                "identity_json": json.dumps(identity),
                "created_at": STAMP,
                "updated_at": STAMP,
            },
        )
    conn.commit()
    yield conn, path
    conn.close()


def _approve(review):
    review = copy.deepcopy(review)
    for record in review["records"]:
        record.update(decision="approve", publication_basis="own_work", license="CC0-1.0")
        record["privacy_review"] = {
            "status": "approved",
            "reviewer": "private-reviewer-not-for-manifest",
        }
        record["consent"] = {
            "required": False,
            "satisfied": False,
            "basis": "Private review rationale, kept outside publication.",
        }
        record["takedown"] = {
            "owner": "private-owner-record",
            "route": "https://example.invalid/takedown",
        }
        record["raw_json_review"] = {
            column: {"classification": "public_original", "extensions_reviewed": True}
            for column in record["raw_json_review"]
        }
    return review


def _review(conn):
    return _approve(ps.plan_public_snapshot(conn, [SEED], observed_at=STAMP))


def _pin(bundle):
    return hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()


def _bundle(source, tmp_path):
    conn, _ = source
    bundle = tmp_path.resolve() / "public-bundle"
    ps.export_public_snapshot(conn, bundle, _review(conn))
    return bundle


def test_plan_is_exact_private_unapproved_and_preserves_source(source):
    conn, path = source
    before = path.read_bytes(), tuple(conn.iterdump()), conn.total_changes
    plan = ps.plan_public_snapshot(conn, [SEED], observed_at=STAMP)
    assert plan["generated_skeleton_is_approval"] is False
    assert all(record["decision"] == "pending" for record in plan["records"])
    assert {row["table"] for row in plan["inventory"]} == set(ps.PUBLIC_TABLES)
    assert any(
        record["values"].get("signature") == "exact-public-witness-signature"
        for record in plan["records"]
    )
    assert (path.read_bytes(), tuple(conn.iterdump()), conn.total_changes) == before
    assert conn.in_transaction is False


def test_fresh_export_preserves_exact_dossier_and_excludes_deleted_source_remnants(
    source, tmp_path
):
    conn, path = source
    marker = "PRIVATE-DELETED-REMNANT-should-never-be-copied"
    secret = marker * 100
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE unrelated_private (content TEXT)")
    conn.execute("INSERT INTO unrelated_private VALUES (?)", (secret,))
    conn.commit()
    conn.execute("DELETE FROM unrelated_private")
    conn.commit()
    assert marker.encode() in path.read_bytes()
    before = path.read_bytes(), tuple(conn.iterdump()), conn.total_changes
    expected = load_claim_dossier(conn, SEED, observed_at=ps.datetime.fromisoformat(STAMP))
    bundle = _bundle(source, tmp_path)
    frozen = ps.load_public_snapshot(bundle, _pin(bundle))
    with frozen.connection() as public:
        actual = load_claim_dossier(public, SEED, observed_at=ps.datetime.fromisoformat(STAMP))
        assert actual == expected
        assert actual["challenges"]["unresolved_count"] == 2
        assert actual["corrections"]["items"]
        assert actual["reliance"]["status"] == "unestablished"
        assert {
            row[0] for row in public.execute("SELECT name FROM sqlite_master WHERE type='table'")
        } == set(ps.PUBLIC_TABLES)
    assert marker.encode() not in (bundle / "snapshot.sqlite3").read_bytes()
    assert (path.read_bytes(), tuple(conn.iterdump()), conn.total_changes) == before
    manifest = frozen.manifest
    assert "private-reviewer-not-for-manifest" not in json.dumps(manifest)
    assert "private-owner-record" not in json.dumps(manifest)
    assert str(path) not in json.dumps(manifest)
    assert hashlib.sha256(frozen.manifest_bytes).hexdigest() == _pin(bundle)


@pytest.mark.parametrize("compatibility", [False, True])
def test_identical_inputs_produce_identical_database_and_manifest_bytes(
    source, tmp_path, monkeypatch, compatibility
):
    if compatibility:
        monkeypatch.setattr(ps, "_HAS_SQLITE_SERIALIZATION", False)
    conn, _ = source
    review = _review(conn)
    one, two = tmp_path.resolve() / "one", tmp_path.resolve() / "two"
    ps.export_public_snapshot(conn, one, review)
    ps.export_public_snapshot(conn, two, review)
    assert (one / "snapshot.sqlite3").read_bytes() == (two / "snapshot.sqlite3").read_bytes()
    assert (one / "manifest.json").read_bytes() == (two / "manifest.json").read_bytes()
    frozen = ps.load_public_snapshot(one, _pin(one))
    with frozen.connection() as public:
        assert list_claims(public, q="条件")["total"] == 1
    assert not list(tmp_path.glob(".public-snapshot-build-*"))


@pytest.mark.parametrize(
    "change",
    [
        "pending",
        "missing_record",
        "unsigned_hash",
        "raw_unclassified",
        "consent",
        "privacy",
        "license",
        "takedown",
        "takedown_url",
    ],
)
def test_incomplete_or_invalid_publication_approval_fails_whole_export(source, tmp_path, change):
    conn, _ = source
    review = _review(conn)
    record = next(row for row in review["records"] if row["table"] == "sab_seed_packets_v1")
    if change == "pending":
        record["decision"] = "pending"
    elif change == "missing_record":
        review["records"].pop()
    elif change == "unsigned_hash":
        record["row_sha256"] = record["values"]["packet_hash"]
    elif change == "raw_unclassified":
        record["raw_json_review"]["packet_json"]["extensions_reviewed"] = False
    elif change == "consent":
        record["consent"].update(required=True, satisfied=False)
    elif change == "privacy":
        record["privacy_review"]["status"] = "pending"
    elif change == "license":
        record["license"] = None
    elif change == "takedown":
        record["takedown"]["owner"] = None
    elif change == "takedown_url":
        record["takedown"]["route"] = "https://[invalid"
    bundle = tmp_path.resolve() / "rejected"
    with pytest.raises(ps.PublicSnapshotError):
        ps.export_public_snapshot(conn, bundle, review)
    assert not bundle.exists()


@pytest.mark.parametrize("change", ["signature", "status", "new_challenge"])
def test_stale_review_binds_mutable_status_signature_and_complete_closure(source, tmp_path, change):
    conn, _ = source
    review = _review(conn)
    if change == "signature":
        raw = json.loads(conn.execute("SELECT packet_json FROM sab_seed_packets_v1").fetchone()[0])
        raw["signature"]["signature"] = "changed-but-unsigned-packet-hash-is-the-same"
        conn.execute("UPDATE sab_seed_packets_v1 SET packet_json=?", (json.dumps(raw),))
    elif change == "status":
        conn.execute("UPDATE sab_challenge_packets_v1 SET status='rejected'")
    else:
        row = dict(conn.execute("SELECT * FROM sab_challenge_packets_v1 LIMIT 1").fetchone())
        row.pop("id")
        row["challenge_id"] = "new_objection"
        _insert(conn, "sab_challenge_packets_v1", row)
    conn.commit()
    with pytest.raises(ps.PublicSnapshotError, match="closure or its observation changed"):
        ps.export_public_snapshot(conn, tmp_path.resolve() / "stale", review)


def test_extra_source_columns_are_not_copied_or_silently_classified(source):
    conn, _ = source
    conn.execute("ALTER TABLE sab_seed_packets_v1 ADD COLUMN secret_notes TEXT")
    conn.execute("UPDATE sab_seed_packets_v1 SET secret_notes='unclassified extension'")
    with pytest.raises(ps.PublicSnapshotError) as error:
        ps.plan_public_snapshot(conn, [SEED], observed_at=STAMP)
    assert error.value.code == "unclassified_source_columns"


@pytest.mark.parametrize(
    "extra",
    [
        {"private_key": "never publish"},
        {"nested": {"api_key": "never publish"}},
        {"ref": "file:///Users/private/evidence"},
        {"ref": "private-local:sha256:private-custody"},
        {"privacy_class": ["public"]},
        {"privacy_class": {"label": "public"}},
        {"value": "-----BEGIN PRIVATE KEY-----"},
    ],
)
def test_defense_in_depth_rejects_obvious_private_material_even_when_approved(
    source, tmp_path, extra
):
    conn, _ = source
    raw = json.loads(conn.execute("SELECT packet_json FROM sab_seed_packets_v1").fetchone()[0])
    raw["unknown_extension"] = extra
    conn.execute("UPDATE sab_seed_packets_v1 SET packet_json=?", (json.dumps(raw),))
    conn.commit()
    with pytest.raises(ps.PublicSnapshotError):
        ps.export_public_snapshot(conn, tmp_path.resolve() / "private-rejected", _review(conn))


def test_explicitly_reviewed_public_raw_extension_is_preserved(source, tmp_path):
    conn, _ = source
    raw = json.loads(conn.execute("SELECT packet_json FROM sab_seed_packets_v1").fetchone()[0])
    raw["unknown_extension"] = {"public_note": "A deliberately reviewed original extension."}
    original = json.dumps(raw, indent=3)
    conn.execute("UPDATE sab_seed_packets_v1 SET packet_json=?", (original,))
    conn.commit()
    bundle = _bundle(source, tmp_path)
    frozen = ps.load_public_snapshot(bundle, _pin(bundle))
    with frozen.connection() as public:
        assert (
            public.execute("SELECT packet_json FROM sab_seed_packets_v1").fetchone()[0] == original
        )


def test_state_event_with_missing_witness_context_fails_closure(source):
    conn, _ = source
    conn.execute("UPDATE sab_seed_events_v1 SET witness_event_id='missing_event'")
    with pytest.raises(ps.PublicSnapshotError) as error:
        ps.plan_public_snapshot(conn, [SEED], observed_at=STAMP)
    assert error.value.code == "incomplete_context"


def test_unselected_seed_is_excluded_and_witness_or_scope_selection_is_complete(source):
    conn, _ = source
    _seed(conn, "other_seed")
    # Preserve even a malformed scope association rather than dropping that
    # witness row from this seed's observed history.
    event = _event(conn, "affirm", "agent_witness", {"recorded": "scope matched"})
    conn.execute(
        "UPDATE sab_witness_events_v1 SET subject_seed_id='other_seed' WHERE event_id=?",
        (event["event_id"],),
    )
    plan = ps.plan_public_snapshot(conn, [SEED], observed_at=STAMP)
    assert all(item["values"].get("seed_id") != "other_seed" for item in plan["records"])
    assert any(item["record_id"] == event["event_id"] for item in plan["records"])


def test_bundle_and_files_are_create_only(source, tmp_path):
    bundle = _bundle(source, tmp_path)
    before = {path.name: path.read_bytes() for path in bundle.iterdir()}
    with pytest.raises(ps.PublicSnapshotError):
        ps.export_public_snapshot(source[0], bundle, _review(source[0]))
    assert {path.name: path.read_bytes() for path in bundle.iterdir()} == before


@pytest.mark.parametrize("pin", [None, "", "0" * 64, "sha256:" + "a" * 64])
def test_loader_requires_exact_out_of_band_manifest_pin(source, tmp_path, pin):
    bundle = _bundle(source, tmp_path)
    with pytest.raises(ps.PublicSnapshotError):
        ps.load_public_snapshot(bundle, pin)


@pytest.mark.parametrize(
    "member",
    ["snapshot.sqlite3-wal", "snapshot.sqlite3-shm", "snapshot.sqlite3-journal", "extra.txt"],
)
def test_loader_rejects_sidecars_and_extra_bundle_members(source, tmp_path, member):
    bundle = _bundle(source, tmp_path)
    (bundle / member).write_bytes(b"not admitted")
    with pytest.raises(ps.PublicSnapshotError) as error:
        ps.load_public_snapshot(bundle, _pin(bundle))
    assert error.value.code == "bundle_contents"


@pytest.mark.parametrize("kind", ["bundle", "manifest", "database"])
def test_loader_rejects_symlinks(source, tmp_path, kind):
    bundle = _bundle(source, tmp_path)
    pin = _pin(bundle)
    if kind == "bundle":
        linked = tmp_path.resolve() / "linked"
        linked.symlink_to(bundle, target_is_directory=True)
        bundle = linked
    else:
        filename = "manifest.json" if kind == "manifest" else "snapshot.sqlite3"
        target = tmp_path.resolve() / ("moved_" + filename)
        (bundle / filename).rename(target)
        (bundle / filename).symlink_to(target)
    with pytest.raises(ps.PublicSnapshotError):
        ps.load_public_snapshot(bundle, pin)


def _repin_after_database_change(bundle):
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    manifest["database"]["sha256"] = hashlib.sha256(
        (bundle / "snapshot.sqlite3").read_bytes()
    ).hexdigest()
    (bundle / "manifest.json").write_bytes(ps._canonical(manifest) + b"\n")
    return _pin(bundle)


@pytest.mark.parametrize(
    "change", ["extra_table", "extra_column", "view", "trigger", "row", "deleted_objection"]
)
def test_frozen_validator_rejects_schema_or_logical_inventory_changes_even_with_new_file_pin(
    source, tmp_path, change
):
    bundle = _bundle(source, tmp_path)
    with sqlite3.connect(bundle / "snapshot.sqlite3") as conn:
        if change == "extra_table":
            conn.execute("CREATE TABLE private_data (secret TEXT)")
        elif change == "extra_column":
            conn.execute("ALTER TABLE sab_seed_packets_v1 ADD COLUMN private_data TEXT")
        elif change == "view":
            conn.execute("CREATE VIEW misleading AS SELECT * FROM sab_seed_packets_v1")
        elif change == "trigger":
            conn.execute(
                "CREATE TRIGGER extra AFTER UPDATE ON sab_seed_packets_v1 BEGIN SELECT 1; END"
            )
        elif change == "row":
            conn.execute("UPDATE sab_seed_packets_v1 SET state='canon'")
        elif change == "deleted_objection":
            conn.execute("DELETE FROM sab_challenge_packets_v1 WHERE status='responded'")
    pin = _repin_after_database_change(bundle)
    with pytest.raises(ps.PublicSnapshotError):
        ps.load_public_snapshot(bundle, pin)


def test_manifest_is_closed_and_database_digest_is_required(source, tmp_path):
    bundle = _bundle(source, tmp_path)
    original_pin = _pin(bundle)
    path = bundle / "snapshot.sqlite3"
    path.write_bytes(path.read_bytes() + b"uncommitted-extra-bytes")
    with pytest.raises(ps.PublicSnapshotError) as error:
        ps.load_public_snapshot(bundle, original_pin)
    assert error.value.code == "database_digest_mismatch"
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    manifest["source_private_path"] = "/Users/private/custody"
    (bundle / "manifest.json").write_bytes(ps._canonical(manifest))
    with pytest.raises(ps.PublicSnapshotError) as error:
        ps.load_public_snapshot(bundle, _pin(bundle))
    assert error.value.code == "manifest_schema"


@pytest.mark.parametrize("compatibility", [False, True])
def test_file_changes_after_load_cannot_change_process_lifetime_reads(
    source, tmp_path, monkeypatch, compatibility
):
    if compatibility:
        monkeypatch.setattr(ps, "_HAS_SQLITE_SERIALIZATION", False)
    bundle = _bundle(source, tmp_path)
    frozen = ps.load_public_snapshot(bundle, _pin(bundle))
    pinned_bytes = frozen.manifest_bytes
    with frozen.connection() as public:
        before = list_claims(public)
    (bundle / "snapshot.sqlite3").write_bytes(b"replaced after load")
    (bundle / "manifest.json").write_bytes(b"replaced after load")
    with frozen.connection() as public:
        assert list_claims(public) == before
    changed_copy = frozen.manifest
    changed_copy["selected_seed_ids"].clear()
    assert frozen.status["seed_count"] == 1
    assert frozen.manifest_bytes == pinned_bytes


@pytest.mark.parametrize(
    "sql",
    [
        "PRAGMA query_only=OFF",
        "CREATE TABLE forbidden (id INTEGER)",
        "CREATE TEMP TABLE forbidden (id INTEGER)",
        "UPDATE sab_seed_packets_v1 SET state='canon'",
        "DELETE FROM sab_seed_packets_v1",
        "ATTACH DATABASE ':memory:' AS extra",
        "PRAGMA writable_schema=ON",
        "PRAGMA user_version=2",
        "SELECT load_extension('anything')",
    ],
)
def test_direct_sql_mutation_and_unsafe_pragma_remain_forbidden(source, tmp_path, sql):
    bundle = _bundle(source, tmp_path)
    frozen = ps.load_public_snapshot(bundle, _pin(bundle))
    with frozen.connection() as public:
        with pytest.raises(sqlite3.DatabaseError):
            public.execute(sql)
        # The authorizer is independent of query_only, and cannot be disabled
        # through the public connection's normal mutation interface.
        with pytest.raises(sqlite3.DatabaseError):
            public.set_authorizer(None)
        public.execute("BEGIN")
        assert public.execute("PRAGMA table_info(sab_seed_packets_v1)").fetchall()
        public.rollback()
        assert public.execute("SELECT count(*) FROM sab_seed_packets_v1").fetchone()[0] == 1


def test_unconfigured_has_no_tables_or_files_and_explicit_empty_has_fixed_schema(tmp_path):
    before = set(tmp_path.iterdir())
    empty = ps.load_public_snapshot(None, None)
    assert empty.configured is False
    assert empty.status["status"] == "not_configured"
    assert empty.manifest is empty.manifest_bytes is None
    with empty.connection() as public:
        assert public.execute("SELECT name FROM sqlite_master").fetchall() == []
        assert list_claims(public)["availability"] == "missing"
        with pytest.raises(sqlite3.DatabaseError):
            public.execute("CREATE TABLE nope (x)")
    assert set(tmp_path.iterdir()) == before
    bundle = tmp_path.resolve() / "explicit_empty"
    ps.export_empty_public_snapshot(bundle, observed_at=STAMP)
    configured = ps.load_public_snapshot(bundle, _pin(bundle))
    assert configured.configured is True
    with configured.connection() as public:
        assert (
            len(public.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()) == 7
        )
        assert list_claims(public)["availability"] == "present"


def test_cli_plan_requires_review_and_empty_is_offline(source, tmp_path):
    conn, source_path = source
    review_path = tmp_path.resolve() / "review.json"
    script = Path(__file__).resolve().parents[1] / "scripts/export_public_snapshot.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "plan",
            "--source",
            str(source_path),
            "--seed-id",
            SEED,
            "--observed-at",
            STAMP,
            "--review-out",
            str(review_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["generated_skeleton_is_approval"] is False
    assert SEED not in result.stdout and "packet_json" not in result.stdout
    assert review_path.stat().st_mode & 0o777 == 0o600
    rejected = subprocess.run(
        [
            sys.executable,
            str(script),
            "export",
            "--source",
            str(source_path),
            "--review",
            str(review_path),
            "--bundle",
            str(tmp_path.resolve() / "pending"),
        ],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert not (tmp_path / "pending").exists()
    review_path.write_text(json.dumps(_approve(json.loads(review_path.read_text()))))
    exported = subprocess.run(
        [
            sys.executable,
            str(script),
            "export",
            "--source",
            str(source_path),
            "--review",
            str(review_path),
            "--bundle",
            str(tmp_path.resolve() / "cli_bundle"),
        ],
        capture_output=True,
        text=True,
    )
    assert exported.returncode == 0, exported.stderr
    assert json.loads(exported.stdout)["manifest_sha256"] == _pin(tmp_path / "cli_bundle")
    offline = subprocess.run(
        [
            sys.executable,
            str(script),
            "empty",
            "--bundle",
            str(tmp_path.resolve() / "offline"),
            "--observed-at",
            STAMP,
        ],
        capture_output=True,
        text=True,
    )
    assert offline.returncode == 0, offline.stderr


def test_public_manifest_matches_published_schema(source, tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    bundle = _bundle(source, tmp_path)
    schema_path = (
        Path(__file__).resolve().parents[1] / "nodes/schemas/sab.public_snapshot.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(
        json.loads((bundle / "manifest.json").read_bytes())
    )


@pytest.mark.parametrize("member", ["manifest.json", "snapshot.sqlite3"])
def test_nonregular_bundle_member_is_rejected_without_blocking(tmp_path, member):
    bundle = tmp_path.resolve() / "fifo-bundle"
    ps.export_empty_public_snapshot(bundle, observed_at=STAMP)
    pin = _pin(bundle)
    (bundle / member).unlink()
    os.mkfifo(bundle / member)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys\n"
            "from agora.public_snapshot import load_public_snapshot, PublicSnapshotError\n"
            "try:\n"
            "    load_public_snapshot(sys.argv[1], sys.argv[2])\n"
            "except PublicSnapshotError as exc:\n"
            "    print(exc.code)\n"
            "    sys.exit(2)\n",
            str(bundle),
            pin,
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 2, result.stderr
    assert result.stdout.strip() == "bundle_file"
