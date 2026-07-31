from __future__ import annotations

import importlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agora.sab_seeding_storage import (
    append_witness_event,
    canonical_payload_sha256,
    get_seed_packet,
    init_sab_seeding_storage,
    persist_seed_packet,
    upsert_spark_projection,
)


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _create_sparks_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE sparks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            content_type TEXT NOT NULL,
            author_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            gate_scores TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('spark', 'canon', 'compost')),
            rv_contraction REAL,
            composite_score REAL DEFAULT 0.0,
            node_coordinate TEXT,
            claim_packet_ref TEXT,
            artifact_refs_json TEXT NOT NULL DEFAULT '[]',
            red_team_refs_json TEXT NOT NULL DEFAULT '[]',
            witness_refs_json TEXT NOT NULL DEFAULT '[]',
            lineage_root_id INTEGER,
            parent_spark_id INTEGER,
            sublation_status TEXT,
            founding_seed INTEGER NOT NULL DEFAULT 0
        )
        """
    )


def _seed_packet() -> dict[str, object]:
    return {
        "schema": "sab.seed_packet.v1",
        "seed_id": "sab_seed_storage_test_001",
        "seed_type": "claim",
        "title": "Storage test seed",
        "status": "pending_seed",
        "loop_position": "spark",
        "north_star": "deepen_truth",
        "claim": {
            "claim_id": "sab_claim_storage_test_001",
            "text": "Canonical storage preserves seed packet hash material.",
            "claim_type": "provenance",
            "scope": "storage tests",
            "decision_context": "schema bootstrap and projection verification",
            "success_conditions": ["round trip hash unchanged"],
            "failure_conditions": ["projection mutates packet"],
        },
        "claimant_identity": {
            "subject_id": "agent_ed25519_storage",
            "identity_ref": "sab_identity_storage",
        },
        "operator_backing": {
            "operator_ref": "operator-storage",
            "disclosure": "test",
            "concentration_attestation": "self_attested",
        },
        "authority_lease": {
            "lease_ref": "sab_lease_storage",
            "scope": "submit one public seed packet for challenge",
            "expires_at": "2026-08-01T00:00:00+00:00",
            "revoker": "sab_policy",
            "challenge_path": "/api/v1/seeds/sab_seed_storage_test_001/challenges",
        },
        "evidence_bundle": [
            {
                "ref": "tests/test_sab_seeding_storage.py",
                "kind": "test",
                "digest": "sha256 optional",
                "notes": "local storage test",
            }
        ],
        "challenge_plan": {
            "required": True,
            "challenge_window": "P7D",
            "strongest_objections": ["storage schema may drift"],
            "challenge_refs": ["red-team-storage-check"],
            "falsification_routes": ["alter packet and expect hash mismatch"],
        },
        "witness_plan": {
            "required_roles": ["storage_reviewer"],
            "minimum_witnesses": 1,
            "non_adjacent_required": True,
            "forbidden_witnesses": [],
        },
        "build_plan": {
            "artifact_refs": [],
            "production_grade_definition": "idempotent sqlite storage",
        },
        "anti_capture_rules": ["identity is not standing"],
        "commons_return": {
            "mode": "public_receipt",
            "minimum_return": "test coverage",
        },
        "canon_compost_policy": {
            "canon_conditions": ["witness chain verifies"],
            "compost_conditions": ["hash mismatch"],
            "revalidation_due": "2026-09-01T00:00:00+00:00",
        },
        "privacy_class": "public",
        "created_at": "2026-07-04T00:00:00+00:00",
        "signature": {
            "alg": "ed25519",
            "signer": "agent_ed25519_storage",
            "signature": "ab" * 64,
            "canonicalization": "json-sort-keys-compact-v1",
        },
    }


def test_init_creates_canonical_tables_and_indexes_idempotently(tmp_path: Path) -> None:
    db_path = tmp_path / "sab_storage.db"
    with _connect(db_path) as conn:
        init_sab_seeding_storage(conn)
        init_sab_seeding_storage(conn)

        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "agent_identities",
            "external_identity_attestations",
            "authority_leases",
            "seed_packets",
            "seed_events",
            "challenge_packets",
            "witness_events",
            "standing_leases",
            "standing_events",
        }.issubset(tables)

        indexes = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        assert {
            "idx_seed_packets_seed_id",
            "idx_seed_packets_claim_id",
            "idx_seed_packets_claimant_identity",
            "idx_seed_packets_status",
            "idx_standing_leases_standing_id",
            "idx_witness_events_chain_head",
        }.issubset(indexes)


def test_seed_packet_round_trips_and_maps_to_spark_without_hash_mutation(tmp_path: Path) -> None:
    packet = _seed_packet()
    expected_hash = canonical_payload_sha256(packet)

    with _connect(tmp_path / "sab_storage.db") as conn:
        _create_sparks_table(conn)
        init_sab_seeding_storage(conn)

        stored = persist_seed_packet(conn, packet, received_at="2026-07-04T00:00:01+00:00")
        assert stored["seed_packet_sha256"] == expected_hash
        assert json.loads(stored["seed_packet_json"]) == packet

        fetched = get_seed_packet(conn, "sab_seed_storage_test_001")
        assert fetched is not None
        assert fetched["claim_id"] == "sab_claim_storage_test_001"
        assert fetched["claimant_identity"] == "agent_ed25519_storage"
        assert fetched["authority_lease_id"] == "sab_lease_storage"

        spark = upsert_spark_projection(conn, "sab_seed_storage_test_001")
        assert spark["claim_packet_ref"] == "sab_seed_storage_test_001"
        assert spark["content"] == "Canonical storage preserves seed packet hash material."
        assert json.loads(spark["artifact_refs_json"]) == ["tests/test_sab_seeding_storage.py"]
        assert json.loads(spark["red_team_refs_json"]) == ["red-team-storage-check"]
        assert json.loads(spark["witness_refs_json"]) == ["storage_reviewer"]
        gate_scores = json.loads(spark["gate_scores"])
        assert gate_scores["seed_packet_sha256"] == expected_hash

        second = upsert_spark_projection(conn, "sab_seed_storage_test_001")
        assert int(second["id"]) == int(spark["id"])
        assert canonical_payload_sha256(packet) == expected_hash
        assert conn.execute("SELECT COUNT(*) FROM sparks").fetchone()[0] == 1


def test_append_witness_events_are_hash_linked_and_update_seed_head(tmp_path: Path) -> None:
    packet = _seed_packet()

    with _connect(tmp_path / "sab_storage.db") as conn:
        init_sab_seeding_storage(conn)
        persist_seed_packet(conn, packet)

        first = append_witness_event(
            conn,
            {
                "schema": "sab.witness_event.v1",
                "event_id": "sab_witness_storage_001",
                "event_type": "submit",
                "actor_identity": "agent_ed25519_storage",
                "subject_type": "seed",
                "subject_id": "sab_seed_storage_test_001",
                "timestamp": "2026-07-04T00:00:02+00:00",
                "payload": {"seed_packet_sha256": canonical_payload_sha256(packet)},
                "signature": {"alg": "ed25519", "signature": "cd" * 64},
            },
        )
        assert first["prev_hash"] == "genesis"
        assert first["chain_head_hash"] == first["event_hash"]

        second = append_witness_event(
            conn,
            {
                "schema": "sab.witness_event.v1",
                "event_id": "sab_witness_storage_002",
                "event_type": "gate_scored",
                "actor_identity": "system",
                "subject_type": "seed",
                "subject_id": "sab_seed_storage_test_001",
                "timestamp": "2026-07-04T00:00:03+00:00",
                "payload": {"status": "challenge_window_open"},
                "signature": {"alg": "ed25519", "signature": "ef" * 64},
            },
        )
        assert second["prev_hash"] == first["event_hash"]
        assert second["chain_head_hash"] == second["event_hash"]

        seed = get_seed_packet(conn, "sab_seed_storage_test_001")
        assert seed is not None
        assert seed["witness_head_hash"] == second["event_hash"]

        duplicate = append_witness_event(
            conn,
            {
                "schema": "sab.witness_event.v1",
                "event_id": "sab_witness_storage_002",
                "event_type": "gate_scored",
                "actor_identity": "system",
                "subject_type": "seed",
                "subject_id": "sab_seed_storage_test_001",
                "timestamp": "2026-07-04T00:00:03+00:00",
                "payload": {"status": "challenge_window_open"},
                "signature": {"alg": "ed25519", "signature": "ef" * 64},
            },
        )
        assert duplicate["event_hash"] == second["event_hash"]


def test_app_init_creates_sab_tables_on_spark_db(tmp_path: Path, monkeypatch) -> None:
    pytest.importorskip("jinja2")
    db_path = tmp_path / "spark.db"
    key_path = tmp_path / ".sab_system_ed25519.key"
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(key_path))

    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]

    web_app = importlib.import_module("agora.app")
    web_app.init_db()
    web_app.init_db()

    with _connect(db_path) as conn:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert {"sparks", "spark_challenges", "spark_witness_chain", "seed_packets"}.issubset(tables)
