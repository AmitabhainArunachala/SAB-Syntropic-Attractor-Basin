from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from agora.sab_artifact_verdict import CompostBatchPreviewV1
from agora.sab_first_verdict_evidence import (
    GENERIC_CLAIM_TEMPLATE,
    GENERIC_CONTRIBUTION_TITLE,
    preview_contract_payload,
    preview_database_readonly,
)


def _packet(seed_id: str, actor: str, claim_text: str, evidence_count: int = 1) -> dict:
    return {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "title": GENERIC_CONTRIBUTION_TITLE,
        "claim": {"text": claim_text},
        "evidence_bundle": [
            {
                "ref": f"evidence:{seed_id}:{index}",
                "kind": "source",
                "digest": hashlib.sha256(f"{seed_id}:{index}".encode()).hexdigest(),
                "privacy_class": "public",
            }
            for index in range(evidence_count)
        ],
        "claimant_identity": {"subject_id": actor},
    }


def _insert_seed(
    conn: sqlite3.Connection,
    *,
    seed_id: str,
    actor: str,
    claim_text: str,
    state: str = "pending_seed",
    title: str = GENERIC_CONTRIBUTION_TITLE,
    evidence_count: int = 1,
) -> None:
    packet = _packet(seed_id, actor, claim_text, evidence_count)
    packet["title"] = title
    packet_json = json.dumps(packet, sort_keys=True, separators=(",", ":"))
    conn.execute(
        "INSERT INTO sab_seed_packets_v1 "
        "(seed_id,title,state,packet_json,packet_hash) VALUES (?,?,?,?,?)",
        (
            seed_id,
            title,
            state,
            packet_json,
            hashlib.sha256(packet_json.encode()).hexdigest(),
        ),
    )


def _preview_database(path: Path) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE sab_seed_packets_v1 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seed_id TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                state TEXT NOT NULL,
                packet_json TEXT NOT NULL,
                packet_hash TEXT NOT NULL
            );
            CREATE TABLE sab_challenge_packets_v1 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_seed_id TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE sab_standing_leases_v1 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_seed_id TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE sab_witness_events_v1 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_scope TEXT NOT NULL,
                subject_seed_id TEXT,
                event_hash TEXT NOT NULL
            );
            CREATE TABLE sab_council_verdicts_v1 (
                verdict_id TEXT PRIMARY KEY,
                target_seed_id TEXT NOT NULL
            );
            CREATE TABLE sab_rehearsal_dispositions_v1 (
                disposition_id TEXT PRIMARY KEY,
                subject_seed_id TEXT NOT NULL
            );
            CREATE TABLE sab_seed_lineage_edges_v1 (
                edge_id TEXT PRIMARY KEY,
                predecessor_seed_id TEXT NOT NULL,
                successor_seed_id TEXT NOT NULL
            );
            """
        )
        for index in range(59):
            actor = "agent_hermes_m5"
            seed_id = f"sab_seed_language_womb_agent_hermes_m5_{index:012x}"
            _insert_seed(
                conn,
                seed_id=seed_id,
                actor=actor,
                claim_text=GENERIC_CLAIM_TEMPLATE.format(actor=actor),
                evidence_count=1 + index % 3,
            )
            conn.execute(
                "INSERT INTO sab_witness_events_v1 "
                "(chain_scope,subject_seed_id,event_hash) VALUES (?,?,?)",
                (seed_id, seed_id, hashlib.sha256(seed_id.encode()).hexdigest()),
            )
        for index in range(2):
            actor = "agent_dharma_cron"
            seed_id = f"sab_seed_language_womb_agent_dharma_cron_{index:012x}"
            _insert_seed(
                conn,
                seed_id=seed_id,
                actor=actor,
                claim_text=GENERIC_CLAIM_TEMPLATE.format(actor=actor),
                evidence_count=2,
            )

        # Six exact exclusions complete the frozen 67-row snapshot.
        _insert_seed(
            conn,
            seed_id="sab_seed_language_womb_agent_dharma_cron_distinct",
            actor="agent_dharma_cron",
            claim_text="A distinct, challengeable epistemic-modality claim.",
        )
        _insert_seed(
            conn,
            seed_id="sab_seed_language_womb_agent_sab_language_womb_scheduler_1",
            actor="agent_scheduler",
            claim_text="The language womb needs challengeable deltas.",
        )
        _insert_seed(
            conn,
            seed_id="sab_seed_master_vision_v1",
            actor="agent_fable",
            claim_text="Master Vision",
            state="challenged",
            title="SAB Master Vision v1.0",
        )
        _insert_seed(
            conn,
            seed_id="sab_seed_dogfood",
            actor="agent_dogfood",
            claim_text="Dogfood",
            state="standing_active",
            title="Dogfood receipt",
        )
        _insert_seed(
            conn,
            seed_id="sab_seed_corrected",
            actor="agent_other",
            claim_text="Corrected",
            state="corrected",
            title="Correction",
        )
        _insert_seed(
            conn,
            seed_id="sab_seed_other_pending",
            actor="agent_other",
            claim_text="Other",
            title="Other",
        )
        conn.execute(
            "INSERT INTO sab_challenge_packets_v1(target_seed_id,status) VALUES (?,?)",
            ("sab_seed_master_vision_v1", "pending"),
        )
        conn.execute(
            "INSERT INTO sab_standing_leases_v1(subject_seed_id,status) VALUES (?,?)",
            ("sab_seed_dogfood", "active"),
        )
        conn.commit()


def test_preview_scans_all_67_and_selects_exact_59_plus_2_without_writes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "copy.sqlite"
    _preview_database(database)
    result = preview_database_readonly(database)

    assert result["scanned_count"] == 67
    assert result["eligible_count"] == 61
    assert result["actor_counts"] == {
        "agent_dharma_cron": 2,
        "agent_hermes_m5": 59,
    }
    assert result["excluded_count"] == 6
    assert result["transition_count"] == 0
    assert result["standing_effect"] == "none"
    assert result["execution_supported"] is False
    assert all(result["no_write_proof"].values())
    assert len(result["eligible"]) == 61
    assert all(item["evidence_bundle"] for item in result["eligible"])
    assert result["evidence_reference_count"] == sum(
        len(item["evidence_bundle"]) for item in result["eligible"]
    )
    assert all(len(item["packet_hash"]) == 64 for item in result["eligible"])
    assert all("witness_heads" in item for item in result["eligible"])
    strict_contract = CompostBatchPreviewV1.model_validate(
        preview_contract_payload(result)
    )
    assert strict_contract.selected_count == 61


def test_preview_records_exact_exclusion_reasons(tmp_path: Path) -> None:
    database = tmp_path / "copy.sqlite"
    _preview_database(database)
    result = preview_database_readonly(database)
    exclusions = {item["seed_id"]: item["reasons"] for item in result["excluded"]}

    assert (
        "claim_text_not_exact_actor_parameterized_template"
        in exclusions["sab_seed_language_womb_agent_dharma_cron_distinct"]
    )
    assert (
        "seed_id_not_in_actor_slots"
        in exclusions["sab_seed_language_womb_agent_sab_language_womb_scheduler_1"]
    )
    assert "state_not_pending_seed" in exclusions["sab_seed_master_vision_v1"]
    assert "challenge_exists" in exclusions["sab_seed_master_vision_v1"]
    assert "standing_exists" in exclusions["sab_seed_dogfood"]


def test_preview_excludes_future_disposition_verdict_and_lineage_relations(
    tmp_path: Path,
) -> None:
    database = tmp_path / "copy.sqlite"
    _preview_database(database)
    with closing(sqlite3.connect(database)) as conn:
        targets = [
            "sab_seed_language_womb_agent_hermes_m5_000000000000",
            "sab_seed_language_womb_agent_hermes_m5_000000000001",
            "sab_seed_language_womb_agent_hermes_m5_000000000002",
        ]
        conn.execute(
            "INSERT INTO sab_council_verdicts_v1 VALUES ('verdict', ?)", (targets[0],)
        )
        conn.execute(
            "INSERT INTO sab_rehearsal_dispositions_v1 VALUES ('disposition', ?)",
            (targets[1],),
        )
        conn.execute(
            "INSERT INTO sab_seed_lineage_edges_v1 VALUES ('edge', ?, 'successor')",
            (targets[2],),
        )
        conn.commit()
    result = preview_database_readonly(database)
    exclusions = {item["seed_id"]: item["reasons"] for item in result["excluded"]}
    assert "effective_verdict_exists" in exclusions[targets[0]]
    assert "effective_verdict_exists" in exclusions[targets[1]]
    assert "lineage_edge_exists" in exclusions[targets[2]]
    assert result["eligible_count"] == 58
