from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

import pytest

from agora.sab_first_verdict_evidence import (
    EvidenceValidationError,
    SQLITE_LIFECYCLE_ALGORITHM,
    SQLITE_LIFECYCLE_TABLES,
    backup_database_readonly,
    canonical_sha256,
    capture_preexisting_table_digests,
    lifecycle_fingerprint,
    open_sqlite_readonly,
    snapshot_database,
    verify_database_snapshot,
    verify_preexisting_table_digests,
)


AUTHORIZED_SOURCE = Path("/Users/dhyana/dharmic-agora/data/spark.db")
A0_LIFECYCLE_SHA256 = "2dc4a5d688d726d7dbe67781e2f6baadcd35813fec60d45601e8b9acd3d8e6bb"
A0_TABLE_CONTENT_SHA256 = {
    "sab_agent_identities_v1": (
        "45aa784fd004e840eb970afeb481b2d825bd63501e74a22c911ea92584abd29d"
    ),
    "sab_challenge_packets_v1": (
        "dc7ed0d28b970f7d870ddf5086fffbc1abe7a20e33312a9d1569710791acfbda"
    ),
    "sab_seed_events_v1": (
        "752e73267a53006359f1feafe584103a3245331e6dafa936f71c8df13a09ce2e"
    ),
    "sab_seed_packets_v1": (
        "6cd45d71dd5331e2ab16acd56a5d5b7f8feebda3132e9004473e6984e684e812"
    ),
    "sab_standing_events_v1": (
        "17af72f5206bd233e74b43346c0cc181184a58ed56fd59ec9291fa1df2e8e768"
    ),
    "sab_standing_leases_v1": (
        "03dab5024c7e02d3f45725fc511c235ee12109ce5c15a7835bed947e243640e8"
    ),
    "sab_witness_events_v1": (
        "bf764a416803600302bc408829fa6e364a79036d36fb229a00b08323fc812440"
    ),
    "spark_challenges": (
        "2c220c0c22afd84f1e48d164b66ca80af00cb637043f37f7cb932f8080eb82b0"
    ),
    "spark_witness_chain": (
        "744e5826f084f5793bfe49f52ded8a0ce402b77318247fb30166482b1dd94d96"
    ),
    "sparks": ("82cc43527555f8a08c6c825d090cb174aa07d9d5ea005962008cef66bd56933f"),
}


def _database(path: Path) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE sab_seed_packets_v1 (
                id INTEGER PRIMARY KEY,
                seed_id TEXT NOT NULL,
                state TEXT NOT NULL,
                packet_hash TEXT NOT NULL
            );
            CREATE TABLE sab_challenge_packets_v1 (
                id INTEGER PRIMARY KEY,
                target_seed_id TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE sab_witness_events_v1 (
                id INTEGER PRIMARY KEY,
                chain_scope TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            CREATE TABLE sab_standing_leases_v1 (
                id INTEGER PRIMARY KEY,
                subject_seed_id TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE user_values (id INTEGER PRIMARY KEY, note TEXT, payload BLOB);
            """
        )
        conn.execute(
            "INSERT INTO sab_seed_packets_v1 VALUES (1, 'seed_a', 'pending_seed', ?)",
            ("a" * 64,),
        )
        conn.execute(
            "INSERT INTO sab_witness_events_v1 VALUES (1, 'seed_a', ?)",
            ("b" * 64,),
        )
        conn.execute("INSERT INTO user_values VALUES (1, '雪', ?)", (b"\x00\xff",))
        conn.commit()


def test_online_backup_is_explicit_private_integral_and_source_unchanged(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.sqlite"
    destination = tmp_path / "copy.sqlite"
    _database(source)
    source_before = source.stat()

    receipt = backup_database_readonly(source, destination)

    assert destination.exists()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert receipt["backup_method"] == "sqlite_online_backup_from_mode_ro_source"
    assert receipt["source_unchanged"] is True
    assert receipt["copy_snapshot"]["integrity"] == "ok"
    assert receipt["source"]["path_ref"].startswith("private-local:sha256:")
    assert receipt["destination"]["path_ref"].startswith("private-local:sha256:")
    assert len(receipt["source"]["sha256"]) == 64
    assert len(receipt["destination"]["sha256"]) == 64
    assert all(receipt["logical_equivalence"].values())
    source_after = source.stat()
    assert source_after.st_mtime_ns == source_before.st_mtime_ns
    assert source_after.st_size == source_before.st_size

    with closing(open_sqlite_readonly(destination)) as conn:
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO user_values VALUES (2, 'blocked', X'00')")


@pytest.mark.parametrize(
    ("kind", "expected_code"),
    [
        ("same", "same_path"),
        ("existing", "destination_exists"),
        ("source_symlink", "source_symlink"),
        ("destination_symlink", "destination_symlink"),
    ],
)
def test_backup_rejects_ambiguous_or_overwriting_paths(
    tmp_path: Path, kind: str, expected_code: str
) -> None:
    source = tmp_path / "source.sqlite"
    _database(source)
    destination = tmp_path / "copy.sqlite"
    if kind == "same":
        destination = source
    elif kind == "existing":
        destination.touch()
    elif kind == "source_symlink":
        link = tmp_path / "source-link.sqlite"
        link.symlink_to(source)
        source = link
    elif kind == "destination_symlink":
        target = tmp_path / "target.sqlite"
        destination.symlink_to(target)

    with pytest.raises(EvidenceValidationError) as raised:
        backup_database_readonly(source, destination)
    assert raised.value.code == expected_code


def test_backup_rejects_destination_inside_git_checkout(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    _database(source)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    with pytest.raises(EvidenceValidationError) as raised:
        backup_database_readonly(source, checkout / "copy.sqlite")
    assert raised.value.code == "destination_inside_git"


def test_preexisting_column_digests_survive_additive_column_but_detect_row_drift(
    tmp_path: Path,
) -> None:
    database = tmp_path / "database.sqlite"
    _database(database)
    with closing(sqlite3.connect(database)) as conn:
        conn.row_factory = sqlite3.Row
        baseline = capture_preexisting_table_digests(conn)
        conn.execute("ALTER TABLE user_values ADD COLUMN additive TEXT DEFAULT 'new'")
        conn.commit()
        assert verify_preexisting_table_digests(conn, baseline)["verified"] is True
        conn.execute("UPDATE user_values SET note='changed' WHERE id=1")
        conn.commit()
        verification = verify_preexisting_table_digests(conn, baseline)
    assert verification["verified"] is False
    assert any(item["table"] == "user_values" for item in verification["mismatches"])


def test_snapshot_is_deterministic_and_tamper_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "database.sqlite"
    _database(database)
    first = snapshot_database(database)
    second = snapshot_database(database)
    assert first == second
    assert first["lifecycle"]["algorithm"] == SQLITE_LIFECYCLE_ALGORITHM
    assert first["lifecycle"]["lifecycle_tables"] == [
        "sab_challenge_packets_v1",
        "sab_seed_packets_v1",
        "sab_standing_leases_v1",
        "sab_witness_events_v1",
    ]
    assert first["lifecycle"]["material"] == first["lifecycle"]["table_content_sha256"]
    assert first["lifecycle"]["sha256"] == canonical_sha256(
        first["lifecycle"]["material"]
    )
    assert first["lifecycle"]["summary"]["seed_count"] == 1
    assert first["lifecycle"]["summary"]["witness_forest_heads"] == {"seed_a": "b" * 64}

    with closing(sqlite3.connect(database)) as conn:
        conn.execute("UPDATE user_values SET note='tampered' WHERE id=1")
        conn.commit()
    verification = verify_database_snapshot(database, first)
    assert verification["verified"] is False
    assert verification["comparisons"]["database_sha256"] is False


@pytest.mark.skipif(
    not AUTHORIZED_SOURCE.is_file(), reason="authorized source database unavailable"
)
def test_sqlite_lifecycle_v1_matches_frozen_a0_source() -> None:
    with closing(open_sqlite_readonly(AUTHORIZED_SOURCE)) as conn:
        fingerprint = lifecycle_fingerprint(conn)

    assert fingerprint["algorithm"] == SQLITE_LIFECYCLE_ALGORITHM
    assert fingerprint["lifecycle_tables"] == list(SQLITE_LIFECYCLE_TABLES)
    assert fingerprint["table_content_sha256"] == A0_TABLE_CONTENT_SHA256
    assert fingerprint["material"] == A0_TABLE_CONTENT_SHA256
    assert fingerprint["sha256"] == A0_LIFECYCLE_SHA256


def test_backup_failure_does_not_leave_partial_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.sqlite"
    destination = tmp_path / "copy.sqlite"
    _database(source)

    def fail_snapshot(_: Path) -> dict[str, object]:
        raise EvidenceValidationError("forced", "forced")

    # Several legacy isolation tests deliberately evict every ``agora`` module
    # from sys.modules.  Patch the collected function's actual globals so this
    # failure injection remains deterministic across full-suite test order.
    monkeypatch.setitem(
        backup_database_readonly.__globals__, "snapshot_database", fail_snapshot
    )
    with pytest.raises(EvidenceValidationError):
        backup_database_readonly(source, destination)
    assert not destination.exists()
    assert os.path.exists(source)
