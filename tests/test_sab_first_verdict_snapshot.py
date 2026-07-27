from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

import pytest

from agora.sab_first_verdict_evidence import (
    EvidenceValidationError,
    backup_database_readonly,
    capture_preexisting_table_digests,
    open_sqlite_readonly,
    snapshot_database,
    verify_database_snapshot,
    verify_preexisting_table_digests,
)


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
    assert first["lifecycle"]["material"]["seed_count"] == 1
    assert first["lifecycle"]["material"]["witness_forest_heads"] == {
        "seed_a": "b" * 64
    }

    with closing(sqlite3.connect(database)) as conn:
        conn.execute("UPDATE user_values SET note='tampered' WHERE id=1")
        conn.commit()
    verification = verify_database_snapshot(database, first)
    assert verification["verified"] is False
    assert verification["comparisons"]["database_sha256"] is False


def test_backup_failure_does_not_leave_partial_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.sqlite"
    destination = tmp_path / "copy.sqlite"
    _database(source)

    def fail_snapshot(_: Path) -> dict[str, object]:
        raise EvidenceValidationError("forced", "forced")

    monkeypatch.setattr(
        "agora.sab_first_verdict_evidence.snapshot_database", fail_snapshot
    )
    with pytest.raises(EvidenceValidationError):
        backup_database_readonly(source, destination)
    assert not destination.exists()
    assert os.path.exists(source)
