from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

import agora.sab_first_verdict_storage as storage_module
from agora.sab_artifact_verdict import canonical_json_bytes, canonical_sha256
from agora.sab_first_verdict_storage import (
    CopyDatabaseAttestation,
    DatabaseSafetyError,
    MIGRATION_DIGEST,
    MIGRATION_ID,
    MIGRATION_STATEMENTS,
    FirstVerdictStorageError,
    ForeignKeysRequired,
    ImmutableConflict,
    LeaseStateConflict,
    MigrationDigestMismatch,
    MigrationSchemaMismatch,
    activate_session_lease,
    ballot_set_sha256_for_case,
    canonical_json_text,
    get_json_record,
    idempotency_lookup,
    immutable_digest_for,
    init_first_verdict_storage,
    open_attested_copy_connection,
    record_idempotency,
    release_session_lease,
    require_copy_or_fixture_connection,
    require_immutable_identity,
    store_artifact_ballot,
    store_artifact_case,
    store_authority_evaluation,
    store_council_verdict,
)


_NOW = "2026-07-28T00:00:00Z"
_LATER = "2026-07-28T00:01:00Z"
_CONTRACT_FIXTURES = Path(__file__).parent / "fixtures" / "sab_first_verdict" / "valid"

_IMMUTABLE_TABLE_IDS = {
    "sab_first_verdict_schema_migrations_v1": ("migration_id", MIGRATION_ID),
    "sab_artifact_cases_v1": ("case_id", "case-1"),
    "sab_artifact_ballots_v1": ("ballot_id", "ballot-1"),
    "sab_disposition_authority_v1": ("evaluation_id", "authority-1"),
    "sab_council_verdicts_v1": ("verdict_id", "verdict-1"),
    "sab_operator_countersigns_v1": ("countersign_id", "countersign-1"),
    "sab_rehearsal_dispositions_v1": ("disposition_id", "disposition-1"),
    "sab_seed_lineage_edges_v1": ("edge_id", "edge-1"),
    "sab_first_verdict_signed_events_v1": ("event_id", "event-1"),
    "sab_first_verdict_idempotency_v1": (
        "idempotency_key",
        "idempotency-key-1",
    ),
}


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _contract_fixture(filename: str) -> dict[str, object]:
    return json.loads((_CONTRACT_FIXTURES / filename).read_text())


def _json_and_digest(payload: dict[str, object]) -> tuple[str, str]:
    encoded = canonical_json_text(payload)
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def test_storage_canonical_json_matches_contract_signing_semantics() -> None:
    payload = {"z": "空", "a": "authority"}
    encoded = canonical_json_text(payload)
    assert encoded == '{"a":"authority","z":"\\u7a7a"}'


def test_migration_rejects_conflicting_preexisting_schema() -> None:
    connection = _connect()
    connection.execute("CREATE TABLE sab_artifact_cases_v1 (case_id TEXT PRIMARY KEY)")
    with pytest.raises(MigrationSchemaMismatch, match="differs from the frozen schema"):
        init_first_verdict_storage(connection, applied_at=_NOW)
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type = 'table' AND name = 'sab_first_verdict_schema_migrations_v1'"
        ).fetchone()[0]
        == 0
    )
    connection.close()


def test_migration_requires_foreign_key_enforcement() -> None:
    connection = sqlite3.connect(":memory:")
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 0
    with pytest.raises(ForeignKeysRequired, match="foreign_keys=ON"):
        init_first_verdict_storage(connection, applied_at=_NOW)
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'sab_%'"
        ).fetchone()[0]
        == 0
    )
    connection.close()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_copy_receipt(source: Path, copied: Path, receipt: Path) -> str:
    source_stat = source.stat()
    payload = {
        "schema_version": "sab.build_a.a0_database_snapshot.v1",
        "content_equal": True,
        "source": {
            "path_ref": str(source.resolve()),
            "opened": "sqlite_uri_mode_ro",
            "sha256": _file_sha256(source),
            "device": source_stat.st_dev,
            "inode": source_stat.st_ino,
            "size": source_stat.st_size,
        },
        "copy": {
            "path_ref": f"private:{copied.resolve()}",
            "sha256": _file_sha256(copied),
            "backup_method": "sqlite_online_backup_from_mode_ro_source",
        },
    }
    receipt.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return _file_sha256(receipt)


def _build_attestation(
    tmp_path: Path,
) -> tuple[Path, Path, Path, CopyDatabaseAttestation]:
    source = tmp_path / "source.db"
    copied = tmp_path / "copied.db"
    receipt = tmp_path / "copy-receipt.json"
    with sqlite3.connect(source) as source_conn:
        source_conn.execute("CREATE TABLE legacy (id INTEGER PRIMARY KEY, value TEXT)")
        source_conn.execute("INSERT INTO legacy VALUES (1, 'preserved')")
        source_conn.commit()
        with sqlite3.connect(copied) as copied_conn:
            source_conn.backup(copied_conn)
    from agora.sab_first_verdict_evidence import lifecycle_fingerprint

    with sqlite3.connect(f"file:{copied}?mode=ro", uri=True) as readonly:
        lifecycle_sha = lifecycle_fingerprint(readonly)["sha256"]
    receipt_sha = _write_copy_receipt(source, copied, receipt)
    attestation = CopyDatabaseAttestation(
        proof_class="copied_live_db_rehearsal",
        database_path=copied,
        source_database_path=source,
        source_backup_sha256=_file_sha256(copied),
        expected_lifecycle_fingerprint=lifecycle_sha,
        copy_receipt_sha256=receipt_sha,
        copy_receipt_path=receipt,
    )
    return source, copied, receipt, attestation


def test_attested_copy_rejects_source_and_opens_existing_copy_rw(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.db"
    copied = tmp_path / "copied.db"
    source_conn = sqlite3.connect(source)
    source_conn.execute("CREATE TABLE legacy (id INTEGER PRIMARY KEY, value TEXT)")
    source_conn.execute("INSERT INTO legacy(value) VALUES ('preserved')")
    source_conn.commit()
    copy_conn = sqlite3.connect(copied)
    source_conn.backup(copy_conn)
    copy_conn.close()
    source_conn.close()

    from agora.sab_first_verdict_evidence import (
        lifecycle_fingerprint,
        open_sqlite_readonly,
    )

    readonly = open_sqlite_readonly(copied)
    try:
        expected_fingerprint = lifecycle_fingerprint(readonly)["sha256"]
    finally:
        readonly.close()
    receipt = tmp_path / "copy-receipt.json"
    receipt_sha256 = _write_copy_receipt(source, copied, receipt)
    attestation = CopyDatabaseAttestation(
        proof_class="copied_live_db_rehearsal",
        database_path=copied,
        source_database_path=source,
        source_backup_sha256=_file_sha256(copied),
        expected_lifecycle_fingerprint=expected_fingerprint,
        copy_receipt_sha256=receipt_sha256,
        copy_receipt_path=receipt,
    )
    guarded = open_attested_copy_connection(attestation, require_pristine_backup=True)
    try:
        assert guarded.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        init_first_verdict_storage(guarded, applied_at=_NOW)
        attached = tmp_path / "attached.db"
        with sqlite3.connect(attached) as attached_conn:
            attached_conn.execute("CREATE TABLE marker (id INTEGER PRIMARY KEY)")
        guarded.execute("ATTACH DATABASE ? AS external", (str(attached),))
        with pytest.raises(DatabaseSafetyError, match="must not attach"):
            init_first_verdict_storage(guarded, applied_at=_NOW)
        guarded.execute("DETACH DATABASE external")
    finally:
        guarded.close()

    raw = sqlite3.connect(copied)
    raw.execute("PRAGMA foreign_keys = ON")
    with pytest.raises(DatabaseSafetyError, match="attested copy connection"):
        init_first_verdict_storage(raw, applied_at=_NOW)
    raw.close()

    same_file = CopyDatabaseAttestation(
        **{
            **attestation.__dict__,
            "database_path": source,
            "source_database_path": source,
            "source_backup_sha256": _file_sha256(source),
        }
    )
    with pytest.raises(DatabaseSafetyError, match="forbidden source"):
        open_attested_copy_connection(same_file, require_pristine_backup=True)

    hardlink = tmp_path / "source-hardlink.db"
    os.link(source, hardlink)
    hardlink_target = CopyDatabaseAttestation(
        **{
            **attestation.__dict__,
            "database_path": hardlink,
            "source_backup_sha256": _file_sha256(hardlink),
        }
    )
    with pytest.raises(DatabaseSafetyError, match="forbidden source"):
        open_attested_copy_connection(hardlink_target, require_pristine_backup=True)

    source_omitted = CopyDatabaseAttestation(
        **{
            **attestation.__dict__,
            "proof_class": "disposable_fixture",
            "source_database_path": None,
        }
    )
    with pytest.raises(DatabaseSafetyError, match="forbidden source path"):
        open_attested_copy_connection(source_omitted)

    missing = CopyDatabaseAttestation(
        **{**attestation.__dict__, "database_path": tmp_path / "missing.db"}
    )
    with pytest.raises(DatabaseSafetyError, match="non-symlink file"):
        open_attested_copy_connection(missing)
    assert not (tmp_path / "missing.db").exists()

    bad_receipt = CopyDatabaseAttestation(
        **{**attestation.__dict__, "copy_receipt_sha256": "0" * 64}
    )
    with pytest.raises(DatabaseSafetyError, match="receipt digest"):
        open_attested_copy_connection(bad_receipt)


def test_in_memory_fixture_rejects_attached_file_backing(tmp_path: Path) -> None:
    attached = tmp_path / "attached.db"
    with sqlite3.connect(attached) as attached_conn:
        attached_conn.execute("CREATE TABLE marker (id INTEGER PRIMARY KEY)")
    conn = _connect()
    try:
        conn.execute("ATTACH DATABASE ? AS external", (str(attached),))
        with pytest.raises(DatabaseSafetyError, match="must not attach"):
            init_first_verdict_storage(conn, applied_at=_NOW)
    finally:
        conn.close()


def test_attested_open_rejects_inode_swap_between_binding_and_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.db"
    copied = tmp_path / "copied.db"
    replacement = tmp_path / "replacement.db"
    with sqlite3.connect(source) as source_conn:
        source_conn.execute("CREATE TABLE legacy (id INTEGER PRIMARY KEY)")
        source_conn.execute("INSERT INTO legacy VALUES (1)")
        source_conn.commit()
        for destination in (copied, replacement):
            destination_conn = sqlite3.connect(destination)
            try:
                source_conn.backup(destination_conn)
                destination_conn.commit()
            finally:
                destination_conn.close()

    from agora.sab_first_verdict_evidence import (
        lifecycle_fingerprint,
        open_sqlite_readonly,
    )

    with open_sqlite_readonly(copied) as readonly:
        expected_fingerprint = lifecycle_fingerprint(readonly)["sha256"]
    receipt = tmp_path / "copy-receipt.json"
    receipt_sha256 = _write_copy_receipt(source, copied, receipt)
    attestation = CopyDatabaseAttestation(
        proof_class="copied_live_db_rehearsal",
        database_path=copied,
        source_database_path=source,
        source_backup_sha256=_file_sha256(copied),
        expected_lifecycle_fingerprint=expected_fingerprint,
        copy_receipt_sha256=receipt_sha256,
        copy_receipt_path=receipt,
    )
    bound_identity = (copied.stat().st_dev, copied.stat().st_ino)
    real_connect = storage_module.sqlite3.connect

    def swap_then_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        replacement.replace(copied)
        return real_connect(*args, **kwargs)

    def descriptor_reopen_must_not_run(
        *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        raise AssertionError("one-way swaps must fail before descriptor reopening")

    monkeypatch.setattr(storage_module.sqlite3, "connect", swap_then_connect)
    monkeypatch.setattr(
        storage_module, "_RAW_SQLITE_CONNECT", descriptor_reopen_must_not_run
    )
    with pytest.raises(DatabaseSafetyError, match="attested copy descriptor"):
        open_attested_copy_connection(
            attestation, expected_file_identity=bound_identity
        )

    with pytest.raises(DatabaseSafetyError, match="bound application file"):
        open_attested_copy_connection(
            attestation, expected_file_identity=bound_identity
        )


def test_attested_open_aba_path_swap_cannot_redirect_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.db"
    copied = tmp_path / "copied.db"
    replacement = tmp_path / "replacement.db"
    displaced = tmp_path / "displaced.db"
    with sqlite3.connect(source) as source_conn:
        source_conn.execute("CREATE TABLE expected_marker (id INTEGER PRIMARY KEY)")
        source_conn.execute("INSERT INTO expected_marker VALUES (1)")
        source_conn.commit()
        with sqlite3.connect(copied) as copied_conn:
            source_conn.backup(copied_conn)
    with sqlite3.connect(replacement) as replacement_conn:
        replacement_conn.execute(
            "CREATE TABLE replacement_marker (id INTEGER PRIMARY KEY)"
        )
        replacement_conn.commit()

    from agora.sab_first_verdict_evidence import (
        lifecycle_fingerprint,
        open_sqlite_readonly,
    )

    with open_sqlite_readonly(copied) as readonly:
        expected_fingerprint = lifecycle_fingerprint(readonly)["sha256"]
    receipt = tmp_path / "copy-receipt.json"
    receipt_sha256 = _write_copy_receipt(source, copied, receipt)
    attestation = CopyDatabaseAttestation(
        proof_class="copied_live_db_rehearsal",
        database_path=copied,
        source_database_path=source,
        source_backup_sha256=_file_sha256(copied),
        expected_lifecycle_fingerprint=expected_fingerprint,
        copy_receipt_sha256=receipt_sha256,
        copy_receipt_path=receipt,
    )
    bound_identity = (copied.stat().st_dev, copied.stat().st_ino)
    real_connect = storage_module.sqlite3.connect
    observed_tables: list[str] = []

    def swap_open_restore(*args: object, **kwargs: object) -> sqlite3.Connection:
        copied.replace(displaced)
        replacement.replace(copied)
        connection = real_connect(*args, **kwargs)
        observed_tables.extend(
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        )
        copied.replace(replacement)
        displaced.replace(copied)
        return connection

    monkeypatch.setattr(storage_module.sqlite3, "connect", swap_open_restore)
    with pytest.raises(DatabaseSafetyError, match="attested copy descriptor"):
        open_attested_copy_connection(
            attestation, expected_file_identity=bound_identity
        )
    # The hook did redirect SQLite, but the pre-write lock challenge detected
    # the mismatch after the path was restored and before any schema mutation.
    assert observed_tables == ["replacement_marker"]
    with real_connect(copied) as restored:
        assert (
            restored.execute("SELECT COUNT(*) FROM expected_marker").fetchone()[0] == 1
        )


def test_attested_open_fails_closed_when_descriptor_reopen_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, _, attestation = _build_attestation(tmp_path)

    def unavailable_descriptor_reopen(
        *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        raise sqlite3.OperationalError("descriptor reopen unavailable")

    monkeypatch.setattr(
        storage_module, "_RAW_SQLITE_CONNECT", unavailable_descriptor_reopen
    )
    with pytest.raises(DatabaseSafetyError, match="could not verify.*lock identity"):
        open_attested_copy_connection(attestation)

    monkeypatch.setattr(storage_module, "_RAW_SQLITE_CONNECT", sqlite3.connect)
    reopened = open_attested_copy_connection(attestation)
    reopened.close()


def test_attested_receipt_rejects_unknown_schema(tmp_path: Path) -> None:
    _, _, receipt, attestation = _build_attestation(tmp_path)
    payload = json.loads(receipt.read_text())
    payload["schema_version"] = "sab.caller_authored_unknown.v1"
    receipt.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    altered = CopyDatabaseAttestation(
        **{
            **attestation.__dict__,
            "copy_receipt_sha256": _file_sha256(receipt),
        }
    )
    with pytest.raises(DatabaseSafetyError, match="schema is not an accepted"):
        open_attested_copy_connection(altered)


def test_online_backup_receipt_requires_complete_logical_equivalence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.db"
    copied = tmp_path / "copied.db"
    receipt = tmp_path / "backup-receipt.json"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE legacy (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO legacy VALUES (1)")
        conn.commit()
    from agora.sab_first_verdict_evidence import backup_database_readonly

    payload = backup_database_readonly(source, copied)
    lifecycle_sha = payload["copy_snapshot"]["lifecycle"]["sha256"]
    payload["logical_equivalence"] = {}
    receipt.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    attestation = CopyDatabaseAttestation(
        proof_class="copied_live_db_rehearsal",
        database_path=copied,
        source_database_path=source,
        source_backup_sha256=_file_sha256(copied),
        expected_lifecycle_fingerprint=lifecycle_sha,
        copy_receipt_sha256=_file_sha256(receipt),
        copy_receipt_path=receipt,
    )
    with pytest.raises(DatabaseSafetyError, match="does not bind"):
        open_attested_copy_connection(attestation)


def test_mutation_guard_rechecks_durable_sqlite_settings(tmp_path: Path) -> None:
    _, _, _, attestation = _build_attestation(tmp_path)
    conn = open_attested_copy_connection(attestation, require_pristine_backup=True)
    try:
        assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        with pytest.raises(DatabaseSafetyError, match="DELETE journal"):
            require_copy_or_fixture_connection(conn)
        assert conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
        conn.execute("PRAGMA synchronous=OFF")
        with pytest.raises(DatabaseSafetyError, match="FULL synchronization"):
            require_copy_or_fixture_connection(conn)
    finally:
        conn.close()


def test_attested_open_rejects_unauthorized_extra_schema(tmp_path: Path) -> None:
    _, copied, _, attestation = _build_attestation(tmp_path)
    with sqlite3.connect(copied) as conn:
        conn.execute("CREATE TABLE caller_smuggled_table (id INTEGER PRIMARY KEY)")
        conn.commit()
    with pytest.raises(DatabaseSafetyError, match="outside the frozen additive"):
        open_attested_copy_connection(attestation, require_pristine_backup=False)


def test_attested_open_binds_source_fd_to_receipt_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _, _, attestation = _build_attestation(tmp_path)
    twin = tmp_path / "source-twin.db"
    displaced = tmp_path / "source-displaced.db"
    shutil.copyfile(source, twin)
    real_open = storage_module.os.open

    def swap_source_then_open(path: object, *args: object, **kwargs: object) -> int:
        if Path(path) == source:
            source.replace(displaced)
            twin.replace(source)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(storage_module.os, "open", swap_source_then_open)
    try:
        with pytest.raises(DatabaseSafetyError, match="anchored A0 receipt"):
            open_attested_copy_connection(attestation)
    finally:
        if displaced.exists():
            if source.exists():
                source.replace(twin)
            displaced.replace(source)


def test_attested_open_rejects_multilink_copy_and_concurrent_runner(
    tmp_path: Path,
) -> None:
    _, copied, _, attestation = _build_attestation(tmp_path)
    alias = tmp_path / "copy-alias.db"
    os.link(copied, alias)
    with pytest.raises(DatabaseSafetyError, match="single-link"):
        open_attested_copy_connection(attestation)
    alias.unlink()

    first = open_attested_copy_connection(attestation)
    try:
        with pytest.raises(DatabaseSafetyError, match="another runner"):
            open_attested_copy_connection(attestation)
    finally:
        first.close()
    second = open_attested_copy_connection(attestation)
    second.close()


def test_attested_delete_journal_recovers_after_process_crash(
    tmp_path: Path,
) -> None:
    source, copied, receipt, attestation = _build_attestation(tmp_path)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import os,sys; from pathlib import Path; "
                "from agora.sab_first_verdict_storage import "
                "CopyDatabaseAttestation,open_attested_copy_connection; "
                "a=CopyDatabaseAttestation(proof_class='copied_live_db_rehearsal',"
                "database_path=Path(sys.argv[1]),source_database_path=Path(sys.argv[2]),"
                "source_backup_sha256=sys.argv[3],"
                "expected_lifecycle_fingerprint=sys.argv[4],"
                "copy_receipt_sha256=sys.argv[5],copy_receipt_path=Path(sys.argv[6])); "
                "c=open_attested_copy_connection(a); c.execute('BEGIN IMMEDIATE'); "
                "c.execute(\"UPDATE legacy SET value='uncommitted-crash' WHERE id=1\"); "
                "os._exit(23)"
            ),
            str(copied),
            str(source),
            attestation.source_backup_sha256,
            attestation.expected_lifecycle_fingerprint,
            attestation.copy_receipt_sha256,
            str(receipt),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parents[1],
        env={
            "PATH": os.environ.get("PATH", ""),
            "LANG": "en_US.UTF-8",
            "TMPDIR": "/private/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": "/private/tmp/sab-storage-crash-pycache",
        },
    )
    assert child.returncode == 23, child.stderr
    journal = Path(f"{copied}-journal")
    assert journal.is_file()

    recovered = open_attested_copy_connection(attestation)
    try:
        assert recovered.execute("SELECT value FROM legacy WHERE id=1").fetchone()[
            0
        ] == ("preserved")
    finally:
        recovered.close()


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    init_first_verdict_storage(connection, applied_at=_NOW)
    try:
        yield connection
    finally:
        connection.close()


def _schema_digest(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        WHERE name LIKE 'sab_%'
        ORDER BY type, name
        """
    ).fetchall()
    payload = [tuple(row) for row in rows]
    return _digest(json.dumps(payload, separators=(",", ":"), ensure_ascii=True))


def _legacy_rows_digest(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        "SELECT record_id, payload, payload_sha256 FROM legacy_records ORDER BY record_id"
    ).fetchall()
    payload = [[str(row[0]), bytes(row[1]).hex(), str(row[2])] for row in rows]
    return _digest(json.dumps(payload, separators=(",", ":")))


def _lease(
    lease_id: str = "lease-1",
    *,
    operations: list[dict[str, str]] | None = None,
    scope: str = "Copy",
) -> dict[str, object]:
    signing_key = SigningKey(hashlib.sha256(b"storage-lease-fixture").digest())
    public_key = signing_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
    allowed_operations = operations or [
        {"method": "POST", "path": "/api/v1/artifact-cases"}
    ]
    unsigned = {
        "schema": "sab.session_write_lease.v1",
        "lease_id": lease_id,
        "session_id": "session-storage-fixture",
        "clerk_identity": "fixture:clerk",
        "allowed_operations": allowed_operations,
        "allowed_operations_sha256": canonical_sha256(
            sorted(
                allowed_operations,
                key=lambda item: (str(item.get("method")), str(item.get("path"))),
            )
        ),
        "accepted_code_sha": "c" * 40,
        "expected_lifecycle_fingerprint": "a" * 64,
        "source_backup_sha256": "b" * 64,
        "issuer_identity": "fixture:test-issuer",
        "issuer_public_key": public_key,
        "issuer_fingerprint": hashlib.sha256(bytes.fromhex(public_key)).hexdigest(),
        "authority_basis": "founder_bootstrap_self_declared",
        "scope": scope,
        "issued_at": _NOW,
        "activated_at": _NOW,
        "expires_at": "2026-07-28T01:00:00Z",
        "standing_effect": "none",
        "live_eligible": False,
    }
    lease_sha256 = canonical_sha256(unsigned)
    signed_payload = {**unsigned, "lease_sha256": lease_sha256}
    message = canonical_json_bytes(signed_payload)
    return {
        **signed_payload,
        "signature": {
            "alg": "ed25519",
            "signer": "fixture:test-issuer",
            "public_key": public_key,
            "signature": signing_key.sign(message).signature.hex(),
            "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
            "canonicalization": "json-sort-keys-compact-v1",
        },
    }


def _insert_graph(conn: sqlite3.Connection) -> dict[str, tuple[str, str]]:
    """Insert one dependency-complete graph for trigger and replay tests."""

    lease = _lease()
    activate_session_lease(conn, lease, activated_at=_NOW)

    case_json, case_sha = _json_and_digest(
        {"case_id": "case-1", "round_no": 1, "target_seed_id": "artifact-1"}
    )
    conn.execute(
        """
        INSERT INTO sab_artifact_cases_v1
            (case_id, target_seed_id, round_no, case_json, case_sha256, created_at)
        VALUES (?, ?, 1, ?, ?, ?)
        """,
        ("case-1", "artifact-1", case_json, case_sha, _NOW),
    )

    ballot_json, ballot_sha = _json_and_digest(
        {
            "ballot_id": "ballot-1",
            "case_id": "case-1",
            "round_no": 1,
            "ballot_source": "fixture_model",
        }
    )
    conn.execute(
        """
        INSERT INTO sab_artifact_ballots_v1
            (ballot_id, case_id, round_no, seat_id, ballot_source,
             credited_cluster, ballot_json, ballot_sha256, created_at)
        VALUES (?, ?, 1, ?, 'fixture_model', ?, ?, ?, ?)
        """,
        ("ballot-1", "case-1", "seat-1", "cluster-1", ballot_json, ballot_sha, _NOW),
    )

    authority_json, authority_sha = _json_and_digest(
        {
            "evaluation_id": "authority-1",
            "case_id": "case-1",
            "result": "Authorized",
            "scope": "Copy",
        }
    )
    conn.execute(
        """
        INSERT INTO sab_disposition_authority_v1
            (evaluation_id, case_id, result, scope, evaluated_state_hash,
             authority_json, authority_sha256, created_at)
        VALUES (?, ?, 'Authorized', 'Copy', ?, ?, ?, ?)
        """,
        (
            "authority-1",
            "case-1",
            _digest("state"),
            authority_json,
            authority_sha,
            _NOW,
        ),
    )

    verdict_json, verdict_sha = _json_and_digest(
        {
            "verdict_id": "verdict-1",
            "case_id": "case-1",
            "evaluation_id": "authority-1",
            "round_no": 1,
        }
    )
    conn.execute(
        """
        INSERT INTO sab_council_verdicts_v1
            (verdict_id, case_id, evaluation_id, round_no, decision,
             ballot_set_sha256, verdict_json, verdict_sha256, created_at)
        VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
        """,
        (
            "verdict-1",
            "case-1",
            "authority-1",
            "compost",
            _digest("ballot-set"),
            verdict_json,
            verdict_sha,
            _NOW,
        ),
    )

    countersign_json, countersign_sha = _json_and_digest(
        {
            "countersign_id": "countersign-1",
            "verdict_id": "verdict-1",
            "write_lease_id": "lease-1",
        }
    )
    conn.execute(
        """
        INSERT INTO sab_operator_countersigns_v1
            (countersign_id, verdict_id, write_lease_id, countersign_json,
             countersign_sha256, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "countersign-1",
            "verdict-1",
            "lease-1",
            countersign_json,
            countersign_sha,
            _NOW,
        ),
    )

    for artifact_id in ("artifact-1", "artifact-2"):
        artifact_json, artifact_sha = _json_and_digest(
            {"artifact_id": artifact_id, "state": "fixture"}
        )
        conn.execute(
            """
            INSERT INTO sab_rehearsal_artifacts_v1
                (artifact_id, state, artifact_json, artifact_sha256,
                 live_eligible, created_at, updated_at)
            VALUES (?, 'fixture', ?, ?, 0, ?, ?)
            """,
            (artifact_id, artifact_json, artifact_sha, _NOW, _NOW),
        )

    disposition_json, disposition_sha = _json_and_digest(
        {
            "disposition_id": "disposition-1",
            "verdict_id": "verdict-1",
            "scope": "Copy",
        }
    )
    conn.execute(
        """
        INSERT INTO sab_rehearsal_dispositions_v1
            (disposition_id, verdict_id, countersign_id, evaluation_id,
             target_artifact_id, successor_artifact_id, scope,
             disposition_json, disposition_sha256, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'Copy', ?, ?, ?)
        """,
        (
            "disposition-1",
            "verdict-1",
            "countersign-1",
            "authority-1",
            "artifact-1",
            "artifact-2",
            disposition_json,
            disposition_sha,
            _NOW,
        ),
    )

    edge_json, edge_sha = _json_and_digest(
        {
            "edge_id": "edge-1",
            "predecessor_seed_id": "seed-1",
            "successor_seed_id": "seed-2",
        }
    )
    conn.execute(
        """
        INSERT INTO sab_seed_lineage_edges_v1
            (edge_id, predecessor_seed_id, successor_seed_id, disposition_id,
             edge_json, edge_sha256, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        ("edge-1", "seed-1", "seed-2", "disposition-1", edge_json, edge_sha, _NOW),
    )

    event_payload = {"event_id": "event-1", "event_type": "fixture"}
    event_json, event_payload_sha = _json_and_digest(event_payload)
    conn.execute(
        """
        INSERT INTO sab_first_verdict_signed_events_v1
            (event_id, event_type, signer, public_key, prev_hash, payload_json,
             payload_sha256, signature, event_hash, created_at)
        VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
        """,
        (
            "event-1",
            "fixture",
            "fixture-signer",
            "11" * 32,
            event_json,
            event_payload_sha,
            "22" * 64,
            _digest("event-1"),
            _NOW,
        ),
    )

    response = {"receipt_id": "receipt-1", "status": "stored"}
    record_idempotency(
        conn,
        operation="fixture-operation",
        idempotency_key="idempotency-key-1",
        request_sha256=_digest("request-1"),
        response=response,
        created_at=_NOW,
    )
    return {
        "case": ("case-1", case_sha),
        "ballot": ("ballot-1", ballot_sha),
        "authority": ("authority-1", authority_sha),
        "verdict": ("verdict-1", verdict_sha),
        "countersign": ("countersign-1", countersign_sha),
        "disposition": ("disposition-1", disposition_sha),
        "lineage": ("edge-1", edge_sha),
    }


def test_migration_is_static_digest_recorded_and_idempotent() -> None:
    connection = _connect()
    try:
        expected_digest = hashlib.sha256(
            "\n".join(statement.strip() for statement in MIGRATION_STATEMENTS).encode()
        ).hexdigest()
        assert MIGRATION_DIGEST == expected_digest

        first = init_first_verdict_storage(connection, applied_at=_NOW)
        schema_after_first = _schema_digest(connection)
        first_record = tuple(
            connection.execute(
                """
                SELECT migration_id, migration_digest, applied_at
                FROM sab_first_verdict_schema_migrations_v1
                """
            ).fetchone()
        )

        second = init_first_verdict_storage(connection, applied_at=_LATER)

        assert first == second == MIGRATION_DIGEST
        assert _schema_digest(connection) == schema_after_first
        assert first_record == (MIGRATION_ID, MIGRATION_DIGEST, _NOW)
        assert (
            tuple(
                connection.execute(
                    """
                SELECT migration_id, migration_digest, applied_at
                FROM sab_first_verdict_schema_migrations_v1
                """
                ).fetchone()
            )
            == first_record
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sab_first_verdict_schema_migrations_v1"
            ).fetchone()[0]
            == 1
        )
    finally:
        connection.close()


def test_migration_digest_mismatch_fails_before_any_new_schema_or_row_change() -> None:
    connection = _connect()
    try:
        connection.execute("CREATE TABLE legacy_records (record_id TEXT, payload BLOB)")
        connection.execute("INSERT INTO legacy_records VALUES ('legacy-1', X'0001ff')")
        connection.execute(
            """
            CREATE TABLE sab_first_verdict_schema_migrations_v1 (
                migration_id TEXT PRIMARY KEY,
                migration_digest TEXT NOT NULL CHECK (length(migration_digest) = 64),
                applied_at TEXT NOT NULL
            )
            """
        )
        wrong_digest = _digest("different migration bytes")
        connection.execute(
            "INSERT INTO sab_first_verdict_schema_migrations_v1 VALUES (?, ?, ?)",
            (MIGRATION_ID, wrong_digest, _NOW),
        )
        connection.commit()
        schema_before = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')"
            )
        }

        with pytest.raises(MigrationDigestMismatch, match="digest mismatch"):
            init_first_verdict_storage(connection)

        assert {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')"
            )
        } == schema_before
        assert (
            bytes(
                connection.execute(
                    "SELECT payload FROM legacy_records WHERE record_id = 'legacy-1'"
                ).fetchone()[0]
            )
            == b"\x00\x01\xff"
        )
        assert tuple(
            connection.execute(
                """
                SELECT migration_id, migration_digest, applied_at
                FROM sab_first_verdict_schema_migrations_v1
                """
            ).fetchone()
        ) == (MIGRATION_ID, wrong_digest, _NOW)
        assert not connection.in_transaction
    finally:
        connection.close()


def test_migration_rejects_weak_preexisting_ledger_schema() -> None:
    connection = _connect()
    connection.execute(
        "CREATE TABLE sab_first_verdict_schema_migrations_v1 "
        "(migration_id TEXT PRIMARY KEY, migration_digest TEXT)"
    )
    connection.commit()
    with pytest.raises(MigrationSchemaMismatch, match="migration ledger differs"):
        init_first_verdict_storage(connection)
    assert {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')"
        )
    } == {"sab_first_verdict_schema_migrations_v1"}
    connection.close()


class _InjectedMigrationFailure(RuntimeError):
    pass


@pytest.mark.parametrize(
    "failure_boundary",
    [f"migration:{index}" for index in range(len(MIGRATION_STATEMENTS))]
    + ["migration:schema-verified", "migration:record"],
)
def test_failure_at_every_migration_boundary_rolls_back_totally(
    failure_boundary: str,
) -> None:
    connection = _connect()
    try:
        connection.execute(
            "CREATE TABLE legacy_records (record_id TEXT PRIMARY KEY, payload BLOB NOT NULL)"
        )
        connection.execute("INSERT INTO legacy_records VALUES ('legacy-1', X'00ff')")
        connection.commit()

        def fail_at_boundary(boundary: str) -> None:
            if boundary == failure_boundary:
                raise _InjectedMigrationFailure(boundary)

        with pytest.raises(_InjectedMigrationFailure, match=failure_boundary):
            init_first_verdict_storage(connection, failure_hook=fail_at_boundary)

        assert [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ] == ["legacy_records"]
        assert (
            bytes(
                connection.execute(
                    "SELECT payload FROM legacy_records WHERE record_id = 'legacy-1'"
                ).fetchone()[0]
            )
            == b"\x00\xff"
        )
        assert not connection.in_transaction
    finally:
        connection.close()


def test_failed_nested_migration_rolls_back_only_its_savepoint() -> None:
    connection = _connect()
    try:
        connection.execute(
            "CREATE TABLE legacy_records (record_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO legacy_records VALUES ('legacy-1', 'original')")
        connection.commit()
        connection.execute("BEGIN")
        connection.execute(
            "UPDATE legacy_records SET payload = 'outer-change' WHERE record_id = 'legacy-1'"
        )

        def fail_at_boundary(boundary: str) -> None:
            if boundary == "migration:2":
                raise _InjectedMigrationFailure(boundary)

        with pytest.raises(_InjectedMigrationFailure, match="migration:2"):
            init_first_verdict_storage(connection, failure_hook=fail_at_boundary)

        assert connection.in_transaction
        assert (
            connection.execute(
                "SELECT payload FROM legacy_records WHERE record_id = 'legacy-1'"
            ).fetchone()[0]
            == "outer-change"
        )
        assert [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ] == ["legacy_records"]
        connection.rollback()
        assert (
            connection.execute(
                "SELECT payload FROM legacy_records WHERE record_id = 'legacy-1'"
            ).fetchone()[0]
            == "original"
        )
    finally:
        connection.close()


def test_migration_preserves_preexisting_row_content_digests() -> None:
    connection = _connect()
    try:
        connection.execute(
            """
            CREATE TABLE legacy_records (
                record_id TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                payload_sha256 TEXT NOT NULL
            )
            """
        )
        records = (("legacy-1", b"\x00\xffsigned-bytes"), ("legacy-2", b"{}"))
        connection.executemany(
            "INSERT INTO legacy_records VALUES (?, ?, ?)",
            [
                (record_id, payload, hashlib.sha256(payload).hexdigest())
                for record_id, payload in records
            ],
        )
        connection.commit()
        before = _legacy_rows_digest(connection)

        init_first_verdict_storage(connection, applied_at=_NOW)
        init_first_verdict_storage(connection, applied_at=_LATER)

        assert _legacy_rows_digest(connection) == before
        for record_id, payload in records:
            row = connection.execute(
                "SELECT payload, payload_sha256 FROM legacy_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            assert bytes(row[0]) == payload
            assert row[1] == hashlib.sha256(payload).hexdigest()
    finally:
        connection.close()


@pytest.mark.parametrize("table", sorted(_IMMUTABLE_TABLE_IDS))
def test_immutable_tables_reject_update_and_delete(
    conn: sqlite3.Connection,
    table: str,
) -> None:
    _insert_graph(conn)
    id_column, object_id = _IMMUTABLE_TABLE_IDS[table]

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute(
            f"UPDATE {table} SET {id_column} = {id_column} WHERE {id_column} = ?",
            (object_id,),
        )
    assert (
        conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {id_column} = ?", (object_id,)
        ).fetchone()[0]
        == 1
    )

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute(f"DELETE FROM {table} WHERE {id_column} = ?", (object_id,))
    assert (
        conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {id_column} = ?", (object_id,)
        ).fetchone()[0]
        == 1
    )


def test_case_ballot_and_verdict_round_number_is_exactly_one(
    conn: sqlite3.Connection,
) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="round_no"):
        conn.execute(
            """
            INSERT INTO sab_artifact_cases_v1
                (case_id, target_seed_id, round_no, case_json, case_sha256, created_at)
            VALUES ('case-invalid', 'artifact-1', 2, '{}', ?, ?)
            """,
            (_digest("invalid-case"), _NOW),
        )

    graph = _insert_graph(conn)
    with pytest.raises(sqlite3.IntegrityError, match="round_no"):
        conn.execute(
            """
            INSERT INTO sab_artifact_ballots_v1
                (ballot_id, case_id, round_no, seat_id, ballot_source,
                 credited_cluster, ballot_json, ballot_sha256, created_at)
            VALUES ('ballot-invalid-round', 'case-1', 2, 'seat-2',
                    'fixture_model', 'cluster-2', '{}', ?, ?)
            """,
            (_digest("invalid-ballot-round"), _NOW),
        )
    with pytest.raises(sqlite3.IntegrityError, match="round_no"):
        conn.execute(
            """
            INSERT INTO sab_council_verdicts_v1
                (verdict_id, case_id, evaluation_id, round_no, decision,
                 ballot_set_sha256, verdict_json, verdict_sha256, created_at)
            VALUES ('verdict-invalid-round', 'case-1', 'authority-1', 2,
                    'appeal', ?, '{}', ?, ?)
            """,
            (_digest("other-ballots"), _digest("invalid-verdict-round"), _NOW),
        )
    assert immutable_digest_for(conn, "case", graph["case"][0]) == graph["case"][1]


def test_strict_contract_storage_binds_case_authority_ballots_and_verdict(
    conn: sqlite3.Connection,
) -> None:
    case = _contract_fixture("sab.artifact_case.v1.json")
    normalized_case, case_sha, case_replay = store_artifact_case(
        conn, case, created_at=_NOW
    )
    assert case_replay is False

    ballot_template = _contract_fixture("sab.artifact_ballot.v1.json")
    for index in range(9):
        ballot = json.loads(json.dumps(ballot_template))
        ballot["ballot_id"] = f"sab_ballot_fixture_seat_{index}"
        ballot["seat_id"] = f"seat-{index}"
        ballot["case_id"] = normalized_case["case_id"]
        ballot["case_sha256"] = case_sha
        _, _, replay = store_artifact_ballot(conn, ballot, created_at=_NOW)
        assert replay is False

    authority = _contract_fixture("sab.disposition_authority.v1.json")
    normalized_authority, authority_sha, authority_replay = store_authority_evaluation(
        conn,
        case_id=str(normalized_case["case_id"]),
        authority=authority,
        created_at=_NOW,
    )
    assert authority_replay is False

    verdict = _contract_fixture("sab.council_verdict.v1.json")
    verdict["case_id"] = normalized_case["case_id"]
    verdict["case_sha256"] = case_sha
    verdict["authority_digest"] = authority_sha
    ballot_set_sha = ballot_set_sha256_for_case(conn, str(normalized_case["case_id"]))
    normalized_verdict, verdict_sha, verdict_replay = store_council_verdict(
        conn,
        evaluation_id=str(normalized_authority["evaluation_id"]),
        verdict=verdict,
        ballot_set_sha256=ballot_set_sha,
        created_at=_NOW,
    )
    assert verdict_replay is False
    assert normalized_verdict["verdict_id"] == verdict["verdict_id"]

    assert (
        store_authority_evaluation(
            conn,
            case_id=str(normalized_case["case_id"]),
            authority=authority,
            created_at=_LATER,
        )[2]
        is True
    )
    assert store_council_verdict(
        conn,
        evaluation_id=str(normalized_authority["evaluation_id"]),
        verdict=verdict,
        ballot_set_sha256=ballot_set_sha,
        created_at=_LATER,
    ) == (normalized_verdict, verdict_sha, True)

    with pytest.raises(ImmutableConflict, match="unknown artifact case"):
        store_authority_evaluation(
            conn,
            case_id="different-case",
            authority=authority,
        )
    wrong_artifact_authority = json.loads(json.dumps(authority))
    wrong_artifact_authority["evaluation_id"] = "authority-wrong-artifact"
    wrong_artifact_authority["artifact_id"] = "different-seed"
    with pytest.raises(ImmutableConflict, match="does not match the case target"):
        store_authority_evaluation(
            conn,
            case_id=str(normalized_case["case_id"]),
            authority=wrong_artifact_authority,
        )
    with pytest.raises(ImmutableConflict, match="ballot-set digest"):
        store_council_verdict(
            conn,
            evaluation_id=str(normalized_authority["evaluation_id"]),
            verdict=verdict,
            ballot_set_sha256="0" * 64,
        )


def test_disposition_schema_rejects_cross_verdict_authority_binding(
    conn: sqlite3.Connection,
) -> None:
    _insert_graph(conn)
    conn.execute(
        """
        INSERT INTO sab_artifact_cases_v1
            (case_id, target_seed_id, round_no, case_json, case_sha256, created_at)
        VALUES ('case-2', 'artifact-1', 1, '{}', ?, ?)
        """,
        (_digest("case-2"), _NOW),
    )
    conn.execute(
        """
        INSERT INTO sab_disposition_authority_v1
            (evaluation_id, case_id, result, scope, evaluated_state_hash,
             authority_json, authority_sha256, created_at)
        VALUES ('authority-2', 'case-2', 'Authorized', 'Copy', ?, '{}', ?, ?)
        """,
        (_digest("state-2"), _digest("authority-2"), _NOW),
    )
    conn.execute(
        """
        INSERT INTO sab_disposition_authority_v1
            (evaluation_id, case_id, result, scope, evaluated_state_hash,
             authority_json, authority_sha256, created_at)
        VALUES ('authority-3', 'case-2', 'Authorized', 'Copy', ?, '{}', ?, ?)
        """,
        (_digest("state-3"), _digest("authority-3"), _NOW),
    )
    conn.execute(
        """
        INSERT INTO sab_council_verdicts_v1
            (verdict_id, case_id, evaluation_id, round_no, decision,
             ballot_set_sha256, verdict_json, verdict_sha256, created_at)
        VALUES ('verdict-2', 'case-2', 'authority-2', 1, 'compost', ?, '{}', ?, ?)
        """,
        (_digest("ballot-set-2"), _digest("verdict-2"), _NOW),
    )
    activate_session_lease(conn, _lease("lease-2"), activated_at=_NOW)
    conn.execute(
        """
        INSERT INTO sab_operator_countersigns_v1
            (countersign_id, verdict_id, write_lease_id, countersign_json,
             countersign_sha256, created_at)
        VALUES ('countersign-2', 'verdict-2', 'lease-2', '{}', ?, ?)
        """,
        (_digest("countersign-2"), _NOW),
    )
    for artifact_id in ("artifact-3", "artifact-4"):
        conn.execute(
            """
            INSERT INTO sab_rehearsal_artifacts_v1
                (artifact_id, state, artifact_json, artifact_sha256,
                 live_eligible, created_at, updated_at)
            VALUES (?, 'fixture', '{}', ?, 0, ?, ?)
            """,
            (artifact_id, _digest(artifact_id), _NOW, _NOW),
        )
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        conn.execute(
            """
            INSERT INTO sab_rehearsal_dispositions_v1
                (disposition_id, verdict_id, countersign_id, evaluation_id,
                 target_artifact_id, successor_artifact_id, scope,
                 disposition_json, disposition_sha256, created_at)
            VALUES ('disposition-cross-binding', 'verdict-2', 'countersign-2',
                    'authority-3', 'artifact-3', 'artifact-4', 'Copy', '{}', ?, ?)
            """,
            (_digest("disposition-cross-binding"), _NOW),
        )


@pytest.mark.parametrize("invalid_source", ["provider", "fixture", "", None])
def test_ballot_source_is_required_and_closed_to_two_exact_values(
    conn: sqlite3.Connection,
    invalid_source: str | None,
) -> None:
    _insert_graph(conn)
    with pytest.raises(sqlite3.IntegrityError, match="ballot_source|NOT NULL"):
        conn.execute(
            """
            INSERT INTO sab_artifact_ballots_v1
                (ballot_id, case_id, round_no, seat_id, ballot_source,
                 credited_cluster, ballot_json, ballot_sha256, created_at)
            VALUES (?, 'case-1', 1, ?, ?, 'cluster-2', '{}', ?, ?)
            """,
            (
                f"ballot-invalid-{invalid_source!s}",
                f"seat-invalid-{invalid_source!s}",
                invalid_source,
                _digest(f"invalid-source-{invalid_source!s}"),
                _NOW,
            ),
        )


def test_lease_has_only_active_to_one_terminal_state_transitions(
    conn: sqlite3.Connection,
) -> None:
    lease = _lease()
    assert activate_session_lease(conn, lease, activated_at=_NOW) == lease
    assert activate_session_lease(conn, lease, activated_at=_NOW) == lease
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM sab_session_write_leases_v1 WHERE lease_id = 'lease-1'"
        ).fetchone()[0]
        == 1
    )

    assert (
        release_session_lease(
            conn, "lease-1", terminal_status="released", released_at=_LATER
        )
        == lease
    )
    row = conn.execute(
        "SELECT status, released_at FROM sab_session_write_leases_v1 WHERE lease_id = 'lease-1'"
    ).fetchone()
    assert tuple(row) == ("released", _LATER)
    assert (
        release_session_lease(
            conn,
            "lease-1",
            terminal_status="released",
            released_at="2099-01-01T00:00:00Z",
        )
        == lease
    )
    assert tuple(
        conn.execute(
            "SELECT status, released_at FROM sab_session_write_leases_v1 WHERE lease_id = 'lease-1'"
        ).fetchone()
    ) == ("released", _LATER)

    with pytest.raises(LeaseStateConflict, match="already released"):
        activate_session_lease(conn, lease, activated_at=_NOW)

    with pytest.raises(LeaseStateConflict, match="already released"):
        release_session_lease(conn, "lease-1", terminal_status="revoked")
    with pytest.raises(
        sqlite3.IntegrityError, match="invalid session write lease transition"
    ):
        conn.execute(
            "UPDATE sab_session_write_leases_v1 SET status = 'active' WHERE lease_id = 'lease-1'"
        )
    with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
        conn.execute(
            "DELETE FROM sab_session_write_leases_v1 WHERE lease_id = 'lease-1'"
        )


def test_lease_activation_timestamp_must_match_signed_contract(
    conn: sqlite3.Connection,
) -> None:
    with pytest.raises(LeaseStateConflict, match="differs from signed lease"):
        activate_session_lease(conn, _lease(), activated_at=_LATER)
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_session_write_leases_v1").fetchone()[0]
        == 0
    )


def test_lease_rejects_unknown_or_invalid_terminal_transitions(
    conn: sqlite3.Connection,
) -> None:
    with pytest.raises(LeaseStateConflict, match="unknown lease"):
        release_session_lease(conn, "missing")
    activate_session_lease(conn, _lease(), activated_at=_NOW)
    with pytest.raises(LeaseStateConflict, match="invalid terminal"):
        release_session_lease(conn, "lease-1", terminal_status="active")
    with pytest.raises(
        sqlite3.IntegrityError, match="invalid session write lease transition"
    ):
        conn.execute(
            """
            UPDATE sab_session_write_leases_v1
            SET status = 'released', released_at = ?, operations_json = '[]'
            WHERE lease_id = 'lease-1'
            """,
            (_LATER,),
        )


@pytest.mark.parametrize(
    ("operations", "reason"),
    [
        ([{"method": "POST", "path": "/api/v1/*"}], "wildcard path"),
        ([{"method": "*", "path": "/api/v1/artifact-cases"}], "wildcard method"),
        (
            [{"method": "POST", "path": "/api/v1/compost-batches/apply"}],
            "Great Composting activation",
        ),
        ([{"method": "DELETE", "path": "/api/v1/artifact-cases"}], "forbidden method"),
        (
            [
                {"method": "POST", "path": "/api/v1/artifact-cases"},
                {"method": "POST", "path": "/api/v1/artifact-cases"},
            ],
            "duplicate operation",
        ),
    ],
)
def test_storage_boundary_rejects_non_exact_lease_operations(
    conn: sqlite3.Connection,
    operations: list[dict[str, str]],
    reason: str,
) -> None:
    with pytest.raises((FirstVerdictStorageError, ValueError), match=".*"):
        activate_session_lease(conn, _lease("invalid-lease", operations=operations))
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM sab_session_write_leases_v1 WHERE lease_id = 'invalid-lease'"
        ).fetchone()[0]
        == 0
    ), reason


def test_storage_boundary_rejects_non_copy_lease(
    conn: sqlite3.Connection,
) -> None:
    with pytest.raises((FirstVerdictStorageError, ValueError), match=".*"):
        activate_session_lease(conn, _lease("live-lease", scope="Live"))
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM sab_session_write_leases_v1 WHERE lease_id = 'live-lease'"
        ).fetchone()[0]
        == 0
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allowed_operations_sha256", "0" * 64),
        ("lease_sha256", "0" * 64),
        ("unexpected_field", "not-allowed"),
    ],
)
def test_storage_boundary_rejects_tampered_or_extra_lease_fields(
    conn: sqlite3.Connection,
    field: str,
    value: str,
) -> None:
    lease = _lease("tampered-lease")
    lease[field] = value
    with pytest.raises(LeaseStateConflict, match="invalid session write lease"):
        activate_session_lease(conn, lease, activated_at=_NOW)
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_session_write_leases_v1").fetchone()[0]
        == 0
    )


def test_storage_boundary_rejects_bad_lease_signature_and_lowercase_method(
    conn: sqlite3.Connection,
) -> None:
    bad_signature = _lease("bad-signature")
    bad_signature["signature"]["signature"] = "0" * 128
    with pytest.raises(LeaseStateConflict, match="signature verification failed"):
        activate_session_lease(conn, bad_signature, activated_at=_NOW)

    lowercase = _lease(
        "lowercase-method",
        operations=[{"method": "post", "path": "/api/v1/artifact-cases"}],
    )
    with pytest.raises(LeaseStateConflict, match="invalid session write lease"):
        activate_session_lease(conn, lowercase, activated_at=_NOW)
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_session_write_leases_v1").fetchone()[0]
        == 0
    )


def test_valid_lease_persists_exact_operation_pairs_and_digest(
    conn: sqlite3.Connection,
) -> None:
    operations = [
        {"method": "POST", "path": "/api/v1/artifact-cases"},
        {
            "method": "POST",
            "path": "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        },
    ]
    lease = _lease(operations=operations)
    activate_session_lease(conn, lease, activated_at=_NOW)
    row = conn.execute(
        """
        SELECT scope, operations_json, operations_sha256, status
        FROM sab_session_write_leases_v1
        WHERE lease_id = 'lease-1'
        """
    ).fetchone()
    operations_json = canonical_json_text(operations)
    assert tuple(row) == (
        "Copy",
        operations_json,
        hashlib.sha256(operations_json.encode("utf-8")).hexdigest(),
        "active",
    )


@pytest.mark.parametrize(
    "kind",
    ["case", "ballot", "authority", "verdict", "countersign", "disposition", "lineage"],
)
def test_immutable_identity_exact_replay_and_conflict(
    conn: sqlite3.Connection,
    kind: str,
) -> None:
    assert (
        require_immutable_identity(conn, kind, "not-present", _digest("absent"))
        is False
    )
    records = _insert_graph(conn)
    object_id, digest = records[kind]

    assert immutable_digest_for(conn, kind, object_id) == digest
    assert require_immutable_identity(conn, kind, object_id, digest) is True
    with pytest.raises(ImmutableConflict, match="different content"):
        require_immutable_identity(conn, kind, object_id, _digest(f"changed-{kind}"))
    assert immutable_digest_for(conn, kind, object_id) == digest


def test_json_record_lookup_uses_only_frozen_identifier_combinations(
    conn: sqlite3.Connection,
) -> None:
    records = _insert_graph(conn)
    case_id, _ = records["case"]
    assert (
        get_json_record(
            conn,
            table="sab_artifact_cases_v1",
            id_column="case_id",
            json_column="case_json",
            object_id=case_id,
        )
        is not None
    )

    with pytest.raises(ValueError, match="unsupported first-verdict record lookup"):
        get_json_record(
            conn,
            table="sab_artifact_cases_v1 WHERE 1 = 1 --",
            id_column="case_id",
            json_column="case_json",
            object_id=case_id,
        )


def test_idempotency_lookup_replays_exact_response_and_rejects_conflict(
    conn: sqlite3.Connection,
) -> None:
    request_sha = _digest("request")
    response = {"receipt_id": "receipt-1", "nested": {"z": 2, "a": 1}}
    assert (
        idempotency_lookup(
            conn,
            operation="rehearsal-disposition",
            idempotency_key="idem-1",
            request_sha256=request_sha,
        )
        is None
    )

    record_idempotency(
        conn,
        operation="rehearsal-disposition",
        idempotency_key="idem-1",
        request_sha256=request_sha,
        response=response,
        created_at=_NOW,
    )
    record_idempotency(
        conn,
        operation="rehearsal-disposition",
        idempotency_key="idem-1",
        request_sha256=request_sha,
        response=response,
        created_at=_LATER,
    )

    assert (
        idempotency_lookup(
            conn,
            operation="rehearsal-disposition",
            idempotency_key="idem-1",
            request_sha256=request_sha,
        )
        == response
    )
    row = conn.execute(
        """
        SELECT request_sha256, response_json, response_sha256, created_at
        FROM sab_first_verdict_idempotency_v1
        WHERE operation = 'rehearsal-disposition' AND idempotency_key = 'idem-1'
        """
    ).fetchone()
    response_json = canonical_json_text(response)
    assert tuple(row) == (
        request_sha,
        response_json,
        hashlib.sha256(response_json.encode("utf-8")).hexdigest(),
        _NOW,
    )

    with pytest.raises(ImmutableConflict, match="conflicting content"):
        idempotency_lookup(
            conn,
            operation="rehearsal-disposition",
            idempotency_key="idem-1",
            request_sha256=_digest("different-request"),
        )
    with pytest.raises(ImmutableConflict, match="conflicting response"):
        record_idempotency(
            conn,
            operation="rehearsal-disposition",
            idempotency_key="idem-1",
            request_sha256=request_sha,
            response={"receipt_id": "different"},
        )
    assert (
        conn.execute(
            """
        SELECT COUNT(*) FROM sab_first_verdict_idempotency_v1
        WHERE operation = 'rehearsal-disposition' AND idempotency_key = 'idem-1'
        """
        ).fetchone()[0]
        == 1
    )


@pytest.mark.parametrize(
    ("response_json", "response_sha256", "reason"),
    [
        ('{"ok":true}', "0" * 64, "digest mismatch"),
        ('{"z":2, "a":1}', _digest('{"z":2, "a":1}'), "canonical JSON"),
        ("not-json", _digest("not-json"), "not valid JSON"),
    ],
)
def test_idempotency_lookup_rejects_corrupt_persisted_response(
    conn: sqlite3.Connection,
    response_json: str,
    response_sha256: str,
    reason: str,
) -> None:
    request_sha = _digest(reason)
    conn.execute(
        """
        INSERT INTO sab_first_verdict_idempotency_v1
            (operation, idempotency_key, request_sha256,
             response_json, response_sha256, created_at)
        VALUES ('corrupt', ?, ?, ?, ?, ?)
        """,
        (reason, request_sha, response_json, response_sha256, _NOW),
    )
    with pytest.raises(ImmutableConflict, match=reason):
        idempotency_lookup(
            conn,
            operation="corrupt",
            idempotency_key=reason,
            request_sha256=request_sha,
        )
