from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import base64
from collections import Counter
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import agora.sab_first_verdict_fixture as fixture_module

from agora.sab_first_verdict_evidence import backup_database_readonly
from agora.sab_first_verdict_fixture import (
    FixtureRunnerError,
    IDEMPOTENCY_KEY,
    SUCCESSOR_ID,
    TARGET_ID,
    verify_completed_rehearsal,
)
from agora.sab_first_verdict_lifecycle import ACTIVATION_OPERATION
from agora.sab_artifact_verdict import canonical_json, canonical_json_sha256
from agora.sab_first_verdict_storage import (
    CopyDatabaseAttestation,
    open_attested_copy_connection,
)
from agora.sab_verdict_verify import verify_signature_evidence_table
from scripts.sab_first_verdict import main


CODE_SHA = "c" * 40
REQUIRED_SIGNATURE_TYPES = (
    "policy",
    "lease",
    "case",
    "ballot",
    "countersign",
    "lineage",
    "successor",
    "lifecycle_event",
)
EXPECTED_SIGNATURE_HISTOGRAM = {
    "ballot": 9,
    "case": 1,
    "countersign": 1,
    "lease": 1,
    "lifecycle_event": 1,
    "lineage": 1,
    "policy": 1,
    "successor": 1,
}


def _create_source_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE sab_agent_identities_v1 (
                identity_id TEXT PRIMARY KEY,
                identity_json TEXT NOT NULL
            );
            CREATE TABLE sab_standing_leases_v1 (
                standing_id TEXT PRIMARY KEY,
                status TEXT NOT NULL
            );
            CREATE TABLE unrelated_operator_notes (
                note_id TEXT PRIMARY KEY,
                note BLOB NOT NULL
            );
            INSERT INTO sab_agent_identities_v1
                VALUES ('identity-existing', '{"kind":"fixture"}');
            INSERT INTO sab_standing_leases_v1
                VALUES ('standing-existing', 'active');
            INSERT INTO unrelated_operator_notes
                VALUES ('note-existing', X'00ff10');
            """
        )
        conn.commit()
    finally:
        conn.close()


def _write_a0_receipt(
    path: Path,
    *,
    source: Path,
    copied: Path,
    source_backup_sha256: str,
) -> str:
    source_stat = source.stat()
    payload = {
        "schema_version": "sab.build_a.a0_database_snapshot.v1",
        "content_equal": True,
        "source": {
            "path_ref": str(source.resolve()),
            "opened": "sqlite_uri_mode_ro",
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "device": source_stat.st_dev,
            "inode": source_stat.st_ino,
            "size": source_stat.st_size,
        },
        "copy": {
            "path_ref": f"private:{copied.resolve()}",
            "sha256": source_backup_sha256,
            "backup_method": "sqlite_online_backup_from_mode_ro_source",
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def _attestation(
    *,
    source: Path,
    copied: Path,
    receipt: Path,
    source_backup_sha256: str,
    lifecycle_sha256: str,
) -> CopyDatabaseAttestation:
    return CopyDatabaseAttestation(
        proof_class="copied_live_db_rehearsal",
        database_path=copied,
        source_database_path=source,
        source_backup_sha256=source_backup_sha256,
        expected_lifecycle_fingerprint=lifecycle_sha256,
        copy_receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest(),
        copy_receipt_path=receipt,
    )


def _prepared_cli(tmp_path: Path) -> tuple[Path, Path, Path, list[str]]:
    source = tmp_path / "source.db"
    copied = tmp_path / "copied.db"
    receipt_path = tmp_path / "backup-receipt.json"
    _create_source_database(source)
    backup = backup_database_readonly(source, copied)
    receipt_path.write_text(
        json.dumps(backup, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    arguments = [
        "run-rehearsal",
        "--copy-database",
        str(copied),
        "--forbidden-source-database",
        str(source),
        "--a0-copy-receipt",
        str(receipt_path),
        "--a0-copy-receipt-sha256",
        hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "--source-backup-sha256",
        str(backup["destination"]["sha256"]),
        "--expected-lifecycle-fingerprint",
        str(backup["copy_snapshot"]["lifecycle"]["sha256"]),
        "--code-sha",
        CODE_SHA,
    ]
    return source, copied, receipt_path, arguments


def test_cli_runs_copy_only_fixture_and_reopens_signature_proof(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    source = tmp_path / "source.db"
    copied = tmp_path / "copied.db"
    receipt_path = tmp_path / "a0-copy-receipt.json"
    _create_source_database(source)
    backup = backup_database_readonly(source, copied)
    lifecycle_sha256 = str(backup["copy_snapshot"]["lifecycle"]["sha256"])
    source_backup_sha256 = str(backup["destination"]["sha256"])
    # The backup command's native receipt is directly consumable by the
    # rehearsal command; no caller-authored translation layer is required.
    receipt_path.write_text(
        json.dumps(backup, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    source_before = (
        source.read_bytes(),
        source.stat().st_mtime_ns,
        source.stat().st_size,
    )

    def no_network(*_args, **_kwargs):
        raise AssertionError("fixture runner attempted network access")

    monkeypatch.setattr(socket, "socket", no_network)
    arguments = [
        "run-rehearsal",
        "--copy-database",
        str(copied),
        "--forbidden-source-database",
        str(source),
        "--a0-copy-receipt",
        str(receipt_path),
        "--a0-copy-receipt-sha256",
        receipt_sha256,
        "--source-backup-sha256",
        source_backup_sha256,
        "--expected-lifecycle-fingerprint",
        lifecycle_sha256,
        "--code-sha",
        CODE_SHA,
        "--verify-exact-retry",
    ]
    result = main(arguments)

    assert result == 0
    output = capsys.readouterr().out
    assert output.endswith("\n")
    assert "\n " not in output
    receipt = json.loads(output)
    assert receipt["proof_class"] == "copied_live_db_rehearsal"
    assert receipt["scope"] == "Copy"
    assert receipt["signature_replay"]["signature_count"] == 16
    assert receipt["persisted_signature_count"] == 16
    assert (
        dict(
            sorted(
                Counter(
                    record["artifact_type"]
                    for record in receipt["signature_replay"]["records"]
                ).items()
            )
        )
        == EXPECTED_SIGNATURE_HISTOGRAM
    )
    assert receipt["standing_effect"] == "none"
    assert receipt["identity_effect"] == "none"
    assert receipt["live_eligible"] is False
    assert receipt["live_mutations"] == 0
    assert receipt["provider_calls"] == 0
    assert receipt["external_actions"] == 0

    # A genuinely fresh OS process has no private keys.  It must verify and
    # return the persisted canonical receipt instead of minting new keys.
    resumed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).parents[1] / "scripts/sab_first_verdict.py"),
            *arguments[:-1],
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", ""),
            "LANG": "en_US.UTF-8",
            "TMPDIR": "/private/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": "/private/tmp/sab-runner-test-pycache",
        },
    )
    assert resumed.returncode == 0, resumed.stderr
    resumed_output = resumed.stdout
    assert resumed_output == output
    assert (
        source.read_bytes(),
        source.stat().st_mtime_ns,
        source.stat().st_size,
    ) == source_before
    assert not os.path.samefile(source, copied)

    attestation = _attestation(
        source=source,
        copied=copied,
        receipt=receipt_path,
        source_backup_sha256=source_backup_sha256,
        lifecycle_sha256=lifecycle_sha256,
    )
    conn = open_attested_copy_connection(attestation, require_pristine_backup=False)
    try:
        replay = verify_signature_evidence_table(
            conn, required_artifact_types=REQUIRED_SIGNATURE_TYPES
        )
        assert replay["signature_count"] == 16
        assert replay["persisted_after_reopen"] is True
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sab_first_verdict_signature_evidence_v1"
            ).fetchone()[0]
            == 16
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sab_first_verdict_signed_events_v1"
            ).fetchone()[0]
            == 1
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sab_first_verdict_idempotency_v1 "
                "WHERE operation=? AND idempotency_key=?",
                (ACTIVATION_OPERATION, IDEMPOTENCY_KEY),
            ).fetchone()[0]
            == 1
        )
        assert (
            conn.execute(
                "SELECT state FROM sab_rehearsal_artifacts_v1 WHERE artifact_id=?",
                (TARGET_ID,),
            ).fetchone()[0]
            == "superseded"
        )
        assert (
            conn.execute(
                "SELECT state FROM sab_rehearsal_artifacts_v1 WHERE artifact_id=?",
                (SUCCESSOR_ID,),
            ).fetchone()[0]
            == "pending"
        )
        assert conn.execute(
            "SELECT identity_json FROM sab_agent_identities_v1"
        ).fetchall() == [('{"kind":"fixture"}',)]
        assert conn.execute(
            "SELECT standing_id, status FROM sab_standing_leases_v1"
        ).fetchall() == [("standing-existing", "active")]
        assert conn.execute(
            "SELECT note_id, note FROM unrelated_operator_notes"
        ).fetchall() == [("note-existing", b"\x00\xff\x10")]
    finally:
        conn.close()

    copied_bytes = copied.read_bytes()
    assert b"private_key" not in copied_bytes
    assert b"secret_key" not in copied_bytes
    assert b"provider_api_key" not in copied_bytes


def test_runner_rejects_fabricated_receipt_for_logically_different_copy(
    tmp_path: Path, capsys
) -> None:
    source = tmp_path / "source.db"
    copied = tmp_path / "unrelated.db"
    receipt_path = tmp_path / "fabricated-a0.json"
    _create_source_database(source)
    with sqlite3.connect(copied) as conn:
        conn.execute("CREATE TABLE unrelated_copy_only (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO unrelated_copy_only VALUES (1)")
        conn.commit()
    copied_sha = hashlib.sha256(copied.read_bytes()).hexdigest()
    receipt_sha = _write_a0_receipt(
        receipt_path,
        source=source,
        copied=copied,
        source_backup_sha256=copied_sha,
    )
    from agora.sab_first_verdict_evidence import lifecycle_fingerprint

    with sqlite3.connect(f"file:{copied}?mode=ro", uri=True) as conn:
        lifecycle_sha = lifecycle_fingerprint(conn)["sha256"]
    result = main(
        [
            "run-rehearsal",
            "--copy-database",
            str(copied),
            "--forbidden-source-database",
            str(source),
            "--a0-copy-receipt",
            str(receipt_path),
            "--a0-copy-receipt-sha256",
            receipt_sha,
            "--source-backup-sha256",
            copied_sha,
            "--expected-lifecycle-fingerprint",
            lifecycle_sha,
            "--code-sha",
            CODE_SHA,
        ]
    )
    assert result == 2
    error = json.loads(capsys.readouterr().out)
    assert "preexisting tables differ" in error["detail"]


def test_fresh_resume_rejects_changed_code_sha(tmp_path: Path, capsys) -> None:
    _, _, _, arguments = _prepared_cli(tmp_path)
    assert main(arguments) == 0
    capsys.readouterr()
    changed = list(arguments)
    changed[changed.index("--code-sha") + 1] = "d" * 40
    assert main(changed) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["error"] == "signed_context_mismatch"


@pytest.mark.parametrize("tamper", ("self_hash", "proof_and_counter"))
def test_resume_rejects_rewritten_persisted_receipt(
    tmp_path: Path,
    capsys,
    tamper: str,
) -> None:
    _, copied, _, arguments = _prepared_cli(tmp_path)
    assert main(arguments) == 0
    capsys.readouterr()
    with sqlite3.connect(copied) as conn:
        conn.execute("DROP TRIGGER sab_first_verdict_idempotency_v1_reject_update")
        row = conn.execute(
            "SELECT response_json FROM sab_first_verdict_idempotency_v1 "
            "WHERE operation=? AND idempotency_key=?",
            (ACTIVATION_OPERATION, IDEMPOTENCY_KEY),
        ).fetchone()
        assert row is not None
        receipt = json.loads(str(row[0]))
        if tamper == "self_hash":
            receipt["receipt_sha256"] = "0" * 64
        else:
            receipt["proof_class"] = "fabricated_live_claim"
            receipt["persisted_signature_count"] = 999
            without_hash = {
                key: value for key, value in receipt.items() if key != "receipt_sha256"
            }
            receipt["receipt_sha256"] = canonical_json_sha256(without_hash)
        response_json = canonical_json(receipt)
        conn.execute(
            "UPDATE sab_first_verdict_idempotency_v1 "
            "SET response_json=?, response_sha256=? "
            "WHERE operation=? AND idempotency_key=?",
            (
                response_json,
                hashlib.sha256(response_json.encode()).hexdigest(),
                ACTIVATION_OPERATION,
                IDEMPOTENCY_KEY,
            ),
        )
        conn.commit()
    assert main(arguments) == 2
    error = json.loads(capsys.readouterr().out)
    # Dropping an immutable trigger is itself an attestation failure, so the
    # corrupted receipt cannot reach or influence resume verification.
    assert error["error"] == "evidence_error"
    assert "schema" in error["detail"]


def test_resume_rederives_request_digest_instead_of_trusting_rewritten_row(
    tmp_path: Path,
    capsys,
) -> None:
    _, copied, _, arguments = _prepared_cli(tmp_path)
    assert main(arguments) == 0
    capsys.readouterr()
    with sqlite3.connect(copied) as conn:
        trigger_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='sab_first_verdict_idempotency_v1_reject_update'"
        ).fetchone()[0]
        conn.execute("DROP TRIGGER sab_first_verdict_idempotency_v1_reject_update")
        row = conn.execute(
            "SELECT response_json FROM sab_first_verdict_idempotency_v1 "
            "WHERE operation=? AND idempotency_key=?",
            (ACTIVATION_OPERATION, IDEMPOTENCY_KEY),
        ).fetchone()
        assert row is not None
        receipt = json.loads(str(row[0]))
        forged_request_sha256 = "d" * 64
        receipt["request_sha256"] = forged_request_sha256
        unsigned = {
            key: value for key, value in receipt.items() if key != "receipt_sha256"
        }
        receipt["receipt_sha256"] = canonical_json_sha256(unsigned)
        response_json = canonical_json(receipt)
        conn.execute(
            "UPDATE sab_first_verdict_idempotency_v1 "
            "SET request_sha256=?, response_json=?, response_sha256=? "
            "WHERE operation=? AND idempotency_key=?",
            (
                forged_request_sha256,
                response_json,
                hashlib.sha256(response_json.encode()).hexdigest(),
                ACTIVATION_OPERATION,
                IDEMPOTENCY_KEY,
            ),
        )
        conn.execute(str(trigger_sql))
        conn.commit()

    assert main(arguments) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["error"] == "request_rederivation_mismatch"


@pytest.mark.parametrize(
    ("tamper", "error_code"),
    (
        ("self_hash", "receipt_self_hash_mismatch"),
        ("proof", "receipt_contract_mismatch"),
        ("counter", "signature_multiplicity_mismatch"),
    ),
)
def test_reopen_verifier_rejects_altered_receipt_claims(
    tmp_path: Path,
    capsys,
    tamper: str,
    error_code: str,
) -> None:
    source, copied, receipt_path, arguments = _prepared_cli(tmp_path)
    assert main(arguments) == 0
    receipt = json.loads(capsys.readouterr().out)
    attestation = _attestation(
        source=source,
        copied=copied,
        receipt=receipt_path,
        source_backup_sha256=arguments[arguments.index("--source-backup-sha256") + 1],
        lifecycle_sha256=arguments[
            arguments.index("--expected-lifecycle-fingerprint") + 1
        ],
    )
    if tamper == "self_hash":
        receipt["receipt_sha256"] = "0" * 64
    elif tamper == "proof":
        receipt["proof_class"] = "fabricated_live_claim"
    else:
        receipt["persisted_signature_count"] = 999
    if tamper != "self_hash":
        without_hash = {
            key: value for key, value in receipt.items() if key != "receipt_sha256"
        }
        receipt["receipt_sha256"] = canonical_json_sha256(without_hash)
    with pytest.raises(FixtureRunnerError) as raised:
        verify_completed_rehearsal(
            attestation,
            receipt,
            code_sha=CODE_SHA,
        )
    assert raised.value.code == error_code


def test_fixture_private_key_material_is_never_persisted(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, copied, _, arguments = _prepared_cli(tmp_path)
    private_seeds: list[bytes] = []
    counter = 0

    def deterministic_generate() -> SigningKey:
        nonlocal counter
        counter += 1
        seed = hashlib.sha256(f"fixture-private-seed:{counter}".encode()).digest()
        private_seeds.append(seed)
        return SigningKey(seed)

    monkeypatch.setattr(
        fixture_module.SigningKey,
        "generate",
        staticmethod(deterministic_generate),
    )
    assert main(arguments) == 0
    capsys.readouterr()
    copied_bytes = copied.read_bytes()
    assert private_seeds
    for seed in private_seeds:
        assert seed not in copied_bytes
        assert seed.hex().encode() not in copied_bytes
        assert base64.b64encode(seed) not in copied_bytes


def test_cli_rejects_copy_path_equal_to_forbidden_source(
    tmp_path: Path, capsys
) -> None:
    source = tmp_path / "source.db"
    receipt_path = tmp_path / "a0-copy-receipt.json"
    _create_source_database(source)
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    readonly = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        from agora.sab_first_verdict_evidence import lifecycle_fingerprint

        lifecycle_sha256 = lifecycle_fingerprint(readonly)["sha256"]
    finally:
        readonly.close()
    receipt_sha256 = _write_a0_receipt(
        receipt_path,
        source=source,
        copied=source,
        source_backup_sha256=source_sha256,
    )
    before = (source.read_bytes(), source.stat().st_mtime_ns)

    result = main(
        [
            "run-rehearsal",
            "--copy-database",
            str(source),
            "--forbidden-source-database",
            str(source),
            "--a0-copy-receipt",
            str(receipt_path),
            "--a0-copy-receipt-sha256",
            receipt_sha256,
            "--source-backup-sha256",
            source_sha256,
            "--expected-lifecycle-fingerprint",
            lifecycle_sha256,
            "--code-sha",
            CODE_SHA,
        ]
    )

    assert result == 2
    error = json.loads(capsys.readouterr().out)
    assert error["ok"] is False
    assert "forbidden source" in error["detail"]
    assert (source.read_bytes(), source.stat().st_mtime_ns) == before
