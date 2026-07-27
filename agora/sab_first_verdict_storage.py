"""Additive, copy-only storage for the SAB first-verdict Build A slice.

This module deliberately does not discover a database path, import the public
application, or commit caller-owned lifecycle transactions.  A caller must
provide an explicit SQLite connection to a disposable fixture or copied
database.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import quote

from .sab_artifact_verdict import (
    ArtifactBallotV1,
    ArtifactCaseV1,
    CouncilVerdictV1,
    DISPOSITION_AUTHORITY_ADAPTER,
    SessionWriteLeaseV1,
    canonical_json,
    canonical_json_sha256 as contract_json_sha256,
    verify_contract_signature,
)


MIGRATION_ID = "20260728_first_verdict_build_a_v1"

FROZEN_METHOD_PATHS = frozenset(
    {
        ("GET", "/health"),
        ("POST", "/api/v1/session-write-leases/activate"),
        ("POST", "/api/v1/session-write-leases/{lease_id}/release"),
        ("GET", "/api/v1/session-write-leases/{lease_id}"),
        ("POST", "/api/v1/artifact-cases"),
        ("GET", "/api/v1/artifact-cases/{case_id}"),
        ("POST", "/api/v1/artifact-cases/{case_id}/ballots"),
        ("POST", "/api/v1/artifact-cases/{case_id}/authority-evaluations"),
        ("POST", "/api/v1/artifact-cases/{case_id}/verdicts"),
        ("GET", "/api/v1/artifact-verdicts/{verdict_id}"),
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        ),
        ("GET", "/api/v1/rehearsal-dispositions/{disposition_id}"),
        ("GET", "/api/v1/seeds/{seed_id}/lineage"),
        ("POST", "/api/v1/compost-batches/preview"),
    }
)


class FirstVerdictStorageError(RuntimeError):
    """Base class for deterministic storage failures."""


class MigrationDigestMismatch(FirstVerdictStorageError):
    """The recorded migration ID exists with different bytes."""


class MigrationSchemaMismatch(FirstVerdictStorageError):
    """A pre-existing object conflicts with the additive migration schema."""


class ForeignKeysRequired(FirstVerdictStorageError):
    """The caller did not enable SQLite foreign-key enforcement."""


class DatabaseSafetyError(FirstVerdictStorageError):
    """A database is not proven to be a disposable or copied Build A target."""


class ImmutableConflict(FirstVerdictStorageError):
    """An immutable identity was reused with different content."""


class LeaseStateConflict(FirstVerdictStorageError):
    """A lease transition was invalid or conflicted with prior state."""


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json_text(value: Any) -> str:
    return canonical_json(value)


def canonical_json_sha256(value: Any) -> str:
    return contract_json_sha256(value)


@dataclass(frozen=True)
class CopyDatabaseAttestation:
    """Out-of-band binding for the only file-backed writable storage surface."""

    proof_class: str
    database_path: Path
    source_database_path: Path | None
    source_backup_sha256: str
    expected_lifecycle_fingerprint: str
    copy_receipt_sha256: str

    def validate(self, *, require_pristine_backup: bool) -> Path:
        if self.proof_class not in {
            "copied_live_db_rehearsal",
            "disposable_fixture",
        }:
            raise DatabaseSafetyError("database proof class is not copy/fixture scoped")
        for field_name in (
            "source_backup_sha256",
            "expected_lifecycle_fingerprint",
            "copy_receipt_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(getattr(self, field_name))):
                raise DatabaseSafetyError(f"{field_name} is not lowercase SHA-256")
        candidate = Path(self.database_path)
        if (
            not candidate.is_absolute()
            or candidate.is_symlink()
            or not candidate.is_file()
        ):
            raise DatabaseSafetyError(
                "copy database must be an explicit absolute non-symlink file"
            )
        resolved = candidate.resolve(strict=True)
        if any(
            (parent / ".git").exists()
            for parent in (resolved.parent, *resolved.parents)
        ):
            raise DatabaseSafetyError("copy database must be outside a Git checkout")
        if self.source_database_path is None:
            raise DatabaseSafetyError(
                "every file-backed target requires an explicit forbidden source path"
            )
        source = Path(self.source_database_path)
        if not source.is_absolute() or source.is_symlink() or not source.is_file():
            raise DatabaseSafetyError(
                "source database must be an explicit absolute non-symlink file"
            )
        if source.resolve(strict=True) == resolved or os.path.samefile(
            source, resolved
        ):
            raise DatabaseSafetyError("copy database is the forbidden source file")
        if require_pristine_backup:
            digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if digest != self.source_backup_sha256:
                raise DatabaseSafetyError(
                    "copy database does not match source-backup digest"
                )
        return resolved


class AttestedSQLiteConnection(sqlite3.Connection):
    """SQLite connection carrying an out-of-band copy attestation."""

    sab_copy_attestation: CopyDatabaseAttestation


def require_copy_or_fixture_connection(conn: sqlite3.Connection) -> None:
    """Permit in-memory fixtures or a connection opened by the attested opener."""

    database_rows = conn.execute("PRAGMA database_list").fetchall()
    main_path = next(
        (str(row[2]) for row in database_rows if str(row[1]) == "main"), ""
    )
    if not main_path:
        return
    if not isinstance(conn, AttestedSQLiteConnection) or not hasattr(
        conn, "sab_copy_attestation"
    ):
        raise DatabaseSafetyError(
            "file-backed storage mutation requires an attested copy connection"
        )
    attestation = conn.sab_copy_attestation
    expected = attestation.validate(require_pristine_backup=False)
    actual = Path(main_path).resolve(strict=True)
    if not os.path.samefile(actual, expected):
        raise DatabaseSafetyError("active connection differs from attested copy path")


def open_attested_copy_connection(
    attestation: CopyDatabaseAttestation,
    *,
    require_pristine_backup: bool = False,
) -> sqlite3.Connection:
    """Open an existing attested copy with ``mode=rw``; never create a DB."""

    resolved = attestation.validate(require_pristine_backup=require_pristine_backup)
    uri = f"file:{quote(str(resolved), safe='/')}?mode=rw"
    conn = sqlite3.connect(uri, uri=True, factory=AttestedSQLiteConnection)
    conn.sab_copy_attestation = attestation
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise DatabaseSafetyError("could not enable SQLite foreign keys")
        from .sab_first_verdict_evidence import lifecycle_fingerprint

        actual = lifecycle_fingerprint(conn)["sha256"]
        if actual != attestation.expected_lifecycle_fingerprint:
            raise DatabaseSafetyError(
                "copy lifecycle fingerprint differs from attestation"
            )
    except Exception:
        conn.close()
        raise
    return conn


_LEDGER_STATEMENT = """
    CREATE TABLE IF NOT EXISTS sab_first_verdict_schema_migrations_v1 (
        migration_id TEXT PRIMARY KEY,
        migration_digest TEXT NOT NULL CHECK (length(migration_digest) = 64),
        applied_at TEXT NOT NULL
    )
    """


_TABLE_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS sab_session_write_leases_v1 (
        lease_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL CHECK (scope = 'Copy'),
        operations_json TEXT NOT NULL,
        operations_sha256 TEXT NOT NULL CHECK (length(operations_sha256) = 64),
        lease_json TEXT NOT NULL,
        lease_json_sha256 TEXT NOT NULL UNIQUE CHECK (length(lease_json_sha256) = 64),
        lease_sha256 TEXT NOT NULL UNIQUE CHECK (length(lease_sha256) = 64),
        status TEXT NOT NULL CHECK (status IN ('active', 'released', 'expired', 'revoked')),
        activated_at TEXT NOT NULL,
        released_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_artifact_cases_v1 (
        case_id TEXT PRIMARY KEY,
        target_seed_id TEXT NOT NULL,
        round_no INTEGER NOT NULL CHECK (round_no = 1),
        case_json TEXT NOT NULL,
        case_sha256 TEXT NOT NULL UNIQUE CHECK (length(case_sha256) = 64),
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_artifact_ballots_v1 (
        ballot_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES sab_artifact_cases_v1(case_id),
        round_no INTEGER NOT NULL CHECK (round_no = 1),
        seat_id TEXT NOT NULL,
        ballot_source TEXT NOT NULL CHECK (ballot_source IN ('real_external_model', 'fixture_model')),
        credited_cluster TEXT NOT NULL,
        ballot_json TEXT NOT NULL,
        ballot_sha256 TEXT NOT NULL UNIQUE CHECK (length(ballot_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (case_id, round_no, seat_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_disposition_authority_v1 (
        evaluation_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES sab_artifact_cases_v1(case_id),
        result TEXT NOT NULL CHECK (result IN ('Authorized', 'AdvisoryOnly', 'NoJurisdiction')),
        scope TEXT NOT NULL CHECK (scope IN ('Copy', 'Live', 'All')),
        evaluated_state_hash TEXT NOT NULL CHECK (length(evaluated_state_hash) = 64),
        authority_json TEXT NOT NULL,
        authority_sha256 TEXT NOT NULL UNIQUE CHECK (length(authority_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (evaluation_id, case_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_council_verdicts_v1 (
        verdict_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES sab_artifact_cases_v1(case_id),
        evaluation_id TEXT NOT NULL REFERENCES sab_disposition_authority_v1(evaluation_id),
        round_no INTEGER NOT NULL CHECK (round_no = 1),
        decision TEXT NOT NULL,
        ballot_set_sha256 TEXT NOT NULL CHECK (length(ballot_set_sha256) = 64),
        verdict_json TEXT NOT NULL,
        verdict_sha256 TEXT NOT NULL UNIQUE CHECK (length(verdict_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (case_id, round_no),
        UNIQUE (verdict_id, evaluation_id),
        UNIQUE (verdict_id, evaluation_id, case_id),
        FOREIGN KEY (evaluation_id, case_id)
            REFERENCES sab_disposition_authority_v1(evaluation_id, case_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_operator_countersigns_v1 (
        countersign_id TEXT PRIMARY KEY,
        verdict_id TEXT NOT NULL UNIQUE REFERENCES sab_council_verdicts_v1(verdict_id),
        write_lease_id TEXT NOT NULL REFERENCES sab_session_write_leases_v1(lease_id),
        countersign_json TEXT NOT NULL,
        countersign_sha256 TEXT NOT NULL UNIQUE CHECK (length(countersign_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (countersign_id, verdict_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_rehearsal_artifacts_v1 (
        artifact_id TEXT PRIMARY KEY,
        state TEXT NOT NULL,
        artifact_json TEXT NOT NULL,
        artifact_sha256 TEXT NOT NULL UNIQUE CHECK (length(artifact_sha256) = 64),
        live_eligible INTEGER NOT NULL CHECK (live_eligible = 0),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_rehearsal_dispositions_v1 (
        disposition_id TEXT PRIMARY KEY,
        verdict_id TEXT NOT NULL UNIQUE REFERENCES sab_council_verdicts_v1(verdict_id),
        countersign_id TEXT NOT NULL UNIQUE REFERENCES sab_operator_countersigns_v1(countersign_id),
        evaluation_id TEXT NOT NULL REFERENCES sab_disposition_authority_v1(evaluation_id),
        target_artifact_id TEXT NOT NULL REFERENCES sab_rehearsal_artifacts_v1(artifact_id),
        successor_artifact_id TEXT REFERENCES sab_rehearsal_artifacts_v1(artifact_id),
        scope TEXT NOT NULL CHECK (scope = 'Copy'),
        disposition_json TEXT NOT NULL,
        disposition_sha256 TEXT NOT NULL UNIQUE CHECK (length(disposition_sha256) = 64),
        created_at TEXT NOT NULL,
        FOREIGN KEY (verdict_id, evaluation_id)
            REFERENCES sab_council_verdicts_v1(verdict_id, evaluation_id),
        FOREIGN KEY (countersign_id, verdict_id)
            REFERENCES sab_operator_countersigns_v1(countersign_id, verdict_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_seed_lineage_edges_v1 (
        edge_id TEXT PRIMARY KEY,
        predecessor_seed_id TEXT NOT NULL,
        successor_seed_id TEXT NOT NULL,
        disposition_id TEXT NOT NULL REFERENCES sab_rehearsal_dispositions_v1(disposition_id),
        edge_json TEXT NOT NULL,
        edge_sha256 TEXT NOT NULL UNIQUE CHECK (length(edge_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (predecessor_seed_id, successor_seed_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_first_verdict_signed_events_v1 (
        event_id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        signer TEXT NOT NULL,
        public_key TEXT NOT NULL,
        prev_hash TEXT,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
        signature TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_first_verdict_idempotency_v1 (
        operation TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
        response_json TEXT NOT NULL,
        response_sha256 TEXT NOT NULL CHECK (length(response_sha256) = 64),
        created_at TEXT NOT NULL,
        PRIMARY KEY (operation, idempotency_key)
    )
    """,
)


_IMMUTABLE_TABLES = (
    "sab_first_verdict_schema_migrations_v1",
    "sab_artifact_cases_v1",
    "sab_artifact_ballots_v1",
    "sab_disposition_authority_v1",
    "sab_council_verdicts_v1",
    "sab_operator_countersigns_v1",
    "sab_rehearsal_dispositions_v1",
    "sab_seed_lineage_edges_v1",
    "sab_first_verdict_signed_events_v1",
    "sab_first_verdict_idempotency_v1",
)


def _trigger_statements() -> tuple[str, ...]:
    statements = []
    for table in _IMMUTABLE_TABLES:
        statements.extend(
            (
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_reject_update
                BEFORE UPDATE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, '{table} is immutable');
                END
                """,
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_reject_delete
                BEFORE DELETE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, '{table} is immutable');
                END
                """,
            )
        )
    statements.extend(
        (
            """
            CREATE TRIGGER IF NOT EXISTS sab_session_write_leases_v1_reject_delete
            BEFORE DELETE ON sab_session_write_leases_v1
            BEGIN
                SELECT RAISE(ABORT, 'session write leases cannot be deleted');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS sab_session_write_leases_v1_restrict_update
            BEFORE UPDATE ON sab_session_write_leases_v1
            WHEN NOT (
                OLD.status = 'active'
                AND NEW.status IN ('released', 'expired', 'revoked')
                AND NEW.lease_id = OLD.lease_id
                AND NEW.scope = OLD.scope
                AND NEW.operations_json = OLD.operations_json
                AND NEW.operations_sha256 = OLD.operations_sha256
                AND NEW.lease_json = OLD.lease_json
                AND NEW.lease_json_sha256 = OLD.lease_json_sha256
                AND NEW.lease_sha256 = OLD.lease_sha256
                AND NEW.activated_at = OLD.activated_at
                AND NEW.released_at IS NOT NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid session write lease transition');
            END
            """,
        )
    )
    return tuple(statements)


MIGRATION_STATEMENTS = (_LEDGER_STATEMENT,) + _TABLE_STATEMENTS + _trigger_statements()
MIGRATION_DIGEST = hashlib.sha256(
    "\n".join(statement.strip() for statement in MIGRATION_STATEMENTS).encode()
).hexdigest()


_SCHEMA_OBJECT = re.compile(
    r"^CREATE\s+(?:TABLE|TRIGGER)\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


def _normalized_schema_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip()).replace(" IF NOT EXISTS ", " ")


def _verify_migration_schema(conn: sqlite3.Connection) -> None:
    """Reject a same-named table/trigger whose realized DDL differs.

    ``CREATE ... IF NOT EXISTS`` alone is not an attestation: without this
    check, a partial or hostile pre-existing object could be silently accepted
    and the migration digest recorded anyway.
    """

    for statement in MIGRATION_STATEMENTS:
        match = _SCHEMA_OBJECT.match(statement.strip())
        if match is None:
            raise MigrationSchemaMismatch("unrecognized migration statement")
        name = match.group(1)
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = ?", (name,)
        ).fetchone()
        expected = _normalized_schema_sql(statement)
        actual = (
            "" if row is None or row[0] is None else _normalized_schema_sql(str(row[0]))
        )
        if actual != expected:
            raise MigrationSchemaMismatch(
                f"migration object {name} differs from the frozen schema"
            )


def _invoke_failure(hook: Optional[Callable[[str], None]], boundary: str) -> None:
    if hook is not None:
        hook(boundary)


def init_first_verdict_storage(
    conn: sqlite3.Connection,
    *,
    applied_at: Optional[str] = None,
    failure_hook: Optional[Callable[[str], None]] = None,
) -> str:
    """Install the additive migration atomically and return its digest.

    The function uses ``BEGIN IMMEDIATE`` when it owns the connection
    transaction and a savepoint otherwise.  Reusing the migration ID with
    different bytes fails closed.
    """

    require_copy_or_fixture_connection(conn)
    if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        raise ForeignKeysRequired(
            "PRAGMA foreign_keys=ON is required before the migration transaction"
        )

    owns_transaction = not conn.in_transaction
    savepoint = "sab_first_verdict_migration"
    if owns_transaction:
        conn.execute("BEGIN IMMEDIATE")
    else:
        conn.execute(f"SAVEPOINT {savepoint}")
    try:
        conn.execute(_LEDGER_STATEMENT)
        ledger_name = "sab_first_verdict_schema_migrations_v1"
        ledger_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (ledger_name,),
        ).fetchone()
        if (
            ledger_row is None
            or ledger_row[0] is None
            or _normalized_schema_sql(str(ledger_row[0]))
            != _normalized_schema_sql(_LEDGER_STATEMENT)
        ):
            raise MigrationSchemaMismatch(
                "migration ledger differs from the frozen schema"
            )
        existing = conn.execute(
            """
            SELECT migration_digest
            FROM sab_first_verdict_schema_migrations_v1
            WHERE migration_id = ?
            """,
            (MIGRATION_ID,),
        ).fetchone()
        if existing is not None and str(existing[0]) != MIGRATION_DIGEST:
            raise MigrationDigestMismatch(
                f"{MIGRATION_ID} digest mismatch: {existing[0]} != {MIGRATION_DIGEST}"
            )
        _invoke_failure(failure_hook, "migration:0")
        for index, statement in enumerate(MIGRATION_STATEMENTS[1:], start=1):
            conn.execute(statement)
            _invoke_failure(failure_hook, f"migration:{index}")
        _verify_migration_schema(conn)
        _invoke_failure(failure_hook, "migration:schema-verified")
        conn.execute(
            """
            INSERT OR IGNORE INTO sab_first_verdict_schema_migrations_v1
                (migration_id, migration_digest, applied_at)
            VALUES (?, ?, ?)
            """,
            (MIGRATION_ID, MIGRATION_DIGEST, applied_at or utc_now_text()),
        )
        _invoke_failure(failure_hook, "migration:record")
        if owns_transaction:
            conn.commit()
        else:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        if owns_transaction:
            conn.rollback()
        else:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    return MIGRATION_DIGEST


_IMMUTABLE_SPECS: Dict[str, tuple[str, str, str]] = {
    "case": ("sab_artifact_cases_v1", "case_id", "case_sha256"),
    "ballot": ("sab_artifact_ballots_v1", "ballot_id", "ballot_sha256"),
    "authority": (
        "sab_disposition_authority_v1",
        "evaluation_id",
        "authority_sha256",
    ),
    "verdict": ("sab_council_verdicts_v1", "verdict_id", "verdict_sha256"),
    "countersign": (
        "sab_operator_countersigns_v1",
        "countersign_id",
        "countersign_sha256",
    ),
    "disposition": (
        "sab_rehearsal_dispositions_v1",
        "disposition_id",
        "disposition_sha256",
    ),
    "lineage": ("sab_seed_lineage_edges_v1", "edge_id", "edge_sha256"),
}


def immutable_digest_for(
    conn: sqlite3.Connection,
    kind: str,
    object_id: str,
) -> Optional[str]:
    table, id_column, digest_column = _IMMUTABLE_SPECS[kind]
    row = conn.execute(
        f"SELECT {digest_column} FROM {table} WHERE {id_column} = ?", (object_id,)
    ).fetchone()
    return None if row is None else str(row[0])


def require_immutable_identity(
    conn: sqlite3.Connection,
    kind: str,
    object_id: str,
    digest: str,
) -> bool:
    """Return True for an exact replay, False for a new identity."""

    existing = immutable_digest_for(conn, kind, object_id)
    if existing is None:
        return False
    if existing != digest:
        raise ImmutableConflict(
            f"{kind} {object_id} already exists with different content"
        )
    return True


def store_artifact_case(
    conn: sqlite3.Connection,
    case: Dict[str, Any],
    *,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        normalized = ArtifactCaseV1.model_validate(case).canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(f"invalid artifact case contract: {exc}") from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    case_id = str(normalized["case_id"])
    replay = require_immutable_identity(conn, "case", case_id, digest)
    if not replay:
        conn.execute(
            """
            INSERT INTO sab_artifact_cases_v1
                (case_id, target_seed_id, round_no, case_json,
                 case_sha256, created_at)
            VALUES (?, ?, 1, ?, ?, ?)
            """,
            (
                case_id,
                str(normalized["target_seed_id"]),
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def store_artifact_ballot(
    conn: sqlite3.Connection,
    ballot: Dict[str, Any],
    *,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        normalized = ArtifactBallotV1.model_validate(ballot).canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(f"invalid artifact ballot contract: {exc}") from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    ballot_id = str(normalized["ballot_id"])
    case_row = conn.execute(
        "SELECT case_sha256 FROM sab_artifact_cases_v1 WHERE case_id = ?",
        (str(normalized["case_id"]),),
    ).fetchone()
    if case_row is None or str(case_row[0]) != str(normalized["case_sha256"]):
        raise ImmutableConflict("ballot case digest does not match stored case")
    replay = require_immutable_identity(conn, "ballot", ballot_id, digest)
    if not replay:
        conn.execute(
            """
            INSERT INTO sab_artifact_ballots_v1
                (ballot_id, case_id, round_no, seat_id, ballot_source,
                 credited_cluster, ballot_json, ballot_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ballot_id,
                str(normalized["case_id"]),
                int(normalized["round_no"]),
                str(normalized["seat_id"]),
                str(normalized["ballot_source"]),
                str(normalized["credited_cluster"]),
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def store_authority_evaluation(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    authority: Dict[str, Any],
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        model = DISPOSITION_AUTHORITY_ADAPTER.validate_python(authority)
        normalized = model.canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(
            f"invalid disposition authority contract: {exc}"
        ) from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    evaluation_id = str(normalized["evaluation_id"])
    case_row = conn.execute(
        "SELECT target_seed_id FROM sab_artifact_cases_v1 WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    if case_row is None:
        raise ImmutableConflict(f"unknown artifact case {case_id}")
    if str(case_row[0]) != str(normalized["artifact_id"]):
        raise ImmutableConflict(
            "authority artifact does not match the case target seed"
        )
    replay = require_immutable_identity(conn, "authority", evaluation_id, digest)
    if replay:
        row = conn.execute(
            "SELECT case_id FROM sab_disposition_authority_v1 WHERE evaluation_id = ?",
            (evaluation_id,),
        ).fetchone()
        if row is None or str(row[0]) != case_id:
            raise ImmutableConflict(
                f"authority {evaluation_id} has conflicting case binding"
            )
    else:
        conn.execute(
            """
            INSERT INTO sab_disposition_authority_v1
                (evaluation_id, case_id, result, scope, evaluated_state_hash,
                 authority_json, authority_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evaluation_id,
                case_id,
                str(normalized["result"]),
                str(normalized["scope"]),
                str(normalized["evaluated_state_hash"]),
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def ballot_set_sha256_for_case(conn: sqlite3.Connection, case_id: str) -> str:
    rows = conn.execute(
        """
        SELECT ballot_id, ballot_sha256
        FROM sab_artifact_ballots_v1
        WHERE case_id = ? AND round_no = 1
        ORDER BY ballot_id
        """,
        (case_id,),
    ).fetchall()
    members = [{"ballot_id": str(row[0]), "ballot_sha256": str(row[1])} for row in rows]
    return canonical_json_sha256(members)


def store_council_verdict(
    conn: sqlite3.Connection,
    *,
    evaluation_id: str,
    verdict: Dict[str, Any],
    ballot_set_sha256: str,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        normalized = CouncilVerdictV1.model_validate(verdict).canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(f"invalid council verdict contract: {exc}") from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    verdict_id = str(normalized["verdict_id"])
    case_id = str(normalized["case_id"])
    authority_row = conn.execute(
        """
        SELECT case_id, authority_sha256
        FROM sab_disposition_authority_v1
        WHERE evaluation_id = ?
        """,
        (evaluation_id,),
    ).fetchone()
    if authority_row is None:
        raise ImmutableConflict(f"unknown authority evaluation {evaluation_id}")
    if str(authority_row[0]) != case_id:
        raise ImmutableConflict("verdict case does not match authority evaluation case")
    if str(authority_row[1]) != str(normalized["authority_digest"]):
        raise ImmutableConflict("verdict authority digest does not match evaluation")
    case_row = conn.execute(
        "SELECT case_sha256 FROM sab_artifact_cases_v1 WHERE case_id = ?", (case_id,)
    ).fetchone()
    if case_row is None or str(case_row[0]) != str(normalized["case_sha256"]):
        raise ImmutableConflict("verdict case digest does not match stored case")
    ballot_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM sab_artifact_ballots_v1 WHERE case_id = ? AND round_no = 1",
            (case_id,),
        ).fetchone()[0]
    )
    if ballot_count != 9:
        raise ImmutableConflict("Build A verdict requires exactly nine stored ballots")
    expected_ballot_set = ballot_set_sha256_for_case(conn, case_id)
    if ballot_set_sha256 != expected_ballot_set:
        raise ImmutableConflict(
            "verdict ballot-set digest does not match stored ballots"
        )
    replay = require_immutable_identity(conn, "verdict", verdict_id, digest)
    if replay:
        row = conn.execute(
            """
            SELECT evaluation_id, ballot_set_sha256, case_id
            FROM sab_council_verdicts_v1 WHERE verdict_id = ?
            """,
            (verdict_id,),
        ).fetchone()
        if row is None or tuple(str(value) for value in row) != (
            evaluation_id,
            ballot_set_sha256,
            case_id,
        ):
            raise ImmutableConflict(
                f"verdict {verdict_id} has conflicting relational bindings"
            )
    else:
        conn.execute(
            """
            INSERT INTO sab_council_verdicts_v1
                (verdict_id, case_id, evaluation_id, round_no, decision,
                 ballot_set_sha256, verdict_json, verdict_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verdict_id,
                case_id,
                evaluation_id,
                int(normalized["round_no"]),
                str(normalized["decision"]),
                ballot_set_sha256,
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def create_rehearsal_artifact(
    conn: sqlite3.Connection,
    artifact: Dict[str, Any],
    *,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    payload_json = canonical_json_text(artifact)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    artifact_id = str(artifact["artifact_id"])
    row = conn.execute(
        """
        SELECT artifact_sha256, artifact_json
        FROM sab_rehearsal_artifacts_v1
        WHERE artifact_id = ?
        """,
        (artifact_id,),
    ).fetchone()
    if row is not None:
        if str(row[0]) != digest or str(row[1]) != payload_json:
            raise ImmutableConflict(
                f"rehearsal artifact {artifact_id} exists with different content"
            )
        return artifact, digest, True
    timestamp = created_at or utc_now_text()
    conn.execute(
        """
        INSERT INTO sab_rehearsal_artifacts_v1
            (artifact_id, state, artifact_json, artifact_sha256,
             live_eligible, created_at, updated_at)
        VALUES (?, ?, ?, ?, 0, ?, ?)
        """,
        (
            artifact_id,
            str(artifact["state"]),
            payload_json,
            digest,
            timestamp,
            timestamp,
        ),
    )
    return artifact, digest, False


def idempotency_lookup(
    conn: sqlite3.Connection,
    *,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
        raise ImmutableConflict("idempotency request digest is not lowercase SHA-256")
    row = conn.execute(
        """
        SELECT request_sha256, response_json, response_sha256
        FROM sab_first_verdict_idempotency_v1
        WHERE operation = ? AND idempotency_key = ?
        """,
        (operation, idempotency_key),
    ).fetchone()
    if row is None:
        return None
    if str(row[0]) != request_sha256:
        raise ImmutableConflict(
            f"idempotency identity {operation}/{idempotency_key} has conflicting content"
        )
    response_json = str(row[1])
    response_sha256 = str(row[2])
    try:
        response = json.loads(response_json)
    except json.JSONDecodeError as exc:
        raise ImmutableConflict(
            "stored idempotency response is not valid JSON"
        ) from exc
    if canonical_json_text(response) != response_json:
        raise ImmutableConflict("stored idempotency response is not canonical JSON")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", response_sha256)
        or hashlib.sha256(response_json.encode()).hexdigest() != response_sha256
    ):
        raise ImmutableConflict("stored idempotency response digest mismatch")
    return response


def record_idempotency(
    conn: sqlite3.Connection,
    *,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
    response: Dict[str, Any],
    created_at: Optional[str] = None,
) -> None:
    require_copy_or_fixture_connection(conn)
    if not operation or not idempotency_key:
        raise ImmutableConflict("idempotency operation and key must be non-empty")
    if not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
        raise ImmutableConflict("idempotency request digest is not lowercase SHA-256")
    response_json = canonical_json_text(response)
    existing = idempotency_lookup(
        conn,
        operation=operation,
        idempotency_key=idempotency_key,
        request_sha256=request_sha256,
    )
    if existing is not None:
        if canonical_json_text(existing) != response_json:
            raise ImmutableConflict(
                f"idempotency identity {operation}/{idempotency_key} has conflicting response"
            )
        return
    conn.execute(
        """
        INSERT INTO sab_first_verdict_idempotency_v1
            (operation, idempotency_key, request_sha256,
             response_json, response_sha256, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            operation,
            idempotency_key,
            request_sha256,
            response_json,
            hashlib.sha256(response_json.encode()).hexdigest(),
            created_at or utc_now_text(),
        ),
    )


def activate_session_lease(
    conn: sqlite3.Connection,
    lease: Dict[str, Any],
    *,
    activated_at: Optional[str] = None,
) -> Dict[str, Any]:
    require_copy_or_fixture_connection(conn)
    try:
        model = SessionWriteLeaseV1.model_validate(lease)
    except Exception as exc:
        raise LeaseStateConflict(
            f"invalid session write lease contract: {exc}"
        ) from exc
    if model.signature.signer != model.issuer_identity:
        raise LeaseStateConflict(
            "lease signature signer does not match issuer identity"
        )
    if model.signature.public_key != model.issuer_public_key:
        raise LeaseStateConflict("lease signature key does not match issuer key")
    if not verify_contract_signature(
        model.canonical_bytes(exclude={"signature"}), model.signature
    ):
        raise LeaseStateConflict("lease signature verification failed")
    signed_activated_at = model.activated_at.isoformat().replace("+00:00", "Z")
    if activated_at is not None and activated_at != signed_activated_at:
        raise LeaseStateConflict(
            "database activation timestamp differs from signed lease activation"
        )
    normalized_lease = model.canonical_payload()
    operations = normalized_lease["allowed_operations"]
    payload_json = canonical_json_text(normalized_lease)
    payload_sha = hashlib.sha256(payload_json.encode()).hexdigest()
    semantic_lease_sha = model.lease_sha256
    lease_id = model.lease_id
    row = conn.execute(
        """
        SELECT lease_json_sha256, lease_sha256, lease_json, status
        FROM sab_session_write_leases_v1
        WHERE lease_id = ?
        """,
        (lease_id,),
    ).fetchone()
    if row is not None:
        if (
            str(row[0]) != payload_sha
            or str(row[1]) != semantic_lease_sha
            or str(row[2]) != payload_json
        ):
            raise ImmutableConflict(
                f"lease {lease_id} already exists with different content"
            )
        if str(row[3]) != "active":
            raise LeaseStateConflict(f"lease {lease_id} is already {row[3]}")
        return json.loads(str(row[2]))
    operations_json = canonical_json_text(operations)
    conn.execute(
        """
        INSERT INTO sab_session_write_leases_v1
            (lease_id, scope, operations_json, operations_sha256,
             lease_json, lease_json_sha256, lease_sha256,
             status, activated_at, released_at)
        VALUES (?, 'Copy', ?, ?, ?, ?, ?, 'active', ?, NULL)
        """,
        (
            lease_id,
            operations_json,
            hashlib.sha256(operations_json.encode()).hexdigest(),
            payload_json,
            payload_sha,
            semantic_lease_sha,
            signed_activated_at,
        ),
    )
    return normalized_lease


def release_session_lease(
    conn: sqlite3.Connection,
    lease_id: str,
    *,
    terminal_status: str = "released",
    released_at: Optional[str] = None,
) -> Dict[str, Any]:
    require_copy_or_fixture_connection(conn)
    if terminal_status not in {"released", "expired", "revoked"}:
        raise LeaseStateConflict(f"invalid terminal lease status: {terminal_status}")
    row = conn.execute(
        "SELECT status, lease_json FROM sab_session_write_leases_v1 WHERE lease_id = ?",
        (lease_id,),
    ).fetchone()
    if row is None:
        raise LeaseStateConflict(f"unknown lease: {lease_id}")
    current = str(row[0])
    if current == terminal_status:
        return json.loads(str(row[1]))
    if current != "active":
        raise LeaseStateConflict(f"lease {lease_id} is already {current}")
    conn.execute(
        """
        UPDATE sab_session_write_leases_v1
        SET status = ?, released_at = ?
        WHERE lease_id = ? AND status = 'active'
        """,
        (terminal_status, released_at or utc_now_text(), lease_id),
    )
    return json.loads(str(row[1]))


def get_json_record(
    conn: sqlite3.Connection,
    *,
    table: str,
    id_column: str,
    json_column: str,
    object_id: str,
) -> Optional[Dict[str, Any]]:
    allowed = {
        ("sab_session_write_leases_v1", "lease_id", "lease_json"),
        ("sab_artifact_cases_v1", "case_id", "case_json"),
        ("sab_council_verdicts_v1", "verdict_id", "verdict_json"),
        (
            "sab_rehearsal_dispositions_v1",
            "disposition_id",
            "disposition_json",
        ),
    }
    if (table, id_column, json_column) not in allowed:
        raise ValueError("unsupported first-verdict record lookup")
    row = conn.execute(
        f"SELECT {json_column} FROM {table} WHERE {id_column} = ?", (object_id,)
    ).fetchone()
    return None if row is None else json.loads(str(row[0]))
