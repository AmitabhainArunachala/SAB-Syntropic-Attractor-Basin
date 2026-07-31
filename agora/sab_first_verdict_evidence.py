"""Read-only evidence and replay helpers for SAB First Verdict Build A.

The functions in this module deliberately separate evidence collection from
effect construction.  They can read an explicitly named SQLite database and
create an explicitly named private backup, but they never infer a database
path, overwrite a destination, or mutate the source.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections import Counter
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Sequence
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .sab_artifact_verdict import (
    MASTER_VISION_CHALLENGE_ID,
    MASTER_VISION_SEED_ID,
    MASTER_VISION_SIGNER,
    MasterVisionStateObservationV1,
    _seal_master_vision_observation,
    canonical_sha256 as contract_json_sha256,
)


GENESIS_HASH = "genesis"
GENERIC_PLACEHOLDER_RULE = "language_womb_generic_placeholder_v1"
GENERIC_CONTRIBUTION_TITLE = "Language Womb Grand Challenge Contribution"
GENERIC_CLAIM_TEMPLATE = (
    "{actor} observed source material relevant to claim/evidence/authority semantics "
    "and packaged it for SAB challenge."
)
DEFAULT_ACTOR_SLOTS = {
    "dharma_cron": "agent_dharma_cron",
    "hermes_m5": "agent_hermes_m5",
}
SQLITE_LIFECYCLE_ALGORITHM = "sqlite_lifecycle_v1"
SQLITE_LIFECYCLE_TABLES = (
    "sab_agent_identities_v1",
    "sab_challenge_packets_v1",
    "sab_seed_events_v1",
    "sab_seed_packets_v1",
    "sab_standing_events_v1",
    "sab_standing_leases_v1",
    "sab_witness_events_v1",
    "spark_challenges",
    "spark_witness_chain",
    "sparks",
)
_SQLITE_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class EvidenceValidationError(ValueError):
    """A fail-closed evidence validation error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def canonical_json_bytes(payload: Any) -> bytes:
    """Return canonical_json_v1 bytes.

    This is the checkpoint canonicalization from the Build A controller:
    sorted object keys, preserved array order, compact separators, literal
    non-ASCII UTF-8, and no trailing newline.
    """

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def file_sha256(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_path_ref(path: Path) -> str:
    resolved = str(path.resolve(strict=False))
    return f"private-local:sha256:{hashlib.sha256(resolved.encode()).hexdigest()}"


def _ro_sqlite_uri(path: Path) -> str:
    return f"file:{quote(str(path), safe='/')}?mode=ro"


def open_sqlite_readonly(path: Path | str) -> sqlite3.Connection:
    """Open an existing, non-symlink SQLite file in enforced read-only mode."""

    candidate = Path(path)
    if candidate.is_symlink():
        raise EvidenceValidationError(
            "source_symlink", "SQLite source must not be a symlink"
        )
    if not candidate.is_file():
        raise EvidenceValidationError(
            "source_missing", "SQLite source must be an existing file"
        )
    resolved = candidate.resolve(strict=True)
    conn = sqlite3.connect(_ro_sqlite_uri(resolved), uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def _validate_backup_paths(source: Path, destination: Path) -> tuple[Path, Path]:
    if source.is_symlink():
        raise EvidenceValidationError(
            "source_symlink", "SQLite source must not be a symlink"
        )
    if not source.is_file():
        raise EvidenceValidationError(
            "source_missing", "SQLite source must be an existing file"
        )
    if destination.is_symlink():
        raise EvidenceValidationError(
            "destination_symlink", "SQLite destination must not be a symlink"
        )
    resolved_source = source.resolve(strict=True)
    resolved_destination = destination.resolve(strict=False)
    if resolved_source == resolved_destination:
        raise EvidenceValidationError(
            "same_path", "SQLite source and destination resolve to the same path"
        )
    if destination.exists():
        raise EvidenceValidationError(
            "destination_exists", "SQLite backup destination already exists"
        )
    if not destination.parent.is_dir():
        raise EvidenceValidationError(
            "destination_parent_missing", "SQLite backup destination parent must exist"
        )
    if destination.parent.is_symlink():
        raise EvidenceValidationError(
            "destination_parent_symlink",
            "SQLite backup destination parent must not be a symlink",
        )
    if any(
        (parent / ".git").exists()
        for parent in (destination.parent, *destination.parents)
    ):
        raise EvidenceValidationError(
            "destination_inside_git",
            "SQLite backup destination must be outside a Git checkout",
        )

    return resolved_source, resolved_destination


def backup_database_readonly(
    source: Path | str,
    destination: Path | str,
) -> dict[str, Any]:
    """Create an exclusive, mode-0600 SQLite online backup from a mode=ro source.

    Both paths are mandatory.  Existing destinations, same-path resolutions,
    symlinks, and non-private result permissions fail closed.
    """

    source_path, destination_path = _validate_backup_paths(
        Path(source), Path(destination)
    )
    source_before = source_path.stat()
    source_sha_before = file_sha256(source_path)
    source_snapshot = snapshot_database(source_path)
    fd: int | None = None
    created = False
    try:
        fd = os.open(destination_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        created = True
        os.close(fd)
        fd = None
        with closing(open_sqlite_readonly(source_path)) as source_conn:
            with closing(sqlite3.connect(destination_path)) as destination_conn:
                source_conn.backup(destination_conn)
                destination_conn.commit()
        os.chmod(destination_path, 0o600)

        source_after = source_path.stat()
        source_sha_after = file_sha256(source_path)
        if (
            source_before.st_size != source_after.st_size
            or source_before.st_mtime_ns != source_after.st_mtime_ns
            or source_sha_before != source_sha_after
        ):
            raise EvidenceValidationError(
                "source_changed",
                "SQLite source identity changed during read-only backup",
            )
        permissions = stat.S_IMODE(destination_path.stat().st_mode)
        if permissions != 0o600:
            raise EvidenceValidationError(
                "copy_permissions",
                f"SQLite copy permissions are {oct(permissions)}, expected 0o600",
            )

        copy_snapshot = snapshot_database(destination_path)
        if copy_snapshot["integrity"] != "ok":
            raise EvidenceValidationError(
                "copy_integrity", "SQLite copy failed integrity_check"
            )
        logical_equivalence = {
            "schema_manifest": source_snapshot["schema_manifest"]["sha256"]
            == copy_snapshot["schema_manifest"]["sha256"],
            "preexisting_table_digests": source_snapshot["preexisting_table_digests"]
            == copy_snapshot["preexisting_table_digests"],
            "lifecycle_fingerprint": source_snapshot["lifecycle"]["sha256"]
            == copy_snapshot["lifecycle"]["sha256"],
        }
        if not all(logical_equivalence.values()):
            raise EvidenceValidationError(
                "copy_logical_mismatch",
                "SQLite online backup differs logically from source",
            )
        return {
            "schema_version": "sab.sqlite_online_backup_receipt.v1",
            "source": {
                "path_ref": _private_path_ref(source_path),
                "privacy_class": "private_local",
                "sha256": source_sha_before,
                "device": source_before.st_dev,
                "inode": source_before.st_ino,
                "size": source_before.st_size,
            },
            "destination": {
                "path_ref": _private_path_ref(destination_path),
                "privacy_class": "private_local",
                "sha256": copy_snapshot["database_sha256"],
                "permissions": "0600",
                "size": destination_path.stat().st_size,
            },
            "source_snapshot": source_snapshot,
            "copy_snapshot": copy_snapshot,
            "logical_equivalence": logical_equivalence,
            "source_unchanged": True,
            "backup_method": "sqlite_online_backup_from_mode_ro_source",
        }
    except Exception:
        if fd is not None:
            os.close(fd)
        if created and destination_path.exists():
            destination_path.unlink()
        raise


def _quote_identifier(identifier: str) -> str:
    """Return a quoted identifier after applying the Build A SQL allowlist.

    SQLite cannot bind table or column names as query parameters.  Restricting
    identifiers to this ASCII grammar excludes whitespace, quotes, comments,
    and every SQL metacharacter before any identifier reaches interpolation.
    """

    if not _SQLITE_IDENTIFIER.fullmatch(identifier):
        raise EvidenceValidationError(
            "unsafe_identifier",
            "SQLite identifiers must match [A-Za-z_][A-Za-z0-9_]*",
        )
    return f'"{identifier}"'


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        is not None
    )


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    quoted_table = _quote_identifier(table)
    return [
        str(row[1])
        for row in conn.execute(
            f"PRAGMA table_info({quoted_table})"
        ).fetchall()
    ]


def _typed_sql_value(value: Any) -> dict[str, Any]:
    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, bytes):
        return {"type": "blob", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {"type": "real", "value": value.hex()}
    return {"type": "text", "value": str(value)}


def table_content_digest(
    conn: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
) -> dict[str, Any]:
    """Digest a table over an explicit column set, independent of row order."""

    quoted_table = _quote_identifier(table)
    quoted_columns = [_quote_identifier(column) for column in columns]
    available = set(_table_columns(conn, table))
    if not columns or not set(columns).issubset(available):
        missing = sorted(set(columns) - available)
        raise EvidenceValidationError(
            "preexisting_columns_missing",
            f"{table} is missing pre-existing columns: {missing}",
        )
    select_columns = ",".join(quoted_columns)
    row_hashes = []
    # Identifiers are allowlisted and quoted above; SQLite cannot bind them.
    query = f"SELECT {select_columns} FROM {quoted_table}"  # nosec B608
    for row in conn.execute(query):
        encoded = [_typed_sql_value(value) for value in tuple(row)]
        row_hashes.append(canonical_sha256(encoded))
    row_hashes.sort()
    material = {"table": table, "columns": list(columns), "row_hashes": row_hashes}
    return {
        "columns": list(columns),
        "row_count": len(row_hashes),
        "sha256": canonical_sha256(material),
    }


def sqlite_lifecycle_table_digest(conn: sqlite3.Connection, table: str) -> str:
    """Reproduce A0's deterministic full-table content digest exactly."""

    quoted_table = _quote_identifier(table)
    columns = _table_columns(conn, table)
    # ``quoted_table`` passed the strict identifier allowlist above.
    query = f"SELECT * FROM {quoted_table} ORDER BY rowid"  # nosec B608
    rows = [
        [
            {"bytes_hex": value.hex()} if isinstance(value, bytes) else value
            for value in tuple(row)
        ]
        for row in conn.execute(query)
    ]
    return canonical_sha256({"columns": columns, "rows": rows})


def schema_manifest(conn: sqlite3.Connection) -> dict[str, Any]:
    tables: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    for row in rows:
        name = str(row["name"] if isinstance(row, sqlite3.Row) else row[0])
        sql = row["sql"] if isinstance(row, sqlite3.Row) else row[1]
        quoted_name = _quote_identifier(name)
        columns = []
        for column in conn.execute(f"PRAGMA table_info({quoted_name})"):
            columns.append(
                {
                    "cid": int(column[0]),
                    "name": str(column[1]),
                    "type": str(column[2]),
                    "not_null": bool(column[3]),
                    "default": column[4],
                    "primary_key_position": int(column[5]),
                }
            )
        tables.append(
            {
                "name": name,
                "sql_sha256": hashlib.sha256(str(sql or "").encode()).hexdigest(),
                "columns": columns,
            }
        )
    indexes = [
        {
            "name": str(row[0]),
            "table": str(row[1]),
            "sql_sha256": hashlib.sha256(str(row[2] or "").encode()).hexdigest(),
        }
        for row in conn.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master "
            "WHERE type='index' AND sql IS NOT NULL ORDER BY name"
        )
    ]
    material = {"tables": tables, "indexes": indexes}
    return {**material, "sha256": canonical_sha256(material)}


def capture_preexisting_table_digests(conn: sqlite3.Connection) -> dict[str, Any]:
    """Freeze each existing table's current columns and their content digest."""

    manifest = schema_manifest(conn)
    return {
        table["name"]: table_content_digest(
            conn,
            table["name"],
            [column["name"] for column in table["columns"]],
        )
        for table in manifest["tables"]
    }


def verify_preexisting_table_digests(
    conn: sqlite3.Connection,
    baseline: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Re-digest only frozen columns so additive migrations do not look like drift."""

    mismatches: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for table in sorted(baseline):
        if not _table_exists(conn, table):
            mismatches.append({"table": table, "reason": "table_missing"})
            continue
        expected = baseline[table]
        digest = table_content_digest(conn, table, list(expected["columns"]))
        current[table] = digest
        if (
            digest["row_count"] != expected["row_count"]
            or digest["sha256"] != expected["sha256"]
        ):
            mismatches.append(
                {
                    "table": table,
                    "reason": "content_drift",
                    "expected_sha256": expected["sha256"],
                    "actual_sha256": digest["sha256"],
                }
            )
    return {"verified": not mismatches, "mismatches": mismatches, "current": current}


def _authoritative_table(
    conn: sqlite3.Connection, candidates: Sequence[str]
) -> str | None:
    return next((table for table in candidates if _table_exists(conn, table)), None)


def _histogram(
    conn: sqlite3.Connection, table: str | None, column: str
) -> dict[str, int]:
    if table is None or column not in _table_columns(conn, table):
        return {}
    quoted_column = _quote_identifier(column)
    quoted_table = _quote_identifier(table)
    # Both identifiers are schema-checked, allowlisted, and quoted above.
    query = (
        f"SELECT {quoted_column}, COUNT(*) FROM {quoted_table} "  # nosec B608
        f"GROUP BY {quoted_column}"
    )
    rows = conn.execute(query).fetchall()
    return {str(row[0]): int(row[1]) for row in rows}


def _count(conn: sqlite3.Connection, table: str | None) -> int:
    if table is None:
        return 0
    quoted_table = _quote_identifier(table)
    # ``quoted_table`` passed the strict identifier allowlist above.
    query = f"SELECT COUNT(*) FROM {quoted_table}"  # nosec B608
    return int(conn.execute(query).fetchone()[0])


def witness_forest_heads(conn: sqlite3.Connection) -> dict[str, str]:
    table = _authoritative_table(conn, ("sab_witness_events_v1", "witness_events"))
    if table is None:
        return {}
    quoted_table = _quote_identifier(table)
    columns = set(_table_columns(conn, table))
    if {"chain_scope", "event_hash", "id"}.issubset(columns):
        # ``table`` came from the fixed authoritative-table candidates and was
        # schema-checked, allowlisted, and quoted above.
        query = (
            "SELECT outer_event.chain_scope, outer_event.event_hash "  # nosec B608
            f"FROM {quoted_table} outer_event "
            "WHERE outer_event.id=("
            f"SELECT MAX(inner_event.id) FROM {quoted_table} inner_event "
            "WHERE inner_event.chain_scope=outer_event.chain_scope) "
            "ORDER BY outer_event.chain_scope"
        )
        rows = conn.execute(
            query
        ).fetchall()
    elif {"subject_type", "subject_id", "event_hash", "id"}.issubset(columns):
        # Same fixed-candidate and identifier validation as the branch above.
        query = (
            "SELECT outer_event.subject_type || ':' || outer_event.subject_id AS scope, "  # nosec B608
            "outer_event.event_hash "
            f"FROM {quoted_table} outer_event "
            "WHERE outer_event.id=("
            f"SELECT MAX(inner_event.id) FROM {quoted_table} inner_event "
            "WHERE inner_event.subject_type=outer_event.subject_type "
            "AND inner_event.subject_id=outer_event.subject_id) ORDER BY scope"
        )
        rows = conn.execute(
            query
        ).fetchall()
    else:
        return {}
    return {str(row[0]): str(row[1]) for row in rows}


def _migration_ids(conn: sqlite3.Connection) -> list[str]:
    candidate_tables = (
        "sab_first_verdict_migrations",
        "sab_first_verdict_schema_migrations_v1",
        "sab_first_verdict_schema_migrations",
        "sab_schema_migrations",
        "schema_migrations",
    )
    identifiers: list[str] = []
    for table in candidate_tables:
        if not _table_exists(conn, table):
            continue
        columns = _table_columns(conn, table)
        id_column = next(
            (
                column
                for column in ("migration_id", "version", "id", "digest")
                if column in columns
            ),
            None,
        )
        if id_column:
            quoted_id_column = _quote_identifier(id_column)
            quoted_table = _quote_identifier(table)
            # Both values come from fixed candidates, are confirmed in the
            # schema, and pass the strict identifier allowlist.
            query = (
                f"SELECT {quoted_id_column} FROM {quoted_table} "  # nosec B608
                f"ORDER BY {quoted_id_column}"
            )
            identifiers.extend(
                f"{table}:{row[0]}"
                for row in conn.execute(query)
            )
    return identifiers


def _lifecycle_semantic_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    seed_table = _authoritative_table(conn, ("sab_seed_packets_v1", "seed_packets"))
    challenge_table = _authoritative_table(
        conn, ("sab_challenge_packets_v1", "challenge_packets")
    )
    witness_table = _authoritative_table(
        conn, ("sab_witness_events_v1", "witness_events")
    )
    standing_table = _authoritative_table(
        conn, ("sab_standing_leases_v1", "standing_leases")
    )
    seed_columns = set(_table_columns(conn, seed_table)) if seed_table else set()
    state_column = "state" if "state" in seed_columns else "status"
    packet_hash_column = (
        "packet_hash" if "packet_hash" in seed_columns else "seed_packet_sha256"
    )
    challenge_columns = (
        set(_table_columns(conn, challenge_table)) if challenge_table else set()
    )
    challenge_status = "status" if "status" in challenge_columns else "state"
    standing_columns = (
        set(_table_columns(conn, standing_table)) if standing_table else set()
    )
    standing_status = "status" if "status" in standing_columns else "state"

    seed_hashes: list[str] = []
    if seed_table and packet_hash_column in seed_columns:
        quoted_hash_column = _quote_identifier(packet_hash_column)
        quoted_seed_table = _quote_identifier(seed_table)
        # Both values are selected from fixed candidates, schema-checked, and
        # pass the strict identifier allowlist.
        query = (
            f"SELECT {quoted_hash_column} FROM {quoted_seed_table}"  # nosec B608
        )
        seed_hashes = sorted(
            str(row[0])
            for row in conn.execute(query)
        )
    heads = witness_forest_heads(conn)
    return {
        "seed_count": _count(conn, seed_table),
        "seed_state_histogram": _histogram(conn, seed_table, state_column),
        "challenge_count": _count(conn, challenge_table),
        "challenge_status_histogram": _histogram(
            conn, challenge_table, challenge_status
        ),
        "witness_event_count": _count(conn, witness_table),
        "standing_count": _count(conn, standing_table),
        "standing_status_histogram": _histogram(conn, standing_table, standing_status),
        "witness_forest_heads": heads,
        "witness_forest_sha256": canonical_sha256(heads),
        "seed_packet_hashes": seed_hashes,
        "migration_ids": _migration_ids(conn),
    }


def lifecycle_fingerprint(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the A0-frozen ``sqlite_lifecycle_v1`` fingerprint.

    Only lifecycle tables present in the database participate.  A0 hashes each
    table's schema-ordered columns and rowid-ordered full rows, then hashes the
    ordered name-to-content-digest mapping.  ``summary`` remains diagnostic and
    is deliberately outside the fingerprint material.
    """

    table_content_sha256 = {
        table: sqlite_lifecycle_table_digest(conn, table)
        for table in SQLITE_LIFECYCLE_TABLES
        if _table_exists(conn, table)
    }
    return {
        "algorithm": SQLITE_LIFECYCLE_ALGORITHM,
        "lifecycle_tables": list(table_content_sha256),
        "table_content_sha256": table_content_sha256,
        "material": table_content_sha256,
        "sha256": canonical_sha256(table_content_sha256),
        "summary": _lifecycle_semantic_summary(conn),
    }


def observe_master_vision_state(conn: sqlite3.Connection) -> Any:
    """Derive the exact Master Vision state witness from the opened database.

    This function is read-only.  API and lifecycle callers supply its result as
    an out-of-band evaluator input; request JSON cannot claim these states.
    """

    required_tables = (
        "sab_seed_packets_v1",
        "sab_challenge_packets_v1",
        "sab_witness_events_v1",
        "sab_seed_lineage_edges_v1",
        "sab_rehearsal_dispositions_v1",
        "sab_first_verdict_schema_migrations_v1",
        "web_agents",
    )
    missing = [table for table in required_tables if not _table_exists(conn, table)]
    if missing:
        raise EvidenceValidationError(
            "master_vision_state_tables_missing",
            "Master Vision state cannot be derived from this database",
        )
    # Absence of an effect ledger is not evidence of zero effects.  Require the
    # exact additive migration that creates the disposition and lineage ledgers
    # before their zero row counts can participate in the observation.
    from .sab_first_verdict_storage import MIGRATION_DIGEST, MIGRATION_ID

    migration_rows = conn.execute(
        "SELECT migration_digest FROM sab_first_verdict_schema_migrations_v1 "
        "WHERE migration_id = ?",
        (MIGRATION_ID,),
    ).fetchall()
    if len(migration_rows) != 1 or str(migration_rows[0][0]) != MIGRATION_DIGEST:
        raise EvidenceValidationError(
            "master_vision_effect_ledger_unproven",
            "Master Vision effect ledgers are not bound to the Build A migration",
        )
    seed_rows = conn.execute(
        """
        SELECT state, packet_json, packet_hash
        FROM sab_seed_packets_v1
        WHERE seed_id = ?
        """,
        (MASTER_VISION_SEED_ID,),
    ).fetchall()
    challenge_rows = conn.execute(
        """
        SELECT status, packet_json, packet_hash
        FROM sab_challenge_packets_v1
        WHERE challenge_id = ? AND target_seed_id = ?
        """,
        (MASTER_VISION_CHALLENGE_ID, MASTER_VISION_SEED_ID),
    ).fetchall()
    agent_rows = conn.execute(
        "SELECT public_key FROM web_agents WHERE id = ?",
        (MASTER_VISION_SIGNER,),
    ).fetchall()
    if len(seed_rows) != 1 or len(challenge_rows) != 1 or len(agent_rows) != 1:
        raise EvidenceValidationError(
            "master_vision_state_row_ambiguity",
            "Master Vision state rows are missing or ambiguous",
        )
    seed_state, seed_json, seed_packet_sha256 = seed_rows[0]
    challenge_state, challenge_json, challenge_packet_sha256 = challenge_rows[0]
    try:
        seed_packet = json.loads(str(seed_json))
        challenge_packet = json.loads(str(challenge_json))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(
            "master_vision_state_packet_invalid",
            "Master Vision database packet JSON is invalid",
        ) from exc
    if not isinstance(seed_packet, Mapping) or not isinstance(
        challenge_packet, Mapping
    ):
        raise EvidenceValidationError(
            "master_vision_state_packet_invalid",
            "Master Vision database packets must be objects",
        )
    witness_events = [
        {
            "event_id": str(row[0]),
            "event_type": str(row[1]),
            "event_hash": str(row[2]),
        }
        for row in conn.execute(
            """
            SELECT event_id, event_type, event_hash
            FROM sab_witness_events_v1
            WHERE subject_seed_id = ?
            ORDER BY event_id
            """,
            (MASTER_VISION_SEED_ID,),
        ).fetchall()
    ]
    witness_event_types = tuple(
        sorted({event["event_type"] for event in witness_events})
    )

    # These proof obligations are fixed by the Master Vision observation
    # schema.  Keep their SQL static and bind only the seed value.
    supersession_edge_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM sab_seed_lineage_edges_v1 "
            "WHERE predecessor_seed_id = ? OR successor_seed_id = ?",
            (MASTER_VISION_SEED_ID, MASTER_VISION_SEED_ID),
        ).fetchone()[0]
    )
    effective_disposition_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM sab_rehearsal_dispositions_v1 "
            "WHERE target_artifact_id = ?",
            (MASTER_VISION_SEED_ID,),
        ).fetchone()[0]
    )

    observation = {
        "schema": "sab.master_vision_state_observation.v1",
        "proof_class": "attested_copied_database_observation",
        "database_lifecycle_fingerprint": lifecycle_fingerprint(conn)["sha256"],
        "seed_id": MASTER_VISION_SEED_ID,
        "seed_state": str(seed_state),
        "seed_packet_sha256": str(seed_packet_sha256),
        "seed_packet_json_sha256": contract_json_sha256(seed_packet),
        "challenge_id": MASTER_VISION_CHALLENGE_ID,
        "challenge_state": str(challenge_state),
        "challenge_packet_sha256": str(challenge_packet_sha256),
        "challenge_packet_json_sha256": contract_json_sha256(challenge_packet),
        "signer": MASTER_VISION_SIGNER,
        "signer_public_key": str(agent_rows[0][0]),
        "witness_event_count": len(witness_events),
        "witness_event_types": witness_event_types,
        "witness_event_chain_sha256": contract_json_sha256(witness_events),
        "terminal_witness_count": sum(
            event["event_type"] not in {"submit", "challenge"}
            for event in witness_events
        ),
        "supersession_edge_count": supersession_edge_count,
        "effective_disposition_count": effective_disposition_count,
    }
    observation["observed_state_hash"] = contract_json_sha256(observation)
    try:
        validated = MasterVisionStateObservationV1.model_validate(observation)
    except ValidationError as exc:
        raise EvidenceValidationError(
            "master_vision_state_not_frozen",
            "Master Vision state differs from the signed challenged/pending prefix",
        ) from exc
    return _seal_master_vision_observation(validated)


def snapshot_connection(conn: sqlite3.Connection) -> dict[str, Any]:
    integrity_rows = [
        str(row[0]) for row in conn.execute("PRAGMA integrity_check").fetchall()
    ]
    manifest = schema_manifest(conn)
    table_digests = capture_preexisting_table_digests(conn)
    lifecycle = lifecycle_fingerprint(conn)
    agent_counts = {
        table: _count(conn, table)
        for table in ("sab_agent_identities_v1", "agent_identities", "web_agents")
        if _table_exists(conn, table)
    }
    return {
        "integrity": "ok" if integrity_rows == ["ok"] else "failed",
        "integrity_rows": integrity_rows,
        "schema_manifest": manifest,
        "preexisting_table_digests": table_digests,
        "agent_table_counts": agent_counts,
        "lifecycle": lifecycle,
    }


def snapshot_database(path: Path | str) -> dict[str, Any]:
    candidate = Path(path)
    with closing(open_sqlite_readonly(candidate)) as conn:
        snapshot = snapshot_connection(conn)
    file_stat = candidate.resolve(strict=True).stat()
    return {
        "schema_version": "sab.database_snapshot.v1",
        "path_ref": _private_path_ref(candidate),
        "privacy_class": "private_local",
        "database_sha256": file_sha256(candidate),
        "size": file_stat.st_size,
        **snapshot,
    }


def verify_database_snapshot(
    path: Path | str, expected: Mapping[str, Any]
) -> dict[str, Any]:
    actual = snapshot_database(path)
    comparisons = {
        "database_sha256": actual["database_sha256"] == expected.get("database_sha256"),
        "integrity": actual["integrity"] == "ok" == expected.get("integrity"),
        "schema_manifest": actual["schema_manifest"]["sha256"]
        == expected.get("schema_manifest", {}).get("sha256"),
        "lifecycle_fingerprint": actual["lifecycle"]["sha256"]
        == expected.get("lifecycle", {}).get("sha256"),
    }
    with closing(open_sqlite_readonly(path)) as conn:
        table_verification = verify_preexisting_table_digests(
            conn, expected.get("preexisting_table_digests", {})
        )
    comparisons["preexisting_table_digests"] = table_verification["verified"]
    return {
        "verified": all(comparisons.values()),
        "comparisons": comparisons,
        "actual": actual,
        "table_verification": table_verification,
    }


def _relation_count(
    conn: sqlite3.Connection,
    candidates: Sequence[tuple[str, str]],
    seed_id: str,
) -> int:
    count = 0
    for table, column in candidates:
        if _table_exists(conn, table) and column in _table_columns(conn, table):
            quoted_table = _quote_identifier(table)
            quoted_column = _quote_identifier(column)
            # Candidates are caller-owned fixed tuples; both identifiers are
            # also schema-checked, allowlisted, and quoted above.
            query = (
                f"SELECT COUNT(*) FROM {quoted_table} "  # nosec B608
                f"WHERE {quoted_column}=?"
            )
            count += int(
                conn.execute(
                    query,
                    (seed_id,),
                ).fetchone()[0]
            )
    return count


def _seed_witness_heads(conn: sqlite3.Connection, seed_id: str) -> dict[str, str]:
    if not _table_exists(conn, "sab_witness_events_v1"):
        return {}
    rows = conn.execute(
        "SELECT chain_scope, event_hash FROM sab_witness_events_v1 outer_event "
        "WHERE subject_seed_id=? AND id=(SELECT MAX(id) FROM sab_witness_events_v1 inner_event "
        "WHERE inner_event.chain_scope=outer_event.chain_scope) ORDER BY chain_scope",
        (seed_id,),
    ).fetchall()
    return {str(row[0]): str(row[1]) for row in rows}


def _preview_actor_label(actor: str | None) -> str:
    if actor == "agent_hermes_m5":
        return "Hermes"
    if actor == "agent_dharma_cron":
        return "Dharma-cron"
    return "other"


def _normalized_evidence_refs(
    evidence_bundle: Any,
    *,
    seed_id: str,
    packet_hash: str,
) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    if isinstance(evidence_bundle, list):
        for ordinal, raw in enumerate(evidence_bundle):
            item = raw if isinstance(raw, Mapping) else {"value": raw}
            raw_digest = str(item.get("digest", ""))
            if raw_digest.startswith("sha256:"):
                raw_digest = raw_digest.removeprefix("sha256:")
            content_sha256 = (
                raw_digest
                if len(raw_digest) == 64
                and all(character in "0123456789abcdef" for character in raw_digest)
                else canonical_sha256(item)
            )
            ref = str(item.get("ref") or f"database-row:{seed_id}:evidence:{ordinal}")
            refs.append(
                {
                    "ref": ref,
                    "content_sha256": content_sha256,
                    "proof_class": "referenced_source_unverified",
                }
            )
    if not refs:
        content_sha256 = (
            packet_hash
            if len(packet_hash) == 64
            else hashlib.sha256(packet_hash.encode()).hexdigest()
        )
        refs.append(
            {
                "ref": f"database-row:{seed_id}",
                "content_sha256": content_sha256,
                "proof_class": "database_row_hash_linked",
            }
        )
    return refs


def preview_language_womb_generic_placeholders(
    conn: sqlite3.Connection,
    *,
    actor_slots: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Evaluate the exact 67-record generic-wrapper predicate without writes."""

    actor_slots = dict(actor_slots or DEFAULT_ACTOR_SLOTS)
    if not actor_slots or any(
        not slot or not actor for slot, actor in actor_slots.items()
    ):
        raise EvidenceValidationError(
            "actor_slots", "actor_slots must be explicit and non-empty"
        )
    if not _table_exists(conn, "sab_seed_packets_v1"):
        raise EvidenceValidationError(
            "seed_table_missing",
            "sab_seed_packets_v1 is required for the frozen preview",
        )

    challenge_relations = (("sab_challenge_packets_v1", "target_seed_id"),)
    standing_relations = (("sab_standing_leases_v1", "subject_seed_id"),)
    verdict_relations = (
        ("sab_council_verdicts_v1", "subject_seed_id"),
        ("sab_council_verdicts_v1", "target_seed_id"),
        ("sab_rehearsal_dispositions_v1", "subject_seed_id"),
        ("sab_rehearsal_dispositions_v1", "target_seed_id"),
        ("sab_effective_verdicts_v1", "subject_seed_id"),
        ("sab_effective_verdicts_v1", "target_seed_id"),
        ("sab_artifact_verdicts_v1", "artifact_seed_id"),
        ("sab_artifact_verdicts_v1", "target_seed_id"),
    )
    lineage_relations = (
        ("sab_seed_lineage_edges_v1", "predecessor_seed_id"),
        ("sab_seed_lineage_edges_v1", "successor_seed_id"),
    )

    rows = conn.execute(
        "SELECT seed_id, title, state, packet_json, packet_hash "
        "FROM sab_seed_packets_v1 ORDER BY seed_id"
    ).fetchall()
    eligible: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for row in rows:
        seed_id = str(row["seed_id"])
        packet_hash = str(row["packet_hash"])
        reasons: list[str] = []
        matching_slots = [
            (slot, actor)
            for slot, actor in sorted(actor_slots.items())
            if seed_id.startswith(f"sab_seed_language_womb_agent_{slot}_")
        ]
        actor_slot, actor = (
            matching_slots[0] if len(matching_slots) == 1 else (None, None)
        )
        if actor is None:
            reasons.append("seed_id_not_in_actor_slots")
        if str(row["state"]) != "pending_seed":
            reasons.append("state_not_pending_seed")
        if str(row["title"]) != GENERIC_CONTRIBUTION_TITLE:
            reasons.append("title_not_exact_generic_contribution_title")
        try:
            packet = json.loads(str(row["packet_json"]))
            if not isinstance(packet, dict):
                raise ValueError("packet is not an object")
        except (TypeError, ValueError, json.JSONDecodeError):
            packet = {}
            reasons.append("packet_json_invalid")
        claim = packet.get("claim") if isinstance(packet.get("claim"), dict) else {}
        expected_claim = GENERIC_CLAIM_TEMPLATE.format(actor=actor) if actor else None
        if expected_claim is None or claim.get("text") != expected_claim:
            reasons.append("claim_text_not_exact_actor_parameterized_template")
        challenge_count = _relation_count(conn, challenge_relations, seed_id)
        standing_count = _relation_count(conn, standing_relations, seed_id)
        verdict_count = _relation_count(conn, verdict_relations, seed_id)
        lineage_count = _relation_count(conn, lineage_relations, seed_id)
        if challenge_count:
            reasons.append("challenge_exists")
        if standing_count:
            reasons.append("standing_exists")
        if verdict_count:
            reasons.append("effective_verdict_exists")
        if lineage_count:
            reasons.append("lineage_edge_exists")
        evidence_bundle = packet.get("evidence_bundle", [])
        if not isinstance(evidence_bundle, list):
            evidence_bundle = []
        evidence_refs = _normalized_evidence_refs(
            evidence_bundle,
            seed_id=seed_id,
            packet_hash=packet_hash,
        )
        row_sha256 = canonical_sha256(
            {
                "seed_id": seed_id,
                "title": row["title"],
                "state": row["state"],
                "packet_json": row["packet_json"],
                "packet_hash": packet_hash,
            }
        )
        record = {
            "record_id": seed_id,
            "actor_slot": _preview_actor_label(actor),
            "eligible": not reasons,
            "evidence_refs": evidence_refs,
            "exclusion_reason": ";".join(reasons) if reasons else None,
            "row_sha256": row_sha256,
        }
        records.append(record)
        detail = {
            "seed_id": seed_id,
            "packet_hash": packet_hash,
            "state": str(row["state"]),
            "actor_slot": record["actor_slot"],
            "actor_identity": actor,
            "witness_heads": _seed_witness_heads(conn, seed_id),
            "evidence_bundle": evidence_bundle,
            "evidence_refs": evidence_refs,
            "evidence_reference_count": len(evidence_bundle),
            "row_sha256": row_sha256,
        }
        if reasons:
            excluded.append({**detail, "reasons": reasons})
        else:
            eligible.append(detail)

    actor_counts = dict(
        sorted(Counter(item["actor_identity"] for item in eligible).items())
    )
    lifecycle = lifecycle_fingerprint(conn)
    rule = {
        "schema_version": "sab.compost_preview_rule.v1",
        "rule_id": GENERIC_PLACEHOLDER_RULE,
        "actor_slots": dict(sorted(actor_slots.items())),
        "title": GENERIC_CONTRIBUTION_TITLE,
        "claim_template": GENERIC_CLAIM_TEMPLATE,
        "required_state": "pending_seed",
        "requires_no_challenge": True,
        "requires_no_standing": True,
        "requires_no_effective_verdict": True,
        "requires_no_lineage_edge": True,
    }
    preserved_evidence_refs = [
        {"record_id": record["record_id"], "evidence_refs": record["evidence_refs"]}
        for record in records
    ]
    membership = [item["seed_id"] for item in eligible]
    rule_sha256 = canonical_sha256(rule)
    return {
        "schema": "sab.compost_batch_preview.v1",
        "schema_version": "sab.compost_batch_preview.v1",
        "preview_id": f"sab_preview_{rule_sha256[:24]}",
        "rule": rule,
        "rule_sha256": rule_sha256,
        "scanned_count": len(rows),
        "hermes_count": actor_counts.get("agent_hermes_m5", 0),
        "dharma_cron_count": actor_counts.get("agent_dharma_cron", 0),
        "selected_count": len(eligible),
        "eligible_count": len(eligible),
        "actor_counts": actor_counts,
        "actor_slot_parameterized": True,
        "records": records,
        "eligible": eligible,
        "excluded": excluded,
        "excluded_count": len(excluded),
        "evidence_reference_count": sum(
            item["evidence_reference_count"] for item in eligible
        ),
        "membership_sha256": canonical_sha256(membership),
        "evidence_refs_sha256": canonical_sha256(preserved_evidence_refs),
        "lifecycle_fingerprint": lifecycle["sha256"],
        "manifest_sha256": canonical_sha256(eligible),
        "transition_count": 0,
        "standing_effect": "none",
        "execution_supported": False,
    }


def preview_database_readonly(
    path: Path | str,
    *,
    actor_slots: Mapping[str, str] | None = None,
    expected_file_identity: tuple[int, int] | None = None,
    expected_lifecycle_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Run the preview through mode=ro and attach a file/head/fingerprint proof."""

    requested = Path(path)
    if requested.is_symlink():
        raise EvidenceValidationError(
            "preview_database_symlink",
            "read-only preview database must not be a symlink",
        )
    candidate = requested.resolve(strict=True)
    before_stat = candidate.stat()
    if (
        expected_file_identity is not None
        and (
            before_stat.st_dev,
            before_stat.st_ino,
        )
        != expected_file_identity
    ):
        raise EvidenceValidationError(
            "preview_database_identity_mismatch",
            "read-only preview database identity differs from its runtime binding",
        )
    before_sha = file_sha256(candidate)
    with closing(open_sqlite_readonly(candidate)) as conn:
        before_lifecycle = lifecycle_fingerprint(conn)
        if (
            expected_lifecycle_fingerprint is not None
            and before_lifecycle["sha256"] != expected_lifecycle_fingerprint
        ):
            raise EvidenceValidationError(
                "preview_database_lifecycle_mismatch",
                "read-only preview database lifecycle differs from its attestation",
            )
        before_heads = witness_forest_heads(conn)
        preview = preview_language_womb_generic_placeholders(
            conn, actor_slots=actor_slots
        )
        after_lifecycle = lifecycle_fingerprint(conn)
        after_heads = witness_forest_heads(conn)
    if requested.is_symlink():
        raise EvidenceValidationError(
            "preview_database_replaced",
            "read-only preview database became a symlink during evaluation",
        )
    after_stat = candidate.stat()
    after_sha = file_sha256(candidate)
    proof = {
        "file_sha256_unchanged": before_sha == after_sha,
        "file_size_unchanged": before_stat.st_size == after_stat.st_size,
        "file_mtime_unchanged": before_stat.st_mtime_ns == after_stat.st_mtime_ns,
        "file_identity_unchanged": (
            before_stat.st_dev == after_stat.st_dev
            and before_stat.st_ino == after_stat.st_ino
        ),
        "witness_heads_unchanged": before_heads == after_heads,
        "lifecycle_fingerprint_unchanged": before_lifecycle["sha256"]
        == after_lifecycle["sha256"],
    }
    if not all(proof.values()):
        raise EvidenceValidationError(
            "preview_wrote_state", "read-only preview changed evidence"
        )
    preview["no_write_proof"] = proof
    preview["no_write"] = True
    preview.update(
        {
            "before_database_sha256": before_sha,
            "after_database_sha256": after_sha,
            "before_lifecycle_fingerprint": before_lifecycle["sha256"],
            "after_lifecycle_fingerprint": after_lifecycle["sha256"],
            "before_head_sha256": canonical_sha256(before_heads),
            "after_head_sha256": canonical_sha256(after_heads),
            "before_file_mtime_ns": before_stat.st_mtime_ns,
            "after_file_mtime_ns": after_stat.st_mtime_ns,
            "mutation_count": 0,
        }
    )
    return preview


def preview_contract_payload(preview: Mapping[str, Any]) -> dict[str, Any]:
    """Project a full evidence report into strict ``CompostBatchPreviewV1`` fields."""

    fields = (
        "schema",
        "preview_id",
        "scanned_count",
        "hermes_count",
        "dharma_cron_count",
        "selected_count",
        "excluded_count",
        "actor_slot_parameterized",
        "records",
        "before_database_sha256",
        "after_database_sha256",
        "before_lifecycle_fingerprint",
        "after_lifecycle_fingerprint",
        "before_head_sha256",
        "after_head_sha256",
        "before_file_mtime_ns",
        "after_file_mtime_ns",
        "execution_supported",
        "mutation_count",
    )
    missing = [field for field in fields if field not in preview]
    if missing:
        raise EvidenceValidationError(
            "preview_contract_fields_missing",
            f"preview is missing contract fields: {missing}",
        )
    # Lazy import keeps the lower evidence helpers independent during package
    # development while making the final API projection fail closed against
    # A2's authoritative strict contract after integration.
    from .sab_artifact_verdict import CompostBatchPreviewV1

    model = CompostBatchPreviewV1.model_validate(
        {field: preview[field] for field in fields}
    )
    return model.model_dump(mode="json", by_alias=True)


def checkpoint_sha256(checkpoint: Mapping[str, Any]) -> str:
    unsigned = {
        key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"
    }
    return canonical_sha256(unsigned)


class _CheckpointModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _CheckpointArtifactRef(_CheckpointModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_class: str


class _CheckpointDatabaseRef(_CheckpointModel):
    present: bool
    path_ref: str | None
    sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    integrity: Literal["ok", "failed", "not_checked", "not_present"]
    lifecycle_fingerprint: str | None = Field(pattern=r"^[0-9a-f]{64}$")


class _CheckpointAcceptedBase(_CheckpointModel):
    repo: str
    source_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_tree_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    integration_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    integration_tree_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class _CheckpointWorktree(_CheckpointModel):
    path: str
    branch: str
    head: str = Field(pattern=r"^[0-9a-f]{40}$")
    tree_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    porcelain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _CheckpointAuthority(_CheckpointModel):
    implementation: Literal["authorized_local_build_a"]
    live_effects: Literal["forbidden"]
    authority_refs: tuple[str, ...]

    @field_validator("authority_refs")
    @classmethod
    def unique_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("authority_refs must be unique")
        return value


class _CheckpointDispositionEvaluation(_CheckpointModel):
    case_ref: str = Field(min_length=1)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result: Literal["AuthorizedCopyOnly", "AdvisoryOnly", "NoJurisdiction"]
    scope: Literal["Copy", "Live", "All"]
    authority_refs: tuple[str, ...]
    authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_effects: tuple[str, ...]
    forbidden_effects: tuple[str, ...]
    evaluated_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_artifact: _CheckpointArtifactRef

    @field_validator("authority_refs", "allowed_effects", "forbidden_effects")
    @classmethod
    def unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("checkpoint disposition values must be unique")
        return value


class _CheckpointTestResult(_CheckpointModel):
    command: str
    exit_code: int
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_class: str | None = None


class _CheckpointMutationCounters(_CheckpointModel):
    live_db: Literal[0]
    services: Literal[0]
    providers: Literal[0]
    external: Literal[0]
    source_checkout: Literal[0]
    fixture_or_copy_db: int = Field(default=0, ge=0)


class _CheckpointBlocker(_CheckpointModel):
    code: str
    evidence: tuple[_CheckpointArtifactRef, ...]
    next_safe_action: str


class BuildACheckpointV1(_CheckpointModel):
    """Strict local mirror of the controlling CHECKPOINT_SCHEMA.json."""

    schema_version: Literal["sab.build_a_checkpoint.v1"]
    run_id: str = Field(min_length=1)
    native_goal_id: str | None
    checkpoint_seq: int = Field(ge=0)
    checkpoint_id: str = Field(min_length=1)
    dag_node: Literal[
        "G0",
        "A0",
        "A1",
        "A2",
        "A3",
        "A4",
        "A5",
        "A6",
        "A7",
        "C0",
        "C1",
        "C4",
        "D0",
        "I0",
        "CLOSEOUT",
    ]
    status: Literal["pending", "running", "passed", "failed", "blocked", "skipped"]
    started_at: datetime
    completed_at: datetime | None
    accepted_base: _CheckpointAcceptedBase
    worktree: _CheckpointWorktree
    authority: _CheckpointAuthority
    disposition_evaluations: tuple[_CheckpointDispositionEvaluation, ...]
    source_db: _CheckpointDatabaseRef
    copy_db: _CheckpointDatabaseRef
    inputs: tuple[_CheckpointArtifactRef, ...]
    outputs: tuple[_CheckpointArtifactRef, ...]
    tests: tuple[_CheckpointTestResult, ...]
    commit_sha: str | None = Field(pattern=r"^[0-9a-f]{40}$")
    mutation_counters: _CheckpointMutationCounters
    blockers: tuple[_CheckpointBlocker, ...]
    next_dag_nodes: tuple[str, ...]
    next_safe_action: str = Field(min_length=1)
    previous_checkpoint_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("started_at", "completed_at")
    @classmethod
    def timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("checkpoint timestamps must be timezone-aware")
        return value

    @field_validator("next_dag_nodes")
    @classmethod
    def unique_next_nodes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("next_dag_nodes must be unique")
        return value


def validate_checkpoint_schema(checkpoint: Mapping[str, Any]) -> None:
    """Validate one checkpoint without relying on an optional JSON Schema CLI."""

    try:
        BuildACheckpointV1.model_validate(checkpoint)
    except ValidationError as exc:
        raise EvidenceValidationError(
            "checkpoint_schema_invalid",
            "checkpoint does not conform to CHECKPOINT_SCHEMA.json",
        ) from exc


def seal_checkpoint(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    sealed = dict(checkpoint)
    sealed["checkpoint_sha256"] = checkpoint_sha256(sealed)
    return sealed


def _validate_database_ref(
    database: Any,
    label: str,
    *,
    allow_unchecked: bool = False,
) -> None:
    if not isinstance(database, Mapping):
        raise EvidenceValidationError(
            "database_ref_missing", f"{label} database ref is missing"
        )
    if database.get("present"):
        if not database.get("sha256"):
            raise EvidenceValidationError(
                "database_hash_missing", f"{label} SHA-256 is missing"
            )
        integrity = database.get("integrity")
        if integrity == "failed" or (not allow_unchecked and integrity != "ok"):
            raise EvidenceValidationError(
                "database_integrity_failed", f"{label} integrity is not ok"
            )
        if not allow_unchecked and not database.get("lifecycle_fingerprint"):
            raise EvidenceValidationError(
                "lifecycle_fingerprint_missing",
                f"{label} lifecycle fingerprint is missing",
            )


def validate_checkpoint_chain(
    checkpoints: Iterable[Mapping[str, Any]],
    *,
    expected_head: str | None = None,
    expected_tree_sha: str | None = None,
    expected_database_sha256: str | None = None,
    expected_lifecycle_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Validate checkpoint hashes plus semantic resume invariants.

    JSON Schema validation is intentionally not treated as chain validation;
    callers may perform both.  Current-state expectations bind the final
    checkpoint and detect stale resume evidence.
    """

    chain = list(checkpoints)
    if not chain:
        raise EvidenceValidationError("empty_chain", "checkpoint chain is empty")
    previous_hash: str | None = None
    run_id: str | None = None
    accepted_base: Any = None
    checkpoint_ids: set[str] = set()
    for index, checkpoint in enumerate(chain):
        raw_counters = checkpoint.get("mutation_counters")
        if isinstance(raw_counters, Mapping):
            for counter in (
                "live_db",
                "services",
                "providers",
                "external",
                "source_checkout",
            ):
                if counter in raw_counters and raw_counters[counter] != 0:
                    raise EvidenceValidationError(
                        "forbidden_mutation_recorded",
                        f"checkpoint records nonzero {counter} effects",
                    )
        validate_checkpoint_schema(checkpoint)
        if int(checkpoint.get("checkpoint_seq", -1)) != index:
            raise EvidenceValidationError(
                "non_monotonic_sequence",
                "checkpoint_seq must start at zero and increase by one",
            )
        if index == 0:
            if (
                checkpoint.get("dag_node") != "G0"
                or checkpoint.get("previous_checkpoint_sha256") is not None
            ):
                raise EvidenceValidationError(
                    "invalid_genesis",
                    "checkpoint zero must be G0 with a null predecessor",
                )
            run_id = str(checkpoint.get("run_id", ""))
            accepted_base = checkpoint.get("accepted_base")
        else:
            if checkpoint.get("previous_checkpoint_sha256") != previous_hash:
                raise EvidenceValidationError(
                    "broken_predecessor",
                    "checkpoint predecessor does not match prior digest",
                )
            if (
                checkpoint.get("run_id") != run_id
                or checkpoint.get("accepted_base") != accepted_base
            ):
                raise EvidenceValidationError(
                    "chain_identity_changed",
                    "run_id or accepted base changed within chain",
                )
        actual_hash = checkpoint_sha256(checkpoint)
        if checkpoint.get("checkpoint_sha256") != actual_hash:
            raise EvidenceValidationError(
                "checkpoint_hash_mismatch",
                "checkpoint canonical digest does not match payload",
            )
        checkpoint_id = str(checkpoint.get("checkpoint_id", ""))
        if not checkpoint_id or checkpoint_id in checkpoint_ids:
            raise EvidenceValidationError(
                "checkpoint_id_invalid",
                "checkpoint IDs must be non-empty and unique",
            )
        checkpoint_ids.add(checkpoint_id)
        next_action = checkpoint.get("next_safe_action")
        if not isinstance(next_action, str) or not next_action.strip():
            raise EvidenceValidationError(
                "next_safe_action_missing",
                "checkpoint must name exactly one non-empty next action",
            )
        _validate_database_ref(
            checkpoint.get("source_db"), "source", allow_unchecked=index == 0
        )
        _validate_database_ref(
            checkpoint.get("copy_db"), "copy", allow_unchecked=index == 0
        )
        if index > 0 and not checkpoint["copy_db"].get("present"):
            raise EvidenceValidationError(
                "copy_database_missing",
                "post-G0 checkpoints require copied-database evidence",
            )
        mutation_counters = checkpoint.get("mutation_counters")
        if not isinstance(mutation_counters, Mapping):
            raise EvidenceValidationError(
                "mutation_counters_missing",
                "checkpoint mutation counters are missing",
            )
        for counter in (
            "live_db",
            "services",
            "providers",
            "external",
            "source_checkout",
        ):
            if mutation_counters.get(counter) != 0:
                raise EvidenceValidationError(
                    "forbidden_mutation_recorded",
                    f"checkpoint records nonzero {counter} effects",
                )
        previous_hash = actual_hash

    final = chain[-1]
    worktree = final.get("worktree")
    if not isinstance(worktree, Mapping):
        raise EvidenceValidationError(
            "worktree_ref_missing", "final worktree ref is missing"
        )
    if expected_head is not None and worktree.get("head") != expected_head:
        raise EvidenceValidationError(
            "head_mismatch", "current HEAD differs from checkpoint"
        )
    if expected_tree_sha is not None and worktree.get("tree_sha") != expected_tree_sha:
        raise EvidenceValidationError(
            "tree_mismatch", "current tree differs from checkpoint"
        )
    copy_ref = final.get("copy_db")
    if expected_database_sha256 is not None and (
        not isinstance(copy_ref, Mapping)
        or copy_ref.get("sha256") != expected_database_sha256
    ):
        raise EvidenceValidationError(
            "database_hash_mismatch", "current copied database differs from checkpoint"
        )
    if expected_lifecycle_fingerprint is not None and (
        not isinstance(copy_ref, Mapping)
        or copy_ref.get("lifecycle_fingerprint") != expected_lifecycle_fingerprint
    ):
        raise EvidenceValidationError(
            "lifecycle_fingerprint_changed",
            "current lifecycle fingerprint differs from checkpoint",
        )
    return {
        "valid": True,
        "checkpoint_count": len(chain),
        "run_id": run_id,
        "head_checkpoint_sha256": previous_hash,
        "last_dag_node": final.get("dag_node"),
    }
