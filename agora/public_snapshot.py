"""Explicit whole-record publication and pinned, frozen public SQLite reads.

Publication approval binds every admitted SQL value and the complete selected
seed closure. It grants publication only, never truth, identity, authority or
standing. A fresh database is built from fixed schemas; a private database is
never copied and pruned. The public reader never reopens a source database.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Iterator
from urllib.parse import urlsplit

POLICY_ID = "whole-record-publication-v1"
SNAPSHOT_FILENAME = "snapshot.sqlite3"
MANIFEST_FILENAME = "manifest.json"
MANIFEST_SCHEMA = "sab.public_snapshot.v1"
REVIEW_SCHEMA = "sab.public_snapshot_review.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HAS_SQLITE_SERIALIZATION = hasattr(sqlite3.Connection, "serialize") and hasattr(
    sqlite3.Connection, "deserialize"
)


class PublicSnapshotError(ValueError):
    """A failed publication or frozen-source check, with a safe public code."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(detail)


@dataclass(frozen=True)
class _Table:
    key: str
    columns: tuple[tuple[str, str], ...]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.columns)


_ID = (("id", "INTEGER PRIMARY KEY"),)
_TEXT = "TEXT NOT NULL"
TABLES: dict[str, _Table] = {
    "sab_agent_identities_v1": _Table(
        "subject_id",
        (
            ("subject_id", "TEXT PRIMARY KEY"),
            ("display_name", _TEXT),
            ("public_key", _TEXT),
            ("controller", _TEXT),
            ("operator_id", _TEXT),
            ("operator_backing_json", _TEXT),
            ("identity_json", _TEXT),
            ("created_at", _TEXT),
            ("updated_at", _TEXT),
        ),
    ),
    "sab_seed_packets_v1": _Table(
        "seed_id",
        _ID
        + (
            ("seed_id", "TEXT NOT NULL UNIQUE"),
            ("seed_type", _TEXT),
            ("title", _TEXT),
            ("claim_id", _TEXT),
            ("claimant_identity", _TEXT),
            ("authority_lease_id", _TEXT),
            ("state", _TEXT),
            ("packet_json", _TEXT),
            ("packet_hash", _TEXT),
            ("spark_projection_id", "INTEGER"),
            ("challenge_window_closes_at", "TEXT"),
            ("created_at", _TEXT),
            ("updated_at", _TEXT),
        ),
    ),
    "sab_seed_events_v1": _Table(
        "event_id",
        _ID
        + (
            ("event_id", "TEXT NOT NULL UNIQUE"),
            ("seed_id", _TEXT),
            ("actor_identity", _TEXT),
            ("event_type", _TEXT),
            ("from_state", "TEXT"),
            ("to_state", _TEXT),
            ("payload_json", _TEXT),
            ("witness_event_id", _TEXT),
            ("created_at", _TEXT),
        ),
    ),
    "sab_challenge_packets_v1": _Table(
        "challenge_id",
        _ID
        + (
            ("challenge_id", "TEXT NOT NULL UNIQUE"),
            ("target_seed_id", _TEXT),
            ("target_claim_id", _TEXT),
            ("challenger_identity", _TEXT),
            ("status", _TEXT),
            ("packet_json", _TEXT),
            ("packet_hash", _TEXT),
            ("response_json", "TEXT"),
            ("respond_by", "TEXT"),
            ("prosecute_by", "TEXT"),
            ("created_at", _TEXT),
            ("updated_at", _TEXT),
        ),
    ),
    "sab_witness_events_v1": _Table(
        "event_id",
        _ID
        + (
            ("event_id", "TEXT NOT NULL UNIQUE"),
            ("chain_scope", _TEXT),
            ("event_type", _TEXT),
            ("actor_identity", _TEXT),
            ("subject_type", _TEXT),
            ("subject_id", _TEXT),
            ("subject_seed_id", "TEXT"),
            ("timestamp", _TEXT),
            ("payload_hash", _TEXT),
            ("payload_json", _TEXT),
            ("signature", _TEXT),
            ("prev_hash", _TEXT),
            ("event_hash", _TEXT),
        ),
    ),
    "sab_standing_leases_v1": _Table(
        "standing_id",
        _ID
        + (
            ("standing_id", "TEXT NOT NULL UNIQUE"),
            ("subject_seed_id", _TEXT),
            ("subject_claim_id", _TEXT),
            ("scope", _TEXT),
            ("purpose", _TEXT),
            ("status", _TEXT),
            ("lease_json", _TEXT),
            ("lease_hash", _TEXT),
            ("expiry", _TEXT),
            ("revoker", _TEXT),
            ("challenge_path", _TEXT),
            ("issued_by", _TEXT),
            ("issued_at", _TEXT),
            ("updated_at", _TEXT),
            ("issued_under_json", "TEXT"),
        ),
    ),
    "sab_standing_events_v1": _Table(
        "event_id",
        _ID
        + (
            ("event_id", "TEXT NOT NULL UNIQUE"),
            ("standing_id", _TEXT),
            ("actor_identity", _TEXT),
            ("event_type", _TEXT),
            ("from_status", "TEXT"),
            ("to_status", _TEXT),
            ("payload_json", _TEXT),
            ("witness_event_id", _TEXT),
            ("created_at", _TEXT),
        ),
    ),
}
PUBLIC_TABLES = tuple(sorted(TABLES))
_DDL = {
    name: "CREATE TABLE "
    + name
    + " ("
    + ", ".join(f"{column} {kind}" for column, kind in table.columns)
    + ")"
    for name, table in TABLES.items()
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_json(raw: bytes | str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def number(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("nonfinite JSON number")
        return parsed

    def invalid(value):
        raise ValueError("non-JSON constant")

    return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=invalid)


def _observed_at(value: str | datetime) -> str:
    try:
        instant = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
        if instant.tzinfo is None:
            raise ValueError("timezone required")
        return instant.astimezone(timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise PublicSnapshotError(
            "invalid_observation", "An explicit observation timestamp with timezone is required."
        ) from exc


@contextmanager
def _source_read(conn: sqlite3.Connection) -> Iterator[None]:
    own = not conn.in_transaction
    if own:
        conn.execute("BEGIN")
    try:
        yield
    finally:
        if own:
            conn.rollback()


def _rows(conn: sqlite3.Connection, sql: str, parameters: tuple = ()) -> list[dict[str, Any]]:
    cursor = conn.execute(sql, parameters)
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _typed(value: Any, declaration: str) -> dict[str, Any]:
    if value is None:
        if "NOT NULL" in declaration or "PRIMARY KEY" in declaration:
            raise PublicSnapshotError(
                "unsupported_sql_value", "A required publication column is null."
            )
        return {"type": "null"}
    expected = "integer" if declaration.startswith("INTEGER") else "text"
    if expected == "integer" and type(value) is int:
        return {"type": "integer", "value": value}
    if expected == "text" and isinstance(value, str):
        return {"type": "text", "value": value}
    raise PublicSnapshotError(
        "unsupported_sql_value", "A record has an unsupported SQLite storage type."
    )


def public_record_sha256(table: str, values: dict[str, Any]) -> str:
    """Bind all fixed SQL columns, exact text, storage types and mutable fields."""
    if table not in TABLES or set(values) != set(TABLES[table].names):
        raise PublicSnapshotError(
            "unsupported_columns",
            "A whole-record hash requires exactly the fixed publication columns.",
        )
    columns = TABLES[table].columns
    return _sha(
        _canonical(
            {
                "schema": "sab.public_record.v1",
                "table": table,
                "columns": [name for name, _ in columns],
                "values": [_typed(values[name], declaration) for name, declaration in columns],
            }
        )
    )


def _select(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    identifiers: set[str],
    *,
    alternate: str | None = None,
) -> list[dict[str, Any]]:
    spec = TABLES[table]
    if column not in spec.names or alternate is not None and alternate not in spec.names:
        raise PublicSnapshotError("internal_column", "Unsupported selection column.")
    found: dict[str, dict[str, Any]] = {}
    ordered = sorted(identifiers)
    for start in range(0, len(ordered), 400):
        batch = ordered[start : start + 400]
        placeholders = ",".join("?" for _ in batch)
        where = f"{column} IN ({placeholders})"
        params = tuple(batch)
        if alternate:
            where += f" OR {alternate} IN ({placeholders})"
            params += tuple(batch)
        # Identifiers come only from fixed table metadata; all selection values are bound.
        sql = f"SELECT {', '.join(spec.names)} FROM {table} WHERE {where}"  # nosec B608
        batch_keys = set()
        for row in _rows(conn, sql, params):
            key = row[spec.key]
            if key in batch_keys or key in found and found[key] != row:
                raise PublicSnapshotError(
                    "duplicate_record_identity",
                    "The source contains ambiguous duplicate record identities.",
                )
            batch_keys.add(key)
            found[key] = row
    if found:
        # Extension columns are unsupported by this policy, even if their values are null.
        info = _rows(conn, f"PRAGMA table_xinfo({table})")
        if {row["name"] for row in info} != set(spec.names) or any(row["hidden"] for row in info):
            raise PublicSnapshotError(
                "unclassified_source_columns",
                f"Selected records in {table} have unsupported source columns.",
            )
        for row in found.values():
            public_record_sha256(table, row)
    return [found[key] for key in sorted(found)]


def _capture(conn: sqlite3.Connection, seed_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    available = {
        row["name"] for row in _rows(conn, "SELECT name FROM sqlite_master WHERE type='table'")
    }
    if not set(PUBLIC_TABLES).issubset(available):
        raise PublicSnapshotError(
            "source_schema_missing", "The source lacks required dossier context tables."
        )
    for table in PUBLIC_TABLES:
        columns = {row["name"] for row in _rows(conn, f"PRAGMA table_xinfo({table})")}
        if not set(TABLES[table].names).issubset(columns):
            raise PublicSnapshotError(
                "source_schema_missing", f"Required columns are missing from {table}."
            )
    seeds = set(seed_ids)
    selected = {table: [] for table in PUBLIC_TABLES}
    selected["sab_seed_packets_v1"] = _select(conn, "sab_seed_packets_v1", "seed_id", seeds)
    if {row["seed_id"] for row in selected["sab_seed_packets_v1"]} != seeds:
        raise PublicSnapshotError(
            "seed_missing", "At least one explicitly selected seed is unavailable."
        )
    selected["sab_challenge_packets_v1"] = _select(
        conn, "sab_challenge_packets_v1", "target_seed_id", seeds
    )
    selected["sab_witness_events_v1"] = _select(
        conn, "sab_witness_events_v1", "subject_seed_id", seeds, alternate="chain_scope"
    )
    selected["sab_seed_events_v1"] = _select(conn, "sab_seed_events_v1", "seed_id", seeds)
    selected["sab_standing_leases_v1"] = _select(
        conn, "sab_standing_leases_v1", "subject_seed_id", seeds
    )
    standings = {row["standing_id"] for row in selected["sab_standing_leases_v1"]}
    selected["sab_standing_events_v1"] = _select(
        conn, "sab_standing_events_v1", "standing_id", standings
    )
    actors = set()
    for table, column in (
        ("sab_seed_packets_v1", "claimant_identity"),
        ("sab_challenge_packets_v1", "challenger_identity"),
        ("sab_witness_events_v1", "actor_identity"),
        ("sab_seed_events_v1", "actor_identity"),
        ("sab_standing_leases_v1", "issued_by"),
        ("sab_standing_events_v1", "actor_identity"),
    ):
        for row in selected[table]:
            actor = row[column]
            actors.update((actor, actor.removeprefix("sab_identity_")))
    selected["sab_agent_identities_v1"] = _select(
        conn, "sab_agent_identities_v1", "subject_id", actors
    )
    witness_ids = {row["event_id"] for row in selected["sab_witness_events_v1"]}
    for table in ("sab_seed_events_v1", "sab_standing_events_v1"):
        if any(row["witness_event_id"] not in witness_ids for row in selected[table]):
            raise PublicSnapshotError(
                "incomplete_context",
                "A state event refers to witness context outside the selected closure.",
            )
    return selected


def _inventory(rows: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    return [
        {
            "table": table,
            "row_count": len(rows[table]),
            "records": [
                {
                    "record_id": row[TABLES[table].key],
                    "row_sha256": public_record_sha256(table, row),
                }
                for row in rows[table]
            ],
        }
        for table in PUBLIC_TABLES
    ]


def _observation(rows, seed_ids, observed_at, kind="sqlite_read_transaction"):
    inventory = _inventory(rows)
    scope = {
        "policy": POLICY_ID,
        "observed_at": observed_at,
        "selected_seed_ids": seed_ids,
        "inventory": inventory,
    }
    return {
        "kind": kind,
        "time_basis": "operator_supplied",
        "observed_at": observed_at,
        "closure_sha256": _sha(_canonical(scope)),
        "record_count": sum(item["row_count"] for item in inventory),
    }


def _raw_columns(row: dict[str, Any]) -> list[str]:
    return sorted(
        name for name, value in row.items() if name.endswith("_json") and value is not None
    )


def plan_public_snapshot(
    conn: sqlite3.Connection, seed_ids: list[str], *, observed_at: str | datetime
) -> dict[str, Any]:
    """Produce a private, unapproved exact-record review skeleton; never publish it."""
    if not seed_ids or any(not isinstance(value, str) or not value for value in seed_ids):
        raise PublicSnapshotError(
            "explicit_selection_required",
            "Select at least one exact seed ID, or use the explicit empty export.",
        )
    ids = sorted(set(seed_ids))
    observation_time = _observed_at(observed_at)
    with _source_read(conn):
        rows = _capture(conn, ids)
        observation = _observation(rows, ids, observation_time)
    records = []
    for table in PUBLIC_TABLES:
        for row in rows[table]:
            records.append(
                {
                    "table": table,
                    "record_id": row[TABLES[table].key],
                    "row_sha256": public_record_sha256(table, row),
                    "values": row,
                    "decision": "pending",
                    "publication_basis": None,
                    "license": None,
                    "privacy_review": {"status": "pending", "reviewer": None},
                    "consent": {"required": None, "satisfied": None, "basis": None},
                    "takedown": {"owner": None, "route": None},
                    "raw_json_review": {
                        column: {"classification": "unreviewed", "extensions_reviewed": False}
                        for column in _raw_columns(row)
                    },
                }
            )
    return {
        "schema": REVIEW_SCHEMA,
        "policy": POLICY_ID,
        "observed_at": observation_time,
        "selected_seed_ids": ids,
        "source_observation": observation,
        "inventory": _inventory(rows),
        "records": records,
        "approval_effect": "publication_only",
        "generated_skeleton_is_approval": False,
    }


_SECRET_KEYS = {
    "privatekey",
    "secretkey",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "password",
    "passphrase",
    "mnemonic",
    "seedphrase",
    "clientsecret",
    "authtoken",
}
_PRIVATE_PEM = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_LOCAL_POINTER = re.compile(
    r"(?:^file:|^private-local:|^sqlite:|^~/|^/(?:Users|home|tmp|private|var)/|^[A-Za-z]:[\\/]|(?:^|/)\.dharma(?:/|$))",
    re.IGNORECASE,
)


def _screen_record(row: dict[str, Any]) -> None:
    """Defense in depth only: this is not a privacy proof or an approval source."""
    pending: list[Any] = list(row.values())
    for column in _raw_columns(row):
        try:
            pending.append(_strict_json(row[column]))
        except (TypeError, ValueError, RecursionError):
            # Opaque historical strings still require explicit whole-record review.
            pass
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized in _SECRET_KEYS:
                    raise PublicSnapshotError(
                        "obvious_secret",
                        "An original record contains an explicit secret or private-key field.",
                    )
                if key == "privacy_class":
                    if not isinstance(item, str):
                        raise PublicSnapshotError(
                            "invalid_privacy_class",
                            "A privacy classification is malformed and cannot establish publication eligibility.",
                        )
                    if item in {"private", "private_local", "private_pointer"}:
                        raise PublicSnapshotError(
                            "private_content", "A record explicitly identifies private content."
                        )
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            if _PRIVATE_PEM.search(value):
                raise PublicSnapshotError(
                    "obvious_secret", "An original record contains a private-key marker."
                )
            if _LOCAL_POINTER.search(value):
                raise PublicSnapshotError(
                    "local_pointer",
                    "An original record contains a local-only or private custody pointer.",
                )


def _public_route(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        return False
    try:
        value.encode("utf-8")
        parsed = urlsplit(value)
        parsed.port
    except (ValueError, UnicodeError):
        return False
    if re.search(
        r"private-local:|file:|/(?:Users|home|tmp|private)/|(?:^|/)\.dharma(?:/|$)",
        value,
        re.IGNORECASE,
    ):
        return False
    if parsed.scheme == "https":
        return bool(parsed.hostname) and parsed.username is None and parsed.password is None
    if parsed.scheme == "mailto":
        return bool(parsed.path and "@" in parsed.path) and not parsed.query and not parsed.fragment
    return value.startswith("/") and not value.startswith("//") and not _LOCAL_POINTER.search(value)


def _approved_records(
    review: dict[str, Any], rows: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    supplied = review.get("records")
    if not isinstance(supplied, list):
        raise PublicSnapshotError(
            "approval_missing",
            "Every closure record requires its own explicit publication approval.",
        )
    approvals = {}
    for approval in supplied:
        if not isinstance(approval, dict):
            raise PublicSnapshotError(
                "approval_invalid", "Publication review records must be objects."
            )
        key = (approval.get("table"), approval.get("record_id"))
        if not all(isinstance(value, str) for value in key) or key in approvals:
            raise PublicSnapshotError(
                "approval_invalid", "Publication approvals must identify unique exact records."
            )
        approvals[key] = approval
    expected = {(table, row[TABLES[table].key]) for table in PUBLIC_TABLES for row in rows[table]}
    if set(approvals) != expected:
        raise PublicSnapshotError(
            "partial_approval",
            "Approvals must cover the complete closure exactly, including every objection and event.",
        )
    public = []
    for table in PUBLIC_TABLES:
        for row in rows[table]:
            approval = approvals[(table, row[TABLES[table].key])]
            if approval.get("row_sha256") != public_record_sha256(table, row) or _canonical(
                approval.get("values")
            ) != _canonical(row):
                raise PublicSnapshotError(
                    "stale_approval",
                    "A whole-record approval does not match the current exact SQL values.",
                )
            if approval.get("decision") != "approve":
                raise PublicSnapshotError(
                    "approval_missing",
                    "A generated skeleton or pending decision is not publication approval.",
                )
            basis = approval.get("publication_basis")
            license_id = approval.get("license")
            if not isinstance(basis, str) or basis not in {
                "own_work",
                "explicit_permission",
                "public_domain",
                "compatible_license",
            }:
                raise PublicSnapshotError(
                    "publication_basis_missing",
                    "A supported explicit publication basis is required.",
                )
            if not isinstance(license_id, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.+-]{0,99}", license_id
            ):
                raise PublicSnapshotError(
                    "license_missing",
                    "A public SPDX-style license identifier or LicenseRef is required.",
                )
            privacy = approval.get("privacy_review")
            if (
                not isinstance(privacy, dict)
                or privacy.get("status") != "approved"
                or not isinstance(privacy.get("reviewer"), str)
                or not privacy["reviewer"].strip()
            ):
                raise PublicSnapshotError(
                    "privacy_review_missing",
                    "An identified reviewer must explicitly approve publication privacy.",
                )
            consent = approval.get("consent")
            if (
                not isinstance(consent, dict)
                or type(consent.get("required")) is not bool
                or type(consent.get("satisfied")) is not bool
                or not isinstance(consent.get("basis"), str)
                or not consent["basis"].strip()
                or consent["required"]
                and not consent["satisfied"]
            ):
                raise PublicSnapshotError(
                    "consent_missing",
                    "Explicit consent requirements, satisfaction and rationale are required.",
                )
            takedown = approval.get("takedown")
            if (
                not isinstance(takedown, dict)
                or not isinstance(takedown.get("owner"), str)
                or not takedown["owner"].strip()
                or not _public_route(takedown.get("route"))
            ):
                raise PublicSnapshotError(
                    "takedown_missing", "An owned public takedown route is required."
                )
            raw = approval.get("raw_json_review")
            if (
                not isinstance(raw, dict)
                or set(raw) != set(_raw_columns(row))
                or any(
                    item != {"classification": "public_original", "extensions_reviewed": True}
                    for item in raw.values()
                )
            ):
                raise PublicSnapshotError(
                    "unclassified_raw_content",
                    "Every exact raw JSON document, including unknown extensions, requires explicit public-original classification.",
                )
            _screen_record(row)
            public.append(
                {
                    "table": table,
                    "record_id": row[TABLES[table].key],
                    "row_sha256": approval["row_sha256"],
                    "publication_basis": basis,
                    "license": license_id,
                    "takedown_route": takedown["route"],
                }
            )
    return public


def _populate_database(conn: sqlite3.Connection, rows: dict[str, list[dict[str, Any]]]) -> None:
    conn.execute("PRAGMA page_size=4096")
    conn.execute("PRAGMA encoding='UTF-8'")
    conn.execute("PRAGMA journal_mode=MEMORY")
    conn.execute("PRAGMA user_version=1")
    for table in PUBLIC_TABLES:
        conn.execute(_DDL[table])
        spec = TABLES[table]
        placeholders = ",".join("?" for _ in spec.names)
        # Destination identifiers are fixed; exact approved values are bound.
        sql = f"INSERT INTO {table} ({', '.join(spec.names)}) VALUES ({placeholders})"  # nosec B608
        conn.executemany(sql, [tuple(row[name] for name in spec.names) for row in rows[table]])
    conn.commit()


def _database_bytes(rows: dict[str, list[dict[str, Any]]], scratch_parent: Path) -> bytes:
    if _HAS_SQLITE_SERIALIZATION:
        conn = sqlite3.connect(":memory:")
        try:
            _populate_database(conn, rows)
            return conn.serialize()
        finally:
            conn.close()
    # Python 3.10 has backup but no serialize. This offline build contains
    # only approved rows in a fresh file, never a copy of source pages.
    with tempfile.TemporaryDirectory(
        prefix=".public-snapshot-build-", dir=scratch_parent
    ) as temporary:
        path = Path(temporary) / SNAPSHOT_FILENAME
        conn = sqlite3.connect(path)
        try:
            _populate_database(conn, rows)
        finally:
            conn.close()
        return path.read_bytes()


def _no_symlinks(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise PublicSnapshotError(
                "symlink", "Publication bundle paths cannot contain symlinks."
            )


def _write_new_bundle(
    bundle_dir: Path | str, manifest: dict[str, Any], database: bytes
) -> dict[str, Any]:
    destination = Path(bundle_dir).absolute()
    _no_symlinks(destination)
    if destination.exists() or not destination.parent.is_dir():
        raise PublicSnapshotError(
            "destination_exists_or_missing_parent",
            "Use a new bundle directory under an existing real parent directory.",
        )
    manifest_bytes = _canonical(manifest) + b"\n"
    created: list[Path] = []
    created_directory = False
    try:
        destination.mkdir(mode=0o700)
        created_directory = True
        for name, content in ((SNAPSHOT_FILENAME, database), (MANIFEST_FILENAME, manifest_bytes)):
            path = destination / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except (OSError, ValueError):
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if created_directory:
            destination.rmdir()
        raise
    return copy.deepcopy(manifest)


def _manifest(rows, seed_ids, observed_at, observation, approvals, *, scratch_parent, empty=False):
    database = _database_bytes(rows, scratch_parent)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "policy": POLICY_ID,
        "observed_at": observed_at,
        "snapshot_kind": "explicit_empty" if empty else "approved_dossier_closures",
        "database": {"filename": SNAPSHOT_FILENAME, "sha256": _sha(database)},
        "selected_seed_ids": seed_ids,
        "source_observation": observation,
        "inventory": _inventory(rows),
        "publication_approvals": approvals,
        "publication_effect": "publication_only",
        "truth_effect": "none",
        "identity_effect": "none",
        "authority_effect": "none",
        "standing_effect": "none",
    }
    return manifest, database


def export_public_snapshot(
    conn: sqlite3.Connection,
    bundle_dir: Path | str,
    review: dict[str, Any],
    *,
    observed_at: str | datetime | None = None,
) -> dict[str, Any]:
    """Publish only an explicitly approved, unchanged complete dossier closure."""
    if (
        not isinstance(review, dict)
        or review.get("schema") != REVIEW_SCHEMA
        or review.get("policy") != POLICY_ID
        or review.get("approval_effect") != "publication_only"
        or review.get("generated_skeleton_is_approval") is not False
    ):
        raise PublicSnapshotError(
            "review_schema", "An explicit whole-record public snapshot review is required."
        )
    ids = review.get("selected_seed_ids")
    if (
        not isinstance(ids, list)
        or not ids
        or any(not isinstance(value, str) or not value for value in ids)
        or ids != sorted(set(ids))
    ):
        raise PublicSnapshotError(
            "explicit_selection_required",
            "Review must name a sorted unique nonempty list of exact seed IDs.",
        )
    time = _observed_at(observed_at if observed_at is not None else review.get("observed_at"))
    if review.get("observed_at") != time:
        raise PublicSnapshotError(
            "stale_observation",
            "The explicit review observation does not match export observation.",
        )
    with _source_read(conn):
        rows = _capture(conn, ids)
        observation = _observation(rows, ids, time)
        if (
            review.get("inventory") != _inventory(rows)
            or review.get("source_observation") != observation
        ):
            raise PublicSnapshotError(
                "stale_observation", "The source closure or its observation changed after review."
            )
        approvals = _approved_records(review, rows)
        destination = Path(bundle_dir).absolute()
        _no_symlinks(destination)
        manifest, database = _manifest(
            rows, ids, time, observation, approvals, scratch_parent=destination.parent
        )
    return _write_new_bundle(bundle_dir, manifest, database)


def export_empty_public_snapshot(
    bundle_dir: Path | str, *, observed_at: str | datetime
) -> dict[str, Any]:
    """Create an explicit empty publication bundle offline, without a source DB."""
    time = _observed_at(observed_at)
    rows = {table: [] for table in PUBLIC_TABLES}
    observation = _observation(rows, [], time, "offline_empty")
    destination = Path(bundle_dir).absolute()
    _no_symlinks(destination)
    manifest, database = _manifest(
        rows, [], time, observation, [], scratch_parent=destination.parent, empty=True
    )
    return _write_new_bundle(bundle_dir, manifest, database)


_MANIFEST_KEYS = {
    "schema",
    "policy",
    "observed_at",
    "snapshot_kind",
    "database",
    "selected_seed_ids",
    "source_observation",
    "inventory",
    "publication_approvals",
    "publication_effect",
    "truth_effect",
    "identity_effect",
    "authority_effect",
    "standing_effect",
}


def _validate_manifest(manifest: Any) -> None:
    if (
        not isinstance(manifest, dict)
        or set(manifest) != _MANIFEST_KEYS
        or manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("policy") != POLICY_ID
    ):
        raise PublicSnapshotError(
            "manifest_schema", "The pinned manifest is not an admitted public snapshot manifest."
        )
    if manifest["observed_at"] != _observed_at(manifest["observed_at"]):
        raise PublicSnapshotError(
            "manifest_schema", "The manifest observation must be canonical UTC."
        )
    if manifest["publication_effect"] != "publication_only" or any(
        manifest[name] != "none"
        for name in ("truth_effect", "identity_effect", "authority_effect", "standing_effect")
    ):
        raise PublicSnapshotError(
            "manifest_schema",
            "Publication cannot assert truth, identity, authority or standing effects.",
        )
    database = manifest["database"]
    if (
        not isinstance(database, dict)
        or set(database) != {"filename", "sha256"}
        or database["filename"] != SNAPSHOT_FILENAME
        or not isinstance(database["sha256"], str)
        or not _SHA256.fullmatch(database["sha256"])
    ):
        raise PublicSnapshotError(
            "manifest_schema", "The manifest must bind the fixed database filename and SHA-256."
        )
    ids = manifest["selected_seed_ids"]
    if (
        not isinstance(ids, list)
        or any(not isinstance(value, str) or not value for value in ids)
        or ids != sorted(set(ids))
    ):
        raise PublicSnapshotError("manifest_schema", "Manifest seed selection is invalid.")
    expected_kind = "approved_dossier_closures" if ids else "explicit_empty"
    if manifest["snapshot_kind"] != expected_kind:
        raise PublicSnapshotError("manifest_schema", "The snapshot selection and kind disagree.")


def _read_bundle(bundle_dir: Path | str, expected: str) -> tuple[dict[str, Any], bytes, int, bytes]:
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise PublicSnapshotError(
            "manifest_pin_required",
            "An out-of-band SHA-256 pin for the exact manifest bytes is required.",
        )
    directory = Path(bundle_dir).absolute()
    _no_symlinks(directory)
    database_fd = None
    try:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PublicSnapshotError(
            "bundle_missing", "The configured public bundle is unavailable."
        ) from exc
    try:
        if set(os.listdir(directory_fd)) != {MANIFEST_FILENAME, SNAPSHOT_FILENAME}:
            raise PublicSnapshotError(
                "bundle_contents",
                "The public bundle must contain only its manifest and database, without sidecars.",
            )
        content = {}
        for name in (MANIFEST_FILENAME, SNAPSHOT_FILENAME):
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            except OSError as exc:
                raise PublicSnapshotError(
                    "bundle_file", "A required bundle member cannot be opened safely."
                ) from exc
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise PublicSnapshotError(
                        "bundle_file", "Bundle members must be regular files."
                    )
                content[name] = stream.read()
                if name == SNAPSHOT_FILENAME:
                    database_fd = os.dup(stream.fileno())
            if name == MANIFEST_FILENAME and _sha(content[name]) != expected:
                raise PublicSnapshotError(
                    "manifest_pin_mismatch",
                    "The configured manifest does not match its deployment pin.",
                )
        if set(os.listdir(directory_fd)) != {MANIFEST_FILENAME, SNAPSHOT_FILENAME}:
            raise PublicSnapshotError(
                "bundle_contents", "The bundle changed while its bytes were being captured."
            )
    except BaseException:
        if database_fd is not None:
            os.close(database_fd)
        raise
    finally:
        os.close(directory_fd)
    try:
        try:
            manifest = _strict_json(content[MANIFEST_FILENAME])
        except (TypeError, ValueError, RecursionError) as exc:
            raise PublicSnapshotError(
                "manifest_json", "The pinned manifest is not strict JSON."
            ) from exc
        _validate_manifest(manifest)
        database = content[SNAPSHOT_FILENAME]
        if _sha(database) != manifest["database"]["sha256"]:
            raise PublicSnapshotError(
                "database_digest_mismatch",
                "Public database bytes do not match the pinned manifest.",
            )
        if database[:16] != b"SQLite format 3\0" or database[18:20] != b"\x01\x01":
            raise PublicSnapshotError(
                "database_format",
                "The public database must be a standalone SQLite image without WAL dependence.",
            )
        return manifest, database, database_fd, content[MANIFEST_FILENAME]
    except BaseException:
        os.close(database_fd)
        raise


def _validate_frozen(conn: sqlite3.Connection, manifest: dict[str, Any]) -> None:
    schema = _rows(conn, "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
    expected_indexes = {f"sqlite_autoindex_{table}_1": table for table in PUBLIC_TABLES}
    tables = {}
    for entry in schema:
        if (
            entry["type"] == "table"
            and entry["name"] in TABLES
            and entry["sql"] == _DDL[entry["name"]]
        ):
            tables[entry["name"]] = entry
        elif (
            entry["type"] == "index"
            and expected_indexes.get(entry["name"]) == entry["tbl_name"]
            and entry["sql"] is None
        ):
            pass
        else:
            raise PublicSnapshotError(
                "database_schema",
                "The frozen database contains an unsupported schema object or definition.",
            )
    if set(tables) != set(PUBLIC_TABLES):
        raise PublicSnapshotError(
            "database_schema",
            "The frozen database does not contain exactly the publication tables.",
        )
    if [row[0] for row in conn.execute("PRAGMA integrity_check").fetchall()] != ["ok"]:
        raise PublicSnapshotError(
            "database_integrity", "SQLite integrity checks failed on the frozen copy."
        )
    frozen_rows = {}
    for table in PUBLIC_TABLES:
        spec = TABLES[table]
        info = _rows(conn, f"PRAGMA table_xinfo({table})")
        if tuple(row["name"] for row in info) != spec.names or any(row["hidden"] for row in info):
            raise PublicSnapshotError(
                "database_schema", "The frozen database contains unsupported columns."
            )
        # The complete fixed table is read; no row is filtered from inventory validation.
        rows = _rows(conn, f"SELECT {', '.join(spec.names)} FROM {table}")  # nosec B608
        frozen_rows[table] = sorted(rows, key=lambda row: row[spec.key])
    inventory = _inventory(frozen_rows)
    if manifest["inventory"] != inventory:
        raise PublicSnapshotError(
            "inventory_mismatch",
            "The complete frozen row inventory does not match the pinned manifest.",
        )
    ids = manifest["selected_seed_ids"]
    if [row["seed_id"] for row in frozen_rows["sab_seed_packets_v1"]] != ids:
        raise PublicSnapshotError(
            "selection_mismatch", "Frozen seeds do not match the explicit publication selection."
        )
    captured = _capture(conn, ids) if ids else {table: [] for table in PUBLIC_TABLES}
    if captured != frozen_rows:
        raise PublicSnapshotError(
            "closure_mismatch",
            "The frozen data contains records outside or missing from its complete selected closure.",
        )
    observation = _observation(
        frozen_rows,
        ids,
        manifest["observed_at"],
        "sqlite_read_transaction" if ids else "offline_empty",
    )
    if manifest["source_observation"] != observation:
        raise PublicSnapshotError(
            "observation_mismatch",
            "The source observation does not bind the complete frozen inventory.",
        )
    approvals = manifest["publication_approvals"]
    if not isinstance(approvals, list):
        raise PublicSnapshotError("manifest_schema", "Public approval inventory is invalid.")
    expected = [
        (table, row[TABLES[table].key], public_record_sha256(table, row))
        for table in PUBLIC_TABLES
        for row in frozen_rows[table]
    ]
    actual = []
    for item in approvals:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "table",
                "record_id",
                "row_sha256",
                "publication_basis",
                "license",
                "takedown_route",
            }
            or not isinstance(item["publication_basis"], str)
            or item["publication_basis"]
            not in {"own_work", "explicit_permission", "public_domain", "compatible_license"}
            or not isinstance(item["license"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,99}", item["license"])
            or not _public_route(item["takedown_route"])
        ):
            raise PublicSnapshotError(
                "manifest_schema",
                "Public publication metadata is invalid or contains an unsupported field.",
            )
        actual.append((item["table"], item["record_id"], item["row_sha256"]))
    if actual != expected:
        raise PublicSnapshotError(
            "approval_inventory_mismatch",
            "Public approval digests do not cover every frozen record exactly.",
        )
    for rows in frozen_rows.values():
        for row in rows:
            _screen_record(row)


_READ_FUNCTIONS = {
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "total",
    "coalesce",
    "ifnull",
    "nullif",
    "lower",
    "upper",
    "length",
    "substr",
    "substring",
    "instr",
    "like",
    "glob",
    "hex",
    "quote",
    "typeof",
    "abs",
    "round",
    "printf",
    "replace",
    "trim",
    "ltrim",
    "rtrim",
    "json_valid",
    "json_extract",
    "json_type",
    "json_array_length",
    "sab_dossier_contains",
    "sab_dossier_packet_contains",
    "sab_observed_standing_status",
}


def _read_authorizer(
    action: int, first: str | None, second: str | None, database: str | None, origin: str | None
) -> int:
    if action in {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_RECURSIVE,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_SAVEPOINT,
    }:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        return (
            sqlite3.SQLITE_OK
            if database in {None, "main"} and first in {*PUBLIC_TABLES, "sqlite_master"}
            else sqlite3.SQLITE_DENY
        )
    if action == sqlite3.SQLITE_FUNCTION:
        return (
            sqlite3.SQLITE_OK if (second or "").lower() in _READ_FUNCTIONS else sqlite3.SQLITE_DENY
        )
    if action == sqlite3.SQLITE_PRAGMA:
        name = (first or "").lower()
        if name == "query_only" and (second is None or second.lower() in {"1", "on", "true"}):
            return sqlite3.SQLITE_OK
        if (
            name in {"table_info", "table_xinfo", "index_list", "foreign_key_list"}
            and second in PUBLIC_TABLES
        ):
            return sqlite3.SQLITE_OK
        if (
            name
            in {
                "database_list",
                "schema_version",
                "data_version",
                "user_version",
                "page_count",
                "page_size",
                "freelist_count",
                "encoding",
            }
            and second is None
        ):
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


class _FrozenConnection(sqlite3.Connection):
    _frozen = False

    def set_authorizer(self, callback):
        if self._frozen:
            raise sqlite3.DatabaseError("The public snapshot authorizer is frozen.")
        return super().set_authorizer(callback)

    def deserialize(self, data, /, *, name="main"):
        if self._frozen:
            raise sqlite3.DatabaseError("The public snapshot cannot be replaced.")
        return super().deserialize(data, name=name)

    def backup(self, *args, **kwargs):
        if self._frozen:
            raise sqlite3.DatabaseError("Public snapshot connections cannot create backups.")
        return super().backup(*args, **kwargs)

    def enable_load_extension(self, enabled, /):
        if self._frozen:
            raise sqlite3.DatabaseError("Public snapshot extensions are disabled.")
        return super().enable_load_extension(enabled)

    def load_extension(self, *args, **kwargs):
        raise sqlite3.DatabaseError("Public snapshot extensions are disabled.")

    def create_function(self, name, narg, func, *, deterministic=False):
        if self._frozen and name not in {
            "sab_dossier_contains",
            "sab_dossier_packet_contains",
            "sab_observed_standing_status",
        }:
            raise sqlite3.DatabaseError("Only fixed dossier observation functions are allowed.")
        return super().create_function(name, narg, func, deterministic=deterministic)


class FrozenPublicSnapshot:
    """A process-lifetime frozen source, with no runtime filesystem access."""

    def __init__(
        self,
        conn: _FrozenConnection,
        manifest: dict[str, Any] | None,
        pin: str | None,
        manifest_bytes: bytes | None = None,
    ):
        self._conn = conn
        self._manifest = copy.deepcopy(manifest)
        self._pin = pin
        self._manifest_bytes = manifest_bytes
        self._lock = RLock()
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA query_only=ON")
        conn.set_authorizer(_read_authorizer)
        conn._frozen = True

    @property
    def configured(self) -> bool:
        return self._manifest is not None

    @property
    def manifest(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._manifest)

    @property
    def manifest_bytes(self) -> bytes | None:
        return self._manifest_bytes

    @property
    def status(self) -> dict[str, Any]:
        manifest = self._manifest
        return {
            "status": "ready" if manifest else "not_configured",
            "configured": self.configured,
            "manifest_sha256": self._pin,
            "database_sha256": manifest["database"]["sha256"] if manifest else None,
            "observed_at": manifest["observed_at"] if manifest else None,
            "seed_count": len(manifest["selected_seed_ids"]) if manifest else 0,
        }

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
            finally:
                if self._conn.in_transaction:
                    self._conn.rollback()


def load_public_snapshot(
    bundle_path: Path | str | None, expected_manifest_sha256: str | None
) -> FrozenPublicSnapshot:
    """Load only a deployment-pinned bundle, or an explicit unconfigured source."""
    if bundle_path is None:
        if expected_manifest_sha256 is not None:
            raise PublicSnapshotError(
                "bundle_path_required", "A manifest pin requires an explicit bundle path."
            )
        conn = sqlite3.connect(":memory:", factory=_FrozenConnection, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return FrozenPublicSnapshot(conn, None, None)
    try:
        manifest, database, database_fd, manifest_bytes = _read_bundle(
            bundle_path, expected_manifest_sha256
        )
    except PublicSnapshotError:
        raise
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise PublicSnapshotError(
            "invalid_bundle", "The configured public bundle cannot be validated safely."
        ) from exc
    conn = sqlite3.connect(":memory:", factory=_FrozenConnection, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        if _HAS_SQLITE_SERIALIZATION:
            conn.deserialize(database)
        else:
            # The descriptor is for the public file whose bytes were pinned.
            # SQLite opens it immutable/read-only; no journal or runtime file
            # is created. The entire frozen logical inventory is checked below.
            public_file = sqlite3.connect(
                f"file:/dev/fd/{database_fd}?mode=ro&immutable=1", uri=True
            )
            try:
                public_file.execute("PRAGMA query_only=ON")
                public_file.backup(conn)
            finally:
                public_file.close()
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA query_only=ON")
        _validate_frozen(conn, manifest)
        return FrozenPublicSnapshot(conn, manifest, expected_manifest_sha256, manifest_bytes)
    except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
        conn.close()
        if isinstance(exc, PublicSnapshotError):
            raise
        raise PublicSnapshotError(
            "invalid_snapshot", "The configured public snapshot failed frozen validation."
        ) from exc
    finally:
        os.close(database_fd)
