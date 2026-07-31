"""
Canonical SAB agent-seeding storage helpers.

This module owns the v1 seed-packet authority tables while leaving the existing
``sparks`` tables as compatibility projections. Hashes here are computed from
canonical JSON only; mapping to a spark projection never mutates the stored seed
packet JSON.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Mapping, Optional


GENESIS_HASH = "genesis"
DEFAULT_WITNESS_POLICY_VERSION = "sab-seeding-storage-v1"

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_payload_sha256(payload: Mapping[str, Any]) -> str:
    return sha256_text(canonical_json(payload))


def _assert_identifier(name: str) -> str:
    if not _SAFE_IDENTIFIER.fullmatch(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return name


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    _assert_identifier(table)
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    _assert_identifier(table)
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(row[1]) for row in rows}


def _ensure_column(conn: sqlite3.Connection, table: str, column_name: str, column_def: str) -> None:
    _assert_identifier(table)
    _assert_identifier(column_name)
    if column_name not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")


def _json_object(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _json_array(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _string_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _require_text(value: Any, field_name: str) -> str:
    text = _string_or_none(value)
    if text is None:
        raise ValueError(f"{field_name} is required")
    return text


def _seed_claim(seed_packet: Mapping[str, Any]) -> dict[str, Any]:
    return _json_object(seed_packet.get("claim"))


def _seed_claimant_identity(seed_packet: Mapping[str, Any]) -> Optional[str]:
    claimant = _json_object(seed_packet.get("claimant_identity"))
    return (
        _string_or_none(claimant.get("subject_id"))
        or _string_or_none(claimant.get("identity_ref"))
        or _string_or_none(seed_packet.get("claimant_identity"))
    )


def _seed_authority_lease_id(seed_packet: Mapping[str, Any]) -> Optional[str]:
    lease = _json_object(seed_packet.get("authority_lease"))
    return (
        _string_or_none(lease.get("lease_ref"))
        or _string_or_none(lease.get("lease_id"))
        or _string_or_none(seed_packet.get("authority_lease_id"))
    )


def init_sab_seeding_storage(conn: sqlite3.Connection) -> None:
    """Create or migrate SAB seeding tables idempotently."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_identities (
            subject_id TEXT PRIMARY KEY,
            identity_ref TEXT,
            schema TEXT NOT NULL DEFAULT 'sab.agent_identity.v1',
            display_name TEXT,
            identity_rail TEXT,
            public_key TEXT,
            controller TEXT,
            operator_backing_json TEXT NOT NULL DEFAULT '{}',
            identity_json TEXT NOT NULL,
            revocation_status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    _ensure_column(conn, "agent_identities", "identity_ref", "identity_ref TEXT")
    _ensure_column(
        conn,
        "agent_identities",
        "schema",
        "schema TEXT DEFAULT 'sab.agent_identity.v1'",
    )
    _ensure_column(conn, "agent_identities", "display_name", "display_name TEXT")
    _ensure_column(conn, "agent_identities", "identity_rail", "identity_rail TEXT")
    _ensure_column(conn, "agent_identities", "public_key", "public_key TEXT")
    _ensure_column(conn, "agent_identities", "controller", "controller TEXT")
    _ensure_column(
        conn,
        "agent_identities",
        "operator_backing_json",
        "operator_backing_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(
        conn,
        "agent_identities",
        "identity_json",
        "identity_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(
        conn,
        "agent_identities",
        "revocation_status",
        "revocation_status TEXT NOT NULL DEFAULT 'active'",
    )
    _ensure_column(conn, "agent_identities", "created_at", "created_at TEXT")
    _ensure_column(conn, "agent_identities", "updated_at", "updated_at TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS external_identity_attestations (
            attestation_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            external_subject TEXT,
            attestation_json TEXT NOT NULL,
            evidence_hash TEXT,
            token_digest TEXT,
            status TEXT NOT NULL DEFAULT 'verified',
            verified_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    _ensure_column(conn, "external_identity_attestations", "subject_id", "subject_id TEXT")
    _ensure_column(conn, "external_identity_attestations", "provider", "provider TEXT")
    _ensure_column(
        conn,
        "external_identity_attestations",
        "external_subject",
        "external_subject TEXT",
    )
    _ensure_column(
        conn,
        "external_identity_attestations",
        "attestation_json",
        "attestation_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(conn, "external_identity_attestations", "evidence_hash", "evidence_hash TEXT")
    _ensure_column(conn, "external_identity_attestations", "token_digest", "token_digest TEXT")
    _ensure_column(
        conn,
        "external_identity_attestations",
        "status",
        "status TEXT NOT NULL DEFAULT 'verified'",
    )
    _ensure_column(conn, "external_identity_attestations", "verified_at", "verified_at TEXT")
    _ensure_column(conn, "external_identity_attestations", "created_at", "created_at TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS authority_leases (
            lease_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            scope TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT NOT NULL,
            revoker TEXT NOT NULL,
            challenge_path TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            witness_event_id TEXT,
            lease_json TEXT NOT NULL,
            lease_sha256 TEXT NOT NULL
        )
        """
    )
    _ensure_column(conn, "authority_leases", "subject_id", "subject_id TEXT")
    _ensure_column(conn, "authority_leases", "purpose", "purpose TEXT")
    _ensure_column(conn, "authority_leases", "scope", "scope TEXT")
    _ensure_column(conn, "authority_leases", "status", "status TEXT NOT NULL DEFAULT 'active'")
    _ensure_column(conn, "authority_leases", "expires_at", "expires_at TEXT")
    _ensure_column(conn, "authority_leases", "revoker", "revoker TEXT")
    _ensure_column(conn, "authority_leases", "challenge_path", "challenge_path TEXT")
    _ensure_column(conn, "authority_leases", "issued_at", "issued_at TEXT")
    _ensure_column(conn, "authority_leases", "witness_event_id", "witness_event_id TEXT")
    _ensure_column(conn, "authority_leases", "lease_json", "lease_json TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "authority_leases", "lease_sha256", "lease_sha256 TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seed_packets (
            seed_id TEXT PRIMARY KEY,
            claim_id TEXT,
            claimant_identity TEXT,
            authority_lease_id TEXT,
            seed_type TEXT,
            title TEXT,
            status TEXT NOT NULL DEFAULT 'pending_seed',
            privacy_class TEXT,
            created_at TEXT,
            received_at TEXT NOT NULL,
            seed_packet_json TEXT NOT NULL,
            seed_packet_sha256 TEXT NOT NULL,
            spark_id INTEGER,
            witness_head_hash TEXT
        )
        """
    )
    _ensure_column(conn, "seed_packets", "claim_id", "claim_id TEXT")
    _ensure_column(conn, "seed_packets", "claimant_identity", "claimant_identity TEXT")
    _ensure_column(conn, "seed_packets", "authority_lease_id", "authority_lease_id TEXT")
    _ensure_column(conn, "seed_packets", "seed_type", "seed_type TEXT")
    _ensure_column(conn, "seed_packets", "title", "title TEXT")
    _ensure_column(conn, "seed_packets", "status", "status TEXT NOT NULL DEFAULT 'pending_seed'")
    _ensure_column(conn, "seed_packets", "privacy_class", "privacy_class TEXT")
    _ensure_column(conn, "seed_packets", "created_at", "created_at TEXT")
    _ensure_column(conn, "seed_packets", "received_at", "received_at TEXT")
    _ensure_column(
        conn,
        "seed_packets",
        "seed_packet_json",
        "seed_packet_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(conn, "seed_packets", "seed_packet_sha256", "seed_packet_sha256 TEXT")
    _ensure_column(conn, "seed_packets", "spark_id", "spark_id INTEGER")
    _ensure_column(conn, "seed_packets", "witness_head_hash", "witness_head_hash TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seed_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            seed_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_identity TEXT,
            status TEXT,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            witness_event_id TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    _ensure_column(conn, "seed_events", "event_id", "event_id TEXT")
    _ensure_column(conn, "seed_events", "seed_id", "seed_id TEXT")
    _ensure_column(conn, "seed_events", "event_type", "event_type TEXT")
    _ensure_column(conn, "seed_events", "actor_identity", "actor_identity TEXT")
    _ensure_column(conn, "seed_events", "status", "status TEXT")
    _ensure_column(conn, "seed_events", "payload_json", "payload_json TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "seed_events", "payload_hash", "payload_hash TEXT")
    _ensure_column(conn, "seed_events", "witness_event_id", "witness_event_id TEXT")
    _ensure_column(conn, "seed_events", "created_at", "created_at TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS challenge_packets (
            challenge_id TEXT PRIMARY KEY,
            target_seed_id TEXT NOT NULL,
            target_claim_id TEXT,
            challenger_identity TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            deadline TEXT,
            created_at TEXT,
            challenge_packet_json TEXT NOT NULL,
            challenge_packet_sha256 TEXT NOT NULL,
            spark_challenge_id INTEGER
        )
        """
    )
    _ensure_column(conn, "challenge_packets", "target_seed_id", "target_seed_id TEXT")
    _ensure_column(conn, "challenge_packets", "target_claim_id", "target_claim_id TEXT")
    _ensure_column(conn, "challenge_packets", "challenger_identity", "challenger_identity TEXT")
    _ensure_column(conn, "challenge_packets", "status", "status TEXT NOT NULL DEFAULT 'pending'")
    _ensure_column(conn, "challenge_packets", "deadline", "deadline TEXT")
    _ensure_column(conn, "challenge_packets", "created_at", "created_at TEXT")
    _ensure_column(
        conn,
        "challenge_packets",
        "challenge_packet_json",
        "challenge_packet_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(
        conn,
        "challenge_packets",
        "challenge_packet_sha256",
        "challenge_packet_sha256 TEXT",
    )
    _ensure_column(conn, "challenge_packets", "spark_challenge_id", "spark_challenge_id INTEGER")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS witness_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            actor_identity TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            seed_id TEXT,
            standing_id TEXT,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            payload_ref TEXT NOT NULL DEFAULT 'inline',
            payload_json TEXT NOT NULL,
            verification_policy_version TEXT NOT NULL,
            signature_json TEXT NOT NULL DEFAULT '{}',
            witness_event_json TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            chain_head_hash TEXT NOT NULL
        )
        """
    )
    _ensure_column(conn, "witness_events", "event_id", "event_id TEXT")
    _ensure_column(conn, "witness_events", "event_type", "event_type TEXT")
    _ensure_column(conn, "witness_events", "actor_identity", "actor_identity TEXT")
    _ensure_column(conn, "witness_events", "subject_type", "subject_type TEXT")
    _ensure_column(conn, "witness_events", "subject_id", "subject_id TEXT")
    _ensure_column(conn, "witness_events", "seed_id", "seed_id TEXT")
    _ensure_column(conn, "witness_events", "standing_id", "standing_id TEXT")
    _ensure_column(conn, "witness_events", "timestamp", "timestamp TEXT")
    _ensure_column(conn, "witness_events", "prev_hash", "prev_hash TEXT")
    _ensure_column(conn, "witness_events", "payload_hash", "payload_hash TEXT")
    _ensure_column(
        conn,
        "witness_events",
        "payload_ref",
        "payload_ref TEXT NOT NULL DEFAULT 'inline'",
    )
    _ensure_column(
        conn,
        "witness_events",
        "payload_json",
        "payload_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(
        conn,
        "witness_events",
        "verification_policy_version",
        "verification_policy_version TEXT NOT NULL DEFAULT 'sab-seeding-storage-v1'",
    )
    _ensure_column(
        conn,
        "witness_events",
        "signature_json",
        "signature_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(
        conn,
        "witness_events",
        "witness_event_json",
        "witness_event_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(conn, "witness_events", "event_hash", "event_hash TEXT")
    _ensure_column(conn, "witness_events", "chain_head_hash", "chain_head_hash TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS standing_leases (
            standing_id TEXT PRIMARY KEY,
            subject_seed_id TEXT NOT NULL,
            subject_claim_id TEXT,
            scope TEXT NOT NULL,
            purpose TEXT,
            status TEXT NOT NULL,
            expiry TEXT NOT NULL,
            revoker TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            issued_by TEXT,
            standing_lease_json TEXT NOT NULL,
            standing_lease_sha256 TEXT NOT NULL,
            witness_head_hash TEXT
        )
        """
    )
    _ensure_column(conn, "standing_leases", "subject_seed_id", "subject_seed_id TEXT")
    _ensure_column(conn, "standing_leases", "subject_claim_id", "subject_claim_id TEXT")
    _ensure_column(conn, "standing_leases", "scope", "scope TEXT")
    _ensure_column(conn, "standing_leases", "purpose", "purpose TEXT")
    _ensure_column(conn, "standing_leases", "status", "status TEXT")
    _ensure_column(conn, "standing_leases", "expiry", "expiry TEXT")
    _ensure_column(conn, "standing_leases", "revoker", "revoker TEXT")
    _ensure_column(conn, "standing_leases", "issued_at", "issued_at TEXT")
    _ensure_column(conn, "standing_leases", "issued_by", "issued_by TEXT")
    _ensure_column(
        conn,
        "standing_leases",
        "standing_lease_json",
        "standing_lease_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(conn, "standing_leases", "standing_lease_sha256", "standing_lease_sha256 TEXT")
    _ensure_column(conn, "standing_leases", "witness_head_hash", "witness_head_hash TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS standing_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            standing_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_identity TEXT,
            status TEXT,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            witness_event_id TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    _ensure_column(conn, "standing_events", "event_id", "event_id TEXT")
    _ensure_column(conn, "standing_events", "standing_id", "standing_id TEXT")
    _ensure_column(conn, "standing_events", "event_type", "event_type TEXT")
    _ensure_column(conn, "standing_events", "actor_identity", "actor_identity TEXT")
    _ensure_column(conn, "standing_events", "status", "status TEXT")
    _ensure_column(
        conn,
        "standing_events",
        "payload_json",
        "payload_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(conn, "standing_events", "payload_hash", "payload_hash TEXT")
    _ensure_column(conn, "standing_events", "witness_event_id", "witness_event_id TEXT")
    _ensure_column(conn, "standing_events", "created_at", "created_at TEXT")

    _ensure_spark_projection_columns(conn)
    _create_indexes(conn)


def _ensure_spark_projection_columns(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "sparks"):
        return
    _ensure_column(conn, "sparks", "claim_packet_ref", "claim_packet_ref TEXT")
    _ensure_column(
        conn,
        "sparks",
        "artifact_refs_json",
        "artifact_refs_json TEXT NOT NULL DEFAULT '[]'",
    )
    _ensure_column(
        conn,
        "sparks",
        "red_team_refs_json",
        "red_team_refs_json TEXT NOT NULL DEFAULT '[]'",
    )
    _ensure_column(
        conn,
        "sparks",
        "witness_refs_json",
        "witness_refs_json TEXT NOT NULL DEFAULT '[]'",
    )
    _ensure_column(conn, "sparks", "lineage_root_id", "lineage_root_id INTEGER")
    _ensure_column(conn, "sparks", "parent_spark_id", "parent_spark_id INTEGER")
    _ensure_column(conn, "sparks", "sublation_status", "sublation_status TEXT")
    _ensure_column(conn, "sparks", "founding_seed", "founding_seed INTEGER NOT NULL DEFAULT 0")


def _create_indexes(conn: sqlite3.Connection) -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_agent_identities_status "
        "ON agent_identities(revocation_status)",
        "CREATE INDEX IF NOT EXISTS idx_external_attestations_subject "
        "ON external_identity_attestations(subject_id)",
        "CREATE INDEX IF NOT EXISTS idx_external_attestations_provider "
        "ON external_identity_attestations(provider, status)",
        "CREATE INDEX IF NOT EXISTS idx_authority_leases_subject_status "
        "ON authority_leases(subject_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_authority_leases_status ON authority_leases(status)",
        "CREATE INDEX IF NOT EXISTS idx_seed_packets_seed_id ON seed_packets(seed_id)",
        "CREATE INDEX IF NOT EXISTS idx_seed_packets_claim_id ON seed_packets(claim_id)",
        "CREATE INDEX IF NOT EXISTS idx_seed_packets_claimant_identity "
        "ON seed_packets(claimant_identity)",
        "CREATE INDEX IF NOT EXISTS idx_seed_packets_status ON seed_packets(status)",
        "CREATE INDEX IF NOT EXISTS idx_seed_packets_authority_lease "
        "ON seed_packets(authority_lease_id)",
        "CREATE INDEX IF NOT EXISTS idx_seed_packets_witness_head "
        "ON seed_packets(witness_head_hash)",
        "CREATE INDEX IF NOT EXISTS idx_seed_events_seed_id ON seed_events(seed_id)",
        "CREATE INDEX IF NOT EXISTS idx_seed_events_status ON seed_events(status)",
        "CREATE INDEX IF NOT EXISTS idx_challenge_packets_seed_id "
        "ON challenge_packets(target_seed_id)",
        "CREATE INDEX IF NOT EXISTS idx_challenge_packets_claim_id "
        "ON challenge_packets(target_claim_id)",
        "CREATE INDEX IF NOT EXISTS idx_challenge_packets_challenger_identity "
        "ON challenge_packets(challenger_identity)",
        "CREATE INDEX IF NOT EXISTS idx_challenge_packets_status ON challenge_packets(status)",
        "CREATE INDEX IF NOT EXISTS idx_witness_events_seed_id ON witness_events(seed_id)",
        "CREATE INDEX IF NOT EXISTS idx_witness_events_standing_id "
        "ON witness_events(standing_id)",
        "CREATE INDEX IF NOT EXISTS idx_witness_events_subject "
        "ON witness_events(subject_type, subject_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_witness_events_chain_head "
        "ON witness_events(chain_head_hash)",
        "CREATE INDEX IF NOT EXISTS idx_standing_leases_standing_id "
        "ON standing_leases(standing_id)",
        "CREATE INDEX IF NOT EXISTS idx_standing_leases_seed_id "
        "ON standing_leases(subject_seed_id)",
        "CREATE INDEX IF NOT EXISTS idx_standing_leases_claim_id "
        "ON standing_leases(subject_claim_id)",
        "CREATE INDEX IF NOT EXISTS idx_standing_leases_status ON standing_leases(status)",
        "CREATE INDEX IF NOT EXISTS idx_standing_leases_witness_head "
        "ON standing_leases(witness_head_hash)",
        "CREATE INDEX IF NOT EXISTS idx_standing_events_standing_id "
        "ON standing_events(standing_id)",
        "CREATE INDEX IF NOT EXISTS idx_standing_events_status ON standing_events(status)",
    ]
    if _table_exists(conn, "sparks"):
        statements.append(
            "CREATE INDEX IF NOT EXISTS idx_sparks_claim_packet_ref "
            "ON sparks(claim_packet_ref)"
        )

    for statement in statements:
        conn.execute(statement)


def persist_seed_packet(
    conn: sqlite3.Connection,
    seed_packet: Mapping[str, Any],
    *,
    received_at: Optional[str] = None,
    spark_id: Optional[int] = None,
) -> dict[str, Any]:
    """Persist a canonical seed packet without mutating its hash material."""

    seed_id = _require_text(seed_packet.get("seed_id"), "seed_id")
    claim = _seed_claim(seed_packet)
    claim_id = _string_or_none(claim.get("claim_id"))
    claimant_identity = _seed_claimant_identity(seed_packet)
    authority_lease_id = _seed_authority_lease_id(seed_packet)
    status = _string_or_none(seed_packet.get("status")) or "pending_seed"
    packet_json = canonical_json(seed_packet)
    packet_hash = sha256_text(packet_json)

    existing = conn.execute(
        "SELECT * FROM seed_packets WHERE seed_id = ?",
        (seed_id,),
    ).fetchone()
    if existing is not None:
        existing_hash = str(existing["seed_packet_sha256"])
        if existing_hash != packet_hash:
            raise ValueError(f"seed_id {seed_id!r} already exists with different hash material")
        if spark_id is not None and existing["spark_id"] is None:
            conn.execute(
                "UPDATE seed_packets SET spark_id = ? WHERE seed_id = ?",
                (spark_id, seed_id),
            )
        return _row_to_dict(
            conn.execute("SELECT * FROM seed_packets WHERE seed_id = ?", (seed_id,)).fetchone()
        )

    conn.execute(
        """
        INSERT INTO seed_packets (
            seed_id,
            claim_id,
            claimant_identity,
            authority_lease_id,
            seed_type,
            title,
            status,
            privacy_class,
            created_at,
            received_at,
            seed_packet_json,
            seed_packet_sha256,
            spark_id,
            witness_head_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            seed_id,
            claim_id,
            claimant_identity,
            authority_lease_id,
            _string_or_none(seed_packet.get("seed_type")),
            _string_or_none(seed_packet.get("title")),
            status,
            _string_or_none(seed_packet.get("privacy_class")),
            _string_or_none(seed_packet.get("created_at")),
            received_at or utc_now(),
            packet_json,
            packet_hash,
            spark_id,
            None,
        ),
    )
    row = conn.execute("SELECT * FROM seed_packets WHERE seed_id = ?", (seed_id,)).fetchone()
    return _row_to_dict(row)


def get_seed_packet(conn: sqlite3.Connection, seed_id: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM seed_packets WHERE seed_id = ?", (seed_id,)).fetchone()
    return _row_to_dict(row) if row is not None else None


def append_witness_event(
    conn: sqlite3.Connection,
    witness_event: Mapping[str, Any],
    *,
    seed_id: Optional[str] = None,
    standing_id: Optional[str] = None,
) -> dict[str, Any]:
    """Append a canonical, per-subject hash-linked witness event."""

    event_id = _require_text(witness_event.get("event_id"), "event_id")
    event_type = _require_text(witness_event.get("event_type"), "event_type")
    actor_identity = _require_text(witness_event.get("actor_identity"), "actor_identity")
    subject_type = _require_text(witness_event.get("subject_type"), "subject_type")
    subject_id = _require_text(witness_event.get("subject_id"), "subject_id")

    existing = conn.execute(
        "SELECT * FROM witness_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if existing is not None:
        existing_doc = json.loads(str(existing["witness_event_json"]))
        duplicate_candidate = dict(witness_event)
        duplicate_candidate.setdefault("timestamp", existing["timestamp"])
        duplicate_candidate.setdefault("prev_hash", existing["prev_hash"])
        candidate_doc, _, candidate_hash = _build_witness_event_doc(
            conn,
            duplicate_candidate,
            use_existing_prev_hash=str(existing["prev_hash"]),
        )
        if existing_doc != candidate_doc or str(existing["event_hash"]) != candidate_hash:
            raise ValueError(
                f"witness event {event_id!r} already exists with different hash material"
            )
        return _row_to_dict(existing)

    event_doc, payload_json, event_hash = _build_witness_event_doc(conn, witness_event)
    event_seed_id = seed_id or _string_or_none(witness_event.get("seed_id"))
    event_standing_id = standing_id or _string_or_none(witness_event.get("standing_id"))
    if event_seed_id is None and subject_type == "seed":
        event_seed_id = subject_id
    if event_standing_id is None and subject_type == "standing":
        event_standing_id = subject_id

    witness_event_json = canonical_json(event_doc)
    signature_json = canonical_json(_json_object(event_doc.get("signature")))
    conn.execute(
        """
        INSERT INTO witness_events (
            event_id,
            event_type,
            actor_identity,
            subject_type,
            subject_id,
            seed_id,
            standing_id,
            timestamp,
            prev_hash,
            payload_hash,
            payload_ref,
            payload_json,
            verification_policy_version,
            signature_json,
            witness_event_json,
            event_hash,
            chain_head_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            event_type,
            actor_identity,
            subject_type,
            subject_id,
            event_seed_id,
            event_standing_id,
            event_doc["timestamp"],
            event_doc["prev_hash"],
            event_doc["payload_hash"],
            event_doc["payload_ref"],
            payload_json,
            event_doc["verification_policy_version"],
            signature_json,
            witness_event_json,
            event_hash,
            event_hash,
        ),
    )

    if event_seed_id is not None:
        conn.execute(
            "UPDATE seed_packets SET witness_head_hash = ? WHERE seed_id = ?",
            (event_hash, event_seed_id),
        )
    if event_standing_id is not None:
        conn.execute(
            "UPDATE standing_leases SET witness_head_hash = ? WHERE standing_id = ?",
            (event_hash, event_standing_id),
        )

    row = conn.execute("SELECT * FROM witness_events WHERE event_id = ?", (event_id,)).fetchone()
    return _row_to_dict(row)


def _build_witness_event_doc(
    conn: sqlite3.Connection,
    witness_event: Mapping[str, Any],
    *,
    use_existing_prev_hash: Optional[str] = None,
) -> tuple[dict[str, Any], str, str]:
    subject_type = _require_text(witness_event.get("subject_type"), "subject_type")
    subject_id = _require_text(witness_event.get("subject_id"), "subject_id")
    payload = _json_object(witness_event.get("payload"))
    payload_json = canonical_json(payload)
    payload_hash = _string_or_none(witness_event.get("payload_hash")) or sha256_text(payload_json)
    prev_hash = use_existing_prev_hash or _latest_witness_hash(conn, subject_type, subject_id)
    provided_prev_hash = _string_or_none(witness_event.get("prev_hash"))
    if provided_prev_hash is not None and provided_prev_hash != prev_hash:
        raise ValueError(
            f"prev_hash mismatch for {subject_type}:{subject_id}: "
            f"expected {prev_hash!r}, got {provided_prev_hash!r}"
        )

    event_doc = {
        "schema": _string_or_none(witness_event.get("schema")) or "sab.witness_event.v1",
        "event_id": _require_text(witness_event.get("event_id"), "event_id"),
        "event_type": _require_text(witness_event.get("event_type"), "event_type"),
        "actor_identity": _require_text(witness_event.get("actor_identity"), "actor_identity"),
        "subject_type": subject_type,
        "subject_id": subject_id,
        "timestamp": _string_or_none(witness_event.get("timestamp")) or utc_now(),
        "prev_hash": prev_hash,
        "payload_hash": payload_hash,
        "payload_ref": _string_or_none(witness_event.get("payload_ref")) or "inline",
        "verification_policy_version": (
            _string_or_none(witness_event.get("verification_policy_version"))
            or DEFAULT_WITNESS_POLICY_VERSION
        ),
        "signature": _json_object(witness_event.get("signature")),
    }
    event_hash = sha256_text(canonical_json(event_doc))
    return event_doc, payload_json, event_hash


def _latest_witness_hash(conn: sqlite3.Connection, subject_type: str, subject_id: str) -> str:
    row = conn.execute(
        """
        SELECT event_hash
        FROM witness_events
        WHERE subject_type = ? AND subject_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (subject_type, subject_id),
    ).fetchone()
    return str(row["event_hash"]) if row is not None else GENESIS_HASH


def seed_packet_to_spark_projection(
    seed_packet: Mapping[str, Any],
    *,
    gate_scores: Optional[Mapping[str, Any]] = None,
    spark_status: Optional[str] = None,
) -> dict[str, Any]:
    seed_id = _require_text(seed_packet.get("seed_id"), "seed_id")
    claim = _seed_claim(seed_packet)
    claim_text = _string_or_none(claim.get("text"))
    title = _string_or_none(seed_packet.get("title"))
    packet_hash = canonical_payload_sha256(seed_packet)
    claimant_identity = _seed_claimant_identity(seed_packet) or "unknown"
    seed_status = _string_or_none(seed_packet.get("status")) or "pending_seed"
    projection_scores = dict(gate_scores or {})
    projection_scores.setdefault("sab_seed_projection", True)
    projection_scores.setdefault("seed_id", seed_id)
    if _string_or_none(claim.get("claim_id")):
        projection_scores.setdefault("claim_id", _string_or_none(claim.get("claim_id")))
    projection_scores.setdefault("seed_packet_sha256", packet_hash)

    evidence_refs = [
        str(item.get("ref"))
        for item in _json_array(seed_packet.get("evidence_bundle"))
        if isinstance(item, Mapping) and _string_or_none(item.get("ref"))
    ]
    challenge_plan = _json_object(seed_packet.get("challenge_plan"))
    red_team_refs = [
        str(item)
        for item in _json_array(challenge_plan.get("challenge_refs"))
        if _string_or_none(item)
    ]
    witness_plan = _json_object(seed_packet.get("witness_plan"))
    witness_refs = [
        str(item)
        for item in _json_array(witness_plan.get("required_roles"))
        if _string_or_none(item)
    ]

    return {
        "content": claim_text or title or seed_id,
        "content_type": _string_or_none(seed_packet.get("seed_type")) or "seed",
        "author_id": claimant_identity,
        "created_at": _string_or_none(seed_packet.get("created_at")) or utc_now(),
        "gate_scores": projection_scores,
        "status": spark_status or _seed_status_to_spark_status(seed_status),
        "rv_contraction": None,
        "composite_score": float(projection_scores.get("composite", 0.0) or 0.0),
        "node_coordinate": _string_or_none(seed_packet.get("node_coordinate")),
        "claim_packet_ref": seed_id,
        "artifact_refs": evidence_refs,
        "red_team_refs": red_team_refs,
        "witness_refs": witness_refs,
        "sublation_status": "seed_projection",
        "founding_seed": 0,
    }


def upsert_spark_projection(
    conn: sqlite3.Connection,
    seed_id: str,
    *,
    gate_scores: Optional[Mapping[str, Any]] = None,
    spark_status: Optional[str] = None,
) -> dict[str, Any]:
    """Create or return a ``sparks`` projection for a stored seed packet."""

    if not _table_exists(conn, "sparks"):
        raise ValueError("sparks table is required before creating a seed projection")
    _ensure_spark_projection_columns(conn)

    seed_row = conn.execute("SELECT * FROM seed_packets WHERE seed_id = ?", (seed_id,)).fetchone()
    if seed_row is None:
        raise ValueError(f"unknown seed_id: {seed_id}")
    seed_packet = json.loads(str(seed_row["seed_packet_json"]))
    projection = seed_packet_to_spark_projection(
        seed_packet,
        gate_scores=gate_scores,
        spark_status=spark_status,
    )

    if seed_row["spark_id"] is not None:
        spark = conn.execute(
            "SELECT * FROM sparks WHERE id = ?",
            (int(seed_row["spark_id"]),),
        ).fetchone()
        if spark is not None:
            return _row_to_dict(spark)

    existing = conn.execute(
        "SELECT * FROM sparks WHERE claim_packet_ref = ? ORDER BY id ASC LIMIT 1",
        (seed_id,),
    ).fetchone()
    if existing is not None:
        spark_id = int(existing["id"])
        conn.execute("UPDATE seed_packets SET spark_id = ? WHERE seed_id = ?", (spark_id, seed_id))
        return _row_to_dict(existing)

    columns = _table_columns(conn, "sparks")
    insert_values: dict[str, Any] = {
        "content": projection["content"],
        "content_type": projection["content_type"],
        "author_id": projection["author_id"],
        "created_at": projection["created_at"],
        "gate_scores": canonical_json(projection["gate_scores"]),
        "status": projection["status"],
        "rv_contraction": projection["rv_contraction"],
        "composite_score": projection["composite_score"],
        "node_coordinate": projection["node_coordinate"],
        "claim_packet_ref": projection["claim_packet_ref"],
        "artifact_refs_json": json.dumps(
            projection["artifact_refs"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
        "red_team_refs_json": json.dumps(
            projection["red_team_refs"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
        "witness_refs_json": json.dumps(
            projection["witness_refs"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
        "lineage_root_id": None,
        "parent_spark_id": None,
        "sublation_status": projection["sublation_status"],
        "founding_seed": projection["founding_seed"],
    }
    selected = [name for name in insert_values if name in columns]
    required = {"content", "content_type", "author_id", "created_at", "gate_scores", "status"}
    if not required.issubset(selected):
        raise ValueError("sparks table is missing required projection columns")
    placeholders = ", ".join("?" for _ in selected)
    column_sql = ", ".join(selected)
    # `selected` contains only literal keys from `insert_values`; no caller-
    # controlled identifier reaches this statement, and every value is bound.
    cursor = conn.execute(
        f"INSERT INTO sparks ({column_sql}) VALUES ({placeholders})",  # nosec B608
        tuple(insert_values[name] for name in selected),
    )
    spark_id = int(cursor.lastrowid)
    if "lineage_root_id" in columns:
        conn.execute(
            "UPDATE sparks SET lineage_root_id = COALESCE(lineage_root_id, ?) WHERE id = ?",
            (spark_id, spark_id),
        )
    conn.execute("UPDATE seed_packets SET spark_id = ? WHERE seed_id = ?", (spark_id, seed_id))
    row = conn.execute("SELECT * FROM sparks WHERE id = ?", (spark_id,)).fetchone()
    return _row_to_dict(row)


def _seed_status_to_spark_status(seed_status: str) -> str:
    if seed_status in {"canon", "standing", "standing_active", "canon_candidate"}:
        return "canon"
    if seed_status in {"compost", "rejected", "revoked", "expired"}:
        return "compost"
    return "spark"


def _row_to_dict(row: Optional[sqlite3.Row]) -> dict[str, Any]:
    if row is None:
        return {}
    return {key: row[key] for key in row.keys()}
