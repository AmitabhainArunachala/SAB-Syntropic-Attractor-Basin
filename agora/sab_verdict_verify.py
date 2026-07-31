"""Offline verification for SAB First Verdict evidence.

Legacy witness rows are verified only as hash-linked history.  They are never
promoted to signature-verified evidence.  New Build A artifacts use explicit
Ed25519 public keys and canonical signed payloads and are reported as a
separate ``SignaturesVerified`` suffix.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .sab_first_verdict_evidence import canonical_json_bytes


HASH_LINKED = "HashLinked"
SIGNATURES_VERIFIED = "SignaturesVerified"


class ReplayValidationError(ValueError):
    """A fail-closed replay error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _legacy_event_material(event: Mapping[str, Any]) -> dict[str, Any]:
    required = (
        "event_id",
        "chain_scope",
        "event_type",
        "actor_identity",
        "subject_type",
        "subject_id",
        "subject_seed_id",
        "timestamp",
        "payload_hash",
        "payload_json",
        "signature",
        "prev_hash",
    )
    missing = [field for field in required if field not in event]
    if missing:
        raise ReplayValidationError(
            "legacy_event_fields_missing", f"legacy witness event is missing {missing}"
        )
    return {field: event[field] for field in required}


def verify_legacy_witness_prefix(
    events: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Verify per-scope hashes for legacy SAB witness rows.

    This checks linkage and stored event hashes, not Ed25519 semantics.  The
    output proof class is therefore always ``HashLinked`` on success.
    """

    ordered = sorted(
        (dict(event) for event in events),
        key=lambda event: (str(event.get("chain_scope", "")), int(event.get("id", 0))),
    )
    heads: dict[str, str] = {}
    counts: defaultdict[str, int] = defaultdict(int)
    seen_event_ids: set[str] = set()
    for event in ordered:
        material = _legacy_event_material(event)
        event_id = str(material["event_id"])
        if event_id in seen_event_ids:
            raise ReplayValidationError(
                "duplicate_legacy_event", f"duplicate legacy event_id {event_id}"
            )
        seen_event_ids.add(event_id)
        scope = str(material["chain_scope"])
        expected_prev = heads.get(scope, "genesis")
        if material["prev_hash"] != expected_prev:
            raise ReplayValidationError(
                "legacy_prev_hash_mismatch",
                f"legacy witness predecessor mismatch in {scope}",
            )
        computed_hash = _sha256_bytes(
            json.dumps(
                material,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        )
        if event.get("event_hash") != computed_hash:
            raise ReplayValidationError(
                "legacy_event_hash_mismatch",
                f"legacy witness hash mismatch for {event_id}",
            )
        heads[scope] = computed_hash
        counts[scope] += 1
    return {
        "proof_class": HASH_LINKED,
        "signature_claim": "not_evaluated_not_implied",
        "event_count": len(ordered),
        "scope_counts": dict(sorted(counts.items())),
        "heads": dict(sorted(heads.items())),
        "verified": True,
    }


def verify_ed25519_payload(
    *,
    public_key_hex: str,
    signed_payload: Mapping[str, Any],
    signature_hex: str,
    canonicalization: str = "json-sort-keys-compact-v1",
) -> bool:
    if canonicalization == "canonical_json_v1":
        message = canonical_json_bytes(dict(signed_payload))
    elif canonicalization == "json-sort-keys-compact-v1":
        message = json.dumps(
            dict(signed_payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    else:
        return False
    try:
        key = VerifyKey(public_key_hex.encode("ascii"), encoder=HexEncoder)
        key.verify(message, bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError, TypeError, UnicodeEncodeError):
        return False


def verify_new_signature_suffix(
    records: Sequence[Mapping[str, Any]],
    *,
    required_artifact_types: Iterable[str] = (),
) -> dict[str, Any]:
    """Independently verify every new signature and reject replay/duplicates."""

    required = set(required_artifact_types)
    seen_types: set[str] = set()
    seen_ids: set[str] = set()
    seen_signatures: dict[str, str] = {}
    verified: list[dict[str, Any]] = []
    for record in records:
        artifact_type = str(record.get("artifact_type", "")).strip()
        artifact_id = str(record.get("artifact_id", "")).strip()
        raw_signature = record.get("signature")
        if isinstance(raw_signature, Mapping):
            signer = str(raw_signature.get("signer", "")).strip()
            public_key = str(raw_signature.get("public_key", "")).strip().lower()
            signature = str(raw_signature.get("signature", "")).strip().lower()
            canonicalization = raw_signature.get("canonicalization")
            declared_payload_sha256 = raw_signature.get("signed_payload_sha256")
        else:
            signer = str(record.get("signer", "")).strip()
            public_key = str(record.get("public_key", "")).strip().lower()
            signature = str(raw_signature or "").strip().lower()
            canonicalization = record.get("canonicalization")
            declared_payload_sha256 = record.get("signed_payload_sha256")
        signed_payload = record.get("signed_payload")
        if not artifact_type or not artifact_id or not signer:
            raise ReplayValidationError(
                "signature_identity_missing",
                "artifact type, id, and signer are required",
            )
        if canonicalization not in {
            "canonical_json_v1",
            "json-sort-keys-compact-v1",
        }:
            raise ReplayValidationError(
                "canonicalization_unsupported",
                "new signature canonicalization is unsupported",
            )
        if not isinstance(signed_payload, Mapping):
            raise ReplayValidationError(
                "signed_payload_missing",
                f"{artifact_id} has no canonical signed payload",
            )
        if artifact_id in seen_ids:
            raise ReplayValidationError(
                "duplicate_artifact_id", f"duplicate signed artifact id {artifact_id}"
            )
        seen_ids.add(artifact_id)
        if canonicalization == "canonical_json_v1":
            message = canonical_json_bytes(dict(signed_payload))
        else:
            message = json.dumps(
                dict(signed_payload),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        payload_sha256 = _sha256_bytes(message)
        if (
            declared_payload_sha256 is not None
            and declared_payload_sha256 != payload_sha256
        ):
            raise ReplayValidationError(
                "signed_payload_hash_mismatch",
                f"payload digest mismatch for {artifact_id}",
            )
        prior_payload = seen_signatures.get(signature)
        if prior_payload is not None:
            reason = (
                "duplicate_signature"
                if prior_payload == payload_sha256
                else "signature_reused_for_different_payload"
            )
            raise ReplayValidationError(
                reason, f"signature replay detected for {artifact_id}"
            )
        if not verify_ed25519_payload(
            public_key_hex=public_key,
            signed_payload=signed_payload,
            signature_hex=signature,
            canonicalization=str(canonicalization),
        ):
            raise ReplayValidationError(
                "signature_invalid", f"Ed25519 signature invalid for {artifact_id}"
            )
        seen_signatures[signature] = payload_sha256
        seen_types.add(artifact_type)
        verified.append(
            {
                "artifact_type": artifact_type,
                "artifact_id": artifact_id,
                "signer": signer,
                "public_key_sha256": _sha256_bytes(public_key.encode("ascii")),
                "signed_payload_sha256": payload_sha256,
                "signature_sha256": _sha256_bytes(signature.encode("ascii")),
            }
        )
    missing = sorted(required - seen_types)
    if missing:
        raise ReplayValidationError(
            "required_signature_types_missing",
            f"required signed artifact types missing: {missing}",
        )
    return {
        "proof_class": SIGNATURES_VERIFIED,
        "verified": True,
        "signature_count": len(verified),
        "artifact_types": sorted(seen_types),
        "records": verified,
    }


def verify_evidence_partition(
    *,
    legacy_events: Iterable[Mapping[str, Any]],
    new_signature_records: Sequence[Mapping[str, Any]],
    required_artifact_types: Iterable[str] = (),
) -> dict[str, Any]:
    """Return two explicit proof classes without laundering legacy evidence."""

    return {
        "legacy_prefix": verify_legacy_witness_prefix(legacy_events),
        "new_suffix": verify_new_signature_suffix(
            new_signature_records,
            required_artifact_types=required_artifact_types,
        ),
        "legacy_promoted_to_signature_verified": False,
    }


def _contract_canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _signed_event_hash(row: Mapping[str, Any]) -> str:
    material = {
        field: row[field]
        for field in (
            "event_id",
            "event_type",
            "signer",
            "public_key",
            "prev_hash",
            "payload_sha256",
            "signature",
            "created_at",
        )
    }
    return _sha256_bytes(_contract_canonical_bytes(material))


def verify_new_signature_table(
    conn: sqlite3.Connection,
    *,
    required_event_types: Iterable[str] = (),
    require_nonempty: bool = True,
) -> dict[str, Any]:
    """Replay the new signed-event suffix directly from a copied SQLite DB."""

    table = "sab_first_verdict_signed_events_v1"
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if exists is None:
        raise ReplayValidationError(
            "signed_event_table_missing", f"copied database has no {table}"
        )
    cursor = conn.execute(
        "SELECT event_id,event_type,signer,public_key,prev_hash,payload_json,"
        "payload_sha256,signature,event_hash,created_at "
        "FROM sab_first_verdict_signed_events_v1 ORDER BY created_at,event_id"
    )
    column_names = [str(description[0]) for description in cursor.description]
    rows = [
        dict(zip(column_names, tuple(row), strict=True)) for row in cursor.fetchall()
    ]
    if require_nonempty and not rows:
        raise ReplayValidationError(
            "signed_event_suffix_empty", "new signature suffix contains no events"
        )

    by_hash: dict[str, dict[str, Any]] = {}
    next_by_previous: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
    records: list[dict[str, Any]] = []
    for row in rows:
        event_id = str(row["event_id"])
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ReplayValidationError(
                "signed_event_payload_invalid", f"invalid payload JSON for {event_id}"
            ) from exc
        if not isinstance(payload, Mapping):
            raise ReplayValidationError(
                "signed_event_payload_invalid",
                f"payload for {event_id} is not an object",
            )
        canonical_payload = _contract_canonical_bytes(payload)
        if canonical_payload.decode("utf-8") != row["payload_json"]:
            raise ReplayValidationError(
                "signed_event_payload_noncanonical",
                f"stored payload for {event_id} is not exact canonical JSON",
            )
        payload_sha256 = _sha256_bytes(canonical_payload)
        if row["payload_sha256"] != payload_sha256:
            raise ReplayValidationError(
                "signed_event_payload_hash_mismatch",
                f"stored payload digest differs for {event_id}",
            )
        event_hash = _signed_event_hash(row)
        if row["event_hash"] != event_hash:
            raise ReplayValidationError(
                "signed_event_hash_mismatch",
                f"stored event hash differs for {event_id}",
            )
        if event_hash in by_hash:
            raise ReplayValidationError(
                "duplicate_signed_event_hash", f"duplicate event hash {event_hash}"
            )
        by_hash[event_hash] = row
        previous = row["prev_hash"]
        next_by_previous[None if previous is None else str(previous)].append(row)
        records.append(
            {
                "artifact_type": str(row["event_type"]),
                "artifact_id": event_id,
                "signed_payload": dict(payload),
                "signature": {
                    "alg": "ed25519",
                    "signer": str(row["signer"]),
                    "public_key": str(row["public_key"]),
                    "signature": str(row["signature"]),
                    "signed_payload_sha256": payload_sha256,
                    "canonicalization": "json-sort-keys-compact-v1",
                },
            }
        )

    genesis = next_by_previous.get(None, [])
    if len(genesis) != 1:
        raise ReplayValidationError(
            "signed_event_genesis_invalid",
            "new suffix must contain exactly one null predecessor",
        )
    ordered_event_ids: list[str] = []
    current = genesis[0]
    while True:
        ordered_event_ids.append(str(current["event_id"]))
        successors = next_by_previous.get(str(current["event_hash"]), [])
        if len(successors) > 1:
            raise ReplayValidationError(
                "signed_event_chain_fork",
                f"new suffix forks after {current['event_id']}",
            )
        if not successors:
            break
        current = successors[0]
    if len(ordered_event_ids) != len(rows):
        raise ReplayValidationError(
            "signed_event_chain_disconnected", "new suffix contains an orphan or cycle"
        )

    replay = verify_new_signature_suffix(
        records,
        required_artifact_types=required_event_types,
    )
    replay.update(
        {
            "table": table,
            "ordered_event_ids": ordered_event_ids,
            "head_event_hash": str(current["event_hash"]),
            "signed_events": [
                {
                    "event_id": str(row["event_id"]),
                    "event_hash": str(row["event_hash"]),
                    "public_key": str(row["public_key"]),
                    "signature_verified": True,
                    "replay_result": SIGNATURES_VERIFIED,
                }
                for row in rows
            ],
        }
    )
    return replay


def signature_evidence_record_hash(row: Mapping[str, Any]) -> str:
    """Hash the exact append-only persisted-signature row material."""

    material = {
        field: row[field]
        for field in (
            "sequence_no",
            "record_id",
            "artifact_type",
            "artifact_id",
            "lifecycle_event_id",
            "signer",
            "public_key",
            "prev_hash",
            "payload_sha256",
            "canonicalization",
            "signature",
            "created_at",
        )
    }
    return _sha256_bytes(_contract_canonical_bytes(material))


def verify_signature_evidence_table(
    conn: sqlite3.Connection,
    *,
    required_artifact_types: Iterable[str] = (),
    require_nonempty: bool = True,
) -> dict[str, Any]:
    """Reconstruct and verify every persisted Build A signature after reopen."""

    table = "sab_first_verdict_signature_evidence_v1"
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if exists is None:
        raise ReplayValidationError(
            "signature_evidence_table_missing", f"copied database has no {table}"
        )
    cursor = conn.execute(
        "SELECT sequence_no,record_id,artifact_type,artifact_id,lifecycle_event_id,"
        "signer,public_key,prev_hash,payload_json,payload_sha256,canonicalization,"
        "signature,record_hash,created_at "
        "FROM sab_first_verdict_signature_evidence_v1 ORDER BY sequence_no"
    )
    columns = [str(description[0]) for description in cursor.description]
    rows = [dict(zip(columns, tuple(row), strict=True)) for row in cursor.fetchall()]
    if require_nonempty and not rows:
        raise ReplayValidationError(
            "signature_evidence_empty", "persisted signature evidence is empty"
        )

    records: list[dict[str, Any]] = []
    previous_hash: str | None = None
    ordered_record_ids: list[str] = []
    for expected_sequence, row in enumerate(rows, start=1):
        sequence_no = int(row["sequence_no"])
        record_id = str(row["record_id"])
        if sequence_no != expected_sequence:
            raise ReplayValidationError(
                "signature_evidence_sequence_gap",
                f"persisted signature sequence is not contiguous at {record_id}",
            )
        if row["prev_hash"] != previous_hash:
            raise ReplayValidationError(
                "signature_evidence_chain_mismatch",
                f"persisted signature predecessor differs for {record_id}",
            )
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ReplayValidationError(
                "signature_evidence_payload_invalid",
                f"persisted signature payload is invalid for {record_id}",
            ) from exc
        if not isinstance(payload, Mapping):
            raise ReplayValidationError(
                "signature_evidence_payload_invalid",
                f"persisted signature payload is not an object for {record_id}",
            )
        canonicalization = str(row["canonicalization"])
        if canonicalization == "json-sort-keys-compact-v1":
            payload_bytes = _contract_canonical_bytes(payload)
        elif canonicalization == "canonical_json_v1":
            payload_bytes = canonical_json_bytes(dict(payload))
        else:
            raise ReplayValidationError(
                "canonicalization_unsupported",
                f"persisted canonicalization is unsupported for {record_id}",
            )
        if payload_bytes.decode("utf-8") != str(row["payload_json"]):
            raise ReplayValidationError(
                "signature_evidence_payload_noncanonical",
                f"persisted payload is not canonical for {record_id}",
            )
        payload_sha256 = _sha256_bytes(payload_bytes)
        if payload_sha256 != str(row["payload_sha256"]):
            raise ReplayValidationError(
                "signature_evidence_payload_hash_mismatch",
                f"persisted payload digest differs for {record_id}",
            )
        record_hash = signature_evidence_record_hash(row)
        if record_hash != str(row["record_hash"]):
            raise ReplayValidationError(
                "signature_evidence_record_hash_mismatch",
                f"persisted record hash differs for {record_id}",
            )
        previous_hash = record_hash
        ordered_record_ids.append(record_id)
        records.append(
            {
                "artifact_type": str(row["artifact_type"]),
                "artifact_id": str(row["artifact_id"]),
                "signed_payload": dict(payload),
                "signature": {
                    "alg": "ed25519",
                    "signer": str(row["signer"]),
                    "public_key": str(row["public_key"]),
                    "signature": str(row["signature"]),
                    "signed_payload_sha256": payload_sha256,
                    "canonicalization": canonicalization,
                },
            }
        )

    replay = verify_new_signature_suffix(
        records,
        required_artifact_types=required_artifact_types,
    )
    replay.update(
        {
            "table": table,
            "ordered_record_ids": ordered_record_ids,
            "head_record_hash": previous_hash,
            "persisted_after_reopen": True,
        }
    )
    return replay
