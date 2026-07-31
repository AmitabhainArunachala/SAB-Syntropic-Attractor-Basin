from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from agora.sab_first_verdict_evidence import canonical_json_bytes
from agora.sab_verdict_verify import (
    HASH_LINKED,
    SIGNATURES_VERIFIED,
    ReplayValidationError,
    verify_evidence_partition,
    verify_legacy_witness_prefix,
    verify_new_signature_suffix,
    verify_new_signature_table,
)


def _legacy_event(
    *, event_id: str, scope: str, row_id: int, previous: str, payload: dict
) -> dict:
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    material = {
        "event_id": event_id,
        "chain_scope": scope,
        "event_type": "fixture_event",
        "actor_identity": "agent_fixture",
        "subject_type": "seed",
        "subject_id": scope,
        "subject_seed_id": scope,
        "timestamp": f"2026-07-28T00:00:0{row_id}Z",
        "payload_hash": hashlib.sha256(payload_json.encode()).hexdigest(),
        "payload_json": payload_json,
        "signature": "legacy-unverified-signature",
        "prev_hash": previous,
    }
    event_hash = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {"id": row_id, **material, "event_hash": event_hash}


def _legacy_chain() -> list[dict]:
    first = _legacy_event(
        event_id="legacy_1",
        scope="seed_a",
        row_id=1,
        previous="genesis",
        payload={"n": 1},
    )
    second = _legacy_event(
        event_id="legacy_2",
        scope="seed_a",
        row_id=2,
        previous=first["event_hash"],
        payload={"n": 2},
    )
    parallel = _legacy_event(
        event_id="legacy_3",
        scope="seed_b",
        row_id=3,
        previous="genesis",
        payload={"n": 3},
    )
    return [second, parallel, first]


def _signed_record(key: SigningKey, artifact_type: str, index: int) -> dict:
    payload = {
        "schema_version": f"sab.{artifact_type}.v1",
        "artifact_id": f"{artifact_type}_{index}",
        "authority_scope": "Copy",
        "standing_effect": "none",
        "unicode_probe": "雪",
    }
    signature = key.sign(canonical_json_bytes(payload)).signature.hex()
    return {
        "artifact_type": artifact_type,
        "artifact_id": payload["artifact_id"],
        "signer": f"fixture_signer_{index}",
        "public_key": key.verify_key.encode(encoder=HexEncoder).decode(),
        "signature": signature,
        "signed_payload": payload,
        "signed_payload_sha256": hashlib.sha256(
            canonical_json_bytes(payload)
        ).hexdigest(),
        "canonicalization": "canonical_json_v1",
    }


def _database_event(
    key: SigningKey,
    *,
    event_id: str,
    event_type: str,
    previous: str | None,
    created_at: str,
) -> dict:
    payload = {
        "artifact_id": event_id,
        "event_type": event_type,
        "scope": "Copy",
        "standing_effect": "none",
    }
    payload_json = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
    signature = key.sign(payload_json.encode()).signature.hex()
    row = {
        "event_id": event_id,
        "event_type": event_type,
        "signer": f"fixture_{event_type}",
        "public_key": key.verify_key.encode(encoder=HexEncoder).decode(),
        "prev_hash": previous,
        "payload_json": payload_json,
        "payload_sha256": payload_sha256,
        "signature": signature,
        "created_at": created_at,
    }
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
    row["event_hash"] = hashlib.sha256(
        json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()
    return row


def _insert_database_event(conn: sqlite3.Connection, row: dict) -> None:
    conn.execute(
        "INSERT INTO sab_first_verdict_signed_events_v1 "
        "(event_id,event_type,signer,public_key,prev_hash,payload_json,payload_sha256,"
        "signature,event_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        tuple(
            row[field]
            for field in (
                "event_id",
                "event_type",
                "signer",
                "public_key",
                "prev_hash",
                "payload_json",
                "payload_sha256",
                "signature",
                "event_hash",
                "created_at",
            )
        ),
    )


def _signed_event_database(path: Path) -> list[dict]:
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            """
            CREATE TABLE sab_first_verdict_signed_events_v1 (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                signer TEXT NOT NULL,
                public_key TEXT NOT NULL,
                prev_hash TEXT,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        events: list[dict] = []
        previous = None
        for index, event_type in enumerate(("ballot", "verdict", "countersign")):
            event = _database_event(
                SigningKey.generate(),
                event_id=f"event_{index}",
                event_type=event_type,
                previous=previous,
                created_at=f"2026-07-28T00:00:0{index}Z",
            )
            _insert_database_event(conn, event)
            events.append(event)
            previous = event["event_hash"]
        conn.commit()
    return events


def test_legacy_prefix_is_only_hash_linked() -> None:
    result = verify_legacy_witness_prefix(_legacy_chain())
    assert result["verified"] is True
    assert result["proof_class"] == HASH_LINKED
    assert result["signature_claim"] == "not_evaluated_not_implied"
    assert result["event_count"] == 3


@pytest.mark.parametrize(
    "tamper", ["payload", "predecessor", "event_hash", "duplicate"]
)
def test_legacy_prefix_rejects_hash_or_link_tamper(tamper: str) -> None:
    chain = _legacy_chain()
    if tamper == "payload":
        chain[0]["payload_json"] = "{}"
    elif tamper == "predecessor":
        chain[0]["prev_hash"] = "0" * 64
    elif tamper == "event_hash":
        chain[0]["event_hash"] = "0" * 64
    else:
        chain.append(copy.deepcopy(chain[0]))
    with pytest.raises(ReplayValidationError):
        verify_legacy_witness_prefix(chain)


def test_every_new_signature_replays_offline_as_separate_suffix() -> None:
    artifact_types = ["ballot", "verdict", "countersign", "disposition", "lineage"]
    records = [
        _signed_record(SigningKey.generate(), artifact_type, index)
        for index, artifact_type in enumerate(artifact_types)
    ]
    result = verify_evidence_partition(
        legacy_events=_legacy_chain(),
        new_signature_records=records,
        required_artifact_types=artifact_types,
    )
    assert result["legacy_prefix"]["proof_class"] == HASH_LINKED
    assert result["new_suffix"]["proof_class"] == SIGNATURES_VERIFIED
    assert result["new_suffix"]["signature_count"] == 5
    assert result["legacy_promoted_to_signature_verified"] is False


def test_replay_accepts_strict_contract_signature_envelope() -> None:
    key = SigningKey.generate()
    payload = {"artifact_id": "verdict_contract", "unicode_probe": "雪"}
    message = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    record = {
        "artifact_type": "verdict",
        "artifact_id": "verdict_contract",
        "signed_payload": payload,
        "signature": {
            "alg": "ed25519",
            "signer": "fixture_contract_signer",
            "public_key": key.verify_key.encode(encoder=HexEncoder).decode(),
            "signature": key.sign(message).signature.hex(),
            "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
            "canonicalization": "json-sort-keys-compact-v1",
        },
    }
    result = verify_new_signature_suffix([record], required_artifact_types=("verdict",))
    assert result["proof_class"] == SIGNATURES_VERIFIED


@pytest.mark.parametrize(
    ("tamper", "code"),
    [
        ("payload", "signed_payload_hash_mismatch"),
        ("wrong_key", "signature_invalid"),
        ("signature", "signature_invalid"),
        ("canonicalization", "canonicalization_unsupported"),
        ("duplicate", "duplicate_signature"),
    ],
)
def test_new_signature_replay_fails_closed(tamper: str, code: str) -> None:
    key = SigningKey.generate()
    record = _signed_record(key, "verdict", 1)
    records = [record]
    if tamper == "payload":
        record["signed_payload"]["standing_effect"] = "altered"
    elif tamper == "wrong_key":
        record["public_key"] = (
            SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode()
        )
    elif tamper == "signature":
        record["signature"] = "00" * 64
    elif tamper == "canonicalization":
        record["canonicalization"] = "unsupported-canonicalization"
    else:
        duplicate = copy.deepcopy(record)
        duplicate["artifact_id"] = "verdict_2"
        records.append(duplicate)
    with pytest.raises(ReplayValidationError) as raised:
        verify_new_signature_suffix(records)
    assert raised.value.code == code


def test_new_signature_replay_requires_every_named_artifact_type() -> None:
    record = _signed_record(SigningKey.generate(), "verdict", 1)
    with pytest.raises(ReplayValidationError) as raised:
        verify_new_signature_suffix(
            [record], required_artifact_types=("verdict", "countersign")
        )
    assert raised.value.code == "required_signature_types_missing"


def test_canonical_json_v1_emits_literal_utf8_without_trailing_newline() -> None:
    encoded = canonical_json_bytes({"z": "雪", "a": [2, 1]})
    assert encoded == b'{"a":[2,1],"z":"\xe9\x9b\xaa"}'
    assert not encoded.endswith(b"\n")


def test_signed_event_suffix_replays_directly_from_copied_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / "copy.sqlite"
    events = _signed_event_database(database)
    with closing(sqlite3.connect(database)) as conn:
        result = verify_new_signature_table(
            conn,
            required_event_types=("ballot", "verdict", "countersign"),
        )
    assert result["proof_class"] == SIGNATURES_VERIFIED
    assert result["ordered_event_ids"] == ["event_0", "event_1", "event_2"]
    assert result["head_event_hash"] == events[-1]["event_hash"]
    assert len(result["signed_events"]) == 3
    assert all(item["signature_verified"] for item in result["signed_events"])


@pytest.mark.parametrize(
    ("tamper", "code"),
    [
        ("payload", "signed_event_payload_hash_mismatch"),
        ("event_hash", "signed_event_hash_mismatch"),
        ("signature", "signature_invalid"),
        ("wrong_key", "signature_invalid"),
        ("predecessor", "signed_event_genesis_invalid"),
        ("fork", "signed_event_chain_fork"),
    ],
)
def test_copied_database_suffix_replay_rejects_tamper_and_broken_chain(
    tmp_path: Path, tamper: str, code: str
) -> None:
    database = tmp_path / "copy.sqlite"
    events = _signed_event_database(database)
    with closing(sqlite3.connect(database)) as conn:
        if tamper == "payload":
            conn.execute(
                "UPDATE sab_first_verdict_signed_events_v1 SET payload_json='{}' "
                "WHERE event_id='event_0'"
            )
        elif tamper == "event_hash":
            conn.execute(
                "UPDATE sab_first_verdict_signed_events_v1 SET event_hash=? "
                "WHERE event_id='event_0'",
                ("f" * 64,),
            )
        else:
            target = copy.deepcopy(events[0] if tamper == "predecessor" else events[2])
            if tamper == "signature":
                target["signature"] = "00" * 64
            elif tamper == "wrong_key":
                target["public_key"] = (
                    SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode()
                )
            elif tamper == "predecessor":
                target["prev_hash"] = "e" * 64
            else:
                target["prev_hash"] = events[0]["event_hash"]
            material = {
                field: target[field]
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
            target["event_hash"] = hashlib.sha256(
                json.dumps(
                    material,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode()
            ).hexdigest()
            conn.execute(
                "UPDATE sab_first_verdict_signed_events_v1 "
                "SET public_key=?,prev_hash=?,signature=?,event_hash=? WHERE event_id=?",
                (
                    target["public_key"],
                    target["prev_hash"],
                    target["signature"],
                    target["event_hash"],
                    target["event_id"],
                ),
            )
        conn.commit()
        with pytest.raises(ReplayValidationError) as raised:
            verify_new_signature_table(conn)
    assert raised.value.code == code
