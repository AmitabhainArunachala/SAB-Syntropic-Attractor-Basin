from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = (
    REPO_ROOT
    / "docs/lanes/sab-agent-seeding-v1/contributions/packets"
    / "sab_seed_build_or_see_through_20260723.json"
)
RECEIPT_PATH = (
    REPO_ROOT
    / "docs/lanes/sab-agent-seeding-v1/contributions/receipts"
    / "sab_seed_build_or_see_through_20260723.receipt.json"
)
MASTER_RECEIPT_PATH = (
    REPO_ROOT
    / "docs/lanes/sab-agent-seeding-v1/contributions/receipts"
    / "sab_seed_master_vision_v1_ebe422aab149.receipt.json"
)
SCHEMA_PATH = REPO_ROOT / "nodes/schemas/sab.seed_packet.v1.schema.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _historical_packet_schema_issues(
    packet: dict[str, Any], schema: dict[str, Any]
) -> list[str]:
    properties = schema["properties"]
    claim = packet["claim"]
    claim_schema = properties["claim"]
    authority = packet["authority_lease"]
    authority_schema = properties["authority_lease"]
    evidence_schema = properties["evidence_bundle"]["items"]
    challenge = packet["challenge_plan"]
    challenge_schema = properties["challenge_plan"]
    signature = packet["signature"]
    signature_schema = properties["signature"]

    issues: list[str] = []
    if "text" in claim_schema["required"] and "text" not in claim:
        issues.append("$.claim.text: required")
    if "statement" not in claim_schema["properties"] and "statement" in claim:
        issues.append("$.claim.statement: additional property")
    claim_types = claim_schema["properties"]["claim_type"]["enum"]
    if claim["claim_type"] not in claim_types:
        issues.append(f"$.claim.claim_type: expected one of {claim_types!r}")

    for key in ("allowed_actions", "forbidden_actions", "purpose"):
        if key not in authority_schema["properties"] and key in authority:
            issues.append(f"$.authority_lease.{key}: additional property")

    evidence_kinds = evidence_schema["properties"]["kind"]["enum"]
    if packet["evidence_bundle"][0]["kind"] not in evidence_kinds:
        issues.append(f"$.evidence_bundle[0].kind: expected one of {evidence_kinds!r}")

    for key in ("challenge_refs", "correction_path"):
        if key in challenge_schema["required"] and key not in challenge:
            issues.append(f"$.challenge_plan.{key}: required")
    if challenge_schema["properties"]["challenge_window"][
        "type"
    ] == "string" and not isinstance(challenge["challenge_window"], str):
        issues.append("$.challenge_plan.challenge_window: expected string")
    if (
        "signed_payload" in signature_schema["required"]
        and "signed_payload" not in signature
    ):
        issues.append("$.signature.signed_payload: required")
    return issues


def test_repository_observation_replays_signature_and_schema_failure() -> None:
    packet = _load_json(PACKET_PATH)
    receipt = _load_json(RECEIPT_PATH)
    master_receipt = _load_json(MASTER_RECEIPT_PATH)
    schema = _load_json(SCHEMA_PATH)

    assert set(receipt) == {
        "schema",
        "source_commit",
        "observed_at",
        "scope",
        "observation_scope",
        "seed_id",
        "packet",
        "article",
        "schema_validation",
        "signature_validation",
        "temporal_observation",
        "repository_evidence",
        "derived_state",
        "authority_effect",
        "standing_effect",
        "identity_effect",
        "merge_effect",
        "live_eligible",
        "forbidden_inferences",
    }
    assert receipt["schema"] == "sab.seed_repository_observation.v1"
    assert receipt["scope"] == "Copy"
    assert receipt["observation_scope"] == "repository_only"
    assert receipt["seed_id"] == packet["seed_id"]

    packet_observation = receipt["packet"]
    assert packet_observation["raw_sha256"] == "sha256:" + _sha256_bytes(
        PACKET_PATH.read_bytes()
    )
    assert packet_observation["declared_schema"] == packet["schema"]
    assert packet_observation["declared_status"] == packet["status"] == "pending_seed"
    assert packet_observation["changed_by_observation"] is False

    article = receipt["article"]
    article_path = REPO_ROOT / article["path"]
    article_sha256 = "sha256:" + _sha256_bytes(article_path.read_bytes())
    assert article["declared_sha256"] == article["actual_sha256"] == article_sha256
    assert article["result"] == "MATCH"

    schema_issues = _historical_packet_schema_issues(packet, schema)
    schema_validation = receipt["schema_validation"]
    assert schema_validation["result"] == "invalid"
    assert schema_validation["error_count"] == len(schema_issues) == 11
    assert schema_validation["errors"] == schema_issues

    public_key = master_receipt["api_calls"][0]["response"]["public_key"]
    signature = packet["signature"]
    unsigned_packet = {
        key: value for key, value in packet.items() if key != "signature"
    }
    unsigned_packet_sha256 = _sha256_bytes(_canonical_bytes(unsigned_packet))
    message = {
        "kind": "sab_seed_submit",
        "seed_packet_sha256": unsigned_packet_sha256,
        "claimant_identity": packet["claimant_identity"]["subject_id"],
        "authority_lease_id": packet["authority_lease"]["lease_ref"],
        "created_at": packet["created_at"],
    }
    message_bytes = _canonical_bytes(message)
    VerifyKey(public_key, encoder=HexEncoder).verify(
        message_bytes, bytes.fromhex(signature["signature"])
    )
    signature_validation = receipt["signature_validation"]
    assert signature_validation["result"] == "verified"
    assert signature_validation["public_key"] == public_key
    assert signature_validation["unsigned_packet_sha256"] == unsigned_packet_sha256
    assert signature_validation["message_sha256"] == _sha256_bytes(message_bytes)


def test_repository_observation_grants_no_live_or_standing_effect() -> None:
    packet = _load_json(PACKET_PATH)
    receipt = _load_json(RECEIPT_PATH)
    temporal = receipt["temporal_observation"]
    repository_evidence = receipt["repository_evidence"]

    observed_at = datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00"))
    challenge_closes_at = datetime.fromisoformat(
        temporal["challenge_window_closes_at"].replace("Z", "+00:00")
    )
    lease_expires_at = datetime.fromisoformat(
        temporal["authority_lease_expires_at"].replace("Z", "+00:00")
    )
    assert (
        temporal["challenge_window_closes_at"]
        == packet["challenge_plan"]["challenge_window"]["closes_at"]
    )
    assert (
        temporal["authority_lease_expires_at"]
        == packet["authority_lease"]["expires_at"]
    )
    assert challenge_closes_at < observed_at < lease_expires_at
    assert temporal["challenge_window_time_state"] == "elapsed"
    assert temporal["authority_lease_time_state"] == "not_elapsed"
    assert temporal["live_lease_validity"] == "UNCHECKED"
    assert temporal["revocation_state"] == "UNCHECKED"

    assert repository_evidence == {
        "api_submission_receipt": "MISSING",
        "witness_chain_receipt": "MISSING",
        "challenge_record_state": "UNCHECKED",
        "transition_record_state": "UNCHECKED",
        "external_source_state": "UNCHECKED_OUT_OF_REPOSITORY",
    }
    assert receipt["derived_state"] == "SIGNED_HISTORICAL_SCHEMA_INVALID_PENDING_SEED"
    assert receipt["authority_effect"] == "none"
    assert receipt["standing_effect"] == "none"
    assert receipt["identity_effect"] == "none"
    assert receipt["merge_effect"] == "none"
    assert receipt["live_eligible"] is False
    assert len(receipt["forbidden_inferences"]) == 3
