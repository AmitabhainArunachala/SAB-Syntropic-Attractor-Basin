from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "nodes" / "schemas"
FIXTURE_DIR = REPO_ROOT / "docs" / "lanes" / "sab-agent-seeding-v1" / "fixtures"

VALID_FIXTURE_NAMES = [
    "sab.agent_identity.v1.json",
    "sab.authority_lease.v1.json",
    "sab.seed_packet.v1.json",
    "sab.challenge_packet.v1.json",
    "sab.witness_event.v1.json",
    "sab.standing_lease.v1.json",
]

EXPECTED_INVALID_MARKERS = {
    "sab.agent_identity.claims_standing.json": "$.standing_id: additional property",
    "sab.authority_lease.missing_challenge_path.json": "$.challenge_path: required",
    "sab.authority_lease.missing_expiry.json": "$.expires_at: required",
    "sab.authority_lease.missing_revoker.json": "$.revoker: required",
    "sab.authority_lease.missing_scope.json": "$.scope: required",
    "sab.challenge_packet.missing_signature.json": "$.signature: required",
    "sab.seed_packet.missing_claim_text.json": "$.claim.text: required",
    "sab.seed_packet.missing_signature.json": "$.signature: required",
    "sab.standing_lease.external_reputation_basis.json": (
        "$.standing_basis.basis_type: expected const 'witnessed_challenge'"
    ),
    "sab.standing_lease.missing_witness_event_refs.json": (
        "$.standing_basis.witness_event_refs: required"
    ),
    "sab.witness_event.missing_signature.json": "$.signature: required",
}

EXPECTED_SIGNING_PAYLOADS = {
    "sab.seed_packet.v1": {
        "kind": "sab_seed_submit",
        "required": {
            "kind",
            "seed_packet_sha256",
            "claimant_identity",
            "authority_lease_id",
            "created_at",
        },
    },
    "sab.challenge_packet.v1": {
        "kind": "sab_challenge_submit",
        "required": {
            "kind",
            "target_seed_id",
            "target_claim_id",
            "challenge_packet_sha256",
            "challenger_identity",
            "created_at",
        },
    },
    "sab.witness_event.v1": {
        "kind": "sab_witness_event",
        "required": {
            "kind",
            "event_type",
            "subject_type",
            "subject_id",
            "payload_hash",
            "prev_hash",
            "created_at",
        },
    },
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_for_fixture(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    schema_name = str(payload["schema"])
    schema_path = SCHEMA_DIR / f"{schema_name}.schema.json"
    assert schema_path.exists(), f"missing schema for {path.name}: {schema_path}"
    return _load_json(schema_path)


def _validate(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']!r}")

    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(value, dict):
            return [f"{path}: expected object"]
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}.{key}: required")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}.{key}: additional property")
        for key, subschema in properties.items():
            if key in value:
                errors.extend(_validate(subschema, value[key], f"{path}.{key}"))
        return errors

    if schema_type == "array":
        if not isinstance(value, list):
            return [f"{path}: expected array"]
        if len(value) < int(schema.get("minItems", 0)):
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            errors.append(f"{path}: expected at most {schema['maxItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                errors.extend(_validate(item_schema, item, f"{path}[{idx}]"))
        return errors

    if schema_type == "string":
        if not isinstance(value, str):
            return [f"{path}: expected string"]
        if len(value) < int(schema.get("minLength", 0)):
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
        if "pattern" in schema and re.fullmatch(str(schema["pattern"]), value) is None:
            errors.append(f"{path}: does not match pattern")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: invalid date-time")
        return errors

    if schema_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"{path}: expected integer"]
        if "minimum" in schema and value < int(schema["minimum"]):
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > int(schema["maximum"]):
            errors.append(f"{path}: above maximum {schema['maximum']}")
        return errors

    if schema_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return [f"{path}: expected number"]
        return errors

    if schema_type == "boolean":
        if not isinstance(value, bool):
            return [f"{path}: expected boolean"]
        return errors

    return errors


def test_valid_sab_agent_seeding_fixtures_match_schemas() -> None:
    valid_fixtures = [FIXTURE_DIR / "valid" / name for name in VALID_FIXTURE_NAMES]
    for fixture in valid_fixtures:
        assert fixture.exists(), f"missing valid fixture {fixture}"
        errors = _validate(_schema_for_fixture(fixture), _load_json(fixture))
        assert errors == [], f"{fixture.name} should validate: {errors}"


def test_invalid_sab_agent_seeding_fixtures_fail_schemas() -> None:
    for name, expected_marker in EXPECTED_INVALID_MARKERS.items():
        fixture = FIXTURE_DIR / "invalid" / name
        assert fixture.exists(), f"missing invalid fixture {fixture}"
        errors = _validate(_schema_for_fixture(fixture), _load_json(fixture))
        assert errors, f"{fixture.name} should fail validation"
        assert expected_marker in "\n".join(errors)


def test_schema_declares_canonical_signing_payloads() -> None:
    for schema_name, expected in EXPECTED_SIGNING_PAYLOADS.items():
        schema = _load_json(SCHEMA_DIR / f"{schema_name}.schema.json")
        signature = schema["properties"]["signature"]["properties"]
        signed_payload = signature["signed_payload"]

        assert signature["alg"]["const"] == "ed25519"
        assert signature["canonicalization"]["const"] == "json-sort-keys-compact-v1"
        assert signed_payload["properties"]["kind"]["const"] == expected["kind"]
        assert set(signed_payload["required"]) == expected["required"]


def test_schema_terms_keep_identity_reputation_and_standing_separate() -> None:
    identity_schema = _load_json(SCHEMA_DIR / "sab.agent_identity.v1.schema.json")
    attestation = identity_schema["properties"]["external_attestations"]["items"]
    assert attestation["properties"]["standing_effect"]["const"] == "none"
    assert "standing_id" not in identity_schema["properties"]

    standing_schema = _load_json(SCHEMA_DIR / "sab.standing_lease.v1.schema.json")
    basis = standing_schema["properties"]["standing_basis"]
    assert basis["properties"]["basis_type"]["const"] == "witnessed_challenge"
    assert basis["properties"]["external_attestation_effect"]["const"] == "none"
    assert {"challenge_event_refs", "witness_event_refs", "evidence_refs"} <= set(basis["required"])
