from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import subprocess
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

import agora.sab_first_verdict_api as api_module
from agora.sab_artifact_verdict import (
    ArtifactCaseV1,
    MASTER_VISION_DOCUMENT_SHA256,
    MASTER_VISION_SEED_ID,
    MASTER_VISION_SOURCE_COMMIT,
    MasterVisionPolicyEvidenceV1,
    SessionWriteLeaseV1,
    SignedDispositionPolicyV1,
    allowed_operations_digest,
    canonical_json_bytes,
    canonical_json_sha256,
)
from agora.sab_first_verdict_evidence import (
    file_sha256,
    lifecycle_fingerprint,
    observe_master_vision_state,
)
from agora.sab_first_verdict_lifecycle import FixtureExecutionContext
from agora.sab_first_verdict_storage import (
    AttestedSQLiteConnection,
    CopyDatabaseAttestation,
    DatabaseSafetyError,
    ImmutableConflict,
    LeaseStateConflict,
    activate_session_lease,
    init_first_verdict_storage,
    init_signature_evidence_storage,
    open_attested_copy_connection,
)


FIXTURES = Path(__file__).parent / "fixtures" / "sab_first_verdict" / "valid"
ROOT = Path(__file__).resolve().parents[1]
MASTER_VISION_PACKET_DIR = (
    ROOT / "docs/lanes/sab-agent-seeding-v1/contributions/packets"
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _public_key(key: SigningKey) -> str:
    return key.verify_key.encode(encoder=HexEncoder).decode("ascii")


def _signature(key: SigningKey, signer: str, payload: dict[str, Any]) -> dict[str, str]:
    message = canonical_json_bytes(payload)
    return {
        "alg": "ed25519",
        "signer": signer,
        "public_key": _public_key(key),
        "signature": key.sign(message).signature.hex(),
        "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
        "canonicalization": "json-sort-keys-compact-v1",
    }


def _load_fixture(filename: str) -> dict[str, Any]:
    return json.loads((FIXTURES / filename).read_text())


def _master_vision_policy_evidence() -> MasterVisionPolicyEvidenceV1:
    document = subprocess.run(
        [
            "git",
            "show",
            f"{MASTER_VISION_SOURCE_COMMIT}:docs/SAB_MASTER_VISION_V1.md",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    seed_packet = (
        MASTER_VISION_PACKET_DIR / "sab_seed_master_vision_v1_ebe422aab149.json"
    ).read_bytes()
    challenge_packet = (
        MASTER_VISION_PACKET_DIR / "sab_challenge_master_vision_v1_ebe422aab149.json"
    ).read_bytes()
    return MasterVisionPolicyEvidenceV1(
        document_base64=base64.b64encode(document).decode("ascii"),
        seed_packet_base64=base64.b64encode(seed_packet).decode("ascii"),
        challenge_packet_base64=base64.b64encode(challenge_packet).decode("ascii"),
    )


@dataclass
class APIHarness:
    client: TestClient
    attestation: CopyDatabaseAttestation
    context: FixtureExecutionContext
    operator_key: SigningKey
    clerk_key: SigningKey
    policy_key: SigningKey
    lease: SessionWriteLeaseV1 | None = None


@pytest.fixture
def api_harness(tmp_path: Path) -> APIHarness:
    source_path = tmp_path / "source.db"
    copied_path = tmp_path / "copied.db"
    source = sqlite3.connect(source_path)
    source.execute("CREATE TABLE legacy_fixture (id INTEGER PRIMARY KEY, value TEXT)")
    source.execute("INSERT INTO legacy_fixture(value) VALUES ('preserved')")
    source.executescript(
        """
        CREATE TABLE sab_seed_packets_v1 (
            seed_id TEXT PRIMARY KEY, state TEXT NOT NULL,
            packet_json TEXT NOT NULL, packet_hash TEXT NOT NULL
        );
        CREATE TABLE sab_challenge_packets_v1 (
            challenge_id TEXT PRIMARY KEY, target_seed_id TEXT NOT NULL,
            status TEXT NOT NULL, packet_json TEXT NOT NULL, packet_hash TEXT NOT NULL
        );
        CREATE TABLE sab_witness_events_v1 (
            id INTEGER PRIMARY KEY, event_id TEXT NOT NULL,
            chain_scope TEXT NOT NULL, event_type TEXT NOT NULL,
            subject_seed_id TEXT NOT NULL, event_hash TEXT NOT NULL
        );
        CREATE TABLE web_agents (id TEXT PRIMARY KEY, public_key TEXT NOT NULL);
        """
    )
    master_evidence = _master_vision_policy_evidence()
    seed_packet = json.loads(
        base64.b64decode(master_evidence.seed_packet_base64, validate=True)
    )
    challenge_packet = json.loads(
        base64.b64decode(master_evidence.challenge_packet_base64, validate=True)
    )
    source.execute(
        "INSERT INTO sab_seed_packets_v1 VALUES (?, 'challenged', ?, ?)",
        (
            MASTER_VISION_SEED_ID,
            json.dumps(seed_packet, sort_keys=True, separators=(",", ":")),
            master_evidence.seed_packet_sha256,
        ),
    )
    source.execute(
        "INSERT INTO sab_challenge_packets_v1 VALUES (?, ?, 'pending', ?, ?)",
        (
            "sab_challenge_master_vision_v1_ebe422aab149",
            MASTER_VISION_SEED_ID,
            json.dumps(challenge_packet, sort_keys=True, separators=(",", ":")),
            master_evidence.challenge_packet_sha256,
        ),
    )
    source.executemany(
        "INSERT INTO sab_witness_events_v1 VALUES (?, ?, ?, ?, ?, ?)",
        (
            (
                1,
                "mv-submit",
                MASTER_VISION_SEED_ID,
                "submit",
                MASTER_VISION_SEED_ID,
                "a" * 64,
            ),
            (
                2,
                "mv-challenge",
                MASTER_VISION_SEED_ID,
                "challenge",
                MASTER_VISION_SEED_ID,
                "b" * 64,
            ),
        ),
    )
    source.execute(
        "INSERT INTO web_agents VALUES (?, ?)",
        (master_evidence.signer, master_evidence.signer_public_key),
    )
    source.commit()
    copied = sqlite3.connect(copied_path)
    source.backup(copied)
    copied.close()
    source.close()

    probe = sqlite3.connect(f"file:{copied_path}?mode=ro", uri=True)
    try:
        expected_lifecycle = lifecycle_fingerprint(probe)["sha256"]
    finally:
        probe.close()

    operator_key = SigningKey.generate()
    clerk_key = SigningKey.generate()
    policy_key = SigningKey.generate()
    claimant_key = SigningKey.generate()
    event_key = SigningKey.generate()
    seat_keys = [SigningKey.generate() for _ in range(9)]
    case_fixture = _load_fixture("sab.artifact_case.v1.json")
    source_backup_sha256 = file_sha256(copied_path)
    context = FixtureExecutionContext(
        proof_class="authorized_synthetic_copy_fixture",
        target_artifact_id=str(case_fixture["target_seed_id"]),
        target_artifact_sha256=str(case_fixture["target_seed_packet_sha256"]),
        source_fixture_id="fixture:api",
        copied_database_id="copy:api",
        source_backup_sha256=source_backup_sha256,
        code_sha="c" * 40,
        copied_lifecycle_fingerprint=expected_lifecycle,
        synthetic_state_hash="a" * 64,
        expected_case_head="b" * 64,
        policy_issuer_identity="fixture:policy-issuer",
        policy_issuer_public_key=_public_key(policy_key),
        operator_identity="fixture:operator",
        operator_public_key=_public_key(operator_key),
        clerk_identity="fixture:clerk",
        clerk_public_key=_public_key(clerk_key),
        claimant_identity="fixture:claimant",
        claimant_public_key=_public_key(claimant_key),
        event_signer_identity="fixture:event-signer",
        event_signer_public_key=_public_key(event_key),
        seat_execution_identities=tuple(
            (f"seat-{index}", f"fixture:seat-{index}", _public_key(key))
            for index, key in enumerate(seat_keys)
        ),
    )
    receipt_path = tmp_path / "copy-receipt.json"
    source_stat = source_path.stat()
    receipt_path.write_text(
        json.dumps(
            {
                "schema_version": "sab.build_a.a0_database_snapshot.v1",
                "content_equal": True,
                "source": {
                    "path_ref": str(source_path.resolve()),
                    "opened": "sqlite_uri_mode_ro",
                    "sha256": file_sha256(source_path),
                    "device": source_stat.st_dev,
                    "inode": source_stat.st_ino,
                    "size": source_stat.st_size,
                },
                "copy": {
                    "path_ref": f"private:{copied_path.resolve()}",
                    "sha256": source_backup_sha256,
                    "backup_method": "sqlite_online_backup_from_mode_ro_source",
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    attestation = CopyDatabaseAttestation(
        proof_class="copied_live_db_rehearsal",
        database_path=copied_path,
        source_database_path=source_path,
        source_backup_sha256=source_backup_sha256,
        expected_lifecycle_fingerprint=expected_lifecycle,
        copy_receipt_sha256=file_sha256(receipt_path),
        copy_receipt_path=receipt_path,
    )
    conn = open_attested_copy_connection(attestation, require_pristine_backup=True)
    try:
        init_first_verdict_storage(conn, applied_at="2026-07-27T16:00:00Z")
        init_signature_evidence_storage(conn, applied_at="2026-07-27T16:00:01Z")
    finally:
        conn.close()
    app = api_module.create_sab_first_verdict_app(attestation, context)
    return APIHarness(
        client=TestClient(app),
        attestation=attestation,
        context=context,
        operator_key=operator_key,
        clerk_key=clerk_key,
        policy_key=policy_key,
    )


def _lease(
    harness: APIHarness,
    *,
    operations: list[tuple[str, str]] | None = None,
    at: datetime | None = None,
) -> SessionWriteLeaseV1:
    now = at or datetime.now(timezone.utc)
    pairs = operations or [
        ("POST", "/api/v1/session-write-leases/{lease_id}/release"),
        ("POST", "/api/v1/artifact-cases"),
        (
            "POST",
            "/api/v1/artifact-cases/{case_id}/authority-evaluations",
        ),
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        ),
    ]
    allowed = sorted(
        ({"method": method, "path": path} for method, path in pairs),
        key=lambda item: (item["method"], item["path"]),
    )
    unsigned = {
        "schema": "sab.session_write_lease.v1",
        "lease_id": "sab_lease_api_fixture",
        "session_id": "sab_session_api_fixture",
        "clerk_identity": harness.context.clerk_identity,
        "allowed_operations": allowed,
        "allowed_operations_sha256": allowed_operations_digest(allowed),
        "accepted_code_sha": harness.context.code_sha,
        "expected_lifecycle_fingerprint": (
            harness.context.copied_lifecycle_fingerprint
        ),
        "source_backup_sha256": harness.context.source_backup_sha256,
        "issuer_identity": harness.context.operator_identity,
        "issuer_public_key": harness.context.operator_public_key,
        "issuer_fingerprint": hashlib.sha256(
            bytes.fromhex(harness.context.operator_public_key)
        ).hexdigest(),
        "authority_basis": "founder_bootstrap_self_declared",
        "scope": "Copy",
        "issued_at": (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "activated_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "standing_effect": "none",
        "live_eligible": False,
    }
    body = {
        **unsigned,
        "lease_sha256": canonical_json_sha256(unsigned),
    }
    body["signature"] = _signature(
        harness.operator_key, harness.context.operator_identity, body
    )
    return SessionWriteLeaseV1.model_validate(body)


def _activate(harness: APIHarness, lease: SessionWriteLeaseV1 | None = None) -> str:
    lease = lease or _lease(harness)
    response = harness.client.post(
        "/api/v1/session-write-leases/activate",
        json=lease.canonical_payload(),
    )
    assert response.status_code == 201, response.text
    harness.lease = lease
    return lease.lease_id


def _structural_signed_event(
    harness: APIHarness,
    *,
    verdict_id: str,
    lineage_edge_id: str,
) -> dict[str, Any]:
    digest = "0" * 64
    event_id = f"event:{verdict_id}"
    payload = {
        "schema_version": "sab.first_verdict_lifecycle_event.v1",
        "event_id": event_id,
        "event_type": "rehearsal_supersession_committed",
        "case_id": "case:api-structural",
        "verdict_id": verdict_id,
        "disposition_id": "disposition:api-structural",
        "lineage_edge_id": lineage_edge_id,
        "target_artifact_id": harness.context.target_artifact_id,
        "successor_artifact_id": "successor:api-structural",
        "authority_digest": digest,
        "countersign_sha256": digest,
        "disposition_sha256": digest,
        "lineage_sha256": digest,
        "before_state_hash": digest,
        "after_state_hash": digest,
        "prev_hash": None,
        "scope": "Copy",
        "proof_class": "copied_live_db_rehearsal",
        "standing_effect": "none",
        "live_eligible": False,
    }
    return {
        "artifact_type": "lifecycle_event",
        "artifact_id": event_id,
        "signer_kind": "fixture_ephemeral",
        "signed_payload": payload,
        "signature": {
            "alg": "ed25519",
            "signer": harness.context.event_signer_identity,
            "public_key": harness.context.event_signer_public_key,
            "signature": "0" * 128,
            "signed_payload_sha256": digest,
            "canonicalization": "json-sort-keys-compact-v1",
        },
    }


def _closed_lifecycle_receipt() -> dict[str, Any]:
    digest = "0" * 64
    artifact_ref = {"id": "fixture:artifact", "sha256": digest}
    signature_record = {
        "artifact_type": "policy",
        "artifact_id": "fixture:policy",
        "signer": "fixture:signer",
        "public_key_sha256": digest,
        "signed_payload_sha256": digest,
        "signature_sha256": digest,
    }
    signature_validation = {
        "proof_class": "SignaturesVerified",
        "verified": True,
        "signature_count": 1,
        "artifact_types": ["policy"],
        "records": [signature_record],
    }
    return {
        "schema_version": "sab.rehearsal_lifecycle_receipt.v1",
        "proof_class": "copied_live_db_rehearsal",
        "operation": "rehearsal-disposition:correct-and-supersede:v1",
        "idempotency_key": "api-idempotency-key",
        "request_sha256": digest,
        "validation_order": ["authority"],
        "scope": "Copy",
        "fixture_context_sha256": digest,
        "authority": {
            "evaluation_id": "fixture:evaluation",
            "result": "Authorized",
            "authority_digest": digest,
            "evaluated_state_hash": digest,
        },
        "artifacts": {
            name: dict(artifact_ref)
            for name in (
                "case",
                "lease",
                "verdict",
                "countersign",
                "disposition",
                "lineage",
                "target",
                "successor",
            )
        },
        "state": {
            "synthetic_before_sha256": digest,
            "synthetic_after_sha256": digest,
            "copied_lifecycle_fingerprint": digest,
            "case_head_before": digest,
        },
        "transaction": {
            "mode": "BEGIN IMMEDIATE",
            "boundaries": ["fixture_insert"],
            "commits": 1,
        },
        "invariant_table_digests": {
            "legacy_fixture": {
                "before_sha256": digest,
                "after_sha256": digest,
                "unchanged": True,
            }
        },
        "signature_replay": {
            **signature_validation,
            "table": "sab_first_verdict_signature_evidence_v1",
            "ordered_record_ids": ["fixture:record"],
            "head_record_hash": digest,
            "persisted_after_reopen": True,
        },
        "request_signature_validation": signature_validation,
        "persisted_signature_count": 1,
        "signed_event_table_replay": {
            **signature_validation,
            "table": "sab_first_verdict_signed_events_v1",
            "ordered_event_ids": ["fixture:event"],
            "head_event_hash": digest,
            "signed_events": [
                {
                    "event_id": "fixture:event",
                    "event_hash": digest,
                    "public_key": digest,
                    "signature_verified": True,
                    "replay_result": "SignaturesVerified",
                }
            ],
        },
        "signed_event": {
            "event_id": "fixture:event",
            "event_hash": digest,
            "signature_verified": True,
            "replay_result": "SignaturesVerified",
        },
        "source_fixture_id": "fixture:api",
        "copied_database_id": "copy:api",
        "standing_effect": "none",
        "identity_effect": "none",
        "live_eligible": False,
        "live_mutations": 0,
        "provider_calls": 0,
        "external_actions": 0,
        "receipt_sha256": digest,
    }


def _signed_case(harness: APIHarness, lease_id: str) -> ArtifactCaseV1:
    body = _load_fixture("sab.artifact_case.v1.json")
    body["lease_id"] = lease_id
    body["clerk_identity"] = harness.context.clerk_identity
    body.pop("clerk_signature", None)
    body["clerk_signature"] = _signature(
        harness.clerk_key, harness.context.clerk_identity, body
    )
    return ArtifactCaseV1.model_validate(body)


def test_factory_cross_checks_both_out_of_band_bindings(
    api_harness: APIHarness,
) -> None:
    wrong_source = replace(api_harness.attestation, source_backup_sha256="f" * 64)
    with pytest.raises(DatabaseSafetyError, match="copy receipt"):
        api_module.create_sab_first_verdict_app(wrong_source, api_harness.context)

    wrong_lifecycle = replace(
        api_harness.attestation, expected_lifecycle_fingerprint="e" * 64
    )
    with pytest.raises(DatabaseSafetyError, match="lifecycle fingerprint"):
        api_module.create_sab_first_verdict_app(wrong_lifecycle, api_harness.context)

    with pytest.raises(TypeError, match="FixtureExecutionContext"):
        api_module.create_sab_first_verdict_app(
            api_harness.attestation,
            api_harness.context.__dict__,  # type: ignore[arg-type]
        )


def test_health_and_signed_lease_lifecycle_are_fail_closed(
    api_harness: APIHarness,
) -> None:
    health = api_harness.client.get("/health")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "proof_class": "copied_fixture_maintenance",
        "lifecycle_fingerprint": api_harness.context.copied_lifecycle_fingerprint,
        "live_eligible": False,
    }

    lease = _lease(api_harness)
    tampered = lease.canonical_payload()
    tampered["signature"]["signature"] = "0" * 128
    denied = api_harness.client.post(
        "/api/v1/session-write-leases/activate", json=tampered
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "lease_signature_invalid"

    lease_id = _activate(api_harness, lease)
    fetched = api_harness.client.get(f"/api/v1/session-write-leases/{lease_id}")
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "active"
    assert fetched.json()["lease"]["lease_id"] == lease_id

    missing_header = api_harness.client.post(
        f"/api/v1/session-write-leases/{lease_id}/release"
    )
    assert missing_header.status_code == 422
    assert missing_header.json()["error"]["code"] == "request_validation_error"
    injected_release = api_harness.client.post(
        f"/api/v1/session-write-leases/{lease_id}/release",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json={"private_key": "must-not-cross-http"},
    )
    assert injected_release.status_code == 422
    released = api_harness.client.post(
        f"/api/v1/session-write-leases/{lease_id}/release",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
    )
    assert released.status_code == 200
    assert released.json()["status"] == "released"
    assert released.json()["replayed"] is False
    retried = api_harness.client.post(
        f"/api/v1/session-write-leases/{lease_id}/release",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
    )
    assert retried.status_code == 200
    assert retried.json()["status"] == "released"
    assert retried.json()["replayed"] is True
    fetched = api_harness.client.get(f"/api/v1/session-write-leases/{lease_id}")
    assert fetched.json()["status"] == "released"


def test_expired_signed_lease_cannot_be_activated(
    api_harness: APIHarness,
) -> None:
    expired = _lease(
        api_harness,
        at=datetime.now(timezone.utc) - timedelta(hours=2),
    )

    response = api_harness.client.post(
        "/api/v1/session-write-leases/activate",
        json=expired.canonical_payload(),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "lease_outside_activation_window"


def test_case_write_uses_attested_connection_and_verifies_clerk_signature(
    api_harness: APIHarness,
) -> None:
    lease_id = _activate(api_harness)
    case = _signed_case(api_harness, lease_id)
    invalid = case.canonical_payload()
    invalid["clerk_signature"]["signature"] = "0" * 128
    denied = api_harness.client.post(
        "/api/v1/artifact-cases",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=invalid,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "case_signature_invalid"

    impersonated = case.canonical_payload()
    impersonated["clerk_identity"] = "fixture:impersonated-clerk"
    impersonated_unsigned = {
        key: value for key, value in impersonated.items() if key != "clerk_signature"
    }
    impersonated["clerk_signature"] = _signature(
        api_harness.clerk_key,
        api_harness.context.clerk_identity,
        impersonated_unsigned,
    )
    denied = api_harness.client.post(
        "/api/v1/artifact-cases",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=impersonated,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "case_clerk_identity_mismatch"

    created = api_harness.client.post(
        "/api/v1/artifact-cases",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=case.canonical_payload(),
    )
    assert created.status_code == 201, created.text
    assert created.json()["case"]["case_id"] == case.case_id
    fetched = api_harness.client.get(f"/api/v1/artifact-cases/{case.case_id}")
    assert fetched.status_code == 200
    assert fetched.json()["case"] == case.canonical_payload()

    with closing(open_attested_copy_connection(api_harness.attestation)) as conn:
        assert isinstance(conn, AttestedSQLiteConnection)
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sab_artifact_cases_v1 WHERE case_id = ?",
                (case.case_id,),
            ).fetchone()[0]
            == 1
        )


def test_failed_authority_evaluation_cannot_poison_corrected_policy(
    api_harness: APIHarness,
) -> None:
    lease_id = _activate(api_harness)
    case = _signed_case(api_harness, lease_id)
    created = api_harness.client.post(
        "/api/v1/artifact-cases",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=case.canonical_payload(),
    )
    assert created.status_code == 201

    now = datetime.now(timezone.utc)
    unsigned_policy = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": "sab_policy_api_bad_signature",
        "artifact_id": case.target_seed_id,
        "artifact_sha256": case.target_seed_packet_sha256,
        "disposition_mode": "authorized",
        "scope": "Copy",
        "permitted_effects": ["challenge:resolve", "seed:supersede"],
        "forbidden_effects": [],
        "preconditions": ["challenge_state=pending", "seed_state=challenged"],
        "evaluated_state_hash": api_harness.context.synthetic_state_hash,
        "source_fixture_id": api_harness.context.source_fixture_id,
        "copied_database_id": api_harness.context.copied_database_id,
        "test_issuer": True,
        "live_eligible": False,
        "standing_effect": "none",
        "authority_refs": ["fixture:api-policy"],
        "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "issuer": api_harness.context.policy_issuer_identity,
    }
    policy_body = {
        **unsigned_policy,
        "policy_sha256": canonical_json_sha256(unsigned_policy),
        "signature": {
            "alg": "ed25519",
            "signer": api_harness.context.policy_issuer_identity,
            "public_key": api_harness.context.policy_issuer_public_key,
            "signature": "0" * 128,
            "signed_payload_sha256": "0" * 64,
            "canonicalization": "json-sort-keys-compact-v1",
        },
    }
    policy = SignedDispositionPolicyV1.model_validate(policy_body)
    response = api_harness.client.post(
        f"/api/v1/artifact-cases/{case.case_id}/authority-evaluations",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json={
            "artifact_sha256": case.target_seed_packet_sha256,
            "requested_scope": "Copy",
            "requested_effects": ["challenge:resolve", "seed:supersede"],
            "evaluated_state_hash": api_harness.context.synthetic_state_hash,
            "signed_policy": policy.canonical_payload(),
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["authority"]["result"] == "NoJurisdiction"
    assert "policy_signature_invalid" in response.json()["authority"]["reason_codes"]
    refusal_id = response.json()["authority"]["evaluation_id"]

    valid_body = dict(policy_body)
    valid_unsigned = {
        key: value for key, value in valid_body.items() if key != "signature"
    }
    valid_body["signature"] = _signature(
        api_harness.policy_key,
        api_harness.context.policy_issuer_identity,
        valid_unsigned,
    )
    valid_policy = SignedDispositionPolicyV1.model_validate(valid_body)
    corrected = api_harness.client.post(
        f"/api/v1/artifact-cases/{case.case_id}/authority-evaluations",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json={
            "artifact_sha256": case.target_seed_packet_sha256,
            "requested_scope": "Copy",
            "requested_effects": ["challenge:resolve", "seed:supersede"],
            "evaluated_state_hash": api_harness.context.synthetic_state_hash,
            "signed_policy": valid_policy.canonical_payload(),
        },
    )
    assert corrected.status_code == 201, corrected.text
    assert corrected.json()["authority"]["result"] == "Authorized"
    assert corrected.json()["authority"]["evaluation_id"] != refusal_id


def test_closed_malformed_policy_is_stored_as_no_jurisdiction(
    api_harness: APIHarness,
) -> None:
    lease_id = _activate(api_harness)
    case = _signed_case(api_harness, lease_id)
    created = api_harness.client.post(
        "/api/v1/artifact-cases",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=case.canonical_payload(),
    )
    assert created.status_code == 201

    malformed_but_closed = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": [],
        "artifact_id": {},
        "artifact_sha256": 17,
        "disposition_mode": "ambiguous",
        "scope": ["Copy", "Live"],
        "permitted_effects": 17,
        "forbidden_effects": None,
        "preconditions": {},
        "evaluated_state_hash": False,
        "source_fixture_id": 17,
        "copied_database_id": 17,
        "test_issuer": "maybe",
        "live_eligible": "maybe",
        "standing_effect": "unknown",
        "authority_refs": 17,
        "issued_at": "not-a-time",
        "expires_at": "not-a-time",
        "issuer": [],
        "policy_sha256": 17,
        "signature": "not-a-signature",
    }
    response = api_harness.client.post(
        f"/api/v1/artifact-cases/{case.case_id}/authority-evaluations",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json={
            "artifact_sha256": case.target_seed_packet_sha256,
            "requested_scope": "Copy",
            "requested_effects": [],
            "evaluated_state_hash": api_harness.context.synthetic_state_hash,
            "signed_policy": malformed_but_closed,
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["authority"]["result"] == "NoJurisdiction"
    assert response.json()["authority"]["reason_codes"] == ["invalid_policy_contract"]

    injected = {**malformed_but_closed, "private_key": "must-not-cross-http"}
    rejected = api_harness.client.post(
        f"/api/v1/artifact-cases/{case.case_id}/authority-evaluations",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json={
            "artifact_sha256": case.target_seed_packet_sha256,
            "requested_scope": "Copy",
            "requested_effects": [],
            "evaluated_state_hash": api_harness.context.synthetic_state_hash,
            "signed_policy": injected,
        },
    )
    assert rejected.status_code == 422
    assert rejected.json()["error"]["code"] == "request_validation_error"
    assert "must-not-cross-http" not in rejected.text


def test_exact_master_vision_evidence_reaches_advisory_only_via_api(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_at = datetime(2026, 7, 28, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(api_module, "_utc_now", lambda: observed_at)
    lease_id = _activate(api_harness, _lease(api_harness, at=observed_at))

    case_body = _load_fixture("sab.artifact_case.v1.json")
    case_body.update(
        {
            "case_id": "sab_case_master_vision_api_evidence",
            "target_seed_id": MASTER_VISION_SEED_ID,
            "target_seed_packet_sha256": MASTER_VISION_DOCUMENT_SHA256,
            "lease_id": lease_id,
            "clerk_identity": api_harness.context.clerk_identity,
        }
    )
    case_body.pop("clerk_signature", None)
    case_body["clerk_signature"] = _signature(
        api_harness.clerk_key,
        api_harness.context.clerk_identity,
        case_body,
    )
    case = ArtifactCaseV1.model_validate(case_body)
    created = api_harness.client.post(
        "/api/v1/artifact-cases",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=case.canonical_payload(),
    )
    assert created.status_code == 201, created.text

    evidence = _master_vision_policy_evidence()
    with closing(open_attested_copy_connection(api_harness.attestation)) as conn:
        observation = observe_master_vision_state(conn)
    response = api_harness.client.post(
        f"/api/v1/artifact-cases/{case.case_id}/authority-evaluations",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json={
            "artifact_sha256": MASTER_VISION_DOCUMENT_SHA256,
            "requested_scope": "Copy",
            "requested_effects": ["compost"],
            "evaluated_state_hash": observation.observed_state_hash,
            "signed_policy": evidence.canonical_payload(),
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["authority"]["result"] == "AdvisoryOnly"
    assert (
        "signed_compost_conditions_unmet"
        in response.json()["authority"]["reason_codes"]
    )


def test_lifecycle_route_passes_attested_connection_and_out_of_band_context(
    api_harness: APIHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = [
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        )
    ]
    lease = _lease(api_harness, operations=operation)
    lease_id = _activate(api_harness, lease)
    observed_at = datetime.now(timezone.utc)
    applied_at = observed_at
    captured: dict[str, Any] = {}

    def fake_apply(
        conn: sqlite3.Connection,
        request: dict[str, Any],
        *,
        fixture_context: FixtureExecutionContext,
        now: datetime,
        expected_verdict_id: str,
        expected_write_lease_id: str,
    ) -> dict[str, Any]:
        captured.update(
            conn=conn,
            request=request,
            fixture_context=fixture_context,
            now=now,
            expected_verdict_id=expected_verdict_id,
            expected_write_lease_id=expected_write_lease_id,
            in_transaction=conn.in_transaction,
        )
        return _closed_lifecycle_receipt()

    monkeypatch.setattr(api_module, "apply_rehearsal_lifecycle", fake_apply)
    monkeypatch.setattr(api_module, "_utc_now", lambda: observed_at)
    verdict_id = "sab_verdict_api_fixture"
    request = {
        "schema_version": "sab.rehearsal_lifecycle_request.v1",
        "idempotency_key": "api-idempotency-key",
        "code_sha": api_harness.context.code_sha,
        "artifact_id": api_harness.context.target_artifact_id,
        "artifact_sha256": api_harness.context.target_artifact_sha256,
        "evaluated_state_hash": api_harness.context.synthetic_state_hash,
        "requested_effects": ["challenge:resolve", "seed:supersede"],
        "signed_policy": {},
        "countersign": {"verdict_id": verdict_id, "write_lease_id": lease_id},
        "disposition": {
            "verdict_id": verdict_id,
            "applied_at": applied_at.isoformat(),
        },
        "successor_artifact": {},
        "lineage_edge_id": "sab_lineage_api_fixture",
        "supersession": {},
        "signed_event": _structural_signed_event(
            api_harness,
            verdict_id=verdict_id,
            lineage_edge_id="sab_lineage_api_fixture",
        ),
    }
    response = api_harness.client.post(
        f"/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=request,
    )
    assert response.status_code == 201, response.text
    assert isinstance(captured["conn"], AttestedSQLiteConnection)
    assert captured["in_transaction"] is False
    assert captured["fixture_context"] is api_harness.context
    assert captured["now"] == observed_at
    assert captured["expected_verdict_id"] == verdict_id
    assert captured["expected_write_lease_id"] == lease_id
    assert "fixture_context" not in captured["request"]
    assert "private_key" not in captured["request"]


def test_lifecycle_route_uses_server_time_and_rejects_backdated_expired_lease(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation = [
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        )
    ]
    observed_at = datetime.now(timezone.utc)
    expired = _lease(
        api_harness,
        operations=operation,
        at=observed_at - timedelta(hours=2),
    )
    with closing(open_attested_copy_connection(api_harness.attestation)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        activate_session_lease(conn, expired.canonical_payload())
        conn.commit()

    called = False

    def must_not_apply(*_: Any, **__: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        raise AssertionError("expired lifecycle reached the effect engine")

    monkeypatch.setattr(api_module, "_utc_now", lambda: observed_at)
    monkeypatch.setattr(api_module, "apply_rehearsal_lifecycle", must_not_apply)
    verdict_id = "sab_verdict_api_expired"
    backdated = expired.activated_at + timedelta(seconds=10)
    response = api_harness.client.post(
        f"/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        headers={api_module.WRITE_LEASE_HEADER: expired.lease_id},
        json={
            "schema_version": "sab.rehearsal_lifecycle_request.v1",
            "idempotency_key": "expired-backdate",
            "code_sha": api_harness.context.code_sha,
            "artifact_id": api_harness.context.target_artifact_id,
            "artifact_sha256": api_harness.context.target_artifact_sha256,
            "evaluated_state_hash": api_harness.context.synthetic_state_hash,
            "requested_effects": ["challenge:resolve", "seed:supersede"],
            "signed_policy": {},
            "countersign": {
                "verdict_id": verdict_id,
                "write_lease_id": expired.lease_id,
            },
            "disposition": {
                "verdict_id": verdict_id,
                "applied_at": backdated.isoformat(),
            },
            "successor_artifact": {},
            "lineage_edge_id": "sab_lineage_api_expired",
            "supersession": {},
            "signed_event": _structural_signed_event(
                api_harness,
                verdict_id=verdict_id,
                lineage_edge_id="sab_lineage_api_expired",
            ),
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "write_lease_outside_window"
    assert called is False


def test_request_models_reject_context_or_key_injection(
    api_harness: APIHarness,
) -> None:
    lease = _lease(api_harness)
    injected_lease = lease.canonical_payload()
    injected_lease["fixture_context"] = api_harness.context.__dict__
    injected_lease["private_key"] = "must-not-cross-http"
    response = api_harness.client.post(
        "/api/v1/session-write-leases/activate", json=injected_lease
    )
    assert response.status_code == 422
    assert "must-not-cross-http" not in response.text

    preview = api_harness.client.post(
        "/api/v1/compost-batches/preview",
        json={"actor_slots": {}, "private_key": "must-not-cross-http"},
    )
    assert preview.status_code == 422
    assert "must-not-cross-http" not in preview.text

    lifecycle = {
        "idempotency_key": "strict-input",
        "code_sha": api_harness.context.code_sha,
        "artifact_id": api_harness.context.target_artifact_id,
        "artifact_sha256": api_harness.context.target_artifact_sha256,
        "evaluated_state_hash": api_harness.context.synthetic_state_hash,
        "requested_effects": ["challenge:resolve", "seed:supersede"],
        "signed_policy": {},
        "countersign": {},
        "disposition": {},
        "successor_artifact": {},
        "lineage_edge_id": "edge",
        "supersession": {},
        "signed_event": {},
        "fixture_context": api_harness.context.__dict__,
    }
    response = api_harness.client.post(
        "/api/v1/artifact-verdicts/verdict/rehearsal-dispositions",
        json=lifecycle,
    )
    assert response.status_code == 422


def test_preview_is_read_only_and_does_not_require_a_write_lease(
    api_harness: APIHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_preview(
        path: Path,
        *,
        actor_slots: dict[str, str],
        expected_file_identity: tuple[int, int],
        expected_lifecycle_fingerprint: str,
    ) -> dict[str, Any]:
        captured.update(
            path=path,
            actor_slots=actor_slots,
            expected_file_identity=expected_file_identity,
            expected_lifecycle_fingerprint=expected_lifecycle_fingerprint,
        )
        return {"raw": "read-only-proof"}

    def fake_projection(preview: dict[str, Any]) -> dict[str, Any]:
        assert preview == {"raw": "read-only-proof"}
        digest = "0" * 64
        records = [
            {
                "record_id": f"record-{index}",
                "actor_slot": (
                    "Hermes" if index < 59 else "Dharma-cron" if index < 61 else "other"
                ),
                "eligible": index < 61,
                "evidence_refs": [
                    {
                        "ref": f"fixture:evidence:{index}",
                        "content_sha256": digest,
                        "proof_class": "fixture",
                    }
                ],
                "exclusion_reason": None if index < 61 else "exact fixture exclusion",
                "row_sha256": digest,
            }
            for index in range(67)
        ]
        return {
            "schema": "sab.compost_batch_preview.v1",
            "preview_id": "sab_preview_api_fixture",
            "scanned_count": 67,
            "hermes_count": 59,
            "dharma_cron_count": 2,
            "selected_count": 61,
            "excluded_count": 6,
            "actor_slot_parameterized": True,
            "records": records,
            "before_database_sha256": digest,
            "after_database_sha256": digest,
            "before_lifecycle_fingerprint": digest,
            "after_lifecycle_fingerprint": digest,
            "before_head_sha256": digest,
            "after_head_sha256": digest,
            "before_file_mtime_ns": 1,
            "after_file_mtime_ns": 1,
            "execution_supported": False,
            "mutation_count": 0,
        }

    monkeypatch.setattr(api_module, "preview_database_readonly", fake_preview)
    monkeypatch.setattr(api_module, "preview_contract_payload", fake_projection)
    response = api_harness.client.post("/api/v1/compost-batches/preview", json={})
    assert response.status_code == 200
    assert response.json()["execution_supported"] is False
    assert response.json()["mutation_count"] == 0
    assert len(response.json()["records"]) == 67
    assert captured["path"] == api_harness.attestation.database_path
    assert captured["actor_slots"] == {
        "hermes_m5": "agent_hermes_m5",
        "dharma_cron": "agent_dharma_cron",
    }
    assert captured["expected_lifecycle_fingerprint"] == (
        api_harness.attestation.expected_lifecycle_fingerprint
    )
    assert captured["expected_file_identity"] == (
        api_harness.attestation.database_path.stat().st_dev,
        api_harness.attestation.database_path.stat().st_ino,
    )


def test_preview_revalidates_copy_attestation_after_factory_creation(
    api_harness: APIHarness,
) -> None:
    copied_path = api_harness.attestation.database_path
    source_path = api_harness.attestation.source_database_path
    assert source_path is not None
    copied_path.unlink()
    copied_path.symlink_to(source_path)

    response = api_harness.client.post("/api/v1/compost-batches/preview", json={})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "database_attestation_failed"


def test_preview_rejects_regular_file_replacement_after_factory_creation(
    api_harness: APIHarness,
) -> None:
    copied_path = api_harness.attestation.database_path
    replacement = copied_path.with_name("replacement.db")
    with closing(sqlite3.connect(replacement)) as conn:
        conn.execute("CREATE TABLE replacement_marker (id INTEGER PRIMARY KEY)")
        conn.commit()
    replacement.replace(copied_path)

    response = api_harness.client.post("/api/v1/compost-batches/preview", json={})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == ("preview_database_identity_mismatch")


def test_malformed_write_collections_are_sanitized_422(
    api_harness: APIHarness,
) -> None:
    marker = 987654321
    lease = _lease(api_harness).canonical_payload()
    lease["allowed_operations"] = marker

    case = _load_fixture("sab.artifact_case.v1.json")
    case["evidence_refs"] = marker

    ballot = _load_fixture("sab.artifact_ballot.v1.json")
    ballot["model_lineage_evidence_refs"] = marker

    verdict = _load_fixture("sab.council_verdict.v1.json")
    verdict["requested_effects"] = marker

    lifecycle = {
        "schema_version": "sab.rehearsal_lifecycle_request.v1",
        "idempotency_key": "malformed-collection",
        "code_sha": api_harness.context.code_sha,
        "artifact_id": api_harness.context.target_artifact_id,
        "artifact_sha256": api_harness.context.target_artifact_sha256,
        "evaluated_state_hash": api_harness.context.synthetic_state_hash,
        "requested_effects": marker,
        "signed_policy": {},
        "countersign": {},
        "disposition": {},
        "successor_artifact": {},
        "lineage_edge_id": "fixture:edge",
        "supersession": {},
        "signed_event": _structural_signed_event(
            api_harness,
            verdict_id="fixture:verdict",
            lineage_edge_id="fixture:edge",
        ),
    }
    requests = (
        ("/api/v1/session-write-leases/activate", lease, {}),
        (
            "/api/v1/session-write-leases/fixture:lease/release",
            marker,
            {api_module.WRITE_LEASE_HEADER: "fixture:lease"},
        ),
        (
            "/api/v1/artifact-cases",
            case,
            {api_module.WRITE_LEASE_HEADER: "fixture:lease"},
        ),
        (
            "/api/v1/artifact-cases/fixture:case/ballots",
            ballot,
            {api_module.WRITE_LEASE_HEADER: "fixture:lease"},
        ),
        (
            "/api/v1/artifact-cases/fixture:case/authority-evaluations",
            {
                "artifact_sha256": "0" * 64,
                "requested_effects": marker,
                "evaluated_state_hash": "0" * 64,
            },
            {api_module.WRITE_LEASE_HEADER: "fixture:lease"},
        ),
        (
            "/api/v1/artifact-cases/fixture:case/verdicts",
            {"evaluation_id": "fixture:evaluation", "verdict": verdict},
            {api_module.WRITE_LEASE_HEADER: "fixture:lease"},
        ),
        (
            "/api/v1/artifact-verdicts/fixture:verdict/rehearsal-dispositions",
            lifecycle,
            {api_module.WRITE_LEASE_HEADER: "fixture:lease"},
        ),
    )

    for path, payload, headers in requests:
        response = api_harness.client.post(path, json=payload, headers=headers)
        assert response.status_code == 422, (path, response.text)
        assert response.json()["error"]["code"] == "request_validation_error"
        assert str(marker) not in response.text

    non_string_effect = api_harness.client.post(
        "/api/v1/artifact-cases/fixture:case/authority-evaluations",
        headers={api_module.WRITE_LEASE_HEADER: "fixture:lease"},
        json={
            "artifact_sha256": "0" * 64,
            "requested_effects": ["seed:supersede", marker],
            "evaluated_state_hash": "0" * 64,
        },
    )
    assert non_string_effect.status_code == 422
    assert str(marker) not in non_string_effect.text


def test_expired_lease_read_is_derived_without_mutating_storage(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_at = datetime.now(timezone.utc)
    expired = _lease(api_harness, at=observed_at - timedelta(hours=2))
    with closing(open_attested_copy_connection(api_harness.attestation)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        activate_session_lease(conn, expired.canonical_payload())
        conn.commit()

    monkeypatch.setattr(api_module, "_utc_now", lambda: observed_at)
    response = api_harness.client.get(
        f"/api/v1/session-write-leases/{expired.lease_id}"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "expired"
    with closing(open_attested_copy_connection(api_harness.attestation)) as conn:
        stored_status = conn.execute(
            "SELECT status FROM sab_session_write_leases_v1 WHERE lease_id = ?",
            (expired.lease_id,),
        ).fetchone()[0]
    assert stored_status == "active"


@pytest.mark.parametrize(
    ("error", "expected_code", "expected_message"),
    (
        (
            ImmutableConflict("fixture:secret-token"),
            "immutable_content_conflict",
            "immutable content conflicts with an existing record",
        ),
        (
            LeaseStateConflict("fixture:private-key"),
            "lease_state_conflict",
            "session write lease state conflicts with the requested transition",
        ),
    ),
)
def test_storage_errors_are_constant_and_do_not_reflect_identifiers(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected_code: str,
    expected_message: str,
) -> None:
    def fail_closed(*_: Any, **__: Any) -> dict[str, Any]:
        raise error

    monkeypatch.setattr(api_module, "activate_session_lease", fail_closed)
    response = api_harness.client.post(
        "/api/v1/session-write-leases/activate",
        json=_lease(api_harness).canonical_payload(),
    )

    assert response.status_code == 409
    assert response.json() == {
        "error": {"code": expected_code, "message": expected_message}
    }
    assert "secret-token" not in response.text
    assert "private-key" not in response.text


@pytest.mark.parametrize("corrupt_json", ("not-json:must-not-reflect", "[]"))
def test_stored_contract_corruption_is_a_stable_409(
    api_harness: APIHarness,
    corrupt_json: str,
) -> None:
    lease_id = _activate(api_harness)
    case = _signed_case(api_harness, lease_id)
    created = api_harness.client.post(
        "/api/v1/artifact-cases",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=case.canonical_payload(),
    )
    assert created.status_code == 201

    with closing(sqlite3.connect(api_harness.attestation.database_path)) as conn:
        conn.execute("DROP TRIGGER sab_artifact_cases_v1_reject_update")
        conn.execute(
            "UPDATE sab_artifact_cases_v1 SET case_json = ? WHERE case_id = ?",
            (corrupt_json, case.case_id),
        )
        conn.commit()

    response = api_harness.client.get(f"/api/v1/artifact-cases/{case.case_id}")

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "database_attestation_failed",
            "message": "copied database attestation failed closed",
        }
    }
    assert "must-not-reflect" not in response.text


@pytest.mark.parametrize("edge_json", ("not-json:must-not-reflect", "[]"))
def test_lineage_rejects_invalid_json_or_non_object_rows(
    api_harness: APIHarness,
    edge_json: str,
) -> None:
    seed_id = "fixture:corrupt-seed"
    with closing(sqlite3.connect(api_harness.attestation.database_path)) as conn:
        conn.execute(
            """
            INSERT INTO sab_seed_lineage_edges_v1
                (edge_id, predecessor_seed_id, successor_seed_id, disposition_id,
                 edge_json, edge_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "fixture:corrupt-edge",
                seed_id,
                "fixture:successor",
                "fixture:missing-disposition",
                edge_json,
                "0" * 64,
                "2026-07-28T00:00:00Z",
            ),
        )
        conn.commit()

    response = api_harness.client.get(f"/api/v1/seeds/{seed_id}/lineage")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "stored_lineage_invalid"
    assert "must-not-reflect" not in response.text


def test_lineage_and_receipt_outputs_reject_nested_secret_fields(
    api_harness: APIHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "must-not-cross-response"
    supersession = _load_fixture("sab.seed_supersession.v1.json")
    edge = {
        "edge_id": "fixture:secret-edge",
        **supersession,
        "disposition_id": "fixture:missing-disposition",
        "disposition_sha256": "0" * 64,
        "private_key": marker,
    }
    with closing(sqlite3.connect(api_harness.attestation.database_path)) as conn:
        conn.execute(
            """
            INSERT INTO sab_seed_lineage_edges_v1
                (edge_id, predecessor_seed_id, successor_seed_id, disposition_id,
                 edge_json, edge_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                edge["edge_id"],
                edge["predecessor_seed_id"],
                edge["successor_seed_id"],
                edge["disposition_id"],
                json.dumps(edge, sort_keys=True, separators=(",", ":")),
                canonical_json_sha256(edge),
                "2026-07-28T00:00:00Z",
            ),
        )
        conn.commit()

    lineage = api_harness.client.get(
        f"/api/v1/seeds/{edge['predecessor_seed_id']}/lineage"
    )
    assert lineage.status_code == 409
    assert lineage.json()["error"]["code"] == "stored_lineage_invalid"
    assert marker not in lineage.text

    operation = [
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        )
    ]
    lease_id = _activate(api_harness, _lease(api_harness, operations=operation))
    receipt = _closed_lifecycle_receipt()
    receipt["authority"]["private_key"] = marker
    monkeypatch.setattr(
        api_module,
        "apply_rehearsal_lifecycle",
        lambda *_args, **_kwargs: receipt,
    )
    verdict_id = "fixture:response-verdict"
    lifecycle_request = {
        "schema_version": "sab.rehearsal_lifecycle_request.v1",
        "idempotency_key": "secret-response-test",
        "code_sha": api_harness.context.code_sha,
        "artifact_id": api_harness.context.target_artifact_id,
        "artifact_sha256": api_harness.context.target_artifact_sha256,
        "evaluated_state_hash": api_harness.context.synthetic_state_hash,
        "requested_effects": ["challenge:resolve", "seed:supersede"],
        "signed_policy": {},
        "countersign": {},
        "disposition": {},
        "successor_artifact": {},
        "lineage_edge_id": "fixture:response-edge",
        "supersession": {},
        "signed_event": _structural_signed_event(
            api_harness,
            verdict_id=verdict_id,
            lineage_edge_id="fixture:response-edge",
        ),
    }
    response = api_harness.client.post(
        f"/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        headers={api_module.WRITE_LEASE_HEADER: lease_id},
        json=lifecycle_request,
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "response_contract_invalid"
    assert marker not in response.text
