from __future__ import annotations

import base64
import copy
import hashlib
import json
import sqlite3
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from agora.sab_artifact_verdict import (
    ArtifactBallotV1,
    ArtifactCaseV1,
    CouncilVerdictV1,
    MASTER_VISION_DOCUMENT_SHA256,
    MASTER_VISION_SEED_ID,
    MASTER_VISION_SOURCE_COMMIT,
    MasterVisionPolicyEvidenceV1,
    OperatorCountersignV1,
    RehearsalDispositionV1,
    SeedSupersessionV1,
    SessionWriteLeaseV1,
    SignedDispositionPolicyV1,
    TrustedPolicyIssuerV1,
    allowed_operations_digest,
    canonical_json_bytes,
    canonical_json_sha256,
    evaluate_disposition_authority,
)
from agora.sab_first_verdict_lifecycle import (
    ACTIVATION_METHOD_PATH,
    MUTATION_BOUNDARIES,
    FixtureExecutionContext,
    LifecycleAuthorityDenied,
    LifecycleConflict,
    LifecycleValidationError,
    apply_rehearsal_lifecycle,
    build_effect_payload,
    build_lifecycle_event_payload,
    case_scope_head,
    compute_ballot_set_sha256,
    preview_rehearsal_transition,
    rehearsal_state_fingerprint,
    table_content_digest,
)
from agora.sab_first_verdict_evidence import (
    EvidenceValidationError,
    lifecycle_fingerprint,
    observe_master_vision_state,
)
from agora.sab_first_verdict_storage import (
    CopyDatabaseAttestation,
    DatabaseSafetyError,
    activate_session_lease,
    create_rehearsal_artifact,
    init_first_verdict_storage,
    init_signature_evidence_storage,
    open_attested_copy_connection,
    store_artifact_ballot,
    store_artifact_case,
    store_authority_evaluation,
    store_council_verdict,
)
from agora.sab_verdict_verify import verify_signature_evidence_table


NOW = datetime(2026, 7, 28, 0, 0, tzinfo=timezone.utc)
TARGET_ID = "sab_seed_fixture_first_verdict"
SUCCESSOR_ID = "sab_seed_fixture_first_verdict_v2"
CASE_ID = "sab_case_fixture_first_verdict"
VERDICT_ID = "sab_verdict_fixture_first_verdict"
LEASE_ID = "sab_lease_fixture_first_verdict"
DISPOSITION_ID = "sab_disposition_fixture_first_verdict"
LINEAGE_ID = "sab_lineage_fixture_first_verdict"
EVENT_ID = "sab_event_fixture_first_verdict"
SOURCE_FIXTURE_ID = "fixture:first-verdict"
COPIED_DATABASE_ID = "copy:first-verdict"
CODE_SHA = "c" * 40
EFFECTS = ("challenge:resolve", "seed:supersede")
EXPECTED_MUTATION_BOUNDARIES = (
    "countersign_insert",
    "target_transition",
    "successor_insert",
    "disposition_insert",
    "lineage_insert",
    "signature_evidence_insert",
    "signed_event_insert",
    "idempotency_insert",
)
ROOT = Path(__file__).resolve().parents[1]
MASTER_VISION_SEED_PACKET_PATH = (
    ROOT / "docs/lanes/sab-agent-seeding-v1/contributions/packets/"
    "sab_seed_master_vision_v1_ebe422aab149.json"
)
MASTER_VISION_CHALLENGE_PACKET_PATH = (
    ROOT / "docs/lanes/sab-agent-seeding-v1/contributions/packets/"
    "sab_challenge_master_vision_v1_ebe422aab149.json"
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _git_blob(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _master_vision_policy_evidence() -> MasterVisionPolicyEvidenceV1:
    document = _git_blob(MASTER_VISION_SOURCE_COMMIT, "docs/SAB_MASTER_VISION_V1.md")
    seed_packet = MASTER_VISION_SEED_PACKET_PATH.read_bytes()
    challenge_packet = MASTER_VISION_CHALLENGE_PACKET_PATH.read_bytes()
    return MasterVisionPolicyEvidenceV1(
        document_base64=base64.b64encode(document).decode("ascii"),
        seed_packet_base64=base64.b64encode(seed_packet).decode("ascii"),
        challenge_packet_base64=base64.b64encode(challenge_packet).decode("ascii"),
    )


def _public_key(key: SigningKey) -> str:
    return key.verify_key.encode(encoder=HexEncoder).decode("ascii")


def _dummy_signature(key: SigningKey, signer: str) -> dict[str, Any]:
    return {
        "alg": "ed25519",
        "signer": signer,
        "public_key": _public_key(key),
        "signature": "0" * 128,
        "signed_payload_sha256": "0" * 64,
        "canonicalization": "json-sort-keys-compact-v1",
    }


def _signature(key: SigningKey, signer: str, payload: dict[str, Any]) -> dict[str, Any]:
    message = canonical_json_bytes(payload)
    return {
        "alg": "ed25519",
        "signer": signer,
        "public_key": _public_key(key),
        "signature": key.sign(message).signature.hex(),
        "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
        "canonicalization": "json-sort-keys-compact-v1",
    }


def _signed_model(
    model: Any,
    body: dict[str, Any],
    signature_field: str,
    key: SigningKey,
    signer: str,
) -> Any:
    provisional = model.model_validate(
        {**body, signature_field: _dummy_signature(key, signer)}
    )
    payload = provisional.canonical_payload(exclude={signature_field})
    return model.model_validate(
        {**payload, signature_field: _signature(key, signer, payload)}
    )


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    # These tables model pre-existing domains that the lifecycle must not touch.
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
        CREATE TABLE sab_seed_packets_v1 (
            seed_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            packet_json TEXT NOT NULL,
            packet_hash TEXT NOT NULL
        );
        CREATE TABLE sab_challenge_packets_v1 (
            challenge_id TEXT PRIMARY KEY,
            target_seed_id TEXT NOT NULL,
            status TEXT NOT NULL,
            packet_json TEXT NOT NULL,
            packet_hash TEXT NOT NULL
        );
        CREATE TABLE sab_witness_events_v1 (
            id INTEGER PRIMARY KEY,
            event_id TEXT NOT NULL,
            chain_scope TEXT NOT NULL,
            event_type TEXT NOT NULL,
            subject_seed_id TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        CREATE TABLE web_agents (
            id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL
        );
        INSERT INTO sab_agent_identities_v1 VALUES ('identity-existing', '{"kind":"fixture"}');
        INSERT INTO sab_standing_leases_v1 VALUES ('standing-existing', 'active');
        INSERT INTO unrelated_operator_notes VALUES ('note-existing', X'00ff10');
        """
    )
    seed_packet = json.loads(MASTER_VISION_SEED_PACKET_PATH.read_bytes())
    challenge_packet = json.loads(MASTER_VISION_CHALLENGE_PACKET_PATH.read_bytes())
    conn.execute(
        "INSERT INTO sab_seed_packets_v1 VALUES (?, 'challenged', ?, ?)",
        (
            MASTER_VISION_SEED_ID,
            json.dumps(seed_packet, sort_keys=True, separators=(",", ":")),
            "2513c4d44ca01c5497c007ce4dc8493355e69f7bc71197d119861587395b9a88",
        ),
    )
    conn.execute(
        "INSERT INTO sab_challenge_packets_v1 VALUES (?, ?, 'pending', ?, ?)",
        (
            "sab_challenge_master_vision_v1_ebe422aab149",
            MASTER_VISION_SEED_ID,
            json.dumps(challenge_packet, sort_keys=True, separators=(",", ":")),
            "f0440aae05cf8e470b314148f8e696e9a8981e4510950589e36b7a3a3d37aa95",
        ),
    )
    conn.executemany(
        "INSERT INTO sab_witness_events_v1 VALUES (?, ?, ?, ?, ?, ?)",
        (
            (
                1,
                "sab_seed_submit_master_vision_v1_ebe422aab149",
                MASTER_VISION_SEED_ID,
                "submit",
                MASTER_VISION_SEED_ID,
                "a7dbcede4aad52036c1504b45b0c16f6c7bb0f42da2854add463c5e2221b9767",
            ),
            (
                2,
                "sab_challenge_submit_master_vision_v1_ebe422aab149",
                MASTER_VISION_SEED_ID,
                "challenge",
                MASTER_VISION_SEED_ID,
                "1acfa3eb5b596ea39073b4a3ff753cd5092f02fa9c50ae4871a987cdbaa04492",
            ),
        ),
    )
    conn.execute(
        "INSERT INTO web_agents VALUES (?, ?)",
        (
            "agent_claude_fable_5",
            "0a70c303c0e794d0978e80f9c521e81c655a94a17f95a952ac9b5f7ab901f1f5",
        ),
    )
    conn.commit()
    return conn


def _database_digest(conn: sqlite3.Connection) -> str:
    names = [
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    return canonical_json_sha256(
        {name: table_content_digest(conn, name) for name in names}
    )


def _backup_fixture_to_path(fixture: "LifecycleFixture", destination: Path) -> None:
    copied = sqlite3.connect(destination)
    try:
        fixture.conn.backup(copied)
        copied.commit()
    finally:
        copied.close()


@dataclass
class LifecycleFixture:
    conn: sqlite3.Connection
    attestation: CopyDatabaseAttestation
    temporary_directory: TemporaryDirectory[str]
    request: dict[str, Any]
    context: FixtureExecutionContext
    authority_digest: str
    before_database_digest: str
    target_packet_sha256: str


def _fixture() -> LifecycleFixture:
    base = _connect()
    temporary_directory = TemporaryDirectory(prefix="sab-first-verdict-fixture-")
    fixture_root = Path(temporary_directory.name)
    source_path = fixture_root / "source.db"
    copied_path = fixture_root / "copied.db"
    source = sqlite3.connect(source_path)
    try:
        base.backup(source)
        source.commit()
    finally:
        source.close()
        base.close()
    readonly_source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    copied = sqlite3.connect(copied_path)
    try:
        readonly_source.backup(copied)
        copied.commit()
    finally:
        copied.close()
        readonly_source.close()
    source_backup_sha256 = hashlib.sha256(copied_path.read_bytes()).hexdigest()
    readonly_copy = sqlite3.connect(f"file:{copied_path}?mode=ro", uri=True)
    try:
        copy_lifecycle_fingerprint = lifecycle_fingerprint(readonly_copy)["sha256"]
    finally:
        readonly_copy.close()
    copy_receipt_path = fixture_root / "copy-receipt.json"
    source_stat = source_path.stat()
    copy_receipt_path.write_text(
        json.dumps(
            {
                "schema_version": "sab.build_a.a0_database_snapshot.v1",
                "content_equal": True,
                "source": {
                    "path_ref": str(source_path.resolve()),
                    "opened": "sqlite_uri_mode_ro",
                    "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
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
        expected_lifecycle_fingerprint=copy_lifecycle_fingerprint,
        copy_receipt_sha256=hashlib.sha256(copy_receipt_path.read_bytes()).hexdigest(),
        copy_receipt_path=copy_receipt_path,
    )
    conn = open_attested_copy_connection(attestation, require_pristine_backup=True)
    init_first_verdict_storage(conn, applied_at="2026-07-28T00:00:00Z")
    init_signature_evidence_storage(conn, applied_at="2026-07-28T00:00:01Z")
    issuer_key = SigningKey.generate()
    clerk_key = SigningKey.generate()
    claimant_key = SigningKey.generate()
    event_key = SigningKey.generate()
    seat_keys = [SigningKey.generate() for _ in range(9)]

    target_packet = {
        "schema": "sab.synthetic_seed_packet.v1",
        "seed_id": TARGET_ID,
        "claim": "The synthetic v1 claim contains a named correctable defect.",
        "claimant_identity": "fixture:claimant",
    }
    target_packet_sha = canonical_json_sha256(target_packet)
    target = {
        "artifact_id": TARGET_ID,
        "state": "challenged",
        "packet": target_packet,
        "packet_sha256": target_packet_sha,
        "claimant_identity": "fixture:claimant",
        "challenges": [
            {
                "challenge_id": "sab_challenge_fixture_first_verdict",
                "challenge_packet_sha256": _sha("fixture-challenge"),
                "status": "pending",
            }
        ],
        "source_fixture_id": SOURCE_FIXTURE_ID,
        "copied_database_id": COPIED_DATABASE_ID,
        "standing_effect": "none",
        "live_eligible": False,
    }
    create_rehearsal_artifact(conn, target, created_at="2026-07-27T23:55:00Z")
    conn.commit()
    before_state = rehearsal_state_fingerprint(conn)
    assert lifecycle_fingerprint(conn)["sha256"] == copy_lifecycle_fingerprint
    expected_case_head = case_scope_head(conn, TARGET_ID)

    policy_unsigned = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": "sab_policy_fixture_first_verdict",
        "artifact_id": TARGET_ID,
        "artifact_sha256": target_packet_sha,
        "disposition_mode": "authorized",
        "scope": "Copy",
        "permitted_effects": list(EFFECTS),
        "forbidden_effects": [],
        "preconditions": ["challenge_state=pending", "seed_state=challenged"],
        "evaluated_state_hash": before_state,
        "source_fixture_id": SOURCE_FIXTURE_ID,
        "copied_database_id": COPIED_DATABASE_ID,
        "test_issuer": True,
        "live_eligible": False,
        "standing_effect": "none",
        "authority_refs": ["fixture:signed-copy-policy"],
        "issued_at": (NOW - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "issuer": "fixture:policy-issuer",
    }
    policy_hash = canonical_json_sha256(policy_unsigned)
    policy = _signed_model(
        SignedDispositionPolicyV1,
        {**policy_unsigned, "policy_sha256": policy_hash},
        "signature",
        issuer_key,
        "fixture:policy-issuer",
    )

    operations = [
        {"method": ACTIVATION_METHOD_PATH[0], "path": ACTIVATION_METHOD_PATH[1]}
    ]
    lease_unsigned = {
        "schema": "sab.session_write_lease.v1",
        "lease_id": LEASE_ID,
        "session_id": "sab_session_fixture_first_verdict",
        "clerk_identity": "fixture:clerk",
        "allowed_operations": operations,
        "allowed_operations_sha256": allowed_operations_digest(operations),
        "accepted_code_sha": CODE_SHA,
        "expected_lifecycle_fingerprint": copy_lifecycle_fingerprint,
        "source_backup_sha256": source_backup_sha256,
        "issuer_identity": "fixture:operator",
        "issuer_public_key": _public_key(issuer_key),
        "issuer_fingerprint": hashlib.sha256(
            bytes.fromhex(_public_key(issuer_key))
        ).hexdigest(),
        "authority_basis": "founder_bootstrap_self_declared",
        "scope": "Copy",
        "issued_at": (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "activated_at": (NOW - timedelta(minutes=4)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "standing_effect": "none",
        "live_eligible": False,
    }
    lease_hash = canonical_json_sha256(lease_unsigned)
    lease = _signed_model(
        SessionWriteLeaseV1,
        {**lease_unsigned, "lease_sha256": lease_hash},
        "signature",
        issuer_key,
        "fixture:operator",
    )
    activate_session_lease(
        conn,
        lease.canonical_payload(),
        activated_at="2026-07-27T23:56:00Z",
    )

    evidence_refs = [
        {
            "ref": "fixture:case-evidence",
            "content_sha256": _sha("case-evidence"),
            "proof_class": "signed_fixture",
        }
    ]
    roster: list[dict[str, Any]] = []
    for index, key in enumerate(seat_keys):
        roster.append(
            {
                "seat_id": f"seat-{index}",
                "requested_lab": f"lab-{index}",
                "requested_model": f"requested-model-{index}",
                "adapter": "fixture-adapter",
                "transport": "fixture-transport",
                "requested_route": f"fixture/route/{index}",
                "served_provider": "fixture-provider",
                "served_model": f"served-model-{index}",
                "model_family": f"family-{index}",
                "credited_cluster": f"base-lineage-{index}",
                "cluster_basis": "evidenced_base_model_or_training_lineage",
                "model_lineage_evidence_refs": [
                    {
                        "ref": f"fixture:lineage:{index}",
                        "content_sha256": _sha(f"lineage:{index}"),
                        "proof_class": "signed_fixture",
                    }
                ],
                "possible_underlying_routes": [f"fixture/route/{index}"],
                "transport_correlation_refs": [],
                "correlation_smeared": False,
                "execution_public_key": _public_key(key),
                "key_role": "operator_controlled_execution_attestation",
                "common_operator_backing": "single disclosed fixture operator",
                "liveness_receipt_sha256": _sha(f"liveness:{index}"),
            }
        )
    target_bytes = canonical_json_bytes(target_packet)
    case_body = {
        "schema": "sab.artifact_case.v1",
        "case_id": CASE_ID,
        "target_seed_id": TARGET_ID,
        "target_seed_packet_sha256": target_packet_sha,
        "expected_seed_state": "challenged",
        "expected_case_head": expected_case_head,
        "challenges": copy.deepcopy(target["challenges"]),
        "evidence_refs": evidence_refs,
        "docket_rule": {
            "version": "sab-first-verdict-fixture-v1",
            "rule_sha256": _sha("fixture-docket-rule"),
            "signed_conditions_satisfied": True,
            "challenge_resolution_authorized": True,
            "jurisdiction_established": True,
        },
        "canon_conditions": ["fixture canon condition"],
        "compost_conditions": ["fixture correction condition"],
        "anti_capture_rules": ["same operator is disclosed, never independent"],
        "independence_disclosure": "Synthetic same-operator fixture only.",
        "demanded_correction": "Correct the named synthetic defect.",
        "amendment_clause": "Any self-binding weakening forces appeal.",
        "conflict_flags": {
            "clerk_is_case_author": False,
            "clerk_is_challenger": False,
            "author_is_challenger": False,
        },
        "signed_artifact_b64": base64.b64encode(target_bytes).decode(),
        "signed_artifact_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "frozen_roster": roster,
        "frozen_roster_sha256": canonical_json_sha256(roster),
        "single_operator_adjudicated": True,
        "clerk_identity": "fixture:clerk",
        "lease_id": LEASE_ID,
        "frozen_at": (NOW - timedelta(minutes=3)).isoformat().replace("+00:00", "Z"),
    }
    case = _signed_model(
        ArtifactCaseV1,
        case_body,
        "clerk_signature",
        clerk_key,
        "fixture:clerk",
    )
    _, case_sha, _ = store_artifact_case(
        conn, case.canonical_payload(), created_at="2026-07-27T23:57:00Z"
    )

    authority = evaluate_disposition_authority(
        artifact_id=TARGET_ID,
        artifact_sha256=target_packet_sha,
        requested_scope="Copy",
        requested_effects=EFFECTS,
        evaluated_state_hash=before_state,
        signed_policy=policy,
        trusted_policy_issuer=TrustedPolicyIssuerV1(
            issuer_identity="fixture:policy-issuer",
            issuer_public_key=_public_key(issuer_key),
            source_fixture_id=SOURCE_FIXTURE_ID,
            copied_database_id=COPIED_DATABASE_ID,
            authority_basis="founder_bootstrap_self_declared",
        ),
        now=NOW,
    )
    store_authority_evaluation(
        conn,
        case_id=CASE_ID,
        authority=authority.canonical_payload(),
        created_at="2026-07-27T23:57:10Z",
    )

    ballot_members: list[dict[str, str]] = []
    for index, (seat, key) in enumerate(zip(roster, seat_keys)):
        ballot_body = {
            "schema": "sab.artifact_ballot.v1",
            "ballot_id": f"sab_ballot_fixture_{index}",
            "case_id": CASE_ID,
            "case_sha256": case_sha,
            "seat_id": seat["seat_id"],
            "round_no": 1,
            "stage": "final",
            "decision": "correct_and_supersede",
            "ballot_source": "fixture_model",
            "claim_findings": [
                {
                    "claim_ref": "fixture:claim:0",
                    "finding": "refuted",
                    "rationale": "The named synthetic defect is reproduced.",
                    "evidence_refs": evidence_refs,
                }
            ],
            "self_binding_weakening_finding": {
                "weakens_self_binding_constraint": False,
                "affected_constraints": [],
                "evidence_refs": evidence_refs,
                "explanation": "The correction preserves the fixture constraint.",
            },
            "strongest_case_against_decision": "The synthetic evidence could be incomplete.",
            "unresolved_objections": [],
            "raw_model_output_sha256": _sha(f"raw-ballot:{index}"),
            "transcript_ref": {
                "ref": f"fixture:transcript:{index}",
                "content_sha256": _sha(f"transcript:{index}"),
                "proof_class": "fixture_model_transcript",
            },
            "requested_model": seat["requested_model"],
            "requested_route": seat["requested_route"],
            "served_provider": seat["served_provider"],
            "served_model": seat["served_model"],
            "served_route": seat["requested_route"],
            "credited_cluster": seat["credited_cluster"],
            "cluster_basis": "evidenced_base_model_or_training_lineage",
            "model_lineage_evidence_refs": seat["model_lineage_evidence_refs"],
            "transport_correlation_refs": [],
            "correlation_smeared": False,
            "signature_role": "operator_controlled_execution_attestation",
            "vendor_signature_claimed": False,
        }
        ballot = _signed_model(
            ArtifactBallotV1,
            ballot_body,
            "execution_signature",
            key,
            f"fixture:execution:{index}",
        )
        _, ballot_sha, _ = store_artifact_ballot(
            conn,
            ballot.canonical_payload(),
            created_at=f"2026-07-27T23:58:{index:02d}Z",
        )
        ballot_members.append(
            {"ballot_id": ballot.ballot_id, "ballot_sha256": ballot_sha}
        )

    clusters = [f"base-lineage-{index}" for index in range(9)]
    verdict = CouncilVerdictV1.model_validate(
        {
            "schema": "sab.council_verdict.v1",
            "verdict_id": VERDICT_ID,
            "case_id": CASE_ID,
            "case_sha256": case_sha,
            "round_no": 1,
            "decision": "correct_and_supersede",
            "raw_tally": {"correct_and_supersede": 9},
            "clean_routing_tally": {"correct_and_supersede": 9},
            "credited_clusters_by_result": {"correct_and_supersede": clusters},
            "smeared_seats": [],
            "correlation_removal_result": "stable",
            "terminality": "terminal",
            "appeal_reasons": [],
            "ballot_sources": ["fixture_model"],
            "evidence_provenance": "fixture_models",
            "requested_effects": list(EFFECTS),
            "authority_digest": authority.authority_digest,
            "scope": "Copy",
            "operator_independence": "single_operator_bootstrap",
            "effect_domain": "artifact",
            "standing_effect": "none",
            "compiled_at": (NOW - timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z"),
        }
    )
    _, verdict_sha, _ = store_council_verdict(
        conn,
        evaluation_id=authority.evaluation_id,
        verdict=verdict.canonical_payload(),
        ballot_set_sha256=compute_ballot_set_sha256(ballot_members),
        created_at="2026-07-27T23:59:00Z",
    )
    conn.commit()

    successor_packet = {
        "schema": "sab.synthetic_seed_packet.v1",
        "seed_id": SUCCESSOR_ID,
        "claim": "The synthetic v2 claim corrects the named defect.",
        "claimant_identity": "fixture:claimant",
    }
    successor_packet_sha = canonical_json_sha256(successor_packet)
    successor = {
        "artifact_id": SUCCESSOR_ID,
        "state": "pending",
        "packet": successor_packet,
        "packet_sha256": successor_packet_sha,
        "packet_signature": _signature(
            claimant_key, "fixture:claimant", successor_packet
        ),
        "claimant_identity": "fixture:claimant",
        "challenges": [],
        "source_fixture_id": SOURCE_FIXTURE_ID,
        "copied_database_id": COPIED_DATABASE_ID,
        "standing_effect": "none",
        "live_eligible": False,
    }
    supersession_body = {
        "schema": "sab.seed_supersession.v1",
        "predecessor_seed_id": TARGET_ID,
        "predecessor_packet_sha256": target_packet_sha,
        "successor_seed_id": SUCCESSOR_ID,
        "successor_packet_sha256": successor_packet_sha,
        "correction_summary": "The successor corrects the named synthetic defect.",
        "correction_artifact_sha256": _sha("fixture-correction"),
        "relation": "superseded_by_correction",
        "claimant_identity": "fixture:claimant",
        "authority_lease_id": LEASE_ID,
        "scope": "Copy",
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "standing_effect": "none",
        "live_eligible": False,
    }
    supersession = _signed_model(
        SeedSupersessionV1,
        supersession_body,
        "claimant_signature",
        claimant_key,
        "fixture:claimant",
    )
    supersession_sha = canonical_json_sha256(supersession.canonical_payload())
    transition = preview_rehearsal_transition(
        conn,
        case=case,
        successor_artifact=successor,
        disposition_id=DISPOSITION_ID,
    )
    effect_payload = build_effect_payload(
        effects=EFFECTS,
        disposition_id=DISPOSITION_ID,
        target_artifact_id=TARGET_ID,
        successor_artifact=successor,
        supersession_sha256=supersession_sha,
    )
    countersign_body = {
        "schema": "sab.operator_countersign.v1",
        "countersign_id": "sab_countersign_fixture_first_verdict",
        "verdict_id": VERDICT_ID,
        "verdict_sha256": verdict_sha,
        "case_id": CASE_ID,
        "case_sha256": case_sha,
        "target_seed_id": TARGET_ID,
        "decision": "correct_and_supersede",
        "expected_seed_state": "challenged",
        "expected_case_head": case.expected_case_head,
        "expected_lifecycle_fingerprint": copy_lifecycle_fingerprint,
        "effect_payload": effect_payload,
        "effect_payload_sha256": canonical_json_sha256(effect_payload),
        "successor_envelope_sha256": canonical_json_sha256(successor),
        "write_lease_id": LEASE_ID,
        "lease_sha256": lease.lease_sha256,
        "authority_digest": authority.authority_digest,
        "allowed_operations": operations,
        "allowed_operations_sha256": lease.allowed_operations_sha256,
        "code_sha": CODE_SHA,
        "scope": "Copy",
        "signer_kind": "fixture_ephemeral",
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        "standing_effect": "none",
        "live_eligible": False,
    }
    countersign = _signed_model(
        OperatorCountersignV1,
        countersign_body,
        "signature",
        issuer_key,
        "fixture:operator",
    )
    countersign_sha = canonical_json_sha256(countersign.canonical_payload())
    disposition = RehearsalDispositionV1.model_validate(
        {
            "schema": "sab.rehearsal_disposition.v1",
            "disposition_id": DISPOSITION_ID,
            "verdict_id": VERDICT_ID,
            "verdict_sha256": verdict_sha,
            "case_id": CASE_ID,
            "case_sha256": case_sha,
            "authority": authority.canonical_payload(),
            "countersign_id": countersign.countersign_id,
            "countersign_sha256": countersign_sha,
            "effects": list(EFFECTS),
            "ballot_source": "fixture_model",
            "evidence_provenance": "fixture_models",
            "scope": "Copy",
            "proof_class": "copied_live_db_rehearsal",
            "source_fixture_id": SOURCE_FIXTURE_ID,
            "copied_database_id": COPIED_DATABASE_ID,
            "before_state_hash": transition["before_state_hash"],
            "after_state_hash": transition["after_state_hash"],
            "applied_at": NOW.isoformat().replace("+00:00", "Z"),
            "standing_effect": "none",
            "live_eligible": False,
        }
    )
    disposition_sha = canonical_json_sha256(disposition.canonical_payload())
    lineage_payload = {
        "edge_id": LINEAGE_ID,
        **supersession.canonical_payload(),
        "disposition_id": DISPOSITION_ID,
        "disposition_sha256": disposition_sha,
    }
    lineage_sha = canonical_json_sha256(lineage_payload)
    event_payload = build_lifecycle_event_payload(
        event_id=EVENT_ID,
        case_id=CASE_ID,
        verdict_id=VERDICT_ID,
        disposition_id=DISPOSITION_ID,
        lineage_edge_id=LINEAGE_ID,
        target_artifact_id=TARGET_ID,
        successor_artifact_id=SUCCESSOR_ID,
        authority_digest=authority.authority_digest,
        countersign_sha256=countersign_sha,
        disposition_sha256=disposition_sha,
        lineage_sha256=lineage_sha,
        before_state_hash=transition["before_state_hash"],
        after_state_hash=transition["after_state_hash"],
        prev_hash=None,
    )
    signed_event = {
        "artifact_type": "lifecycle_event",
        "artifact_id": EVENT_ID,
        "signer_kind": "fixture_ephemeral",
        "signed_payload": event_payload,
        "signature": _signature(event_key, "fixture:lifecycle-event", event_payload),
    }
    request = {
        "idempotency_key": "fixture-idempotency-key",
        "code_sha": CODE_SHA,
        "artifact_id": TARGET_ID,
        "artifact_sha256": target_packet_sha,
        "evaluated_state_hash": before_state,
        "requested_effects": list(EFFECTS),
        "signed_policy": policy.canonical_payload(),
        "countersign": countersign.canonical_payload(),
        "disposition": disposition.canonical_payload(),
        "successor_artifact": successor,
        "lineage_edge_id": LINEAGE_ID,
        "supersession": supersession.canonical_payload(),
        "signed_event": signed_event,
    }
    context = FixtureExecutionContext(
        proof_class="authorized_synthetic_copy_fixture",
        target_artifact_id=TARGET_ID,
        target_artifact_sha256=target_packet_sha,
        source_fixture_id=SOURCE_FIXTURE_ID,
        copied_database_id=COPIED_DATABASE_ID,
        source_backup_sha256=source_backup_sha256,
        code_sha=CODE_SHA,
        copied_lifecycle_fingerprint=copy_lifecycle_fingerprint,
        synthetic_state_hash=before_state,
        expected_case_head=expected_case_head,
        policy_issuer_identity="fixture:policy-issuer",
        policy_issuer_public_key=_public_key(issuer_key),
        operator_identity="fixture:operator",
        operator_public_key=_public_key(issuer_key),
        clerk_identity="fixture:clerk",
        clerk_public_key=_public_key(clerk_key),
        claimant_identity="fixture:claimant",
        claimant_public_key=_public_key(claimant_key),
        event_signer_identity="fixture:lifecycle-event",
        event_signer_public_key=_public_key(event_key),
        seat_execution_identities=tuple(
            (
                f"seat-{index}",
                f"fixture:execution:{index}",
                _public_key(key),
            )
            for index, key in enumerate(seat_keys)
        ),
    )
    return LifecycleFixture(
        conn=conn,
        attestation=attestation,
        temporary_directory=temporary_directory,
        request=request,
        context=context,
        authority_digest=authority.authority_digest,
        before_database_digest=_database_digest(conn),
        target_packet_sha256=target_packet_sha,
    )


def test_authorized_fixture_lifecycle_is_one_atomic_copy_only_transaction() -> None:
    fixture = _fixture()
    assert MUTATION_BOUNDARIES == EXPECTED_MUTATION_BOUNDARIES
    statements: list[str] = []
    fixture.conn.set_trace_callback(statements.append)

    receipt = apply_rehearsal_lifecycle(
        fixture.conn,
        fixture.request,
        fixture_context=fixture.context,
        now=NOW,
    )

    begins = [statement for statement in statements if statement == "BEGIN IMMEDIATE"]
    commits = [statement for statement in statements if statement == "COMMIT"]
    assert len(begins) == len(commits) == 1
    assert receipt["proof_class"] == "copied_live_db_rehearsal"
    assert receipt["validation_order"][0] == "DispositionAuthority<Copy>"
    assert receipt["authority"]["authority_digest"] == fixture.authority_digest
    assert receipt["transaction"]["boundaries"] == list(MUTATION_BOUNDARIES)
    assert receipt["signature_replay"]["proof_class"] == "SignaturesVerified"
    assert receipt["signature_replay"]["signature_count"] == 16
    assert receipt["standing_effect"] == receipt["identity_effect"] == "none"
    assert receipt["live_mutations"] == receipt["provider_calls"] == 0

    target = fixture.conn.execute(
        "SELECT state, artifact_json FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
        (TARGET_ID,),
    ).fetchone()
    assert target[0] == "superseded"
    target_json = json.loads(target[1])
    assert target_json["challenges"][0]["status"] == "resolved"
    assert target_json["superseded_by"] == SUCCESSOR_ID
    assert (
        fixture.conn.execute(
            "SELECT state FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
            (SUCCESSOR_ID,),
        ).fetchone()[0]
        == "pending"
    )
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_operator_countersigns_v1"
        ).fetchone()[0]
        == 1
    )
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_rehearsal_dispositions_v1"
        ).fetchone()[0]
        == 1
    )
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_seed_lineage_edges_v1"
        ).fetchone()[0]
        == 1
    )
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_first_verdict_signed_events_v1"
        ).fetchone()[0]
        == 1
    )
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_first_verdict_idempotency_v1"
        ).fetchone()[0]
        == 1
    )
    for digest in receipt["invariant_table_digests"].values():
        assert digest["unchanged"] is True
        assert digest["before_sha256"] == digest["after_sha256"]


@pytest.mark.parametrize("boundary", MUTATION_BOUNDARIES)
def test_failure_after_every_mutation_boundary_rolls_back_everything(
    boundary: str,
) -> None:
    fixture = _fixture()
    before = _database_digest(fixture.conn)

    class Injected(RuntimeError):
        pass

    def fail(selected: str) -> None:
        if selected == boundary:
            raise Injected(selected)

    with pytest.raises(Injected, match=boundary):
        apply_rehearsal_lifecycle(
            fixture.conn,
            fixture.request,
            fixture_context=fixture.context,
            now=NOW,
            failure_hook=fail,
        )

    assert not fixture.conn.in_transaction
    assert _database_digest(fixture.conn) == before
    assert (
        fixture.conn.execute(
            "SELECT state FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
            (TARGET_ID,),
        ).fetchone()[0]
        == "challenged"
    )
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
            (SUCCESSOR_ID,),
        ).fetchone()[0]
        == 0
    )


def test_exact_retry_returns_same_receipt_without_any_extra_event() -> None:
    fixture = _fixture()
    first = apply_rehearsal_lifecycle(
        fixture.conn,
        fixture.request,
        fixture_context=fixture.context,
        now=NOW,
        expected_verdict_id=VERDICT_ID,
        expected_write_lease_id=LEASE_ID,
    )
    after_first = _database_digest(fixture.conn)
    second = apply_rehearsal_lifecycle(
        fixture.conn,
        copy.deepcopy(fixture.request),
        fixture_context=fixture.context,
        now=NOW + timedelta(days=1),
        expected_verdict_id=VERDICT_ID,
        expected_write_lease_id=LEASE_ID,
    )
    assert second == first
    assert json.dumps(second, separators=(",", ":")) == json.dumps(
        first, separators=(",", ":")
    )
    assert _database_digest(fixture.conn) == after_first
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_first_verdict_signed_events_v1"
        ).fetchone()[0]
        == 1
    )
    with pytest.raises(LifecycleConflict) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn,
            copy.deepcopy(fixture.request),
            fixture_context=fixture.context,
            now=NOW + timedelta(days=1),
            expected_verdict_id="sab_verdict_wrong_route",
            expected_write_lease_id=LEASE_ID,
        )
    assert raised.value.code == "idempotency_route_binding_mismatch"


def test_exact_retry_rejects_a_different_out_of_band_fixture_context() -> None:
    fixture = _fixture()
    receipt = apply_rehearsal_lifecycle(
        fixture.conn,
        fixture.request,
        fixture_context=fixture.context,
        now=NOW,
    )
    changed_context = replace(
        fixture.context,
        source_fixture_id="fixture:other-source",
        copied_database_id="copy:other-copy",
    )

    with pytest.raises(LifecycleAuthorityDenied) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn,
            copy.deepcopy(fixture.request),
            fixture_context=changed_context,
            now=NOW,
        )

    assert raised.value.code == "idempotency_context_mismatch"
    assert receipt["fixture_context_sha256"] == fixture.context.digest
    assert changed_context.digest != receipt["fixture_context_sha256"]


def test_same_idempotency_identity_with_different_content_is_domain_conflict() -> None:
    fixture = _fixture()
    apply_rehearsal_lifecycle(
        fixture.conn, fixture.request, fixture_context=fixture.context, now=NOW
    )
    changed = copy.deepcopy(fixture.request)
    changed["successor_artifact"]["packet"]["claim"] = "conflicting content"
    with pytest.raises(LifecycleConflict) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn, changed, fixture_context=fixture.context, now=NOW
        )
    assert raised.value.status_code == 409
    assert raised.value.code == "idempotency_content_conflict"


def test_master_vision_is_advisory_before_merit_and_has_zero_effect() -> None:
    fixture = _fixture()
    evidence = _master_vision_policy_evidence()
    assert evidence.document_sha256 == MASTER_VISION_DOCUMENT_SHA256
    assert evidence.seed_state == "challenged"
    assert evidence.challenge_state == "pending"
    request = copy.deepcopy(fixture.request)
    request["idempotency_key"] = "master-vision-denial"
    request["artifact_id"] = MASTER_VISION_SEED_ID
    request["artifact_sha256"] = MASTER_VISION_DOCUMENT_SHA256
    request["signed_policy"] = evidence.canonical_payload()
    observation = observe_master_vision_state(fixture.conn)
    request["evaluated_state_hash"] = observation.observed_state_hash
    # These malformed post-authority objects prove that merit/effect parsing is
    # unreachable for the jurisdictional refusal.
    request["countersign"] = {"private_key": "must-never-be-parsed"}
    request["successor_artifact"] = {"token": "must-never-be-parsed"}
    master_context = replace(
        fixture.context,
        target_artifact_id=request["artifact_id"],
        target_artifact_sha256=request["artifact_sha256"],
        synthetic_state_hash=observation.observed_state_hash,
        expected_case_head=case_scope_head(fixture.conn, request["artifact_id"]),
    )
    before = _database_digest(fixture.conn)

    with pytest.raises(LifecycleAuthorityDenied) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn, request, fixture_context=master_context, now=NOW
        )

    assert raised.value.code == "authority_advisoryonly"
    assert _database_digest(fixture.conn) == before
    assert (
        fixture.conn.execute(
            "SELECT COUNT(*) FROM sab_rehearsal_dispositions_v1"
        ).fetchone()[0]
        == 0
    )
    target = json.loads(
        fixture.conn.execute(
            "SELECT artifact_json FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
            (TARGET_ID,),
        ).fetchone()[0]
    )
    assert target["state"] == "challenged"
    assert target["challenges"][0]["status"] == "pending"


def test_master_vision_requires_exact_signed_evidence() -> None:
    evidence = _master_vision_policy_evidence()
    fixture = _fixture()
    observation = observe_master_vision_state(fixture.conn)
    kwargs = {
        "artifact_id": MASTER_VISION_SEED_ID,
        "artifact_sha256": MASTER_VISION_DOCUMENT_SHA256,
        "requested_scope": "Copy",
        "requested_effects": EFFECTS,
        "evaluated_state_hash": observation.observed_state_hash,
        "master_vision_observation": observation,
        "now": NOW,
    }

    exact = evaluate_disposition_authority(signed_policy=evidence, **kwargs)
    assert exact.result == "AdvisoryOnly"
    assert exact.allowed_effects == ()
    assert set(exact.forbidden_effects) >= {"compost", "supersede", "canon"}

    missing = evaluate_disposition_authority(signed_policy=None, **kwargs)
    assert missing.result == "NoJurisdiction"
    assert missing.reason_codes == ("invalid_master_vision_policy_evidence",)

    bogus = evaluate_disposition_authority(
        signed_policy={"schema": "sab.master_vision_policy_evidence.v1"}, **kwargs
    )
    assert bogus.result == "NoJurisdiction"

    wrong_artifact = evaluate_disposition_authority(
        signed_policy=evidence,
        **{**kwargs, "artifact_sha256": "0" * 64},
    )
    assert wrong_artifact.result == "NoJurisdiction"
    assert wrong_artifact.reason_codes == ("artifact_binding_mismatch",)

    stale = evaluate_disposition_authority(
        signed_policy=evidence,
        **{**kwargs, "now": datetime(2026, 10, 3, tzinfo=timezone.utc)},
    )
    assert stale.result == "NoJurisdiction"
    assert stale.reason_codes == ("master_vision_revalidation_due",)

    unobserved = evaluate_disposition_authority(
        signed_policy=evidence,
        **{
            key: value
            for key, value in kwargs.items()
            if key != "master_vision_observation"
        },
    )
    assert unobserved.result == "NoJurisdiction"
    assert unobserved.reason_codes == (
        "master_vision_state_observation_missing_or_invalid",
    )

    constructed = MasterVisionPolicyEvidenceV1.model_construct(
        document_base64="Ym9ndXM=",
        seed_packet_base64="Ym9ndXM=",
        challenge_packet_base64="Ym9ndXM=",
    )
    bypass = evaluate_disposition_authority(
        signed_policy=constructed,
        **kwargs,
    )
    assert bypass.result == "NoJurisdiction"


@pytest.mark.parametrize(
    "missing_table",
    (
        "sab_seed_lineage_edges_v1",
        "sab_rehearsal_dispositions_v1",
        "sab_first_verdict_schema_migrations_v1",
    ),
)
def test_master_vision_zero_effect_observation_requires_effect_ledgers(
    missing_table: str,
) -> None:
    fixture = _fixture()
    fixture.conn.execute(f'DROP TABLE "{missing_table}"')
    with pytest.raises(
        EvidenceValidationError, match="Master Vision state cannot be derived"
    ):
        observe_master_vision_state(fixture.conn)


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "preconditions", "reason"),
    [
        (
            NOW + timedelta(hours=1),
            NOW + timedelta(hours=2),
            ["challenge_state=pending", "seed_state=challenged"],
            "policy_not_yet_valid",
        ),
        (
            NOW - timedelta(minutes=1),
            NOW + timedelta(hours=1),
            ["always=true"],
            "policy_preconditions_mismatch",
        ),
    ],
)
def test_authority_rejects_future_or_non_frozen_policy_claims(
    issued_at: datetime,
    expires_at: datetime,
    preconditions: list[str],
    reason: str,
) -> None:
    key = SigningKey.generate()
    artifact_sha256 = _sha("policy-bound-artifact")
    state_hash = _sha("policy-bound-state")
    unsigned = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": f"policy-{reason}",
        "artifact_id": "seed-policy-boundary",
        "artifact_sha256": artifact_sha256,
        "disposition_mode": "authorized",
        "scope": "Copy",
        "permitted_effects": list(EFFECTS),
        "forbidden_effects": [],
        "preconditions": preconditions,
        "evaluated_state_hash": state_hash,
        "source_fixture_id": SOURCE_FIXTURE_ID,
        "copied_database_id": COPIED_DATABASE_ID,
        "test_issuer": True,
        "live_eligible": False,
        "standing_effect": "none",
        "authority_refs": ["fixture:exact-policy-boundary"],
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "issuer": "fixture:policy-issuer",
    }
    policy = _signed_model(
        SignedDispositionPolicyV1,
        {**unsigned, "policy_sha256": canonical_json_sha256(unsigned)},
        "signature",
        key,
        "fixture:policy-issuer",
    )

    authority = evaluate_disposition_authority(
        artifact_id="seed-policy-boundary",
        artifact_sha256=artifact_sha256,
        requested_scope="Copy",
        requested_effects=EFFECTS,
        evaluated_state_hash=state_hash,
        signed_policy=policy,
        trusted_policy_issuer=TrustedPolicyIssuerV1(
            issuer_identity="fixture:policy-issuer",
            issuer_public_key=_public_key(key),
            source_fixture_id=SOURCE_FIXTURE_ID,
            copied_database_id=COPIED_DATABASE_ID,
            authority_basis="founder_bootstrap_self_declared",
        ),
        now=NOW,
    )

    assert authority.result == "NoJurisdiction"
    assert reason in authority.reason_codes


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (
            lambda request: request["countersign"].__setitem__(
                "lease_sha256", "0" * 64
            ),
            "countersign_signature_invalid",
        ),
        (
            lambda request: request["countersign"].__setitem__(
                "authority_digest", "0" * 64
            ),
            "countersign_signature_invalid",
        ),
        (
            lambda request: request["countersign"].__setitem__("code_sha", "0" * 40),
            "countersign_signature_invalid",
        ),
        (
            lambda request: request["signed_event"]["signature"].__setitem__(
                "signature", "0" * 128
            ),
            "signature_invalid",
        ),
    ],
)
def test_tampered_exact_bindings_or_fixture_signatures_fail_without_effect(
    mutator: Any,
    expected_code: str,
) -> None:
    fixture = _fixture()
    changed = copy.deepcopy(fixture.request)
    mutator(changed)
    before = _database_digest(fixture.conn)

    with pytest.raises(LifecycleValidationError) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn, changed, fixture_context=fixture.context, now=NOW
        )

    assert raised.value.code == expected_code
    assert _database_digest(fixture.conn) == before


def test_persisted_new_signature_material_replays_independently() -> None:
    fixture = _fixture()
    receipt = apply_rehearsal_lifecycle(
        fixture.conn, fixture.request, fixture_context=fixture.context, now=NOW
    )
    policy_signature = fixture.request["signed_policy"]["signature"]["signature"]
    assert receipt["signature_replay"]["signature_count"] == 16
    assert receipt["persisted_signature_count"] == 16
    fixture.conn.close()

    reopened = open_attested_copy_connection(fixture.attestation)
    try:
        replay = verify_signature_evidence_table(
            reopened,
            required_artifact_types=(
                "policy",
                "lease",
                "case",
                "ballot",
                "countersign",
                "lineage",
                "successor",
                "lifecycle_event",
            ),
        )
        stored_policy_signature = reopened.execute(
            """
            SELECT signature
            FROM sab_first_verdict_signature_evidence_v1
            WHERE artifact_type = 'policy'
            """
        ).fetchone()[0]
    finally:
        reopened.close()

    assert replay["proof_class"] == "SignaturesVerified"
    assert replay["persisted_after_reopen"] is True
    assert replay["signature_count"] == 16
    assert stored_policy_signature == policy_signature
    assert {record["artifact_type"] for record in replay["records"]} == {
        "policy",
        "lease",
        "case",
        "ballot",
        "countersign",
        "lineage",
        "successor",
        "lifecycle_event",
    }


def test_preview_is_read_only_and_activation_rejects_caller_transaction() -> None:
    fixture = _fixture()
    before = _database_digest(fixture.conn)
    case = json.loads(
        fixture.conn.execute(
            "SELECT case_json FROM sab_artifact_cases_v1 WHERE case_id = ?", (CASE_ID,)
        ).fetchone()[0]
    )
    preview = preview_rehearsal_transition(
        fixture.conn,
        case=case,
        successor_artifact=fixture.request["successor_artifact"],
        disposition_id=DISPOSITION_ID,
    )
    assert preview["mutation_count"] == 0
    assert _database_digest(fixture.conn) == before

    fixture.conn.execute("BEGIN")
    with pytest.raises(LifecycleConflict) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn,
            fixture.request,
            fixture_context=fixture.context,
            now=NOW,
        )
    assert raised.value.code == "caller_transaction_active"
    fixture.conn.rollback()


def test_stale_client_applied_at_cannot_backdate_authorization() -> None:
    fixture = _fixture()
    changed = copy.deepcopy(fixture.request)
    changed["disposition"]["applied_at"] = (
        (NOW - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    )
    before = _database_digest(fixture.conn)

    with pytest.raises(LifecycleValidationError) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn,
            changed,
            fixture_context=fixture.context,
            now=NOW,
        )

    assert raised.value.code == "disposition_time_mismatch"
    assert _database_digest(fixture.conn) == before


def test_successor_effect_envelope_rejects_unknown_secret_fields() -> None:
    fixture = _fixture()
    changed = copy.deepcopy(fixture.request)
    changed["successor_artifact"]["private_key"] = "persisted-secret-marker"
    before = _database_digest(fixture.conn)

    with pytest.raises(LifecycleValidationError) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn,
            changed,
            fixture_context=fixture.context,
            now=NOW,
        )

    assert raised.value.code == "successor_artifact_contract_invalid"
    assert "persisted-secret-marker" not in str(raised.value)
    assert _database_digest(fixture.conn) == before
    assert b"persisted-secret-marker" not in fixture.conn.serialize()


def test_raw_file_backed_lifecycle_connection_is_rejected_before_mutation(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    copied_path = tmp_path / "raw-unattested-copy.db"
    _backup_fixture_to_path(fixture, copied_path)
    fixture.conn.close()

    raw = sqlite3.connect(copied_path)
    raw.execute("PRAGMA foreign_keys = ON")
    before = _database_digest(raw)
    try:
        with pytest.raises(DatabaseSafetyError, match="attested copy connection"):
            apply_rehearsal_lifecycle(
                raw,
                fixture.request,
                fixture_context=fixture.context,
                now=NOW,
            )
        assert _database_digest(raw) == before
        assert (
            raw.execute(
                "SELECT state FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
                (TARGET_ID,),
            ).fetchone()[0]
            == "challenged"
        )
    finally:
        raw.close()


def test_only_receipt_backed_copied_live_attestation_can_mint_effective_proof() -> None:
    fixture = _fixture()
    before = _database_digest(fixture.conn)
    wrong_context = replace(
        fixture.context,
        source_backup_sha256="f" * 64,
    )
    with pytest.raises(LifecycleAuthorityDenied) as raised:
        apply_rehearsal_lifecycle(
            fixture.conn,
            fixture.request,
            fixture_context=wrong_context,
            now=NOW,
        )
    assert raised.value.code == "fixture_copy_attestation_mismatch"
    assert _database_digest(fixture.conn) == before

    receipt = apply_rehearsal_lifecycle(
        fixture.conn,
        fixture.request,
        fixture_context=fixture.context,
        now=NOW,
    )
    assert fixture.attestation.proof_class == "copied_live_db_rehearsal"
    assert fixture.attestation.copy_receipt_path is not None
    assert receipt["proof_class"] == "copied_live_db_rehearsal"
    assert (
        fixture.conn.execute(
            "SELECT state FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
            (TARGET_ID,),
        ).fetchone()[0]
        == "superseded"
    )
