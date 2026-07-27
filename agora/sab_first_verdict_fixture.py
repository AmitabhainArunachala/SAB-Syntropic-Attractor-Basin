"""Production synthetic-fixture runner for SAB First Verdict Build A.

This module is deliberately copy-only and offline.  It accepts an explicit
``CopyDatabaseAttestation``, generates every fixture signing key in memory,
prepares the exact nine-seat synthetic case, applies the rehearsal lifecycle,
then closes and reopens the copied database to verify the persisted receipt and
all signatures.  It has no database discovery, provider, service, or live
activation path.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from .sab_artifact_verdict import (
    ArtifactBallotV1,
    ArtifactCaseV1,
    CouncilVerdictV1,
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
from .sab_first_verdict_evidence import lifecycle_fingerprint
from .sab_first_verdict_lifecycle import (
    ACTIVATION_METHOD_PATH,
    ACTIVATION_OPERATION,
    FROZEN_EFFECTS,
    MUTATION_BOUNDARIES,
    FixtureExecutionContext,
    apply_rehearsal_lifecycle,
    build_effect_payload,
    build_lifecycle_event_payload,
    case_scope_head,
    compute_ballot_set_sha256,
    preview_rehearsal_transition,
    rehearsal_state_fingerprint,
)
from .sab_first_verdict_storage import (
    MIGRATION_DIGEST,
    MIGRATION_ID,
    SIGNATURE_EVIDENCE_MIGRATION_DIGEST,
    SIGNATURE_EVIDENCE_MIGRATION_ID,
    CopyDatabaseAttestation,
    DatabaseSafetyError,
    activate_session_lease,
    canonical_json_text,
    create_rehearsal_artifact,
    init_first_verdict_storage,
    init_signature_evidence_storage,
    open_attested_copy_connection,
    store_artifact_ballot,
    store_artifact_case,
    store_authority_evaluation,
    store_council_verdict,
)
from .sab_verdict_verify import (
    ReplayValidationError,
    verify_new_signature_table,
    verify_signature_evidence_table,
)


TARGET_ID = "sab_seed_fixture_first_verdict"
SUCCESSOR_ID = "sab_seed_fixture_first_verdict_v2"
CASE_ID = "sab_case_fixture_first_verdict"
VERDICT_ID = "sab_verdict_fixture_first_verdict"
LEASE_ID = "sab_lease_fixture_first_verdict"
DISPOSITION_ID = "sab_disposition_fixture_first_verdict"
LINEAGE_ID = "sab_lineage_fixture_first_verdict"
EVENT_ID = "sab_event_fixture_first_verdict"
IDEMPOTENCY_KEY = "sab-first-verdict-synthetic-copy-v1"
SOURCE_FIXTURE_ID = "fixture:first-verdict"
COUNTERSIGN_ID = "sab_countersign_fixture_first_verdict"

_REQUIRED_SIGNATURE_TYPES = (
    "policy",
    "lease",
    "case",
    "ballot",
    "countersign",
    "lineage",
    "successor",
    "lifecycle_event",
)
_EXPECTED_SIGNATURE_HISTOGRAM = {
    "ballot": 9,
    "case": 1,
    "countersign": 1,
    "lease": 1,
    "lifecycle_event": 1,
    "lineage": 1,
    "policy": 1,
    "successor": 1,
}
_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "proof_class",
        "operation",
        "idempotency_key",
        "request_sha256",
        "validation_order",
        "scope",
        "fixture_context_sha256",
        "authority",
        "artifacts",
        "state",
        "transaction",
        "invariant_table_digests",
        "signature_replay",
        "request_signature_validation",
        "persisted_signature_count",
        "signed_event_table_replay",
        "signed_event",
        "source_fixture_id",
        "copied_database_id",
        "standing_effect",
        "identity_effect",
        "live_eligible",
        "live_mutations",
        "provider_calls",
        "external_actions",
        "receipt_sha256",
    }
)


class FixtureRunnerError(RuntimeError):
    """Fail-closed runner error with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PreparedSyntheticFixture:
    """Public material needed for one in-process apply and exact retry."""

    request: dict[str, Any]
    context: FixtureExecutionContext
    now: datetime
    verdict_id: str
    lease_id: str


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise FixtureRunnerError("naive_time", "fixture time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _public_key(key: SigningKey) -> str:
    return key.verify_key.encode(encoder=HexEncoder).decode("ascii")


def _placeholder_signature(key: SigningKey, signer: str) -> dict[str, Any]:
    return {
        "alg": "ed25519",
        "signer": signer,
        "public_key": _public_key(key),
        "signature": "0" * 128,
        "signed_payload_sha256": "0" * 64,
        "canonicalization": "json-sort-keys-compact-v1",
    }


def _signature(
    key: SigningKey, signer: str, payload: Mapping[str, Any]
) -> dict[str, Any]:
    message = canonical_json_bytes(dict(payload))
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
        {**body, signature_field: _placeholder_signature(key, signer)}
    )
    payload = provisional.canonical_payload(exclude={signature_field})
    return model.model_validate(
        {**payload, signature_field: _signature(key, signer, payload)}
    )


def _require_hex(value: str, length: int, field: str) -> str:
    normalized = str(value).strip().lower()
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", normalized):
        raise FixtureRunnerError(
            "invalid_runner_argument",
            f"{field} must be {length} lowercase hex characters",
        )
    return normalized


def _require_attested_copy(
    conn: sqlite3.Connection,
    *,
    source_backup_sha256: str,
    copied_lifecycle_fingerprint: str,
) -> CopyDatabaseAttestation:
    attestation = getattr(conn, "sab_copy_attestation", None)
    if not isinstance(attestation, CopyDatabaseAttestation):
        raise FixtureRunnerError(
            "copy_attestation_missing", "fixture preparation requires an attested copy"
        )
    if attestation.proof_class != "copied_live_db_rehearsal":
        raise FixtureRunnerError(
            "copy_proof_required", "fixture preparation requires copied-live proof"
        )
    if (
        attestation.source_backup_sha256 != source_backup_sha256
        or attestation.expected_lifecycle_fingerprint != copied_lifecycle_fingerprint
    ):
        raise FixtureRunnerError(
            "copy_attestation_mismatch",
            "runner arguments differ from the copy attestation",
        )
    return attestation


def prepare_signed_synthetic_fixture(
    conn: sqlite3.Connection,
    *,
    source_backup_sha256: str,
    copied_lifecycle_fingerprint: str,
    code_sha: str,
    copied_database_id: str,
    now: datetime | None = None,
) -> PreparedSyntheticFixture:
    """Populate the signed nine-seat fixture using only ephemeral private keys.

    The returned request contains signatures and public keys, never private key
    material.  Callers should keep it only long enough to apply the lifecycle
    and, optionally, prove an exact in-process retry.
    """

    current = _utc(now)
    source_backup_sha256 = _require_hex(
        source_backup_sha256, 64, "source_backup_sha256"
    )
    copied_lifecycle_fingerprint = _require_hex(
        copied_lifecycle_fingerprint, 64, "copied_lifecycle_fingerprint"
    )
    code_sha = _require_hex(code_sha, 40, "code_sha")
    if not copied_database_id.strip():
        raise FixtureRunnerError(
            "copied_database_id_missing", "copied database identity must be non-empty"
        )
    _require_attested_copy(
        conn,
        source_backup_sha256=source_backup_sha256,
        copied_lifecycle_fingerprint=copied_lifecycle_fingerprint,
    )
    if conn.in_transaction:
        raise FixtureRunnerError(
            "caller_transaction_active", "fixture preparation owns its transactions"
        )
    if lifecycle_fingerprint(conn)["sha256"] != copied_lifecycle_fingerprint:
        raise FixtureRunnerError(
            "legacy_lifecycle_drift", "copied legacy lifecycle fingerprint has drifted"
        )
    existing = conn.execute(
        "SELECT 1 FROM sab_rehearsal_artifacts_v1 WHERE artifact_id IN (?, ?) LIMIT 1",
        (TARGET_ID, SUCCESSOR_ID),
    ).fetchone()
    if existing is not None:
        raise FixtureRunnerError(
            "fixture_identity_exists",
            "synthetic fixture already exists; verify its stored receipt instead of regenerating keys",
        )

    issuer_key = SigningKey.generate()
    clerk_key = SigningKey.generate()
    claimant_key = SigningKey.generate()
    event_key = SigningKey.generate()
    seat_keys = tuple(SigningKey.generate() for _ in range(9))

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
        "copied_database_id": copied_database_id,
        "standing_effect": "none",
        "live_eligible": False,
    }
    create_rehearsal_artifact(
        conn, target, created_at=_time_text(current - timedelta(minutes=5))
    )
    conn.commit()
    before_state = rehearsal_state_fingerprint(conn)
    expected_case_head = case_scope_head(conn, TARGET_ID)

    policy_unsigned = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": "sab_policy_fixture_first_verdict",
        "artifact_id": TARGET_ID,
        "artifact_sha256": target_packet_sha,
        "disposition_mode": "authorized",
        "scope": "Copy",
        "permitted_effects": list(FROZEN_EFFECTS),
        "forbidden_effects": [],
        "preconditions": ["challenge_state=pending", "seed_state=challenged"],
        "evaluated_state_hash": before_state,
        "source_fixture_id": SOURCE_FIXTURE_ID,
        "copied_database_id": copied_database_id,
        "test_issuer": True,
        "live_eligible": False,
        "standing_effect": "none",
        "authority_refs": ["fixture:signed-copy-policy"],
        "issued_at": _time_text(current - timedelta(minutes=10)),
        "expires_at": _time_text(current + timedelta(hours=1)),
        "issuer": "fixture:policy-issuer",
    }
    policy = _signed_model(
        SignedDispositionPolicyV1,
        {
            **policy_unsigned,
            "policy_sha256": canonical_json_sha256(policy_unsigned),
        },
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
        "accepted_code_sha": code_sha,
        "expected_lifecycle_fingerprint": copied_lifecycle_fingerprint,
        "source_backup_sha256": source_backup_sha256,
        "issuer_identity": "fixture:operator",
        "issuer_public_key": _public_key(issuer_key),
        "issuer_fingerprint": hashlib.sha256(bytes(issuer_key.verify_key)).hexdigest(),
        "authority_basis": "founder_bootstrap_self_declared",
        "scope": "Copy",
        "issued_at": _time_text(current - timedelta(minutes=5)),
        "activated_at": _time_text(current - timedelta(minutes=4)),
        "expires_at": _time_text(current + timedelta(hours=1)),
        "standing_effect": "none",
        "live_eligible": False,
    }
    lease = _signed_model(
        SessionWriteLeaseV1,
        {**lease_unsigned, "lease_sha256": canonical_json_sha256(lease_unsigned)},
        "signature",
        issuer_key,
        "fixture:operator",
    )
    activate_session_lease(
        conn,
        lease.canonical_payload(),
        activated_at=_time_text(current - timedelta(minutes=4)),
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
        "signed_artifact_b64": base64.b64encode(target_bytes).decode("ascii"),
        "signed_artifact_sha256": hashlib.sha256(target_bytes).hexdigest(),
        "frozen_roster": roster,
        "frozen_roster_sha256": canonical_json_sha256(roster),
        "single_operator_adjudicated": True,
        "clerk_identity": "fixture:clerk",
        "lease_id": LEASE_ID,
        "frozen_at": _time_text(current - timedelta(minutes=3)),
    }
    case = _signed_model(
        ArtifactCaseV1, case_body, "clerk_signature", clerk_key, "fixture:clerk"
    )
    _, case_sha, _ = store_artifact_case(
        conn,
        case.canonical_payload(),
        created_at=_time_text(current - timedelta(minutes=3)),
    )

    authority = evaluate_disposition_authority(
        artifact_id=TARGET_ID,
        artifact_sha256=target_packet_sha,
        requested_scope="Copy",
        requested_effects=FROZEN_EFFECTS,
        evaluated_state_hash=before_state,
        signed_policy=policy,
        trusted_policy_issuer=TrustedPolicyIssuerV1(
            issuer_identity="fixture:policy-issuer",
            issuer_public_key=_public_key(issuer_key),
            source_fixture_id=SOURCE_FIXTURE_ID,
            copied_database_id=copied_database_id,
            authority_basis="founder_bootstrap_self_declared",
        ),
        now=current,
    )
    store_authority_evaluation(
        conn,
        case_id=CASE_ID,
        authority=authority.canonical_payload(),
        created_at=_time_text(current - timedelta(minutes=2, seconds=50)),
    )

    ballot_members: list[dict[str, str]] = []
    for index, (seat, key) in enumerate(zip(roster, seat_keys, strict=True)):
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
            "strongest_case_against_decision": (
                "The synthetic evidence could be incomplete."
            ),
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
            created_at=_time_text(current - timedelta(minutes=2, seconds=40 - index)),
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
            "requested_effects": list(FROZEN_EFFECTS),
            "authority_digest": authority.authority_digest,
            "scope": "Copy",
            "operator_independence": "single_operator_bootstrap",
            "effect_domain": "artifact",
            "standing_effect": "none",
            "compiled_at": _time_text(current - timedelta(minutes=1)),
        }
    )
    _, verdict_sha, _ = store_council_verdict(
        conn,
        evaluation_id=authority.evaluation_id,
        verdict=verdict.canonical_payload(),
        ballot_set_sha256=compute_ballot_set_sha256(ballot_members),
        created_at=_time_text(current - timedelta(minutes=1)),
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
        "copied_database_id": copied_database_id,
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
        "created_at": _time_text(current),
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
        effects=FROZEN_EFFECTS,
        disposition_id=DISPOSITION_ID,
        target_artifact_id=TARGET_ID,
        successor_artifact=successor,
        supersession_sha256=supersession_sha,
    )
    countersign_body = {
        "schema": "sab.operator_countersign.v1",
        "countersign_id": COUNTERSIGN_ID,
        "verdict_id": VERDICT_ID,
        "verdict_sha256": verdict_sha,
        "case_id": CASE_ID,
        "case_sha256": case_sha,
        "target_seed_id": TARGET_ID,
        "decision": "correct_and_supersede",
        "expected_seed_state": "challenged",
        "expected_case_head": expected_case_head,
        "expected_lifecycle_fingerprint": copied_lifecycle_fingerprint,
        "effect_payload": effect_payload,
        "effect_payload_sha256": canonical_json_sha256(effect_payload),
        "successor_envelope_sha256": canonical_json_sha256(successor),
        "write_lease_id": LEASE_ID,
        "lease_sha256": lease.lease_sha256,
        "authority_digest": authority.authority_digest,
        "allowed_operations": operations,
        "allowed_operations_sha256": lease.allowed_operations_sha256,
        "code_sha": code_sha,
        "scope": "Copy",
        "signer_kind": "fixture_ephemeral",
        "created_at": _time_text(current),
        "expires_at": _time_text(current + timedelta(minutes=30)),
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
            "effects": list(FROZEN_EFFECTS),
            "ballot_source": "fixture_model",
            "evidence_provenance": "fixture_models",
            "scope": "Copy",
            "proof_class": "copied_live_db_rehearsal",
            "source_fixture_id": SOURCE_FIXTURE_ID,
            "copied_database_id": copied_database_id,
            "before_state_hash": transition["before_state_hash"],
            "after_state_hash": transition["after_state_hash"],
            "applied_at": _time_text(current),
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
        "idempotency_key": IDEMPOTENCY_KEY,
        "code_sha": code_sha,
        "artifact_id": TARGET_ID,
        "artifact_sha256": target_packet_sha,
        "evaluated_state_hash": before_state,
        "requested_effects": list(FROZEN_EFFECTS),
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
        copied_database_id=copied_database_id,
        source_backup_sha256=source_backup_sha256,
        code_sha=code_sha,
        copied_lifecycle_fingerprint=copied_lifecycle_fingerprint,
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
            (f"seat-{index}", f"fixture:execution:{index}", _public_key(key))
            for index, key in enumerate(seat_keys)
        ),
    )
    return PreparedSyntheticFixture(
        request=request,
        context=context,
        now=current,
        verdict_id=VERDICT_ID,
        lease_id=LEASE_ID,
    )


def _validated_receipt(
    receipt: Mapping[str, Any],
    *,
    attestation: CopyDatabaseAttestation,
) -> dict[str, Any]:
    """Strictly validate the persisted lifecycle receipt and its self-hash."""

    parsed = json.loads(canonical_json_text(dict(receipt)))
    if set(parsed) != _RECEIPT_KEYS:
        raise FixtureRunnerError(
            "receipt_contract_mismatch", "lifecycle receipt fields are not exact"
        )
    if (
        parsed["schema_version"] != "sab.rehearsal_lifecycle_receipt.v1"
        or parsed["proof_class"] != "copied_live_db_rehearsal"
        or parsed["operation"] != ACTIVATION_OPERATION
        or parsed["idempotency_key"] != IDEMPOTENCY_KEY
        or parsed["scope"] != "Copy"
    ):
        raise FixtureRunnerError(
            "receipt_contract_mismatch",
            "lifecycle receipt identity or proof class is not frozen",
        )
    _require_hex(str(parsed["request_sha256"]), 64, "request_sha256")
    declared_receipt_sha = _require_hex(
        str(parsed["receipt_sha256"]), 64, "receipt_sha256"
    )
    receipt_without_hash = {
        key: value for key, value in parsed.items() if key != "receipt_sha256"
    }
    if canonical_json_sha256(receipt_without_hash) != declared_receipt_sha:
        raise FixtureRunnerError(
            "receipt_self_hash_mismatch", "lifecycle receipt self-hash does not verify"
        )
    if parsed["validation_order"] != [
        "DispositionAuthority<Copy>",
        "fixture_policy",
        "active_lease",
        "case_and_target",
        "ballot_merit",
        "terminal_verdict",
        "operator_countersign",
        "rehearsal_effect",
    ]:
        raise FixtureRunnerError(
            "receipt_validation_order_mismatch",
            "receipt does not prove authority-before-merit ordering",
        )
    transaction = parsed.get("transaction")
    if not isinstance(transaction, dict) or transaction != {
        "mode": "BEGIN IMMEDIATE",
        "boundaries": list(MUTATION_BOUNDARIES),
        "commits": 1,
    }:
        raise FixtureRunnerError(
            "receipt_transaction_mismatch", "receipt transaction proof is not exact"
        )
    artifacts = parsed.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "case",
        "lease",
        "verdict",
        "countersign",
        "disposition",
        "lineage",
        "target",
        "successor",
    }:
        raise FixtureRunnerError(
            "receipt_artifacts_mismatch", "receipt artifact inventory is not exact"
        )
    if artifacts.get("countersign", {}).get("id") != COUNTERSIGN_ID:
        raise FixtureRunnerError(
            "receipt_countersign_mismatch", "receipt names another countersign"
        )
    expected_copy_id = f"copy:first-verdict:{attestation.source_backup_sha256[:16]}"
    state = parsed.get("state")
    authority = parsed.get("authority")
    if (
        parsed["source_fixture_id"] != SOURCE_FIXTURE_ID
        or parsed["copied_database_id"] != expected_copy_id
        or not isinstance(state, dict)
        or state.get("copied_lifecycle_fingerprint")
        != attestation.expected_lifecycle_fingerprint
        or not isinstance(authority, dict)
        or authority.get("result") != "Authorized"
    ):
        raise FixtureRunnerError(
            "receipt_context_mismatch",
            "receipt does not bind the attested copied-fixture context",
        )
    replay = parsed.get("signature_replay")
    if not isinstance(replay, dict) or not isinstance(replay.get("records"), list):
        raise FixtureRunnerError(
            "signature_replay_mismatch", "receipt signature replay is malformed"
        )
    histogram = Counter(
        str(record.get("artifact_type"))
        for record in replay["records"]
        if isinstance(record, dict)
    )
    if (
        replay.get("signature_count") != 16
        or parsed["persisted_signature_count"] != 16
        or dict(sorted(histogram.items())) != _EXPECTED_SIGNATURE_HISTOGRAM
    ):
        raise FixtureRunnerError(
            "signature_multiplicity_mismatch",
            "receipt must prove the exact 1+1+1+9+1+1+1+1 signature bundle",
        )
    return parsed


def verify_completed_rehearsal(
    attestation: CopyDatabaseAttestation,
    receipt: Mapping[str, Any],
    *,
    code_sha: str,
) -> dict[str, Any]:
    """Reopen the copy and independently replay receipt and signatures."""

    code_sha = _require_hex(code_sha, 40, "code_sha")
    if attestation.proof_class != "copied_live_db_rehearsal":
        raise FixtureRunnerError(
            "copy_proof_required", "completed rehearsal requires copied-live proof"
        )
    expected_receipt = _validated_receipt(receipt, attestation=attestation)
    conn = open_attested_copy_connection(attestation, require_pristine_backup=False)
    try:
        migrations = dict(
            conn.execute(
                "SELECT migration_id, migration_digest "
                "FROM sab_first_verdict_schema_migrations_v1"
            ).fetchall()
        )
        if (
            migrations.get(MIGRATION_ID) != MIGRATION_DIGEST
            or migrations.get(SIGNATURE_EVIDENCE_MIGRATION_ID)
            != SIGNATURE_EVIDENCE_MIGRATION_DIGEST
        ):
            raise FixtureRunnerError(
                "migration_reopen_mismatch",
                "reopened copy has unexpected migration bytes",
            )
        persisted = verify_signature_evidence_table(
            conn, required_artifact_types=_REQUIRED_SIGNATURE_TYPES
        )
        signed_events = verify_new_signature_table(
            conn, required_event_types=("rehearsal_supersession_committed",)
        )
        row = conn.execute(
            "SELECT request_sha256, response_json, response_sha256 "
            "FROM sab_first_verdict_idempotency_v1 "
            "WHERE operation=? AND idempotency_key=?",
            (ACTIVATION_OPERATION, IDEMPOTENCY_KEY),
        ).fetchone()
        if row is None:
            raise FixtureRunnerError(
                "receipt_missing_after_reopen",
                "canonical lifecycle receipt is not persisted",
            )
        if str(row[0]) != expected_receipt["request_sha256"]:
            raise FixtureRunnerError(
                "request_binding_mismatch",
                "idempotency request digest differs from the receipt",
            )
        response_json = str(row[1])
        if hashlib.sha256(response_json.encode("utf-8")).hexdigest() != str(
            row[2]
        ) or response_json != canonical_json_text(expected_receipt):
            raise FixtureRunnerError(
                "receipt_mismatch_after_reopen",
                "persisted receipt differs after reopen",
            )
        if persisted["signature_count"] != 16:
            raise FixtureRunnerError(
                "signature_count_mismatch",
                "reopened copy must contain 16 fixture signatures",
            )
        histogram = Counter(
            str(record["artifact_type"]) for record in persisted["records"]
        )
        if dict(sorted(histogram.items())) != _EXPECTED_SIGNATURE_HISTOGRAM:
            raise FixtureRunnerError(
                "signature_multiplicity_mismatch",
                "reopened signature histogram is not the frozen fixture bundle",
            )
        countersign_row = conn.execute(
            "SELECT countersign_json, countersign_sha256 "
            "FROM sab_operator_countersigns_v1 WHERE countersign_id = ?",
            (COUNTERSIGN_ID,),
        ).fetchone()
        lease_row = conn.execute(
            "SELECT lease_json, lease_sha256 FROM sab_session_write_leases_v1 "
            "WHERE lease_id = ?",
            (LEASE_ID,),
        ).fetchone()
        if countersign_row is None or lease_row is None:
            raise FixtureRunnerError(
                "signed_context_missing",
                "reopened copy is missing its signed lease or countersign",
            )
        countersign = OperatorCountersignV1.model_validate_json(str(countersign_row[0]))
        lease = SessionWriteLeaseV1.model_validate_json(str(lease_row[0]))
        policy_row = conn.execute(
            "SELECT signer, public_key, payload_json, payload_sha256, "
            "canonicalization, signature "
            "FROM sab_first_verdict_signature_evidence_v1 "
            "WHERE artifact_type='policy'"
        ).fetchone()
        if policy_row is None:
            raise FixtureRunnerError(
                "signed_context_missing", "reopened copy is missing its signed policy"
            )
        policy_payload = json.loads(str(policy_row[2]))
        policy = SignedDispositionPolicyV1.model_validate(
            {
                **policy_payload,
                "signature": {
                    "alg": "ed25519",
                    "signer": str(policy_row[0]),
                    "public_key": str(policy_row[1]),
                    "signature": str(policy_row[5]),
                    "signed_payload_sha256": str(policy_row[3]),
                    "canonicalization": str(policy_row[4]),
                },
            }
        )
        expected_artifacts = expected_receipt["artifacts"]
        expected_copy_id = f"copy:first-verdict:{attestation.source_backup_sha256[:16]}"
        if (
            countersign.code_sha != code_sha
            or lease.accepted_code_sha != code_sha
            or lease.source_backup_sha256 != attestation.source_backup_sha256
            or lease.expected_lifecycle_fingerprint
            != attestation.expected_lifecycle_fingerprint
            or policy.source_fixture_id != SOURCE_FIXTURE_ID
            or policy.copied_database_id != expected_copy_id
            or canonical_json_sha256(countersign.canonical_payload())
            != str(countersign_row[1])
            or lease.lease_sha256 != str(lease_row[1])
            or str(countersign_row[1]) != expected_artifacts["countersign"]["sha256"]
            or str(lease_row[1]) != expected_artifacts["lease"]["sha256"]
            or expected_receipt["copied_database_id"] != expected_copy_id
        ):
            raise FixtureRunnerError(
                "signed_context_mismatch",
                "resume inputs differ from the persisted signed fixture context",
            )
        if expected_receipt.get("signature_replay") != persisted:
            raise FixtureRunnerError(
                "signature_replay_mismatch", "receipt replay proof differs after reopen"
            )
        if expected_receipt.get("signed_event_table_replay") != signed_events:
            raise FixtureRunnerError(
                "event_replay_mismatch", "signed-event replay differs after reopen"
            )
        if lifecycle_fingerprint(conn)["sha256"] != (
            attestation.expected_lifecycle_fingerprint
        ):
            raise FixtureRunnerError(
                "legacy_lifecycle_drift", "legacy lifecycle changed during rehearsal"
            )
        if any(
            expected_receipt.get(field) != expected
            for field, expected in (
                ("standing_effect", "none"),
                ("identity_effect", "none"),
                ("live_eligible", False),
                ("live_mutations", 0),
                ("provider_calls", 0),
                ("external_actions", 0),
            )
        ):
            raise FixtureRunnerError(
                "effect_boundary_mismatch",
                "receipt crosses the copy-only effect boundary",
            )
    except ReplayValidationError as exc:
        raise FixtureRunnerError(exc.code, str(exc)) from exc
    finally:
        conn.close()
    return expected_receipt


def run_copied_database_rehearsal(
    attestation: CopyDatabaseAttestation,
    *,
    code_sha: str,
    now: datetime | None = None,
    verify_exact_retry: bool = False,
) -> dict[str, Any]:
    """Install/validate migrations, run once, and independently verify reopen.

    Exact retry, when requested, occurs in the same process while the ephemeral
    request still exists.  Private keys are never returned or persisted.
    """

    current = _utc(now)
    code_sha = _require_hex(code_sha, 40, "code_sha")
    source = Path(attestation.source_database_path or "")
    if not source.is_absolute() or not source.is_file():
        raise DatabaseSafetyError("forbidden source database must be explicit")
    source_before = (
        source.stat().st_size,
        source.stat().st_mtime_ns,
        _file_sha256(source),
    )
    attestation.validate(require_pristine_backup=False)
    copied_database_id = f"copy:first-verdict:{attestation.source_backup_sha256[:16]}"
    conn = open_attested_copy_connection(attestation, require_pristine_backup=False)
    try:
        init_first_verdict_storage(conn, applied_at=_time_text(current))
        init_signature_evidence_storage(
            conn, applied_at=_time_text(current + timedelta(seconds=1))
        )
        stored = conn.execute(
            "SELECT response_json, response_sha256 "
            "FROM sab_first_verdict_idempotency_v1 "
            "WHERE operation=? AND idempotency_key=?",
            (ACTIVATION_OPERATION, IDEMPOTENCY_KEY),
        ).fetchone()
        if stored is not None:
            response_json = str(stored[0])
            if hashlib.sha256(response_json.encode("utf-8")).hexdigest() != str(
                stored[1]
            ):
                raise FixtureRunnerError(
                    "stored_receipt_digest_mismatch",
                    "existing lifecycle receipt digest does not verify",
                )
            try:
                receipt = json.loads(response_json)
            except json.JSONDecodeError as exc:
                raise FixtureRunnerError(
                    "stored_receipt_invalid", "existing lifecycle receipt is not JSON"
                ) from exc
            if canonical_json_text(receipt) != response_json:
                raise FixtureRunnerError(
                    "stored_receipt_noncanonical",
                    "existing lifecycle receipt is not canonical JSON",
                )
        else:
            prepared = prepare_signed_synthetic_fixture(
                conn,
                source_backup_sha256=attestation.source_backup_sha256,
                copied_lifecycle_fingerprint=attestation.expected_lifecycle_fingerprint,
                code_sha=code_sha,
                copied_database_id=copied_database_id,
                now=current,
            )
            receipt = apply_rehearsal_lifecycle(
                conn,
                prepared.request,
                fixture_context=prepared.context,
                now=prepared.now,
                expected_verdict_id=prepared.verdict_id,
                expected_write_lease_id=prepared.lease_id,
            )
            if verify_exact_retry:
                replay = apply_rehearsal_lifecycle(
                    conn,
                    copy.deepcopy(prepared.request),
                    fixture_context=prepared.context,
                    now=prepared.now + timedelta(days=1),
                    expected_verdict_id=prepared.verdict_id,
                    expected_write_lease_id=prepared.lease_id,
                )
                if canonical_json_text(replay) != canonical_json_text(receipt):
                    raise FixtureRunnerError(
                        "exact_retry_mismatch",
                        "exact retry returned different receipt bytes",
                    )
    finally:
        conn.close()

    source_after = (
        source.stat().st_size,
        source.stat().st_mtime_ns,
        _file_sha256(source),
    )
    if source_after != source_before:
        raise FixtureRunnerError(
            "forbidden_source_changed", "forbidden source changed during copy rehearsal"
        )
    return verify_completed_rehearsal(attestation, receipt, code_sha=code_sha)


__all__ = [
    "CASE_ID",
    "DISPOSITION_ID",
    "EVENT_ID",
    "FixtureRunnerError",
    "IDEMPOTENCY_KEY",
    "LEASE_ID",
    "LINEAGE_ID",
    "PreparedSyntheticFixture",
    "SOURCE_FIXTURE_ID",
    "SUCCESSOR_ID",
    "TARGET_ID",
    "VERDICT_ID",
    "prepare_signed_synthetic_fixture",
    "run_copied_database_rehearsal",
    "verify_completed_rehearsal",
]
