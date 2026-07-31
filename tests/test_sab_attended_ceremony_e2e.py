from __future__ import annotations

import hashlib
import json
import socket
import sqlite3
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from agora.sab_artifact_verdict import (
    ArtifactBallotV1,
    AuthorizedDispositionAuthorityV1,
    ContractSignatureV1,
    FrozenSeatV1,
    SignedDispositionPolicyV1,
    TrustedPolicyIssuerV1,
    canonical_json_bytes,
    canonical_sha256,
    evaluate_disposition_authority,
    verify_contract_signature,
)
from agora.sab_first_verdict_approval import (
    SIGNING_INSTRUCTION,
    bind_operator_approval_evidence,
    build_operator_approval_packet,
    canonical_packet_json,
    render_operator_approval_markdown,
    verify_operator_approval_packet,
)
from agora.sab_first_verdict_ceremony import (
    AttendedCeremonyManifestV1,
    BenchCostEnvelopeV1,
    BenchSeatCostV1,
    FROZEN_MAINTENANCE_OPERATIONS_SHA256,
    FounderDecisionReceiptV1,
    FrozenBenchManifestV1,
    FrozenBenchSeatV1,
    LiveWriteLeaseEnvelopeV1,
    MaintenanceControlAuthorityReceiptV1,
    MaintenanceRuntimeAttestationV1,
    ProviderProbeReceiptV1,
    RestorationPlanV1,
    ServiceStateSnapshotV1,
    SignedAuthorityEvaluationEnvelopeV1,
    StructurallyCompleteAwaitingAuthority,
    TickExclusionReceiptV1,
    readiness_is_locally_verified,
    validate_live_preflight_receipts,
    verify_frozen_execution_facts,
)
from agora.sab_first_verdict_compiler import (
    CompiledVerdictV1,
    CouncilTerminalityRuleV1,
    RefusalReceiptV1,
    compile_council_outcome,
    compute_council_terminality_rule_sha256,
    verify_compiled_outcome,
)
from agora.sab_first_verdict_transcript import (
    CEREMONY_STAGES,
    EMPTY_REVEAL_SET_SHA256,
    BallotCommitmentV1,
    BallotExecutionFactsV1,
    BallotRevealV1,
    CeremonyStageEnvelopeV1,
    FinalDeliberationSubjectV1,
    ballot_commitment_preimage_sha256,
    canonical_commitment_set_sha256,
    canonical_reveal_set_sha256,
    init_transcript_storage,
    read_ceremony_transcript,
    store_ceremony_transcript,
    verify_ceremony_transcript,
)


FIXTURES = Path(__file__).parent / "fixtures" / "sab_first_verdict" / "valid"
CASE_TEMPLATE = json.loads((FIXTURES / "sab.artifact_case.v1.json").read_text())
BALLOT_TEMPLATE = json.loads((FIXTURES / "sab.artifact_ballot.v1.json").read_text())
NOW = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
CEREMONY_ID = "ceremony-build-b-offline-e2e"
CASE_ID = "case-build-b-offline-e2e"
ARTIFACT_ID = "artifact-build-b-offline-e2e"
CASE_SHA256 = hashlib.sha256(b"sab-build-b-offline-e2e-case").hexdigest()
STATE_SHA256 = hashlib.sha256(b"sab-build-b-offline-e2e-state").hexdigest()
EFFECTS = ("challenge:resolve", "seed:supersede")
RECORDED_AT = "2026-08-01T00:00:00Z"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fingerprint(key: SigningKey) -> str:
    return hashlib.sha256(bytes(key.verify_key)).hexdigest()


def _signature(key: SigningKey, signer: str, message: bytes) -> ContractSignatureV1:
    return ContractSignatureV1(
        signer=signer,
        public_key=bytes(key.verify_key).hex(),
        signature=key.sign(message).signature.hex(),
        signed_payload_sha256=hashlib.sha256(message).hexdigest(),
    )


def _dummy_signature(key: SigningKey, signer: str) -> ContractSignatureV1:
    return ContractSignatureV1(
        signer=signer,
        public_key=bytes(key.verify_key).hex(),
        signature="0" * 128,
        signed_payload_sha256="0" * 64,
    )


def _evaluate_copy_authority(key: SigningKey, *, disposition_mode: str) -> Any:
    signer = f"fixture:e2e:{disposition_mode}:issuer"
    source_fixture_id = "fixture:sab-build-b-offline-e2e"
    copied_database_id = "copy:memory:sab-build-b-offline-e2e"
    permitted = list(EFFECTS) if disposition_mode == "authorized" else []
    forbidden = list(EFFECTS) if disposition_mode == "advisory_only" else []
    body: dict[str, Any] = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": f"policy-build-b-e2e-{disposition_mode}",
        "artifact_id": ARTIFACT_ID,
        "artifact_sha256": CASE_SHA256,
        "disposition_mode": disposition_mode,
        "scope": "Copy",
        "permitted_effects": permitted,
        "forbidden_effects": forbidden,
        "preconditions": ["challenge_state=pending", "seed_state=challenged"],
        "evaluated_state_hash": STATE_SHA256,
        "source_fixture_id": source_fixture_id,
        "copied_database_id": copied_database_id,
        "test_issuer": True,
        "live_eligible": False,
        "standing_effect": "none",
        "authority_refs": ["fixture:signed-build-b-e2e-policy"],
        "issued_at": (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "issuer": signer,
    }
    unsigned = {**body, "policy_sha256": canonical_sha256(body)}
    policy = SignedDispositionPolicyV1.model_validate(
        {
            **unsigned,
            "signature": _signature(
                key,
                signer,
                canonical_json_bytes(unsigned),
            ).canonical_payload(),
        }
    )
    trusted_issuer = TrustedPolicyIssuerV1(
        issuer_identity=signer,
        issuer_public_key=key.verify_key.encode(encoder=HexEncoder).decode(),
        source_fixture_id=source_fixture_id,
        copied_database_id=copied_database_id,
        authority_basis="founder_bootstrap_self_declared",
    )
    return evaluate_disposition_authority(
        artifact_id=ARTIFACT_ID,
        artifact_sha256=CASE_SHA256,
        requested_scope="Copy",
        requested_effects=EFFECTS if disposition_mode == "authorized" else (),
        evaluated_state_hash=STATE_SHA256,
        signed_policy=policy,
        trusted_policy_issuer=trusted_issuer,
        now=NOW,
    )


def _terminality_rule() -> CouncilTerminalityRuleV1:
    body = {
        "schema": "sab.council_terminality_rule.v1",
        "rule_id": "fixture:build-b-e2e:5-of-9:5-clusters",
        "council_size": 9,
        "minimum_raw_votes": 5,
        "minimum_clean_clusters": 5,
        "terminal_decisions": ["correct_and_supersede"],
        "effects_by_decision": {"correct_and_supersede": list(EFFECTS)},
        "correlation_policy": "remove_smeared_and_appeal_on_change",
        "tie_policy": "no_terminal_verdict",
    }
    return CouncilTerminalityRuleV1.model_validate(
        {
            **body,
            "rule_sha256": compute_council_terminality_rule_sha256(body),
        }
    )


def _roster(keys: tuple[SigningKey, ...]) -> tuple[FrozenSeatV1, ...]:
    roster = []
    for position, (raw, key) in enumerate(
        zip(CASE_TEMPLATE["frozen_roster"], keys, strict=True)
    ):
        exact = deepcopy(raw)
        exact["served_model"] = exact["requested_model"]
        exact["execution_public_key"] = bytes(key.verify_key).hex()
        for reference_index, reference in enumerate(
            exact["model_lineage_evidence_refs"]
        ):
            if reference["content_sha256"] == "0" * 64:
                reference["content_sha256"] = _digest(
                    f"lineage-evidence:{position}:{reference_index}"
                )
        roster.append(FrozenSeatV1.model_validate(exact))
    return tuple(roster)


def _reported_live_authority(
    evaluator_key: SigningKey, *, policy_sha256: str
) -> SignedAuthorityEvaluationEnvelopeV1:
    signer = "fixture:e2e:reported-live-evaluator"
    provisional = SignedAuthorityEvaluationEnvelopeV1(
        evaluation_id="evaluation-build-b-offline-e2e",
        ceremony_id=CEREMONY_ID,
        case_id=CASE_ID,
        case_sha256=CASE_SHA256,
        artifact_id=ARTIFACT_ID,
        artifact_sha256=CASE_SHA256,
        policy_sha256=policy_sha256,
        evaluated_state_sha256=STATE_SHA256,
        requested_effects=EFFECTS,
        reported_result="Authorized",
        reported_allowed_effects=EFFECTS,
        reported_live_eligible=True,
        evaluator_identity=signer,
        evaluator_public_key=bytes(evaluator_key.verify_key).hex(),
        evaluator_fingerprint=_fingerprint(evaluator_key),
        evaluated_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        signature=_dummy_signature(evaluator_key, signer),
    )
    return SignedAuthorityEvaluationEnvelopeV1(
        **provisional.canonical_payload(exclude={"signature"}),
        signature=_signature(evaluator_key, signer, provisional.signing_bytes()),
    )


def _signed_observation(
    model: Any,
    *,
    key: SigningKey,
    signer: str,
    **fields: Any,
) -> Any:
    provisional = model(
        **fields,
        attestor_identity=signer,
        attestor_public_key=bytes(key.verify_key).hex(),
        attestor_fingerprint=_fingerprint(key),
        attestation_signature=_dummy_signature(key, signer),
    )
    return model(
        **provisional.canonical_payload(exclude={"attestation_signature"}),
        attestation_signature=_signature(
            key,
            signer,
            provisional.signing_bytes(),
        ),
    )


def _ceremony_packet(
    *,
    roster: tuple[FrozenSeatV1, ...],
    rule: CouncilTerminalityRuleV1,
    policy_sha256: str,
    keys: Mapping[str, SigningKey],
) -> dict[str, Any]:
    authority = _reported_live_authority(
        keys["evaluator"],
        policy_sha256=policy_sha256,
    )
    founder = _signed_observation(
        FounderDecisionReceiptV1,
        key=keys["founder"],
        signer="fixture:e2e:founder",
        decision_id="founder-decision-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        case_id=CASE_ID,
        case_sha256=CASE_SHA256,
        artifact_id=ARTIFACT_ID,
        artifact_sha256=CASE_SHA256,
        decision="alternate_artifact_terminal_disposition",
        requested_effects=EFFECTS,
        decided_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    probes = tuple(
        _signed_observation(
            ProviderProbeReceiptV1,
            key=keys["provider"],
            signer="fixture:e2e:provider-attestor",
            probe_id=f"probe-build-b-e2e-{index}",
            ceremony_id=CEREMONY_ID,
            provider=seat.served_provider,
            requested_route=seat.requested_route,
            served_route=seat.possible_underlying_routes[0],
            requested_model=seat.requested_model,
            served_model=seat.served_model,
            requested_lineage=seat.model_family,
            served_lineage=seat.model_family,
            requested_correlation_id=f"correlation-build-b-e2e-{index}",
            served_correlation_id=f"correlation-build-b-e2e-{index}",
            frozen_seat=seat,
            catalog_sha256=_digest(f"catalog:{index}"),
            response_sha256=_digest(f"probe-response:{index}"),
            available_balance_microusd=20_000,
            probed_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=4),
        )
        for index, seat in enumerate(roster)
    )
    bench_seats = tuple(
        FrozenBenchSeatV1(
            role=f"jurist-{index}",
            frozen_seat=seat,
            probe_correlation_id=probe.requested_correlation_id,
            provider_probe_sha256=probe.canonical_sha256(),
        )
        for index, (seat, probe) in enumerate(zip(roster, probes, strict=True))
    )
    bench = FrozenBenchManifestV1(
        bench_id="bench-build-b-offline-e2e",
        ceremony_id=CEREMONY_ID,
        case_id=CASE_ID,
        case_sha256=CASE_SHA256,
        seats=bench_seats,
        roster_sha256=canonical_sha256([seat.canonical_payload() for seat in roster]),
        terminality_rule_sha256=rule.rule_sha256,
        frozen_at=NOW - timedelta(minutes=1),
    )
    cost_items = tuple(
        BenchSeatCostV1(
            seat_id=seat.seat_id,
            provider_probe_sha256=probe.canonical_sha256(),
            pricing_catalog_sha256=probe.catalog_sha256,
            maximum_cost_microusd=1_000,
        )
        for seat, probe in zip(roster, probes, strict=True)
    )
    operator = "fixture:e2e:operator"
    operator_key = keys["operator"]
    provisional_cost = BenchCostEnvelopeV1(
        cost_envelope_id="cost-build-b-offline-e2e",
        ceremony_id=CEREMONY_ID,
        bench_manifest_sha256=bench.canonical_sha256(),
        seat_costs=cost_items,
        total_maximum_cost_microusd=9_000,
        spend_cap_microusd=10_000,
        approved_by=operator,
        approver_public_key=bytes(operator_key.verify_key).hex(),
        approver_fingerprint=_fingerprint(operator_key),
        approved_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        approval_signature=_dummy_signature(operator_key, operator),
    )
    cost = BenchCostEnvelopeV1(
        **provisional_cost.canonical_payload(exclude={"approval_signature"}),
        approval_signature=_signature(
            operator_key,
            operator,
            provisional_cost.signing_bytes(),
        ),
    )
    service_control = _signed_observation(
        MaintenanceControlAuthorityReceiptV1,
        key=keys["control"],
        signer="fixture:e2e:control-authority",
        authority_id="service-control-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        control_kind="service",
        target_id="service-build-b-offline-e2e",
        authority_scope="pause_and_restore_exact_prior_service",
        authorized_from=NOW - timedelta(minutes=1),
        authorized_until=NOW + timedelta(minutes=5),
        issued_at=NOW - timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=6),
    )
    tick_control = _signed_observation(
        MaintenanceControlAuthorityReceiptV1,
        key=keys["control"],
        signer="fixture:e2e:control-authority",
        authority_id="tick-control-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        control_kind="tick",
        target_id="tick-build-b-offline-e2e",
        authority_scope="exclude_and_restore_exact_prior_tick",
        authorized_from=NOW - timedelta(minutes=1),
        authorized_until=NOW + timedelta(minutes=5),
        issued_at=NOW - timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=6),
    )
    runtime = _signed_observation(
        MaintenanceRuntimeAttestationV1,
        key=keys["maintenance"],
        signer="fixture:e2e:maintenance-attestor",
        attestation_id="runtime-attestation-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        runtime_id="runtime-build-b-offline-e2e",
        writer_id="writer-build-b-offline-e2e",
        active_writer_ids=("writer-build-b-offline-e2e",),
        code_commit="a" * 40,
        openapi_sha256=_digest("openapi"),
        runtime_sha256=_digest("runtime"),
        maintenance_operations_sha256=FROZEN_MAINTENANCE_OPERATIONS_SHA256,
        database_sha256=_digest("copied-database"),
        lifecycle_fingerprint=_digest("lifecycle"),
        bind_host="127.0.0.1",
        bind_port=8765,
        process_evidence_sha256=_digest("process-evidence"),
        started_at=NOW - timedelta(minutes=2),
        attested_at=NOW - timedelta(seconds=20),
        expires_at=NOW + timedelta(minutes=4),
    )
    snapshot = _signed_observation(
        ServiceStateSnapshotV1,
        key=keys["maintenance"],
        signer="fixture:e2e:maintenance-attestor",
        snapshot_id="service-snapshot-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        service_name="service-build-b-offline-e2e",
        maintenance_runtime_id=runtime.runtime_id,
        active_writer_ids=(runtime.writer_id,),
        prior_service_state="running",
        prior_service_instance_id="service-build-b-prior",
        prior_service_definition_sha256=_digest("prior-service-definition"),
        prior_writer_ids=("prior-writer-build-b-e2e",),
        tick_id="tick-build-b-offline-e2e",
        prior_tick_state="enabled",
        prior_tick_definition_sha256=_digest("prior-tick-definition"),
        service_control_authority_sha256=service_control.canonical_sha256(),
        tick_control_authority_sha256=tick_control.canonical_sha256(),
        database_sha256=runtime.database_sha256,
        lifecycle_fingerprint=runtime.lifecycle_fingerprint,
        backup_sha256=_digest("backup"),
        backup_completed_at=NOW - timedelta(minutes=2),
        captured_at=NOW - timedelta(seconds=15),
        expires_at=NOW + timedelta(minutes=4),
    )
    tick = _signed_observation(
        TickExclusionReceiptV1,
        key=keys["maintenance"],
        signer="fixture:e2e:maintenance-attestor",
        receipt_id="tick-exclusion-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        tick_id=snapshot.tick_id,
        tick_definition_sha256=snapshot.prior_tick_definition_sha256,
        tick_control_authority_sha256=tick_control.canonical_sha256(),
        excluded_from=NOW - timedelta(minutes=1),
        excluded_until=NOW + timedelta(minutes=5),
        ceremony_window_start=NOW - timedelta(seconds=30),
        ceremony_window_end=NOW + timedelta(minutes=3),
        last_tick_completed_at=NOW - timedelta(minutes=2),
        next_tick_not_before=NOW + timedelta(minutes=5),
        observed_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=4),
    )
    restoration = _signed_observation(
        RestorationPlanV1,
        key=keys["maintenance"],
        signer="fixture:e2e:maintenance-attestor",
        plan_id="restoration-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        service_state_snapshot_sha256=snapshot.canonical_sha256(),
        maintenance_runtime_id=runtime.runtime_id,
        restore_service_name=snapshot.service_name,
        restore_service_state=snapshot.prior_service_state,
        restore_service_instance_id=snapshot.prior_service_instance_id,
        restore_service_definition_sha256=snapshot.prior_service_definition_sha256,
        restore_writer_ids=snapshot.prior_writer_ids,
        restore_tick_id=snapshot.tick_id,
        restore_tick_state=snapshot.prior_tick_state,
        restore_tick_definition_sha256=snapshot.prior_tick_definition_sha256,
        restore_database_sha256=snapshot.database_sha256,
        restore_lifecycle_fingerprint=snapshot.lifecycle_fingerprint,
        service_control_authority_sha256=service_control.canonical_sha256(),
        tick_control_authority_sha256=tick_control.canonical_sha256(),
        generated_at=NOW - timedelta(seconds=5),
    )
    lease = _signed_observation(
        LiveWriteLeaseEnvelopeV1,
        key=keys["lease"],
        signer="fixture:e2e:lease-issuer",
        lease_id="live-write-lease-build-b-e2e",
        ceremony_id=CEREMONY_ID,
        runtime_id=runtime.runtime_id,
        writer_id=runtime.writer_id,
        database_sha256=runtime.database_sha256,
        lifecycle_fingerprint=runtime.lifecycle_fingerprint,
        allowed_effects=EFFECTS,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    manifest = AttendedCeremonyManifestV1(
        ceremony_id=CEREMONY_ID,
        case_id=CASE_ID,
        case_sha256=CASE_SHA256,
        artifact_id=ARTIFACT_ID,
        artifact_sha256=CASE_SHA256,
        policy_sha256=policy_sha256,
        requested_effects=EFFECTS,
        founder_decision="alternate_artifact_terminal_disposition",
        founder_decision_receipt_sha256=founder.canonical_sha256(),
        authority_evaluation_sha256=authority.canonical_sha256(),
        bench_manifest_sha256=bench.canonical_sha256(),
        frozen_roster_sha256=bench.roster_sha256,
        terminality_rule_sha256=rule.rule_sha256,
        bench_cost_envelope_sha256=cost.canonical_sha256(),
        provider_probe_sha256s=tuple(probe.canonical_sha256() for probe in probes),
        maintenance_runtime_attestation_sha256=runtime.canonical_sha256(),
        service_state_snapshot_sha256=snapshot.canonical_sha256(),
        tick_exclusion_receipt_sha256=tick.canonical_sha256(),
        restoration_plan_sha256=restoration.canonical_sha256(),
        expected_code_commit=runtime.code_commit,
        expected_openapi_sha256=runtime.openapi_sha256,
        expected_runtime_sha256=runtime.runtime_sha256,
        expected_maintenance_operations_sha256=runtime.maintenance_operations_sha256,
        expected_database_sha256=runtime.database_sha256,
        expected_lifecycle_fingerprint=runtime.lifecycle_fingerprint,
        expected_evaluated_state_sha256=STATE_SHA256,
        expected_runtime_id=runtime.runtime_id,
        expected_writer_id=runtime.writer_id,
        expected_service_name=snapshot.service_name,
        expected_tick_id=tick.tick_id,
        service_control_authority_sha256=service_control.canonical_sha256(),
        tick_control_authority_sha256=tick_control.canonical_sha256(),
        live_write_lease_sha256=lease.canonical_sha256(),
        operator_identity=operator,
        operator_public_key=bytes(operator_key.verify_key).hex(),
        operator_fingerprint=_fingerprint(operator_key),
        frozen_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        maintenance_window_start=NOW - timedelta(seconds=30),
        maintenance_window_end=NOW + timedelta(minutes=3),
    )
    frozen = verify_frozen_execution_facts(
        manifest=manifest,
        founder_decision_receipt=founder,
        authority_evaluation=authority,
        provider_probes=probes,
        bench_manifest=bench,
        cost_envelope=cost,
        trusted_founder_fingerprints={_fingerprint(keys["founder"])},
        trusted_evaluator_fingerprints={_fingerprint(keys["evaluator"])},
        trusted_operator_fingerprints={_fingerprint(keys["operator"])},
        trusted_provider_attestor_fingerprints={_fingerprint(keys["provider"])},
        now=NOW,
    )
    live = validate_live_preflight_receipts(
        manifest=manifest,
        frozen_facts=frozen,
        runtime_attestation=runtime,
        service_state_snapshot=snapshot,
        tick_exclusion_receipt=tick,
        restoration_plan=restoration,
        service_control_authority_receipt=service_control,
        tick_control_authority_receipt=tick_control,
        write_lease=lease,
        trusted_maintenance_attestor_fingerprints={_fingerprint(keys["maintenance"])},
        trusted_control_authority_fingerprints={_fingerprint(keys["control"])},
        trusted_write_lease_issuer_fingerprints={_fingerprint(keys["lease"])},
        now=NOW,
    )
    return {
        "authority": authority,
        "founder": founder,
        "probes": probes,
        "bench": bench,
        "cost": cost,
        "runtime": runtime,
        "snapshot": snapshot,
        "tick": tick,
        "restoration": restoration,
        "service_control": service_control,
        "tick_control": tick_control,
        "lease": lease,
        "manifest": manifest,
        "frozen_readiness": frozen,
        "live_readiness": live,
    }


def _ballot(
    *,
    stage: str,
    position: int,
    seat: FrozenSeatV1,
    key: SigningKey,
) -> ArtifactBallotV1:
    signer = seat.seat_id
    payload = deepcopy(BALLOT_TEMPLATE)
    payload.update(
        {
            "ballot_id": f"ballot:{stage}:{position}",
            "case_id": CASE_ID,
            "case_sha256": CASE_SHA256,
            "seat_id": seat.seat_id,
            "stage": stage,
            "decision": ("correct_and_supersede" if position < 5 else "compost"),
            "requested_model": seat.requested_model,
            "requested_route": seat.requested_route,
            "served_provider": seat.served_provider,
            "served_model": seat.served_model,
            "served_route": seat.possible_underlying_routes[0],
            "credited_cluster": seat.credited_cluster,
            "cluster_basis": seat.cluster_basis,
            "model_lineage_evidence_refs": [
                item.canonical_payload() for item in seat.model_lineage_evidence_refs
            ],
            "transport_correlation_refs": list(seat.transport_correlation_refs),
            "correlation_smeared": seat.correlation_smeared,
            "raw_model_output_sha256": _digest(f"raw:{stage}:{position}"),
            "transcript_ref": {
                "ref": f"offline:transcript:{stage}:{position}",
                "content_sha256": _digest(f"transcript:{stage}:{position}"),
                "proof_class": "offline_fixture",
            },
            "execution_signature": _dummy_signature(key, signer).canonical_payload(),
        }
    )
    provisional = ArtifactBallotV1.model_validate(payload)
    return ArtifactBallotV1(
        **provisional.canonical_payload(exclude={"execution_signature"}),
        execution_signature=_signature(
            key,
            signer,
            provisional.canonical_bytes(exclude={"execution_signature"}),
        ),
    )


def _stage(
    *,
    stage: str,
    preceding_reveal_set_sha256: str,
    roster: tuple[FrozenSeatV1, ...],
    keys: tuple[SigningKey, ...],
    authority_digest: str,
    rule_digest: str,
) -> CeremonyStageEnvelopeV1:
    stage_index = CEREMONY_STAGES.index(stage)  # type: ignore[arg-type]
    stage_input_sha256 = _digest(f"stage-input:{stage}")
    roster_sha256 = canonical_sha256([seat.canonical_payload() for seat in roster])
    subject = None
    subject_sha256 = None
    if stage == "final":
        subject = FinalDeliberationSubjectV1(
            case_id=CASE_ID,
            case_sha256=CASE_SHA256,
            frozen_roster_sha256=roster_sha256,
            authority_digest=authority_digest,
            rule_digest=rule_digest,
            cross_examination_reveal_set_sha256=preceding_reveal_set_sha256,
            stage_input_sha256=stage_input_sha256,
            question="Render a final ballot over the exact prior reveal set.",
            deliberation_material_sha256=_digest("final-deliberation-material"),
        )
        subject_sha256 = subject.canonical_sha256()

    commitments = []
    ballots = []
    nonces = []
    for position, (seat, key) in enumerate(zip(roster, keys, strict=True)):
        ballot = _ballot(stage=stage, position=position, seat=seat, key=key)
        facts = BallotExecutionFactsV1.from_ballot(ballot)
        nonce = f"offline-public-nonce:{stage}:{position:02d}"
        draft: dict[str, Any] = {
            "commitment_id": f"commitment:{stage}:{position}",
            "case_id": CASE_ID,
            "case_sha256": CASE_SHA256,
            "frozen_roster_sha256": roster_sha256,
            "frozen_seat_sha256": seat.canonical_sha256(),
            "authority_digest": authority_digest,
            "rule_digest": rule_digest,
            "stage": stage,
            "stage_index": stage_index,
            "stage_input_sha256": stage_input_sha256,
            "preceding_reveal_set_sha256": preceding_reveal_set_sha256,
            "final_deliberation_subject_sha256": subject_sha256,
            "seat_id": seat.seat_id,
            "seat_position": position,
            "execution_facts": facts,
        }
        commitments.append(
            BallotCommitmentV1(
                **draft,
                committed_preimage_sha256=ballot_commitment_preimage_sha256(
                    draft,
                    nonce=nonce,
                    ballot=ballot,
                ),
            )
        )
        ballots.append(ballot)
        nonces.append(nonce)

    commitment_set_sha256 = canonical_commitment_set_sha256(commitments)
    reveals = tuple(
        BallotRevealV1(
            reveal_id=f"reveal:{stage}:{position}",
            commitment_id=commitment.commitment_id,
            commitment_sha256=commitment.canonical_sha256(),
            commitment_set_sha256=commitment_set_sha256,
            case_id=commitment.case_id,
            case_sha256=commitment.case_sha256,
            frozen_roster_sha256=commitment.frozen_roster_sha256,
            frozen_seat_sha256=commitment.frozen_seat_sha256,
            authority_digest=commitment.authority_digest,
            rule_digest=commitment.rule_digest,
            stage=commitment.stage,
            stage_index=commitment.stage_index,
            stage_input_sha256=commitment.stage_input_sha256,
            preceding_reveal_set_sha256=commitment.preceding_reveal_set_sha256,
            final_deliberation_subject_sha256=(
                commitment.final_deliberation_subject_sha256
            ),
            seat_id=commitment.seat_id,
            seat_position=commitment.seat_position,
            execution_facts=commitment.execution_facts,
            nonce=nonces[position],
            ballot=ballots[position],
            ballot_sha256=ballots[position].canonical_sha256(),
        )
        for position, commitment in enumerate(commitments)
    )
    return CeremonyStageEnvelopeV1(
        envelope_id=f"envelope:{stage}",
        case_id=CASE_ID,
        case_sha256=CASE_SHA256,
        frozen_roster=roster,
        frozen_roster_sha256=roster_sha256,
        expected_seat_ids=tuple(seat.seat_id for seat in roster),
        authority_digest=authority_digest,
        rule_digest=rule_digest,
        stage=stage,
        stage_index=stage_index,
        stage_input_sha256=stage_input_sha256,
        preceding_reveal_set_sha256=preceding_reveal_set_sha256,
        final_deliberation_subject=subject,
        final_deliberation_subject_sha256=subject_sha256,
        commitments=tuple(commitments),
        commitment_set_sha256=commitment_set_sha256,
        reveals=reveals,
        reveal_set_sha256=canonical_reveal_set_sha256(reveals),
    )


def _transcript(
    *,
    roster: tuple[FrozenSeatV1, ...],
    keys: tuple[SigningKey, ...],
    authority_digest: str,
    rule_digest: str,
) -> tuple[CeremonyStageEnvelopeV1, ...]:
    first = _stage(
        stage="sealed_first_pass",
        preceding_reveal_set_sha256=EMPTY_REVEAL_SET_SHA256,
        roster=roster,
        keys=keys,
        authority_digest=authority_digest,
        rule_digest=rule_digest,
    )
    cross = _stage(
        stage="cross_examination",
        preceding_reveal_set_sha256=first.reveal_set_sha256,
        roster=roster,
        keys=keys,
        authority_digest=authority_digest,
        rule_digest=rule_digest,
    )
    final = _stage(
        stage="final",
        preceding_reveal_set_sha256=cross.reveal_set_sha256,
        roster=roster,
        keys=keys,
        authority_digest=authority_digest,
        rule_digest=rule_digest,
    )
    return first, cross, final


class _MeritsBomb:
    def __iter__(self) -> Any:
        raise AssertionError("authority refusal inspected merit-bearing input")

    def __len__(self) -> int:
        raise AssertionError("authority refusal measured merit-bearing input")


def build_attended_ceremony_fixture() -> dict[str, Any]:
    """Construct the complete signed, offline Build B evidence graph."""

    keys = {
        name: SigningKey.generate()
        for name in (
            "policy",
            "evaluator",
            "operator",
            "founder",
            "provider",
            "maintenance",
            "control",
            "lease",
        )
    }
    seat_keys = tuple(SigningKey.generate() for _ in range(9))
    copy_authority = _evaluate_copy_authority(
        keys["policy"],
        disposition_mode="authorized",
    )
    assert isinstance(copy_authority, AuthorizedDispositionAuthorityV1)

    rule = _terminality_rule()
    roster = _roster(seat_keys)
    ceremony = _ceremony_packet(
        roster=roster,
        rule=rule,
        policy_sha256=copy_authority.policy_sha256,
        keys=keys,
    )
    transcript = _transcript(
        roster=roster,
        keys=seat_keys,
        authority_digest=copy_authority.authority_digest,
        rule_digest=rule.rule_sha256,
    )
    validated = verify_ceremony_transcript(transcript, expected_roster=roster)
    compiler_arguments = {
        "authority": copy_authority,
        "case_id": CASE_ID,
        "case_sha256": CASE_SHA256,
        "ballots": validated.ordered_final_ballots,
        "rule": rule,
        "frozen_roster": roster,
        "requested_scope": "Copy",
        "requested_effects": EFFECTS,
        "compiled_at": NOW,
    }
    outcome = compile_council_outcome(**compiler_arguments)
    assert isinstance(outcome, CompiledVerdictV1)

    closeout_bytes = json.dumps(
        {
            "schema": "sab.first_verdict.build_a_merge_closeout.v1",
            "created_at_utc": "2026-07-31T15:31:25Z",
            "repository": "AmitabhainArunachala/SAB-Syntropic-Attractor-Basin",
            "pull_request": {
                "number": 11,
                "url": (
                    "https://github.com/AmitabhainArunachala/"
                    "SAB-Syntropic-Attractor-Basin/pull/11"
                ),
                "state": "MERGED",
                "head": "d" * 40,
                "head_tree": "c" * 40,
                "merge_commit": "b" * 40,
                "merge_tree": "c" * 40,
                "merged_at_utc": "2026-07-31T15:31:25Z",
            },
            "github_ci": {
                "run_id": 30_643_074_765,
                "test_python_3_10": "PASS",
                "test_python_3_11": "PASS",
                "test_python_3_12": "PASS",
                "security": "PASS",
                "lint": "PASS",
                "docker": "PASS",
            },
            "final_local_verification": {
                "full_pytest": "732 passed, 33 warnings in 35.46s",
                "atomic_pytest": "31 passed",
                "bandit": "0 high, 0 medium, 0 low",
                "ruff_check": "PASS",
                "ruff_format_check": "PASS",
                "compileall": "PASS",
                "governance_and_orientation": "PASS",
                "worktree_clean": True,
            },
            "ci_repairs": {"e" * 40: "fixture repair proved by green CI"},
            "prior_receipts": {
                "integration_replay": "fixture:integration-replay",
                "integration_replay_sha256": _digest("integration-replay"),
                "linux_portability": "fixture:linux-portability",
                "linux_portability_sha256": _digest("linux-portability"),
            },
            "terminal_claim": {
                "engineering_status": "proven_on_copy_and_merged",
                "historic_live_win": False,
                "live_mutations": 0,
                "service_mutations": 0,
                "provider_calls": 0,
                "standing_effect": "none",
                "master_vision_effect": "none",
                "build_b": "not_run_at_build_a_merge",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    binding_arguments = {
        "manifest": ceremony["manifest"],
        "frozen_readiness": ceremony["frozen_readiness"],
        "live_readiness": ceremony["live_readiness"],
        "founder_decision_receipt": ceremony["founder"],
        "authority_evaluation": ceremony["authority"],
        "compiler_authority": copy_authority,
        "provider_probes": ceremony["probes"],
        "bench_manifest": ceremony["bench"],
        "cost_envelope": ceremony["cost"],
        "transcript": transcript,
        "transcript_validation": validated,
        "terminality_rule": rule,
        "compiled_outcome": outcome,
        "runtime_attestation": ceremony["runtime"],
        "service_state_snapshot": ceremony["snapshot"],
        "tick_exclusion_receipt": ceremony["tick"],
        "restoration_plan": ceremony["restoration"],
        "service_control_authority": ceremony["service_control"],
        "tick_control_authority": ceremony["tick_control"],
        "live_write_lease": ceremony["lease"],
        "build_a_closeout_bytes": closeout_bytes,
        "prepared_at": NOW,
    }
    evidence = bind_operator_approval_evidence(**binding_arguments)
    packet = build_operator_approval_packet(evidence)
    return {
        "keys": keys,
        "seat_keys": seat_keys,
        "copy_authority": copy_authority,
        "rule": rule,
        "roster": roster,
        "ceremony": ceremony,
        "transcript": transcript,
        "validated": validated,
        "compiler_arguments": compiler_arguments,
        "outcome": outcome,
        "binding_arguments": binding_arguments,
        "build_a_closeout_bytes": closeout_bytes,
        "evidence": evidence,
        "packet": packet,
    }


def test_offline_attended_ceremony_is_copy_only_non_authorizing_and_sealed(
    monkeypatch: Any,
) -> None:
    def network_forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("offline ceremony attempted socket I/O")

    monkeypatch.setattr(socket.socket, "connect", network_forbidden)
    monkeypatch.setattr(socket, "socket", network_forbidden)
    monkeypatch.setattr(socket, "create_connection", network_forbidden)

    fixture = build_attended_ceremony_fixture()
    ceremony = fixture["ceremony"]
    roster = fixture["roster"]
    transcript = fixture["transcript"]
    validated = fixture["validated"]
    outcome = fixture["outcome"]
    packet = fixture["packet"]

    assert fixture["copy_authority"].scope == "Copy"
    assert fixture["copy_authority"].live_eligible is False
    assert len(ceremony["bench"].seats) == 9
    assert ceremony["bench"].transcript_roster == roster
    for bench_seat, frozen_seat, probe in zip(
        ceremony["bench"].seats,
        roster,
        ceremony["probes"],
        strict=True,
    ):
        assert bench_seat.frozen_seat == frozen_seat
        assert probe.frozen_seat == frozen_seat
        assert bench_seat.provider_probe_sha256 == probe.canonical_sha256()

    for phase, readiness in (
        ("frozen_execution_facts", ceremony["frozen_readiness"]),
        ("live_maintenance_preflight", ceremony["live_readiness"]),
    ):
        assert isinstance(readiness, StructurallyCompleteAwaitingAuthority)
        assert readiness_is_locally_verified(readiness, phase=phase)
        assert readiness.live_authority_state == "absent"
        assert readiness.permits_live_effect is False
        assert readiness.standing_effect == "none"

    for envelope in transcript:
        for reveal, frozen_seat in zip(envelope.reveals, roster, strict=True):
            ballot = reveal.ballot
            assert ballot.execution_signature.public_key == (
                frozen_seat.execution_public_key
            )
            assert verify_contract_signature(
                ballot.canonical_bytes(exclude={"execution_signature"}),
                ballot.execution_signature,
            )
    assert validated.ok is True
    assert validated.validated_stages == CEREMONY_STAGES
    assert validated.frozen_roster_sha256 == ceremony["bench"].roster_sha256
    assert validated.rule_digest == fixture["rule"].rule_sha256
    assert len(validated.ordered_final_ballots) == 9
    assert validated.authority_effect == "none"
    assert validated.live_eligible is False

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    assert conn.execute("PRAGMA database_list").fetchone()[2] == ""
    init_transcript_storage(conn, applied_at=RECORDED_AT)
    storage_receipt = store_ceremony_transcript(
        conn,
        transcript,
        expected_roster=roster,
        recorded_at=RECORDED_AT,
    )
    assert storage_receipt.transcript_sha256 == validated.transcript_sha256
    assert storage_receipt.authority_effect == "none"
    assert storage_receipt.live_eligible is False
    assert read_ceremony_transcript(conn, CASE_ID) == transcript

    assert outcome.terminality == "terminal"
    assert outcome.decision == "correct_and_supersede"
    assert outcome.requested_effects == EFFECTS
    assert outcome.frozen_roster_sha256 == ceremony["bench"].roster_sha256
    assert verify_compiled_outcome(outcome, **fixture["compiler_arguments"])

    verified = verify_operator_approval_packet(packet)
    rendered = render_operator_approval_markdown(packet)
    assert packet["status"] == "awaiting_operator_countersign"
    assert packet["operator_signature"] is None
    assert packet["effect_executable"] is False
    assert packet["live_authority_created"] is False
    assert packet["signing_instruction"] == SIGNING_INSTRUCTION
    payload = packet["approval_payload"]
    assert payload["code"]["runtime_commit_sha"] == "a" * 40
    assert payload["code"]["build_a_merge_commit"] == "b" * 40
    assert (
        payload["code"]["runtime_commit_sha"] != payload["code"]["build_a_merge_commit"]
    )
    assert {
        item["proposal"]["effect_type"]: (
            item["proposal"]["target_kind"],
            item["proposal"]["target_id"],
        )
        for item in payload["proposed_effects"]
    } == {
        "challenge:resolve": ("case", CASE_ID),
        "seed:supersede": ("artifact", ARTIFACT_ID),
    }
    assert verified["packet_integrity_valid"] is True
    assert verified["evidence_reverified"] is False
    assert verified["live_authority_created"] is False
    assert verified["effect_executable"] is False
    assert "Out-of-band trust-anchor set digests" in rendered

    advisory_key = SigningKey.generate()
    advisory = _evaluate_copy_authority(
        advisory_key,
        disposition_mode="advisory_only",
    )
    refusal = compile_council_outcome(
        authority=advisory,
        case_id=_MeritsBomb(),
        case_sha256=_MeritsBomb(),
        ballots=_MeritsBomb(),
        rule=_MeritsBomb(),
        frozen_roster=_MeritsBomb(),
        requested_scope="Copy",
        requested_effects=EFFECTS,
        compiled_at=_MeritsBomb(),
    )
    assert isinstance(refusal, RefusalReceiptV1)
    assert refusal.reason == "authority_advisory_only"
    assert refusal.ballots_inspected is False
    assert refusal.merits_parsed is False
    assert refusal.effects == ()

    persisted_sql = "\n".join(conn.iterdump())
    visible_artifacts = "\n".join(
        (
            persisted_sql,
            ceremony["frozen_readiness"].canonical_json(),
            ceremony["live_readiness"].canonical_json(),
            outcome.canonical_json(),
            canonical_packet_json(packet),
            rendered,
        )
    )
    all_ephemeral_keys = (
        *fixture["keys"].values(),
        *fixture["seat_keys"],
        advisory_key,
    )
    for key in all_ephemeral_keys:
        assert key.encode().hex() not in visible_artifacts
    lowered = visible_artifacts.lower()
    assert "private_key" not in lowered
    assert "api_key" not in lowered
    assert "seed_phrase" not in lowered
    assert "access_token" not in lowered
    assert ("Authorized" + "<Live>") not in visible_artifacts
    conn.close()
