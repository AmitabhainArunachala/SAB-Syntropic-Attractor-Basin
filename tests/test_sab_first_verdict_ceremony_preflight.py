from __future__ import annotations

import ast
import copy
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey
from pydantic import ValidationError

from agora.sab_artifact_verdict import (
    ContractSignatureV1,
    EvidenceRefV1,
    FrozenSeatV1,
    MASTER_VISION_SEED_ID,
    canonical_json_bytes,
    canonical_sha256,
)
from agora.sab_first_verdict_ceremony import (
    AttendedCeremonyManifestV1,
    BenchCostEnvelopeV1,
    BenchSeatCostV1,
    Blocked,
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
    SuccessfulCloseoutPlanV2,
    TickExclusionReceiptV1,
    readiness_is_locally_verified,
    validate_live_preflight_receipts,
    verify_frozen_execution_facts,
)


NOW = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
GIT_A = "a" * 40
EFFECT = "record_terminal_disposition"


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _key(label: str) -> SigningKey:
    """Return a deterministic key which exists only inside this test process."""

    return SigningKey(hashlib.sha256(f"sab-test-key:{label}".encode()).digest())


def _public_key(key: SigningKey) -> str:
    return bytes(key.verify_key).hex()


def _fingerprint(key: SigningKey) -> str:
    return hashlib.sha256(bytes(key.verify_key)).hexdigest()


def _signature(key: SigningKey, signer: str, message: bytes) -> ContractSignatureV1:
    return ContractSignatureV1(
        signer=signer,
        public_key=_public_key(key),
        signature=key.sign(message).signature.hex(),
        signed_payload_sha256=hashlib.sha256(message).hexdigest(),
    )


def _dummy_signature(key: SigningKey, signer: str) -> ContractSignatureV1:
    """Structurally valid nonzero metadata used only to derive signing bytes."""

    return ContractSignatureV1(
        signer=signer,
        public_key=_public_key(key),
        signature="01" * 64,
        signed_payload_sha256="01" * 32,
    )


def _signed_observation(
    model_type: type[Any],
    key: SigningKey,
    signer: str,
    **payload: Any,
) -> Any:
    """Construct, sign, and reconstruct any signed observation model."""

    provisional = model_type(
        **payload,
        attestor_identity=signer,
        attestor_public_key=_public_key(key),
        attestor_fingerprint=_fingerprint(key),
        attestation_signature=_dummy_signature(key, signer),
    )
    return model_type(
        **provisional.canonical_payload(exclude={"attestation_signature"}),
        attestation_signature=_signature(key, signer, provisional.signing_bytes()),
    )


def _signed_authority(
    evaluator_key: SigningKey,
    *,
    effect: str = EFFECT,
) -> SignedAuthorityEvaluationEnvelopeV1:
    signer = "evaluator.primary"
    provisional = SignedAuthorityEvaluationEnvelopeV1(
        evaluation_id="evaluation-1",
        ceremony_id="ceremony-1",
        case_id="case-1",
        case_sha256=SHA_A,
        artifact_id="artifact-1",
        artifact_sha256=SHA_B,
        policy_sha256=SHA_C,
        evaluated_state_sha256=SHA_D,
        requested_effects=(effect,),
        reported_result="Authorized",
        reported_allowed_effects=(effect,),
        reported_live_eligible=True,
        evaluator_identity=signer,
        evaluator_public_key=_public_key(evaluator_key),
        evaluator_fingerprint=_fingerprint(evaluator_key),
        evaluated_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        signature=_dummy_signature(evaluator_key, signer),
    )
    return SignedAuthorityEvaluationEnvelopeV1(
        **provisional.canonical_payload(exclude={"signature"}),
        signature=_signature(evaluator_key, signer, provisional.signing_bytes()),
    )


def _frozen_seat(index: int, execution_key: SigningKey) -> FrozenSeatV1:
    seat = f"seat-{index:02d}"
    route = f"route-{index:02d}"
    correlation = f"correlation-{index:02d}"
    return FrozenSeatV1(
        seat_id=seat,
        requested_lab=f"lab-{index:02d}",
        requested_model=f"model-{index:02d}",
        adapter="provider-api-v1",
        transport="https",
        requested_route=route,
        served_provider=f"provider-{index:02d}",
        served_model=f"model-{index:02d}",
        model_family=f"lineage-{index:02d}",
        credited_cluster=f"cluster-{index:02d}",
        model_lineage_evidence_refs=(
            EvidenceRefV1(
                ref=f"fixture://lineage/{index:02d}",
                content_sha256=_sha(f"lineage-evidence-{index:02d}"),
                proof_class="deterministic_test_fixture",
            ),
        ),
        possible_underlying_routes=(route,),
        transport_correlation_refs=(correlation,),
        correlation_smeared=True,
        execution_public_key=_public_key(execution_key),
        common_operator_backing="ephemeral deterministic test operator",
        liveness_receipt_sha256=_sha(f"liveness-{index:02d}"),
    )


def _signed_probe(
    index: int,
    *,
    seat: FrozenSeatV1,
    provider_key: SigningKey,
    balance_microusd: int,
    probed_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=4),
) -> ProviderProbeReceiptV1:
    correlation = f"correlation-{index:02d}"
    return _signed_observation(
        ProviderProbeReceiptV1,
        provider_key,
        "provider.attestor",
        probe_id=f"probe-{index:02d}",
        ceremony_id="ceremony-1",
        provider=seat.served_provider,
        requested_route=seat.requested_route,
        served_route=seat.requested_route,
        requested_model=seat.requested_model,
        served_model=seat.served_model,
        requested_lineage=seat.model_family,
        served_lineage=seat.model_family,
        requested_correlation_id=correlation,
        served_correlation_id=correlation,
        frozen_seat=seat,
        catalog_sha256=_sha(f"catalog-{index:02d}"),
        response_sha256=_sha(f"probe-response-{index:02d}"),
        available_balance_microusd=balance_microusd,
        probed_at=probed_at,
        expires_at=expires_at,
    )


def _signed_cost(
    operator_key: SigningKey,
    *,
    bench: FrozenBenchManifestV1,
    probes: tuple[ProviderProbeReceiptV1, ...],
    maximum_cost_microusd: int = 100,
    spend_cap_microusd: int = 1_500,
    approved_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=4),
) -> BenchCostEnvelopeV1:
    signer = "operator.primary"
    seat_costs = tuple(
        BenchSeatCostV1(
            seat_id=seat.seat_id,
            provider_probe_sha256=probe.canonical_sha256(),
            pricing_catalog_sha256=probe.catalog_sha256,
            maximum_cost_microusd=maximum_cost_microusd,
        )
        for seat, probe in zip(bench.seats, probes, strict=True)
    )
    provisional = BenchCostEnvelopeV1(
        cost_envelope_id="cost-1",
        ceremony_id="ceremony-1",
        bench_manifest_sha256=bench.canonical_sha256(),
        seat_costs=seat_costs,
        total_maximum_cost_microusd=maximum_cost_microusd * len(seat_costs),
        spend_cap_microusd=spend_cap_microusd,
        approved_by=signer,
        approver_public_key=_public_key(operator_key),
        approver_fingerprint=_fingerprint(operator_key),
        approved_at=approved_at,
        expires_at=expires_at,
        approval_signature=_dummy_signature(operator_key, signer),
    )
    return BenchCostEnvelopeV1(
        **provisional.canonical_payload(exclude={"approval_signature"}),
        approval_signature=_signature(
            operator_key, signer, provisional.signing_bytes()
        ),
    )


def _packet(
    *,
    balance_microusd: int = 5_000,
    probe_probed_at: datetime = NOW - timedelta(minutes=1),
    probe_expires_at: datetime = NOW + timedelta(minutes=4),
    bench_frozen_at: datetime = NOW - timedelta(minutes=1),
    cost_approved_at: datetime = NOW - timedelta(minutes=1),
) -> dict[str, Any]:
    keys = {
        name: _key(name)
        for name in (
            "founder",
            "evaluator",
            "provider",
            "operator",
            "maintenance",
            "control",
            "lease",
        )
    }
    execution_keys = tuple(_key(f"execution-{index:02d}") for index in range(1, 10))

    founder = _signed_observation(
        FounderDecisionReceiptV1,
        keys["founder"],
        "founder.primary",
        decision_id="founder-decision-1",
        ceremony_id="ceremony-1",
        case_id="case-1",
        case_sha256=SHA_A,
        artifact_id="artifact-1",
        artifact_sha256=SHA_B,
        decision="alternate_artifact_terminal_disposition",
        requested_effects=(EFFECT,),
        decided_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    authority = _signed_authority(keys["evaluator"])

    frozen_seats = tuple(
        _frozen_seat(index, execution_keys[index - 1]) for index in range(1, 10)
    )
    probes = tuple(
        _signed_probe(
            index,
            seat=frozen_seats[index - 1],
            provider_key=keys["provider"],
            balance_microusd=balance_microusd,
            probed_at=probe_probed_at,
            expires_at=probe_expires_at,
        )
        for index in range(1, 10)
    )
    bench_seats = tuple(
        FrozenBenchSeatV1(
            role=f"jurist-{index:02d}",
            frozen_seat=frozen_seats[index - 1],
            probe_correlation_id=f"correlation-{index:02d}",
            provider_probe_sha256=probes[index - 1].canonical_sha256(),
        )
        for index in range(1, 10)
    )
    bench = FrozenBenchManifestV1(
        bench_id="bench-1",
        ceremony_id="ceremony-1",
        case_id="case-1",
        case_sha256=SHA_A,
        seats=bench_seats,
        roster_sha256=canonical_sha256(
            [seat.canonical_payload() for seat in frozen_seats]
        ),
        terminality_rule_sha256=_sha("council-terminality-rule-v1"),
        frozen_at=bench_frozen_at,
    )
    cost = _signed_cost(
        keys["operator"],
        bench=bench,
        probes=probes,
        approved_at=cost_approved_at,
    )

    runtime = _signed_observation(
        MaintenanceRuntimeAttestationV1,
        keys["maintenance"],
        "maintenance.attestor",
        attestation_id="runtime-attestation-1",
        ceremony_id="ceremony-1",
        runtime_id="maintenance-runtime-1",
        writer_id="maintenance-writer-1",
        active_writer_ids=("maintenance-writer-1",),
        code_commit=GIT_A,
        openapi_sha256=SHA_B,
        runtime_sha256=SHA_C,
        maintenance_operations_sha256=FROZEN_MAINTENANCE_OPERATIONS_SHA256,
        database_sha256=SHA_D,
        lifecycle_fingerprint=SHA_E,
        bind_host="127.0.0.1",
        bind_port=8765,
        process_evidence_sha256=SHA_F,
        started_at=NOW - timedelta(minutes=2),
        attested_at=NOW - timedelta(seconds=20),
        expires_at=NOW + timedelta(minutes=4),
    )
    service_control = _signed_observation(
        MaintenanceControlAuthorityReceiptV1,
        keys["control"],
        "control.authority",
        authority_id="service-control-1",
        ceremony_id="ceremony-1",
        control_kind="service",
        target_id="agora-live",
        authority_scope="pause_and_restore_exact_prior_service",
        authorized_from=NOW - timedelta(seconds=30),
        authorized_until=NOW + timedelta(minutes=3),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    tick_control = _signed_observation(
        MaintenanceControlAuthorityReceiptV1,
        keys["control"],
        "control.authority",
        authority_id="tick-control-1",
        ceremony_id="ceremony-1",
        control_kind="tick",
        target_id="agora-tick",
        authority_scope="exclude_and_restore_exact_prior_tick",
        authorized_from=NOW - timedelta(seconds=30),
        authorized_until=NOW + timedelta(minutes=3),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    lease = _signed_observation(
        LiveWriteLeaseEnvelopeV1,
        keys["lease"],
        "lease.issuer",
        lease_id="live-write-lease-1",
        ceremony_id="ceremony-1",
        runtime_id=runtime.runtime_id,
        writer_id=runtime.writer_id,
        database_sha256=runtime.database_sha256,
        lifecycle_fingerprint=runtime.lifecycle_fingerprint,
        allowed_effects=(EFFECT,),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    snapshot = _signed_observation(
        ServiceStateSnapshotV1,
        keys["maintenance"],
        "maintenance.attestor",
        snapshot_id="service-snapshot-1",
        ceremony_id="ceremony-1",
        service_name="agora-live",
        maintenance_runtime_id=runtime.runtime_id,
        active_writer_ids=(runtime.writer_id,),
        prior_service_state="running",
        prior_service_instance_id="agora-live-old-1",
        prior_service_definition_sha256=SHA_A,
        prior_writer_ids=("agora-live-writer",),
        tick_id="agora-tick",
        prior_tick_state="enabled",
        prior_tick_definition_sha256=SHA_B,
        service_control_authority_sha256=service_control.canonical_sha256(),
        tick_control_authority_sha256=tick_control.canonical_sha256(),
        database_sha256=runtime.database_sha256,
        lifecycle_fingerprint=runtime.lifecycle_fingerprint,
        backup_sha256=SHA_F,
        backup_completed_at=NOW - timedelta(minutes=2),
        captured_at=NOW - timedelta(seconds=15),
        expires_at=NOW + timedelta(minutes=4),
    )
    tick = _signed_observation(
        TickExclusionReceiptV1,
        keys["maintenance"],
        "maintenance.attestor",
        receipt_id="tick-exclusion-1",
        ceremony_id="ceremony-1",
        tick_id=snapshot.tick_id,
        tick_definition_sha256=snapshot.prior_tick_definition_sha256,
        tick_control_authority_sha256=tick_control.canonical_sha256(),
        excluded_from=NOW - timedelta(seconds=30),
        excluded_until=NOW + timedelta(minutes=3),
        ceremony_window_start=NOW - timedelta(seconds=30),
        ceremony_window_end=NOW + timedelta(minutes=3),
        last_tick_completed_at=NOW - timedelta(minutes=2),
        next_tick_not_before=NOW + timedelta(minutes=3),
        observed_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=4),
    )
    restoration = _signed_observation(
        RestorationPlanV1,
        keys["maintenance"],
        "maintenance.attestor",
        plan_id="restoration-1",
        ceremony_id="ceremony-1",
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
    manifest = AttendedCeremonyManifestV1(
        ceremony_id="ceremony-1",
        case_id="case-1",
        case_sha256=SHA_A,
        artifact_id="artifact-1",
        artifact_sha256=SHA_B,
        policy_sha256=SHA_C,
        requested_effects=(EFFECT,),
        founder_decision="alternate_artifact_terminal_disposition",
        founder_decision_receipt_sha256=founder.canonical_sha256(),
        authority_evaluation_sha256=authority.canonical_sha256(),
        bench_manifest_sha256=bench.canonical_sha256(),
        frozen_roster_sha256=bench.roster_sha256,
        terminality_rule_sha256=bench.terminality_rule_sha256,
        bench_cost_envelope_sha256=cost.canonical_sha256(),
        provider_probe_sha256s=tuple(
            sorted(probe.canonical_sha256() for probe in probes)
        ),
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
        expected_evaluated_state_sha256=authority.evaluated_state_sha256,
        expected_runtime_id=runtime.runtime_id,
        expected_writer_id=runtime.writer_id,
        expected_service_name=snapshot.service_name,
        expected_tick_id=tick.tick_id,
        service_control_authority_sha256=service_control.canonical_sha256(),
        tick_control_authority_sha256=tick_control.canonical_sha256(),
        live_write_lease_sha256=lease.canonical_sha256(),
        operator_identity="operator.primary",
        operator_public_key=_public_key(keys["operator"]),
        operator_fingerprint=_fingerprint(keys["operator"]),
        frozen_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        maintenance_window_start=NOW - timedelta(seconds=30),
        maintenance_window_end=NOW + timedelta(minutes=3),
    )
    return {
        "keys": keys,
        "execution_keys": execution_keys,
        "founder": founder,
        "authority": authority,
        "probes": probes,
        "bench": bench,
        "cost": cost,
        "runtime": runtime,
        "service_control": service_control,
        "tick_control": tick_control,
        "lease": lease,
        "snapshot": snapshot,
        "tick": tick,
        "restoration": restoration,
        "manifest": manifest,
    }


def _successful_closeout_plan(
    packet: dict[str, Any], **overrides: Any
) -> dict[str, Any]:
    snapshot = packet["snapshot"]
    payload = {
        "plan_id": "successful-closeout-1",
        "ceremony_id": "ceremony-1",
        "service_state_snapshot_sha256": snapshot.canonical_sha256(),
        "maintenance_runtime_id": packet["runtime"].runtime_id,
        "closeout_mode": "preserve_verified_post_effect_state",
        "database_disposition": "preserve_separately_verified_post_effect_root",
        "lifecycle_disposition": (
            "preserve_separately_verified_post_effect_fingerprint"
        ),
        "successful_effect_receipt_requirement": "required",
        "post_effect_state_verification_requirement": (
            "database_sha256_and_lifecycle_fingerprint_required"
        ),
        "success_branch_control_restore_precondition": (
            "success_branch_successful_effect_receipt_and_post_effect_state_verification"
        ),
        "success_branch_apply_precondition": (
            "success_branch_only_after_successful_effect_receipt_and_post_effect_state_verification"
        ),
        "failure_trigger": ("effect_failure_or_post_effect_state_verification_failure"),
        "failure_disposition": (
            "rollback_to_captured_pre_ceremony_database_and_lifecycle_roots"
        ),
        "failure_database_sha256": snapshot.database_sha256,
        "failure_lifecycle_fingerprint": snapshot.lifecycle_fingerprint,
        "failure_rollback_verification_requirement": (
            "database_sha256_and_lifecycle_fingerprint_required_before_control_restore"
        ),
        "failure_branch_apply_precondition": (
            "failure_branch_effect_failure_or_post_effect_state_verification_failure_then_verified_snapshot_rollback_before_control_restore"
        ),
        "control_and_runtime_completion_requirement": (
            "restore_exact_prior_controls_and_stop_maintenance_runtime_on_success_or_failure"
        ),
        "stop_maintenance_runtime": True,
        "restore_service_name": snapshot.service_name,
        "restore_service_state": snapshot.prior_service_state,
        "restore_service_instance_id": snapshot.prior_service_instance_id,
        "restore_service_definition_sha256": (snapshot.prior_service_definition_sha256),
        "restore_writer_ids": snapshot.prior_writer_ids,
        "restore_tick_id": snapshot.tick_id,
        "restore_tick_state": snapshot.prior_tick_state,
        "restore_tick_definition_sha256": snapshot.prior_tick_definition_sha256,
        "service_control_authority_sha256": (snapshot.service_control_authority_sha256),
        "tick_control_authority_sha256": snapshot.tick_control_authority_sha256,
        "generated_at": NOW - timedelta(seconds=5),
        "effect_executable": False,
        "live_authority_created": False,
        "permits_live_effect": False,
        "standing_effect": "none",
    }
    payload.update(overrides)
    plan = _signed_observation(
        SuccessfulCloseoutPlanV2,
        packet["keys"]["maintenance"],
        "maintenance.attestor",
        **payload,
    )
    manifest_payload = packet["manifest"].canonical_payload()
    manifest_payload["restoration_plan_sha256"] = plan.canonical_sha256()
    manifest = AttendedCeremonyManifestV1.model_validate(manifest_payload)
    return {**packet, "restoration": plan, "manifest": manifest}


def _frozen(packet: dict[str, Any], **overrides: Any):
    arguments = {
        "manifest": packet["manifest"],
        "founder_decision_receipt": packet["founder"],
        "authority_evaluation": packet["authority"],
        "provider_probes": packet["probes"],
        "bench_manifest": packet["bench"],
        "cost_envelope": packet["cost"],
        "trusted_founder_fingerprints": {_fingerprint(packet["keys"]["founder"])},
        "trusted_evaluator_fingerprints": {_fingerprint(packet["keys"]["evaluator"])},
        "trusted_operator_fingerprints": {_fingerprint(packet["keys"]["operator"])},
        "trusted_provider_attestor_fingerprints": {
            _fingerprint(packet["keys"]["provider"])
        },
        "now": NOW,
    }
    arguments.update(overrides)
    return verify_frozen_execution_facts(**arguments)


def _live(packet: dict[str, Any], **overrides: Any):
    arguments = {
        "manifest": packet["manifest"],
        "frozen_facts": _frozen(packet),
        "runtime_attestation": packet["runtime"],
        "service_state_snapshot": packet["snapshot"],
        "tick_exclusion_receipt": packet["tick"],
        "restoration_plan": packet["restoration"],
        "service_control_authority_receipt": packet["service_control"],
        "tick_control_authority_receipt": packet["tick_control"],
        "write_lease": packet["lease"],
        "trusted_maintenance_attestor_fingerprints": {
            _fingerprint(packet["keys"]["maintenance"])
        },
        "trusted_control_authority_fingerprints": {
            _fingerprint(packet["keys"]["control"])
        },
        "trusted_write_lease_issuer_fingerprints": {
            _fingerprint(packet["keys"]["lease"])
        },
        "now": NOW,
    }
    arguments.update(overrides)
    return validate_live_preflight_receipts(**arguments)


def _codes(result: Blocked) -> set[str]:
    return {issue.code for issue in result.blockers}


def _tampered_signature(
    value: Any, field: str = "attestation_signature"
) -> dict[str, Any]:
    raw = value.canonical_payload()
    raw[field]["signature"] = "02" * 64
    return raw


def test_genuine_frozen_facts_are_locally_sealed_and_non_authorizing() -> None:
    packet = _packet()
    result = _frozen(packet)

    assert isinstance(result, StructurallyCompleteAwaitingAuthority)
    assert readiness_is_locally_verified(result, phase="frozen_execution_facts")
    assert result.status == "StructurallyCompleteAwaitingAuthority"
    assert result.phase == "frozen_execution_facts"
    assert result.live_authority_state == "absent"
    assert result.permits_live_effect is False
    assert result.blockers == ()
    assert result.manifest_sha256 == packet["manifest"].canonical_sha256()
    assert result.canonical_bytes() == canonical_json_bytes(result.canonical_payload())
    assert "Authorized<Live>" not in result.canonical_json()


def test_cost_signature_never_claims_operator_signing_rail_approval() -> None:
    packet = _packet()
    manifest_payload = packet["manifest"].canonical_payload()
    frozen = _frozen(packet)

    assert packet["cost"].approval_signature.signature
    assert manifest_payload["operator_signing_rail_state"] == "approval_required"
    assert "operator_signing_rail_approved" not in manifest_payload
    assert "operator_signing_rail_approved" not in frozen.canonical_payload()
    assert (
        frozen.next_requirement
        == "fresh_authority_capability_and_attended_operator_rail_approval"
    )

    old_claim = copy.deepcopy(manifest_payload)
    old_claim["operator_signing_rail_approved"] = True
    with pytest.raises(ValidationError):
        AttendedCeremonyManifestV1.model_validate(old_claim)

    false_promotion = copy.deepcopy(manifest_payload)
    false_promotion["operator_signing_rail_state"] = "approved"
    with pytest.raises(ValidationError):
        AttendedCeremonyManifestV1.model_validate(false_promotion)


def test_genuine_live_preflight_is_locally_sealed_but_never_live_authority() -> None:
    packet = _packet()
    result = _live(packet)

    assert isinstance(result, StructurallyCompleteAwaitingAuthority)
    assert readiness_is_locally_verified(result, phase="live_maintenance_preflight")
    assert result.phase == "live_maintenance_preflight"
    assert (
        result.next_requirement
        == "fresh_authority_capability_and_attended_operator_rail_approval"
    )
    assert result.live_authority_state == "absent"
    assert result.permits_live_effect is False
    assert "Authorized<Live>" not in result.canonical_json()


@pytest.mark.parametrize("seat_count", [1, 8, 10])
def test_non_nine_seat_benches_are_rejected(seat_count: int) -> None:
    packet = _packet()
    raw = packet["bench"].canonical_payload()
    if seat_count <= 9:
        raw["seats"] = raw["seats"][:seat_count]
    else:
        raw["seats"] = [*raw["seats"], copy.deepcopy(raw["seats"][-1])]
    raw["roster_sha256"] = canonical_sha256(
        [seat["frozen_seat"] for seat in raw["seats"]]
    )

    with pytest.raises(ValidationError):
        FrozenBenchManifestV1.model_validate(raw)
    result = _frozen(packet, bench_manifest=raw)
    assert isinstance(result, Blocked)
    assert "bench_manifest_invalid" in _codes(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("execution_public_key", _public_key(_key("substituted-execution-key"))),
        ("requested_route", "route-substituted"),
        ("credited_cluster", "cluster-substituted"),
    ],
)
def test_frozen_seat_key_route_or_cluster_mutation_blocks(
    field: str, value: str
) -> None:
    packet = _packet()
    raw = packet["bench"].canonical_payload()
    raw["seats"][0]["frozen_seat"][field] = value
    raw["roster_sha256"] = canonical_sha256(
        [seat["frozen_seat"] for seat in raw["seats"]]
    )

    result = _frozen(packet, bench_manifest=raw)
    assert isinstance(result, Blocked)
    assert _codes(result) & {"bench_binding_mismatch", "bench_route_substitution"}


def test_noncanonical_seat_order_is_rejected_not_silently_repaired() -> None:
    packet = _packet()
    raw = packet["bench"].canonical_payload()
    raw["seats"] = list(reversed(raw["seats"]))

    with pytest.raises(ValidationError, match="canonical seat-id order"):
        FrozenBenchManifestV1.model_validate(raw)
    result = _frozen(packet, bench_manifest=raw)
    assert isinstance(result, Blocked)
    assert "bench_manifest_invalid" in _codes(result)


def test_transcript_roster_is_the_exact_nested_frozen_seat_roster() -> None:
    packet = _packet()

    assert packet["bench"].transcript_roster == tuple(
        seat.frozen_seat for seat in packet["bench"].seats
    )
    assert packet["bench"].roster_sha256 == canonical_sha256(
        [seat.canonical_payload() for seat in packet["bench"].transcript_roster]
    )


@pytest.mark.parametrize("condition", ["missing", "stale"])
def test_missing_or_stale_provider_probe_fails_closed(condition: str) -> None:
    packet = _packet()
    if condition == "missing":
        probes: tuple[ProviderProbeReceiptV1, ...] = ()
    else:
        raw = packet["probes"][0].canonical_payload()
        raw["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
        probes = (raw, *packet["probes"][1:])  # type: ignore[assignment]

    result = _frozen(packet, provider_probes=probes)
    assert isinstance(result, Blocked)
    assert _codes(result) & {
        "provider_probes_missing",
        "provider_probe_invalid",
        "provider_probe_stale",
        "provider_probe_set_mismatch",
    }


@pytest.mark.parametrize(
    "field",
    ["served_route", "served_model", "served_lineage", "served_correlation_id"],
)
def test_requested_served_substitution_is_rejected(field: str) -> None:
    packet = _packet()
    raw_probe = packet["probes"][0].canonical_payload()
    raw_probe[field] = "substituted"

    with pytest.raises(ValidationError, match="substitution"):
        ProviderProbeReceiptV1.model_validate(raw_probe)
    result = _frozen(packet, provider_probes=(raw_probe, *packet["probes"][1:]))
    assert isinstance(result, Blocked)
    assert "provider_probe_invalid" in _codes(result)


def test_probe_rejects_a_multi_route_seat_even_when_the_served_route_is_listed() -> (
    None
):
    packet = _packet()
    raw_probe = packet["probes"][0].canonical_payload()
    raw_probe["frozen_seat"]["possible_underlying_routes"].append(
        "route-unprobed-substitute"
    )

    with pytest.raises(ValidationError, match="exact frozen seat"):
        ProviderProbeReceiptV1.model_validate(raw_probe)
    result = _frozen(packet, provider_probes=(raw_probe, *packet["probes"][1:]))
    assert isinstance(result, Blocked)
    assert "provider_probe_invalid" in _codes(result)


@pytest.mark.parametrize(
    ("trust_override", "receipt_override", "expected_code"),
    [
        ({SHA_F}, None, "founder_decision_attestor_untrusted"),
        (None, "tamper", "founder_decision_signature_invalid"),
    ],
)
def test_founder_receipt_must_be_trusted_and_cryptographically_valid(
    trust_override: set[str] | None,
    receipt_override: str | None,
    expected_code: str,
) -> None:
    packet = _packet()
    overrides: dict[str, Any] = {}
    if trust_override is not None:
        overrides["trusted_founder_fingerprints"] = trust_override
    if receipt_override:
        overrides["founder_decision_receipt"] = _tampered_signature(packet["founder"])

    result = _frozen(packet, **overrides)
    assert isinstance(result, Blocked)
    assert expected_code in _codes(result)


def test_provider_receipt_must_be_trusted_and_cryptographically_valid() -> None:
    packet = _packet()
    untrusted = _frozen(packet, trusted_provider_attestor_fingerprints={SHA_F})
    assert isinstance(untrusted, Blocked)
    assert "provider_probe_attestor_untrusted" in _codes(untrusted)

    probes = list(packet["probes"])
    probes[0] = _tampered_signature(probes[0])
    tampered = _frozen(packet, provider_probes=tuple(probes))
    assert isinstance(tampered, Blocked)
    assert "provider_probe_signature_invalid" in _codes(tampered)


def test_evaluator_and_cost_approval_signatures_are_verified() -> None:
    packet = _packet()
    untrusted = _frozen(packet, trusted_evaluator_fingerprints={SHA_F})
    assert isinstance(untrusted, Blocked)
    assert "evaluator_untrusted" in _codes(untrusted)

    authority = _tampered_signature(packet["authority"], "signature")
    bad_authority = _frozen(packet, authority_evaluation=authority)
    assert isinstance(bad_authority, Blocked)
    assert "authority_signature_invalid" in _codes(bad_authority)

    cost = _tampered_signature(packet["cost"], "approval_signature")
    bad_cost = _frozen(packet, cost_envelope=cost)
    assert isinstance(bad_cost, Blocked)
    assert "cost_approval_signature_invalid" in _codes(bad_cost)


def test_aggregate_provider_balance_must_cover_each_frozen_maximum() -> None:
    packet = _packet(balance_microusd=99)
    result = _frozen(packet)

    assert isinstance(result, Blocked)
    assert "provider_balance_insufficient" in _codes(result)


@pytest.mark.parametrize("malformed", ["100", 100.0, True])
def test_money_fields_reject_scalar_type_coercion(malformed: object) -> None:
    packet = _packet()

    probe = packet["probes"][0].canonical_payload()
    probe["available_balance_microusd"] = malformed
    with pytest.raises(ValidationError):
        ProviderProbeReceiptV1.model_validate(probe)

    seat_cost = packet["cost"].seat_costs[0].canonical_payload()
    seat_cost["maximum_cost_microusd"] = malformed
    with pytest.raises(ValidationError):
        BenchSeatCostV1.model_validate(seat_cost)

    for field in ("total_maximum_cost_microusd", "spend_cap_microusd"):
        cost = packet["cost"].canonical_payload()
        cost[field] = malformed
        with pytest.raises(ValidationError):
            BenchCostEnvelopeV1.model_validate(cost)

    runtime = packet["runtime"].canonical_payload()
    runtime["bind_port"] = malformed
    with pytest.raises(ValidationError):
        MaintenanceRuntimeAttestationV1.model_validate(runtime)


@pytest.mark.parametrize(
    ("packet_overrides", "expected_code"),
    [
        (
            {"probe_probed_at": NOW - timedelta(seconds=59)},
            "provider_probe_after_bench_freeze",
        ),
        (
            {"cost_approved_at": NOW - timedelta(seconds=61)},
            "cost_approval_before_bench_freeze",
        ),
    ],
)
def test_frozen_evidence_must_precede_the_object_which_commits_to_it(
    packet_overrides: dict[str, Any],
    expected_code: str,
) -> None:
    packet = _packet(**packet_overrides)
    result = _frozen(packet)

    assert isinstance(result, Blocked)
    assert expected_code in _codes(result)


def test_cost_approval_must_precede_every_provider_probe_expiry() -> None:
    packet = _packet(
        probe_expires_at=NOW + timedelta(seconds=10),
        cost_approved_at=NOW + timedelta(seconds=10),
    )
    result = _frozen(packet)

    assert isinstance(result, Blocked)
    assert "provider_probe_expired_before_cost_approval" in _codes(result)


@pytest.mark.parametrize(
    ("receipt_name", "argument_name", "expected_code"),
    [
        ("runtime", "runtime_attestation", "maintenance_runtime_signature_invalid"),
        ("snapshot", "service_state_snapshot", "service_state_signature_invalid"),
        ("tick", "tick_exclusion_receipt", "tick_exclusion_signature_invalid"),
        ("restoration", "restoration_plan", "restoration_plan_signature_invalid"),
    ],
)
def test_maintenance_observations_require_valid_signatures(
    receipt_name: str, argument_name: str, expected_code: str
) -> None:
    packet = _packet()
    result = _live(packet, **{argument_name: _tampered_signature(packet[receipt_name])})

    assert isinstance(result, Blocked)
    assert expected_code in _codes(result)


def test_maintenance_observations_require_out_of_band_trust() -> None:
    packet = _packet()
    result = _live(packet, trusted_maintenance_attestor_fingerprints={SHA_F})

    assert isinstance(result, Blocked)
    assert {
        "maintenance_runtime_attestor_untrusted",
        "service_state_attestor_untrusted",
        "tick_exclusion_attestor_untrusted",
        "restoration_plan_attestor_untrusted",
    }.issubset(_codes(result))


@pytest.mark.parametrize(
    ("receipt_name", "argument_name", "expected_code"),
    [
        (
            "service_control",
            "service_control_authority_receipt",
            "service_control_signature_invalid",
        ),
        (
            "tick_control",
            "tick_control_authority_receipt",
            "tick_control_signature_invalid",
        ),
    ],
)
def test_control_receipts_require_valid_signatures(
    receipt_name: str, argument_name: str, expected_code: str
) -> None:
    packet = _packet()
    result = _live(packet, **{argument_name: _tampered_signature(packet[receipt_name])})

    assert isinstance(result, Blocked)
    assert expected_code in _codes(result)


def test_control_receipts_require_out_of_band_trust() -> None:
    packet = _packet()
    result = _live(packet, trusted_control_authority_fingerprints={SHA_F})

    assert isinstance(result, Blocked)
    assert {
        "service_control_attestor_untrusted",
        "tick_control_attestor_untrusted",
    }.issubset(_codes(result))


@pytest.mark.parametrize(
    ("receipt_name", "argument_name", "expected_code"),
    [
        (
            "service_control",
            "service_control_authority_receipt",
            "service_control_authority_binding_mismatch",
        ),
        (
            "tick_control",
            "tick_control_authority_receipt",
            "tick_control_authority_binding_mismatch",
        ),
    ],
)
def test_control_authority_must_equal_not_enclose_the_ceremony_window(
    receipt_name: str, argument_name: str, expected_code: str
) -> None:
    packet = _packet()
    broad = packet[receipt_name].canonical_payload()
    broad["authorized_from"] = (NOW - timedelta(seconds=31)).isoformat()
    broad["authorized_until"] = (NOW + timedelta(minutes=3, seconds=1)).isoformat()
    MaintenanceControlAuthorityReceiptV1.model_validate(broad)

    result = _live(packet, **{argument_name: broad})

    assert isinstance(result, Blocked)
    assert expected_code in _codes(result)


def test_long_lived_control_authority_is_structurally_rejected() -> None:
    packet = _packet()
    long_lived = packet["service_control"].canonical_payload()
    long_lived["expires_at"] = (NOW + timedelta(minutes=10)).isoformat()

    with pytest.raises(ValidationError, match="control authority window is invalid"):
        MaintenanceControlAuthorityReceiptV1.model_validate(long_lived)

    result = _live(packet, service_control_authority_receipt=long_lived)
    assert isinstance(result, Blocked)
    assert "service_control_authority_invalid" in _codes(result)


def test_snapshot_capture_must_be_inside_both_control_windows() -> None:
    packet = _packet()
    early = packet["snapshot"].canonical_payload()
    early["captured_at"] = (NOW - timedelta(seconds=45)).isoformat()
    ServiceStateSnapshotV1.model_validate(early)

    result = _live(packet, service_state_snapshot=early)

    assert isinstance(result, Blocked)
    assert "service_snapshot_outside_control_window" in _codes(result)


def test_tick_observation_and_exclusion_must_be_inside_tick_control_window() -> None:
    packet = _packet()
    early = packet["tick"].canonical_payload()
    early["excluded_from"] = (NOW - timedelta(seconds=45)).isoformat()
    early["observed_at"] = (NOW - timedelta(seconds=40)).isoformat()
    TickExclusionReceiptV1.model_validate(early)

    result = _live(packet, tick_exclusion_receipt=early)

    assert isinstance(result, Blocked)
    assert "tick_exclusion_outside_control_window" in _codes(result)


def test_restoration_plan_generation_must_be_inside_both_control_windows() -> None:
    packet = _packet()
    early = packet["restoration"].canonical_payload()
    early["generated_at"] = (NOW - timedelta(seconds=45)).isoformat()
    RestorationPlanV1.model_validate(early)

    result = _live(packet, restoration_plan=early)

    assert isinstance(result, Blocked)
    assert "restoration_plan_outside_control_window" in _codes(result)


def test_v1_restoration_is_historical_rollback_only() -> None:
    packet = _packet()
    plan = packet["restoration"]

    assert plan.closeout_mode == "rollback_to_pre_ceremony_state"
    assert plan.effect_executable is False
    assert plan.restore_database_sha256 == packet["snapshot"].database_sha256
    assert (
        plan.restore_lifecycle_fingerprint == packet["snapshot"].lifecycle_fingerprint
    )
    assert "closeout_mode" not in plan.canonical_payload()

    false_success = plan.canonical_payload()
    false_success["closeout_mode"] = "preserve_verified_post_effect_state"
    with pytest.raises(ValidationError):
        RestorationPlanV1.model_validate(false_success)


def test_v1_zero_lifecycle_root_remains_wire_compatible_but_drift_is_blocked() -> None:
    packet = _packet()
    payload = packet["restoration"].canonical_payload(
        exclude={
            "attestation_signature",
            "attestor_identity",
            "attestor_public_key",
            "attestor_fingerprint",
        }
    )
    payload["restore_lifecycle_fingerprint"] = "0" * 64
    historical = _signed_observation(
        RestorationPlanV1,
        packet["keys"]["maintenance"],
        "maintenance.attestor",
        **payload,
    )
    wire = historical.canonical_bytes()

    reparsed = RestorationPlanV1.model_validate_json(wire)

    assert reparsed.canonical_bytes() == wire
    manifest_payload = packet["manifest"].canonical_payload()
    manifest_payload["restoration_plan_sha256"] = historical.canonical_sha256()
    historical_packet = {
        **packet,
        "restoration": historical,
        "manifest": AttendedCeremonyManifestV1.model_validate(manifest_payload),
    }
    result = _live(historical_packet)
    assert isinstance(result, Blocked)
    assert "restoration_drift" in _codes(result)


@pytest.mark.parametrize(
    "field", ["restore_database_sha256", "restore_lifecycle_fingerprint"]
)
def test_v1_rollback_roots_must_match_the_pre_ceremony_snapshot(field: str) -> None:
    packet = _packet()
    drifted = packet["restoration"].canonical_payload()
    drifted[field] = _sha(f"drifted-{field}")

    result = _live(packet, restoration_plan=drifted)

    assert isinstance(result, Blocked)
    assert "restoration_drift" in _codes(result)


def test_successful_closeout_plan_binds_both_branches_without_authority() -> None:
    packet = _successful_closeout_plan(_packet())
    plan = packet["restoration"]
    payload = plan.canonical_payload()

    assert plan.closeout_mode == "preserve_verified_post_effect_state"
    assert plan.database_disposition == "preserve_separately_verified_post_effect_root"
    assert (
        plan.lifecycle_disposition
        == "preserve_separately_verified_post_effect_fingerprint"
    )
    assert plan.successful_effect_receipt_requirement == "required"
    assert (
        plan.post_effect_state_verification_requirement
        == "database_sha256_and_lifecycle_fingerprint_required"
    )
    assert (
        plan.success_branch_control_restore_precondition
        == "success_branch_successful_effect_receipt_and_post_effect_state_verification"
    )
    assert (
        plan.success_branch_apply_precondition
        == "success_branch_only_after_successful_effect_receipt_and_post_effect_state_verification"
    )
    assert (
        plan.failure_trigger
        == "effect_failure_or_post_effect_state_verification_failure"
    )
    assert (
        plan.failure_disposition
        == "rollback_to_captured_pre_ceremony_database_and_lifecycle_roots"
    )
    assert plan.failure_database_sha256 == packet["snapshot"].database_sha256
    assert (
        plan.failure_lifecycle_fingerprint == packet["snapshot"].lifecycle_fingerprint
    )
    assert (
        plan.failure_rollback_verification_requirement
        == "database_sha256_and_lifecycle_fingerprint_required_before_control_restore"
    )
    assert (
        plan.failure_branch_apply_precondition
        == "failure_branch_effect_failure_or_post_effect_state_verification_failure_then_verified_snapshot_rollback_before_control_restore"
    )
    assert (
        plan.success_branch_apply_precondition != plan.failure_branch_apply_precondition
    )
    assert (
        plan.control_and_runtime_completion_requirement
        == "restore_exact_prior_controls_and_stop_maintenance_runtime_on_success_or_failure"
    )
    assert plan.stop_maintenance_runtime is True
    for future_fact in (
        "successful_effect_receipt_sha256",
        "post_effect_state_verification_sha256",
        "post_effect_database_sha256",
        "post_effect_lifecycle_fingerprint",
        "effect_completed_at",
        "post_effect_state_verified_at",
    ):
        assert future_fact not in payload
    assert "restore_database_sha256" not in payload
    assert "restore_lifecycle_fingerprint" not in payload
    assert plan.effect_executable is False
    assert plan.live_authority_created is False
    assert plan.permits_live_effect is False

    result = _live(packet)

    assert isinstance(result, StructurallyCompleteAwaitingAuthority)
    assert readiness_is_locally_verified(result, phase="live_maintenance_preflight")
    assert result.live_authority_state == "absent"
    assert result.permits_live_effect is False


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("remove:closeout_mode", None),
        ("closeout_mode", "rollback_to_pre_ceremony_state"),
        ("remove:successful_effect_receipt_requirement", None),
        ("successful_effect_receipt_requirement", "optional"),
        ("remove:post_effect_state_verification_requirement", None),
        ("post_effect_state_verification_requirement", "database_only"),
        ("remove:success_branch_control_restore_precondition", None),
        ("success_branch_control_restore_precondition", "failure_rollback"),
        (
            "success_branch_control_restore_precondition",
            "successful_effect_receipt_and_post_effect_state_verification",
        ),
        ("remove:success_branch_apply_precondition", None),
        ("success_branch_apply_precondition", "effect_attempted"),
        ("success_branch_apply_precondition", True),
        ("database_disposition", "restore_pre_effect_root"),
        ("remove:failure_trigger", None),
        ("failure_trigger", "effect_failure_only"),
        ("remove:failure_disposition", None),
        ("failure_disposition", "leave_maintenance_running"),
        ("remove:failure_database_sha256", None),
        ("remove:failure_lifecycle_fingerprint", None),
        ("remove:failure_rollback_verification_requirement", None),
        ("failure_rollback_verification_requirement", "optional"),
        ("remove:failure_branch_apply_precondition", None),
        ("failure_branch_apply_precondition", "effect_failure_only"),
        ("remove:control_and_runtime_completion_requirement", None),
        ("control_and_runtime_completion_requirement", "success_only"),
        ("effect_executable", True),
        ("restore_database_sha256", SHA_A),
    ],
)
def test_successful_closeout_plan_rejects_missing_or_contradictory_requirements(
    mutation: str, value: Any
) -> None:
    packet = _successful_closeout_plan(_packet())
    raw = packet["restoration"].canonical_payload()
    if mutation.startswith("remove:"):
        raw.pop(mutation.removeprefix("remove:"))
    else:
        raw[mutation] = value

    with pytest.raises(ValidationError):
        SuccessfulCloseoutPlanV2.model_validate(raw)
    result = _live(packet, restoration_plan=raw)
    assert isinstance(result, Blocked)
    assert "restoration_plan_invalid" in _codes(result)


@pytest.mark.parametrize(
    "field",
    [
        "successful_effect_receipt_sha256",
        "post_effect_state_verification_sha256",
        "post_effect_database_sha256",
        "post_effect_lifecycle_fingerprint",
        "effect_completed_at",
        "post_effect_state_verified_at",
    ],
)
def test_successful_closeout_plan_rejects_claimed_future_evidence(field: str) -> None:
    packet = _successful_closeout_plan(_packet())
    raw = packet["restoration"].canonical_payload()
    raw[field] = NOW.isoformat() if field.endswith("_at") else SHA_A

    with pytest.raises(ValidationError):
        SuccessfulCloseoutPlanV2.model_validate(raw)
    result = _live(packet, restoration_plan=raw)
    assert isinstance(result, Blocked)
    assert "restoration_plan_invalid" in _codes(result)


@pytest.mark.parametrize(
    "field",
    [
        "control_restore_precondition",
        "apply_only_after_successful_effect_verification",
    ],
)
def test_successful_closeout_plan_rejects_old_unscoped_preconditions(
    field: str,
) -> None:
    packet = _successful_closeout_plan(_packet())
    raw = packet["restoration"].canonical_payload()
    raw[field] = (
        "successful_effect_receipt_and_post_effect_state_verification"
        if field == "control_restore_precondition"
        else True
    )

    with pytest.raises(ValidationError):
        SuccessfulCloseoutPlanV2.model_validate(raw)
    result = _live(packet, restoration_plan=raw)
    assert isinstance(result, Blocked)
    assert "restoration_plan_invalid" in _codes(result)


def test_successful_closeout_plan_follows_snapshot_tick_and_lease() -> None:
    packet = _successful_closeout_plan(
        _packet(), generated_at=NOW - timedelta(seconds=12)
    )

    result = _live(packet)

    assert isinstance(result, Blocked)
    assert "successful_closeout_plan_chronology_invalid" in _codes(result)


@pytest.mark.parametrize(
    "field", ["failure_database_sha256", "failure_lifecycle_fingerprint"]
)
def test_successful_closeout_failure_roots_bind_the_snapshot(field: str) -> None:
    packet = _successful_closeout_plan(_packet(), **{field: _sha(f"drifted-{field}")})

    result = _live(packet)

    assert isinstance(result, Blocked)
    assert "restoration_drift" in _codes(result)


@pytest.mark.parametrize(
    "field",
    [
        "restore_service_definition_sha256",
        "restore_tick_definition_sha256",
        "service_control_authority_sha256",
        "tick_control_authority_sha256",
    ],
)
def test_successful_closeout_restores_exact_prior_service_and_tick_controls(
    field: str,
) -> None:
    packet = _successful_closeout_plan(_packet(), **{field: _sha(f"drifted-{field}")})

    result = _live(packet)

    assert isinstance(result, Blocked)
    assert "restoration_drift" in _codes(result)


def test_successful_closeout_signature_is_evidence_not_execution_authority() -> None:
    packet = _successful_closeout_plan(_packet())
    tampered = _tampered_signature(packet["restoration"])

    result = _live(packet, restoration_plan=tampered)

    assert isinstance(result, Blocked)
    assert "restoration_plan_signature_invalid" in _codes(result)
    assert result.live_authority_state == "absent"
    assert result.permits_live_effect is False


def test_write_lease_is_mandatory_trusted_and_signed() -> None:
    packet = _packet()

    missing = _live(packet, write_lease=None)
    assert isinstance(missing, Blocked)
    assert "write_lease_invalid" in _codes(missing)

    untrusted = _live(packet, trusted_write_lease_issuer_fingerprints={SHA_F})
    assert isinstance(untrusted, Blocked)
    assert "write_lease_attestor_untrusted" in _codes(untrusted)

    tampered = _live(packet, write_lease=_tampered_signature(packet["lease"]))
    assert isinstance(tampered, Blocked)
    assert "write_lease_signature_invalid" in _codes(tampered)


@pytest.mark.parametrize(
    ("model_type", "receipt_name", "field"),
    [
        (FounderDecisionReceiptV1, "founder", "case_sha256"),
        (ProviderProbeReceiptV1, "probe", "response_sha256"),
        (MaintenanceRuntimeAttestationV1, "runtime", "process_evidence_sha256"),
        (MaintenanceControlAuthorityReceiptV1, "control", "attestor_fingerprint"),
        (LiveWriteLeaseEnvelopeV1, "lease", "database_sha256"),
        (AttendedCeremonyManifestV1, "manifest", "live_write_lease_sha256"),
    ],
)
def test_zero_hash_placeholders_are_rejected(
    model_type: type[Any], receipt_name: str, field: str
) -> None:
    packet = _packet()
    source = {
        "probe": packet["probes"][0],
        "control": packet["service_control"],
        **packet,
    }[receipt_name]
    raw = source.canonical_payload()
    raw[field] = "0" * 64

    with pytest.raises(ValidationError):
        model_type.model_validate(raw)


def test_direct_serialized_and_tampered_copies_of_readiness_are_unverifiable() -> None:
    packet = _packet()
    genuine = _frozen(packet)
    assert isinstance(genuine, StructurallyCompleteAwaitingAuthority)
    assert readiness_is_locally_verified(genuine, phase="frozen_execution_facts")

    direct = StructurallyCompleteAwaitingAuthority.model_validate(
        genuine.canonical_payload()
    )
    serialized = genuine.canonical_payload()
    tampered_copy = genuine.model_copy(
        update={"valid_until": NOW + timedelta(minutes=3)}
    )
    privately_resealed_copy = genuine.model_copy(
        update={
            "verified_receipt_sha256s": ("1" * 64,),
            "trust_anchor_set_sha256s": ("2" * 64,),
        }
    )
    object.__setattr__(privately_resealed_copy, "_verifier_token", object())
    object.__setattr__(
        privately_resealed_copy,
        "_sealed_payload_sha256",
        privately_resealed_copy.canonical_sha256(),
    )

    for forged in (direct, serialized, tampered_copy, privately_resealed_copy):
        result = _live(packet, frozen_facts=forged)
        assert isinstance(result, Blocked)
        assert "frozen_facts_unverifiable" in _codes(result)


def test_missing_frozen_facts_and_cross_manifest_rebind_fail_closed() -> None:
    packet = _packet()
    missing = _live(packet, frozen_facts=None)
    assert isinstance(missing, Blocked)
    assert "frozen_facts_missing" in _codes(missing)

    other_manifest = packet["manifest"].model_copy(update={"case_sha256": SHA_F})
    rebound = _live(packet, manifest=other_manifest)
    assert isinstance(rebound, Blocked)
    assert "frozen_manifest_mismatch" in _codes(rebound)


@pytest.mark.parametrize("field", ["code_commit", "openapi_sha256", "runtime_sha256"])
def test_wrong_runtime_identity_is_rejected(field: str) -> None:
    packet = _packet()
    raw = packet["runtime"].canonical_payload()
    raw[field] = "f" * (40 if field == "code_commit" else 64)

    result = _live(packet, runtime_attestation=raw)
    assert isinstance(result, Blocked)
    assert "maintenance_runtime_identity_mismatch" in _codes(result)


def test_all_zero_runtime_git_object_is_rejected_at_both_roots() -> None:
    packet = _packet()
    runtime = packet["runtime"].canonical_payload()
    runtime["code_commit"] = "0" * 40
    with pytest.raises(ValidationError, match="all-zero Git object"):
        MaintenanceRuntimeAttestationV1.model_validate(runtime)

    manifest = packet["manifest"].canonical_payload()
    manifest["expected_code_commit"] = "0" * 40
    with pytest.raises(ValidationError, match="all-zero Git object"):
        AttendedCeremonyManifestV1.model_validate(manifest)

    result = _live(packet, runtime_attestation=runtime)
    assert isinstance(result, Blocked)
    assert "maintenance_runtime_invalid" in _codes(result)


def test_restoration_plan_must_exactly_replay_captured_prior_state() -> None:
    packet = _packet()
    drifted = packet["restoration"].canonical_payload()
    drifted["restore_service_definition_sha256"] = SHA_F

    result = _live(packet, restoration_plan=drifted)
    assert isinstance(result, Blocked)
    assert "restoration_drift" in _codes(result)


def test_models_are_frozen_extra_forbid_and_canonical() -> None:
    packet = _packet()
    manifest = packet["manifest"]
    with pytest.raises(ValidationError):
        AttendedCeremonyManifestV1.model_validate(
            {**manifest.canonical_payload(), "private_key": "forbidden"}
        )
    with pytest.raises(ValidationError):
        manifest.case_id = "changed"  # type: ignore[misc]


def test_module_has_no_live_io_or_private_key_surface() -> None:
    source_path = (
        Path(__file__).resolve().parents[1] / "agora" / "sab_first_verdict_ceremony.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imported_roots.intersection(
        {"socket", "requests", "httpx", "subprocess", "sqlite3", "os", "pathlib"}
    )
    for model in (
        FounderDecisionReceiptV1,
        SignedAuthorityEvaluationEnvelopeV1,
        ProviderProbeReceiptV1,
        FrozenBenchManifestV1,
        BenchCostEnvelopeV1,
        AttendedCeremonyManifestV1,
        MaintenanceRuntimeAttestationV1,
        ServiceStateSnapshotV1,
        TickExclusionReceiptV1,
        RestorationPlanV1,
        SuccessfulCloseoutPlanV2,
        MaintenanceControlAuthorityReceiptV1,
        LiveWriteLeaseEnvelopeV1,
    ):
        assert "private_key" not in model.model_fields
        assert "secret" not in model.model_fields


def test_adversarial_input_never_changes_result_type_into_live_authority() -> None:
    packet = _packet()
    raw = copy.deepcopy(packet["manifest"].canonical_payload())
    raw["live_authority_state"] = "Authorized<Live>"
    raw["permits_live_effect"] = True

    result = _frozen(packet, manifest=raw)
    assert isinstance(result, Blocked)
    assert result.live_authority_state == "absent"
    assert result.permits_live_effect is False


def test_master_vision_signed_terms_cannot_be_reclassified_as_terminal() -> None:
    packet = _packet()
    raw = packet["manifest"].canonical_payload()
    raw["artifact_id"] = MASTER_VISION_SEED_ID

    with pytest.raises(ValidationError, match="jurisdictional refusal only"):
        AttendedCeremonyManifestV1.model_validate(raw)
