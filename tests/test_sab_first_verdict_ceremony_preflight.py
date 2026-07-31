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
    FrozenBenchManifestV1,
    FrozenBenchSeatV1,
    MaintenanceRuntimeAttestationV1,
    ProviderProbeReceiptV1,
    RestorationPlanV1,
    ServiceStateSnapshotV1,
    SignedAuthorityEvaluationEnvelopeV1,
    StructurallyCompleteAwaitingAuthority,
    TickExclusionReceiptV1,
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


def _signed_authority(
    evaluator_key: SigningKey,
    *,
    effect: str = "record_terminal_disposition",
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
        evaluator_public_key=bytes(evaluator_key.verify_key).hex(),
        evaluator_fingerprint=_fingerprint(evaluator_key),
        evaluated_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        signature=_dummy_signature(evaluator_key, signer),
    )
    message = provisional.signing_bytes()
    return SignedAuthorityEvaluationEnvelopeV1(
        **provisional.canonical_payload(exclude={"signature"}),
        signature=_signature(evaluator_key, signer, message),
    )


def _signed_cost(
    operator_key: SigningKey,
    *,
    bench: FrozenBenchManifestV1,
    probe: ProviderProbeReceiptV1,
    maximum_cost_microusd: int = 1_000,
    spend_cap_microusd: int = 1_500,
) -> BenchCostEnvelopeV1:
    signer = "operator.primary"
    provisional = BenchCostEnvelopeV1(
        cost_envelope_id="cost-1",
        ceremony_id="ceremony-1",
        bench_manifest_sha256=bench.canonical_sha256(),
        seat_costs=(
            BenchSeatCostV1(
                seat_id="seat-1",
                provider_probe_sha256=probe.canonical_sha256(),
                pricing_catalog_sha256=probe.catalog_sha256,
                maximum_cost_microusd=maximum_cost_microusd,
            ),
        ),
        total_maximum_cost_microusd=maximum_cost_microusd,
        spend_cap_microusd=spend_cap_microusd,
        approved_by=signer,
        approver_public_key=bytes(operator_key.verify_key).hex(),
        approver_fingerprint=_fingerprint(operator_key),
        approved_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        approval_signature=_dummy_signature(operator_key, signer),
    )
    message = provisional.signing_bytes()
    return BenchCostEnvelopeV1(
        **provisional.canonical_payload(exclude={"approval_signature"}),
        approval_signature=_signature(operator_key, signer, message),
    )


def _packet(*, balance_microusd: int = 5_000) -> dict[str, Any]:
    evaluator_key = SigningKey(bytes(range(32)))
    operator_key = SigningKey(bytes(reversed(range(32))))
    authority = _signed_authority(evaluator_key)
    probe = ProviderProbeReceiptV1(
        probe_id="probe-1",
        ceremony_id="ceremony-1",
        provider="provider-a",
        requested_route="route-a",
        served_route="route-a",
        requested_model="model-a",
        served_model="model-a",
        requested_lineage="lineage-a",
        served_lineage="lineage-a",
        requested_correlation_id="correlation-a",
        served_correlation_id="correlation-a",
        catalog_sha256=SHA_E,
        response_sha256=SHA_F,
        available_balance_microusd=balance_microusd,
        probed_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    seat = FrozenBenchSeatV1(
        seat_id="seat-1",
        role="jurist-1",
        provider=probe.provider,
        route=probe.requested_route,
        model=probe.requested_model,
        lineage=probe.requested_lineage,
        transport_correlation_id=probe.requested_correlation_id,
        provider_probe_sha256=probe.canonical_sha256(),
    )
    bench = FrozenBenchManifestV1(
        bench_id="bench-1",
        ceremony_id="ceremony-1",
        case_id="case-1",
        case_sha256=SHA_A,
        seats=(seat,),
        roster_sha256=canonical_sha256([seat.canonical_payload()]),
        frozen_at=NOW - timedelta(minutes=1),
    )
    cost = _signed_cost(operator_key, bench=bench, probe=probe)

    runtime = MaintenanceRuntimeAttestationV1(
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
    snapshot = ServiceStateSnapshotV1(
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
        service_control_authority_sha256=SHA_C,
        tick_control_authority_sha256=SHA_D,
        database_sha256=runtime.database_sha256,
        lifecycle_fingerprint=runtime.lifecycle_fingerprint,
        backup_sha256=SHA_F,
        backup_completed_at=NOW - timedelta(minutes=2),
        captured_at=NOW - timedelta(seconds=15),
        expires_at=NOW + timedelta(minutes=4),
    )
    tick = TickExclusionReceiptV1(
        receipt_id="tick-exclusion-1",
        ceremony_id="ceremony-1",
        tick_id=snapshot.tick_id,
        tick_definition_sha256=snapshot.prior_tick_definition_sha256,
        tick_control_authority_sha256=snapshot.tick_control_authority_sha256,
        excluded_from=NOW - timedelta(minutes=1),
        excluded_until=NOW + timedelta(minutes=6),
        ceremony_window_start=NOW - timedelta(seconds=30),
        ceremony_window_end=NOW + timedelta(minutes=5),
        last_tick_completed_at=NOW - timedelta(minutes=2),
        next_tick_not_before=NOW + timedelta(minutes=6),
        observed_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=4),
    )
    restoration = RestorationPlanV1(
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
        service_control_authority_sha256=snapshot.service_control_authority_sha256,
        tick_control_authority_sha256=snapshot.tick_control_authority_sha256,
        generated_at=NOW - timedelta(seconds=5),
    )
    manifest = AttendedCeremonyManifestV1(
        ceremony_id="ceremony-1",
        case_id="case-1",
        case_sha256=SHA_A,
        artifact_id="artifact-1",
        artifact_sha256=SHA_B,
        policy_sha256=SHA_C,
        requested_effects=("record_terminal_disposition",),
        founder_decision="alternate_artifact_terminal_disposition",
        founder_decision_receipt_sha256=SHA_F,
        authority_evaluation_sha256=authority.canonical_sha256(),
        bench_manifest_sha256=bench.canonical_sha256(),
        bench_cost_envelope_sha256=cost.canonical_sha256(),
        provider_probe_sha256s=(probe.canonical_sha256(),),
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
        service_control_authority_sha256=snapshot.service_control_authority_sha256,
        tick_control_authority_sha256=snapshot.tick_control_authority_sha256,
        operator_identity="operator.primary",
        operator_public_key=bytes(operator_key.verify_key).hex(),
        operator_fingerprint=_fingerprint(operator_key),
        frozen_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
        maintenance_window_start=NOW - timedelta(seconds=30),
        maintenance_window_end=NOW + timedelta(minutes=5),
    )
    return {
        "evaluator_key": evaluator_key,
        "operator_key": operator_key,
        "authority": authority,
        "probe": probe,
        "bench": bench,
        "cost": cost,
        "runtime": runtime,
        "snapshot": snapshot,
        "tick": tick,
        "restoration": restoration,
        "manifest": manifest,
    }


def _frozen(packet: dict[str, Any], **overrides: Any):
    arguments = {
        "manifest": packet["manifest"],
        "authority_evaluation": packet["authority"],
        "provider_probes": (packet["probe"],),
        "bench_manifest": packet["bench"],
        "cost_envelope": packet["cost"],
        "trusted_evaluator_fingerprints": {packet["authority"].evaluator_fingerprint},
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
        "now": NOW,
    }
    arguments.update(overrides)
    return validate_live_preflight_receipts(**arguments)


def _codes(result: Blocked) -> set[str]:
    return {issue.code for issue in result.blockers}


def test_frozen_facts_are_canonical_and_explicitly_non_authorizing() -> None:
    packet = _packet()
    result = _frozen(packet)

    assert isinstance(result, StructurallyCompleteAwaitingAuthority)
    assert result.status == "StructurallyCompleteAwaitingAuthority"
    assert result.phase == "frozen_execution_facts"
    assert result.live_authority_state == "absent"
    assert result.permits_live_effect is False
    assert result.blockers == ()
    assert result.manifest_sha256 == packet["manifest"].canonical_sha256()
    assert result.canonical_bytes() == canonical_json_bytes(result.canonical_payload())
    assert "Authorized<Live>" not in result.canonical_json()


def test_valid_maintenance_receipts_still_await_authority_and_human_signature() -> None:
    packet = _packet()
    result = _live(packet)

    assert isinstance(result, StructurallyCompleteAwaitingAuthority)
    assert result.phase == "live_maintenance_preflight"
    assert (
        result.next_requirement == "fresh_authority_capability_and_operator_signature"
    )
    assert result.live_authority_state == "absent"
    assert result.permits_live_effect is False


@pytest.mark.parametrize("condition", ["missing", "stale"])
def test_missing_or_stale_provider_probe_fails_closed(condition: str) -> None:
    packet = _packet()
    if condition == "missing":
        probes: tuple[ProviderProbeReceiptV1, ...] = ()
    else:
        probes = (
            packet["probe"].model_copy(
                update={
                    "probed_at": NOW - timedelta(minutes=9),
                    "expires_at": NOW - timedelta(seconds=1),
                }
            ),
        )
    result = _frozen(packet, provider_probes=probes)

    assert isinstance(result, Blocked)
    assert result.permits_live_effect is False
    assert _codes(result) & {
        "provider_probes_missing",
        "provider_probe_stale",
        "provider_probe_set_mismatch",
    }


@pytest.mark.parametrize(
    "field",
    [
        "served_route",
        "served_model",
        "served_lineage",
        "served_correlation_id",
    ],
)
def test_requested_served_substitution_is_rejected(field: str) -> None:
    packet = _packet()
    raw_probe = packet["probe"].canonical_payload()
    raw_probe[field] = "substituted"

    with pytest.raises(ValidationError, match="substitution"):
        ProviderProbeReceiptV1.model_validate(raw_probe)
    result = _frozen(packet, provider_probes=(raw_probe,))
    assert isinstance(result, Blocked)
    assert "provider_probe_invalid" in _codes(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [("costs_known", False), ("spend_cap_microusd", 999)],
)
def test_unknown_or_over_cap_cost_is_rejected(field: str, value: Any) -> None:
    packet = _packet()
    raw_cost = packet["cost"].canonical_payload()
    raw_cost[field] = value

    result = _frozen(packet, cost_envelope=raw_cost)
    assert isinstance(result, Blocked)
    assert "cost_envelope_invalid" in _codes(result)


def test_aggregate_provider_balance_must_cover_frozen_maximum() -> None:
    packet = _packet(balance_microusd=999)
    result = _frozen(packet)

    assert isinstance(result, Blocked)
    assert "provider_balance_insufficient" in _codes(result)


def test_evaluator_must_be_trusted_and_signature_must_verify() -> None:
    packet = _packet()
    untrusted = _frozen(packet, trusted_evaluator_fingerprints={SHA_F})
    assert isinstance(untrusted, Blocked)
    assert "evaluator_untrusted" in _codes(untrusted)

    tampered = packet["authority"].canonical_payload()
    tampered["signature"]["signature"] = "0" * 128
    bad_signature = _frozen(packet, authority_evaluation=tampered)
    assert isinstance(bad_signature, Blocked)
    assert "authority_signature_invalid" in _codes(bad_signature)


def test_cost_approval_signature_and_operator_rail_are_verified() -> None:
    packet = _packet()
    tampered = packet["cost"].canonical_payload()
    tampered["approval_signature"]["signature"] = "0" * 128

    result = _frozen(packet, cost_envelope=tampered)
    assert isinstance(result, Blocked)
    assert "cost_approval_signature_invalid" in _codes(result)


def test_bench_cannot_substitute_probed_route() -> None:
    packet = _packet()
    raw_bench = packet["bench"].canonical_payload()
    raw_bench["seats"][0]["route"] = "route-substituted"
    raw_bench["roster_sha256"] = canonical_sha256(raw_bench["seats"])

    result = _frozen(packet, bench_manifest=raw_bench)
    assert isinstance(result, Blocked)
    assert "bench_route_substitution" in _codes(result)


@pytest.mark.parametrize("field", ["code_commit", "openapi_sha256", "runtime_sha256"])
def test_wrong_code_openapi_or_runtime_identity_is_rejected(field: str) -> None:
    packet = _packet()
    raw_runtime = packet["runtime"].canonical_payload()
    raw_runtime[field] = "f" * (40 if field == "code_commit" else 64)

    result = _live(packet, runtime_attestation=raw_runtime)
    assert isinstance(result, Blocked)
    assert "maintenance_runtime_identity_mismatch" in _codes(result)


def test_non_loopback_bind_and_competing_writers_are_rejected() -> None:
    packet = _packet()
    public_bind = packet["runtime"].canonical_payload()
    public_bind["bind_host"] = "0.0.0.0"
    assert isinstance(_live(packet, runtime_attestation=public_bind), Blocked)

    competitors = packet["runtime"].canonical_payload()
    competitors["active_writer_ids"] = ["maintenance-writer-1", "legacy-writer"]
    result = _live(packet, runtime_attestation=competitors)
    assert isinstance(result, Blocked)
    assert "maintenance_runtime_invalid" in _codes(result)


def test_tick_overlap_is_rejected() -> None:
    packet = _packet()
    raw_tick = packet["tick"].canonical_payload()
    raw_tick["overlapping_tick_ids"] = ["tick-run-overlap"]

    result = _live(packet, tick_exclusion_receipt=raw_tick)
    assert isinstance(result, Blocked)
    assert "tick_exclusion_invalid" in _codes(result)


def test_missing_prior_state_has_specific_fail_closed_blocker() -> None:
    packet = _packet()
    raw_snapshot = packet["snapshot"].canonical_payload()
    del raw_snapshot["prior_service_state"]
    del raw_snapshot["prior_tick_state"]

    result = _live(packet, service_state_snapshot=raw_snapshot)
    assert isinstance(result, Blocked)
    assert {"prior_state_missing", "service_state_invalid"}.issubset(_codes(result))


def test_restoration_plan_must_exactly_replay_captured_prior_state() -> None:
    packet = _packet()
    drifted = packet["restoration"].canonical_payload()
    drifted["restore_service_definition_sha256"] = SHA_F

    result = _live(packet, restoration_plan=drifted)
    assert isinstance(result, Blocked)
    assert "restoration_drift" in _codes(result)


def test_frozen_facts_receipt_is_mandatory_and_cannot_be_rebound() -> None:
    packet = _packet()
    missing = _live(packet, frozen_facts=None)
    assert isinstance(missing, Blocked)
    assert "frozen_facts_missing" in _codes(missing)

    other_manifest = packet["manifest"].model_copy(update={"case_sha256": SHA_F})
    rebound = _live(packet, manifest=other_manifest)
    assert isinstance(rebound, Blocked)
    assert "frozen_manifest_mismatch" in _codes(rebound)


def test_models_are_frozen_extra_forbid_and_canonicalize_set_like_fields() -> None:
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
        SignedAuthorityEvaluationEnvelopeV1,
        ProviderProbeReceiptV1,
        FrozenBenchManifestV1,
        BenchCostEnvelopeV1,
        AttendedCeremonyManifestV1,
        MaintenanceRuntimeAttestationV1,
        ServiceStateSnapshotV1,
        TickExclusionReceiptV1,
        RestorationPlanV1,
    ):
        assert "private_key" not in model.model_fields
        assert "secret" not in model.model_fields


def test_adversarial_input_never_changes_the_result_type_into_live_authority() -> None:
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
