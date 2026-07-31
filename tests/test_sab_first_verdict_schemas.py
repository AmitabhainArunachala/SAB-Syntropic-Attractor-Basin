from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agora.sab_artifact_verdict import (
    AllowedOperationV1,
    ArtifactBallotV1,
    ArtifactCaseV1,
    CompostBatchPreviewV1,
    ContractSignatureV1,
    CouncilVerdictV1,
    DISPOSITION_AUTHORITY_ADAPTER,
    FirstVerdictRunReceiptV1,
    FrozenSeatV1,
    OperatorCountersignV1,
    RehearsalDispositionV1,
    SCHEMA_EXPORTS,
    SeedSupersessionV1,
    SessionWriteLeaseV1,
    allowed_operations_digest,
    canonical_json,
    canonical_sha256,
    exported_json_schemas,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "nodes" / "schemas"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "sab_first_verdict"
NOW = datetime(2026, 7, 27, 15, 0, tzinfo=timezone.utc)
H = "a" * 64
H2 = "b" * 64
CODE_SHA = "c" * 40
PUBLIC_KEY = "11" * 32


def signature(seed: str = "d") -> dict[str, Any]:
    return {
        "alg": "ed25519",
        "signer": "fixture:test-issuer",
        "public_key": PUBLIC_KEY,
        "signature": seed * 128,
        "signed_payload_sha256": H,
        "canonicalization": "json-sort-keys-compact-v1",
    }


def evidence(index: int = 0) -> dict[str, Any]:
    return {
        "ref": f"fixture:evidence:{index}",
        "content_sha256": f"{index % 16:x}" * 64,
        "proof_class": "signed_fixture",
    }


def operation() -> dict[str, str]:
    return {"method": "POST", "path": "/api/v1/artifact-cases"}


def authorized_copy() -> dict[str, Any]:
    return {
        "schema": "sab.disposition_authority.v1",
        "evaluation_id": "sab_authority_fixture_copy",
        "artifact_id": "sab_seed_fixture_first_verdict",
        "result": "Authorized",
        "scope": "Copy",
        "authority_refs": ["fixture:signed-policy"],
        "allowed_effects": ["challenge:resolve", "seed:supersede"],
        "forbidden_effects": [],
        "policy_sha256": H,
        "content_sha256": H2,
        "evaluated_state_hash": H,
        "reason_codes": ["signed_policy_authorizes_exact_scope_and_effects"],
        "live_eligible": False,
        "standing_effect": "none",
    }


def authorized_live() -> dict[str, Any]:
    payload = authorized_copy()
    payload.update(
        evaluation_id="sab_authority_fixture_live",
        scope="Live",
        live_eligible=True,
    )
    return payload


def frozen_seat(index: int) -> dict[str, Any]:
    return {
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
        "model_lineage_evidence_refs": [evidence(index)],
        "possible_underlying_routes": [f"fixture/route/{index}"],
        "transport_correlation_refs": [],
        "correlation_smeared": False,
        "execution_public_key": PUBLIC_KEY,
        "key_role": "operator_controlled_execution_attestation",
        "common_operator_backing": "single disclosed fixture operator",
        "liveness_receipt_sha256": f"{(index + 1) % 16:x}" * 64,
    }


def case_payload() -> dict[str, Any]:
    roster = [frozen_seat(index) for index in range(9)]
    canonical_roster = [
        FrozenSeatV1.model_validate(seat).canonical_payload() for seat in roster
    ]
    artifact = b'{"signed":"fixture artifact"}'
    return {
        "schema": "sab.artifact_case.v1",
        "case_id": "sab_case_fixture_first_verdict",
        "target_seed_id": "sab_seed_fixture_first_verdict",
        "target_seed_packet_sha256": H,
        "expected_seed_state": "challenged",
        "expected_case_head": H2,
        "challenges": [
            {
                "challenge_id": "sab_challenge_fixture",
                "challenge_packet_sha256": H2,
                "status": "pending",
            }
        ],
        "evidence_refs": [evidence()],
        "docket_rule": {
            "version": "sab-first-verdict-v1",
            "rule_sha256": H,
            "signed_conditions_satisfied": True,
            "challenge_resolution_authorized": True,
            "jurisdiction_established": True,
        },
        "canon_conditions": ["fixture condition"],
        "compost_conditions": ["fixture condition"],
        "anti_capture_rules": ["same operator never counts as independent"],
        "independence_disclosure": "Synthetic same-operator fixture only.",
        "demanded_correction": "Correct the named fixture defect.",
        "amendment_clause": "Any weakening forces appeal.",
        "conflict_flags": {
            "clerk_is_case_author": False,
            "clerk_is_challenger": False,
            "author_is_challenger": False,
        },
        "signed_artifact_b64": base64.b64encode(artifact).decode("ascii"),
        "signed_artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "frozen_roster": roster,
        "frozen_roster_sha256": canonical_sha256(canonical_roster),
        "single_operator_adjudicated": True,
        "clerk_identity": "fixture:clerk",
        "lease_id": "sab_lease_fixture",
        "frozen_at": "2026-07-27T15:00:00Z",
        "clerk_signature": signature(),
    }


def ballot_payload() -> dict[str, Any]:
    return {
        "schema": "sab.artifact_ballot.v1",
        "ballot_id": "sab_ballot_fixture_seat_1",
        "case_id": "sab_case_fixture_first_verdict",
        "case_sha256": H,
        "seat_id": "seat-1",
        "round_no": 1,
        "stage": "final",
        "decision": "correct_and_supersede",
        "ballot_source": "fixture_model",
        "claim_findings": [
            {
                "claim_ref": "fixture:claim:1",
                "finding": "supported",
                "rationale": "Fixture evidence supports this bounded claim.",
                "evidence_refs": [evidence(1)],
            }
        ],
        "self_binding_weakening_finding": {
            "weakens_self_binding_constraint": False,
            "affected_constraints": [],
            "evidence_refs": [evidence(2)],
            "explanation": "No self-binding constraint is weakened.",
        },
        "strongest_case_against_decision": "The fixture could be under-specified.",
        "unresolved_objections": [],
        "raw_model_output_sha256": H,
        "transcript_ref": evidence(3),
        "requested_model": "fixture-model",
        "requested_route": "fixture/requested",
        "served_provider": "fixture-provider",
        "served_model": "fixture-model",
        "served_route": "fixture/served",
        "credited_cluster": "fixture-base-lineage",
        "cluster_basis": "evidenced_base_model_or_training_lineage",
        "model_lineage_evidence_refs": [evidence(4)],
        "transport_correlation_refs": [],
        "correlation_smeared": False,
        "signature_role": "operator_controlled_execution_attestation",
        "vendor_signature_claimed": False,
        "execution_signature": signature("e"),
    }


def verdict_payload() -> dict[str, Any]:
    return {
        "schema": "sab.council_verdict.v1",
        "verdict_id": "sab_verdict_fixture",
        "case_id": "sab_case_fixture_first_verdict",
        "case_sha256": H,
        "round_no": 1,
        "decision": "correct_and_supersede",
        "raw_tally": {"correct_and_supersede": 9},
        "clean_routing_tally": {"correct_and_supersede": 9},
        "credited_clusters_by_result": {
            "correct_and_supersede": [f"lineage-{index}" for index in range(9)]
        },
        "smeared_seats": [],
        "correlation_removal_result": "stable",
        "terminality": "terminal",
        "appeal_reasons": [],
        "ballot_sources": ["fixture_model"],
        "evidence_provenance": "fixture_models",
        "requested_effects": ["challenge:resolve", "seed:supersede"],
        "authority_digest": H,
        "scope": "Copy",
        "operator_independence": "single_operator_bootstrap",
        "effect_domain": "artifact",
        "standing_effect": "none",
        "compiled_at": "2026-07-27T15:00:00Z",
    }


def lease_payload() -> dict[str, Any]:
    op = AllowedOperationV1.model_validate(operation())
    pk_fingerprint = hashlib.sha256(bytes.fromhex(PUBLIC_KEY)).hexdigest()
    fields: dict[str, Any] = {
        "schema_": "sab.session_write_lease.v1",
        "lease_id": "sab_lease_fixture",
        "session_id": "sab_session_fixture",
        "clerk_identity": "fixture:clerk",
        "allowed_operations": (op,),
        "allowed_operations_sha256": allowed_operations_digest((op,)),
        "accepted_code_sha": CODE_SHA,
        "expected_lifecycle_fingerprint": H,
        "source_backup_sha256": H2,
        "issuer_identity": "fixture:test-issuer",
        "issuer_public_key": PUBLIC_KEY,
        "issuer_fingerprint": pk_fingerprint,
        "authority_basis": "founder_bootstrap_self_declared",
        "scope": "Copy",
        "issued_at": NOW,
        "activated_at": NOW,
        "expires_at": datetime(2026, 7, 27, 16, 0, tzinfo=timezone.utc),
        "lease_sha256": H,
        "signature": ContractSignatureV1.model_validate(signature()),
        "standing_effect": "none",
        "live_eligible": False,
    }
    draft = SessionWriteLeaseV1.model_construct(**fields)
    fields["lease_sha256"] = draft.canonical_sha256(
        exclude={"lease_sha256", "signature"}
    )
    return SessionWriteLeaseV1.model_validate(fields).canonical_payload()


def countersign_payload() -> dict[str, Any]:
    effect = {"challenge": "resolve", "seed": "supersede"}
    ops = [operation()]
    return {
        "schema": "sab.operator_countersign.v1",
        "countersign_id": "sab_countersign_fixture",
        "verdict_id": "sab_verdict_fixture",
        "verdict_sha256": H,
        "case_id": "sab_case_fixture_first_verdict",
        "case_sha256": H,
        "target_seed_id": "sab_seed_fixture_first_verdict",
        "decision": "correct_and_supersede",
        "expected_seed_state": "challenged",
        "expected_case_head": H,
        "expected_lifecycle_fingerprint": H2,
        "effect_payload": effect,
        "effect_payload_sha256": canonical_sha256(effect),
        "successor_envelope_sha256": H2,
        "write_lease_id": "sab_lease_fixture",
        "lease_sha256": H,
        "authority_digest": H2,
        "allowed_operations": ops,
        "allowed_operations_sha256": allowed_operations_digest(ops),
        "code_sha": CODE_SHA,
        "scope": "Copy",
        "signer_kind": "fixture_ephemeral",
        "created_at": "2026-07-27T15:00:00Z",
        "expires_at": "2026-07-27T16:00:00Z",
        "signature": signature("f"),
        "standing_effect": "none",
        "live_eligible": False,
    }


def rehearsal_payload() -> dict[str, Any]:
    return {
        "schema": "sab.rehearsal_disposition.v1",
        "disposition_id": "sab_rehearsal_fixture",
        "verdict_id": "sab_verdict_fixture",
        "verdict_sha256": H,
        "case_id": "sab_case_fixture_first_verdict",
        "case_sha256": H,
        "authority": authorized_copy(),
        "countersign_id": "sab_countersign_fixture",
        "countersign_sha256": H,
        "effects": ["challenge:resolve", "seed:supersede"],
        "ballot_source": "fixture_model",
        "evidence_provenance": "fixture_models",
        "scope": "Copy",
        "proof_class": "copied_live_db_rehearsal",
        "source_fixture_id": "fixture:first-verdict",
        "copied_database_id": "copy:sha256:fixture",
        "before_state_hash": H,
        "after_state_hash": H2,
        "applied_at": "2026-07-27T15:00:00Z",
        "standing_effect": "none",
        "live_eligible": False,
    }


def effective_payload() -> dict[str, Any]:
    return {
        "schema": "sab.effective_verdict.v1",
        "effective_verdict_id": "sab_effective_fixture",
        "verdict_id": "sab_verdict_fixture",
        "verdict_sha256": H,
        "authority": authorized_live(),
        "effects": ["challenge:resolve"],
        "evidence_provenance": "real_external_models",
        "scope": "Live",
        "fixture_derived": False,
        "applied_at": "2026-07-27T15:00:00Z",
        "standing_effect": "none",
    }


def supersession_payload() -> dict[str, Any]:
    return {
        "schema": "sab.seed_supersession.v1",
        "predecessor_seed_id": "sab_seed_fixture_v1",
        "predecessor_packet_sha256": H,
        "successor_seed_id": "sab_seed_fixture_v2",
        "successor_packet_sha256": H2,
        "correction_summary": "The successor corrects the synthetic defect.",
        "correction_artifact_sha256": H,
        "relation": "superseded_by_correction",
        "claimant_identity": "fixture:claimant",
        "authority_lease_id": "sab_lease_fixture",
        "scope": "Copy",
        "created_at": "2026-07-27T15:00:00Z",
        "claimant_signature": signature(),
        "standing_effect": "none",
        "live_eligible": False,
    }


def preview_payload() -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for index in range(67):
        eligible = index < 61
        actor = "Hermes" if index < 59 else "Dharma-cron" if index < 61 else "other"
        records.append(
            {
                "record_id": f"seed-{index:02d}",
                "actor_slot": actor,
                "eligible": eligible,
                "evidence_refs": [evidence(index)],
                "exclusion_reason": None
                if eligible
                else "not a selected language-womb wrapper",
                "row_sha256": f"{index % 16:x}" * 64,
            }
        )
    return {
        "schema": "sab.compost_batch_preview.v1",
        "preview_id": "sab_preview_fixture",
        "scanned_count": 67,
        "hermes_count": 59,
        "dharma_cron_count": 2,
        "selected_count": 61,
        "excluded_count": 6,
        "actor_slot_parameterized": True,
        "records": records,
        "before_database_sha256": H,
        "after_database_sha256": H,
        "before_lifecycle_fingerprint": H2,
        "after_lifecycle_fingerprint": H2,
        "before_head_sha256": H,
        "after_head_sha256": H,
        "before_file_mtime_ns": 123456,
        "after_file_mtime_ns": 123456,
        "execution_supported": False,
        "mutation_count": 0,
    }


def run_receipt_payload() -> dict[str, Any]:
    artifacts = {
        name: {"id": f"sab_{name}_fixture", "sha256": H}
        for name in (
            "case",
            "lease",
            "verdict",
            "countersign",
            "disposition",
            "lineage",
        )
    }
    boundaries = ["case_insert", "verdict_insert"]
    return {
        "schema_version": "sab.first_verdict_run_receipt.v1",
        "run_id": "sab_build_a_fixture_run",
        "created_at": "2026-07-27T15:00:00Z",
        "proof_class": "copied_live_db_rehearsal",
        "accepted_base": {
            "integration_sha": CODE_SHA,
            "integration_tree": "d" * 40,
            "current_head": CODE_SHA,
            "current_tree": "e" * 40,
        },
        "authority": {
            "result": "AuthorizedCopyOnly",
            "scope": "Copy",
            "authority_digest": H,
            "allowed_effects": ["challenge:resolve", "seed:supersede"],
            "evaluated_state_hash": H2,
            "refs": ["fixture:signed-policy"],
        },
        "source_db": {
            "path_ref": f"private-local:sha256:{H}",
            "sha256": H,
            "integrity": "ok",
            "lifecycle_fingerprint": H,
        },
        "copy_db": {
            "path_ref": f"private-local:sha256:{H2}",
            "sha256": H2,
            "integrity": "ok",
            "lifecycle_fingerprint": H,
        },
        "artifacts": artifacts,
        "transaction": {
            "idempotency_key": "fixture-idempotency-key",
            "request_sha256": H,
            "response_sha256": H2,
            "boundaries": boundaries,
            "injected_failure_matrix": [
                {
                    "boundary": boundary,
                    "injected": True,
                    "rolled_back": True,
                    "state_sha256": H,
                }
                for boundary in boundaries
            ],
        },
        "invariant_table_digests": [
            {
                "table": "sab_standing_v1",
                "columns": ["standing_id", "subject_id"],
                "before_sha256": H,
                "after_sha256": H,
                "unchanged": True,
            }
        ],
        "signed_events": [
            {
                "event_id": "sab_event_fixture",
                "event_hash": H,
                "public_key": PUBLIC_KEY,
                "signature_verified": True,
                "replay_result": "SignaturesVerified",
            }
        ],
        "preview": {
            "scanned": 67,
            "eligible": 61,
            "hermes": 59,
            "dharma_cron": 2,
            "membership_sha256": H,
            "evidence_refs_sha256": H2,
            "no_write": True,
        },
        "checkpoint_chain": {"head": H, "count": 9, "valid": True},
        "mutation_counters": {
            "live_db": 0,
            "services": 0,
            "providers": 0,
            "external": 0,
            "source_checkout": 0,
            "fixture_or_copy_db": 1,
        },
        "tests": [
            {
                "command": "python -m pytest -q",
                "exit_code": 0,
                "stdout_sha256": H,
                "proof_class": "local_offline_test",
            }
        ],
        "blockers": [],
        "terminal_claim": {
            "engineering_status": "proven_on_copy",
            "historic_live_win": False,
            "live_mutations": 0,
            "service_mutations": 0,
            "provider_calls": 0,
            "external_actions": 0,
            "standing_effect": "none",
            "master_vision_effect": "none",
            "build_b": "not_run_authority_unresolved",
        },
    }


MODEL_FIXTURES: dict[str, tuple[Any, Any]] = {
    "sab.disposition_authority.v1.schema.json": (
        DISPOSITION_AUTHORITY_ADAPTER,
        authorized_copy,
    ),
    "sab.session_write_lease.v1.schema.json": (SessionWriteLeaseV1, lease_payload),
    "sab.artifact_case.v1.schema.json": (ArtifactCaseV1, case_payload),
    "sab.artifact_ballot.v1.schema.json": (ArtifactBallotV1, ballot_payload),
    "sab.council_verdict.v1.schema.json": (CouncilVerdictV1, verdict_payload),
    "sab.operator_countersign.v1.schema.json": (
        OperatorCountersignV1,
        countersign_payload,
    ),
    "sab.rehearsal_disposition.v1.schema.json": (
        RehearsalDispositionV1,
        rehearsal_payload,
    ),
    "sab.seed_supersession.v1.schema.json": (SeedSupersessionV1, supersession_payload),
    "sab.compost_batch_preview.v1.schema.json": (
        CompostBatchPreviewV1,
        preview_payload,
    ),
    "sab.first_verdict_run_receipt.v1.schema.json": (
        FirstVerdictRunReceiptV1,
        run_receipt_payload,
    ),
}


def _validate(adapter_or_model: Any, payload: dict[str, Any]) -> Any:
    if adapter_or_model is DISPOSITION_AUTHORITY_ADAPTER:
        return adapter_or_model.validate_python(payload)
    return adapter_or_model.model_validate(payload)


def write_fixture_corpus() -> None:
    """Materialize deterministic valid/invalid instances for every schema."""

    (FIXTURE_ROOT / "valid").mkdir(parents=True, exist_ok=True)
    (FIXTURE_ROOT / "invalid").mkdir(parents=True, exist_ok=True)
    for schema_name, (_, factory) in MODEL_FIXTURES.items():
        stem = schema_name.removesuffix(".schema.json")
        valid = factory()
        invalid = copy.deepcopy(valid)
        invalid["unexpected_authority_escalation"] = True
        (FIXTURE_ROOT / "valid" / f"{stem}.json").write_text(
            json.dumps(valid, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (FIXTURE_ROOT / "invalid" / f"{stem}.json").write_text(
            json.dumps(invalid, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


@pytest.mark.parametrize("schema_name", sorted(MODEL_FIXTURES))
def test_valid_and_invalid_fixtures_match_strict_pydantic(schema_name: str) -> None:
    adapter_or_model, _ = MODEL_FIXTURES[schema_name]
    stem = schema_name.removesuffix(".schema.json")
    valid = json.loads((FIXTURE_ROOT / "valid" / f"{stem}.json").read_text())
    invalid = json.loads((FIXTURE_ROOT / "invalid" / f"{stem}.json").read_text())
    _validate(adapter_or_model, valid)
    with pytest.raises(ValidationError):
        _validate(adapter_or_model, invalid)


def test_checked_in_schemas_are_exact_pydantic_exports() -> None:
    generated = exported_json_schemas()
    assert set(generated) == set(SCHEMA_EXPORTS)
    for filename, expected in generated.items():
        actual = json.loads((SCHEMA_ROOT / filename).read_text())
        assert canonical_json(actual) == canonical_json(expected), filename
        assert actual["$schema"] == "https://json-schema.org/draft/2020-12/schema"


@pytest.mark.parametrize("schema_name", sorted(MODEL_FIXTURES))
def test_system_jsonschema_cli_agrees_with_fixture_corpus(schema_name: str) -> None:
    cli = shutil.which("jsonschema")
    if cli is None:
        pytest.skip("optional jsonschema CLI unavailable")
    stem = schema_name.removesuffix(".schema.json")
    schema_path = SCHEMA_ROOT / schema_name
    valid_path = FIXTURE_ROOT / "valid" / f"{stem}.json"
    invalid_path = FIXTURE_ROOT / "invalid" / f"{stem}.json"
    valid = subprocess.run(
        [cli, "-i", str(valid_path), str(schema_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert valid.returncode == 0, valid.stderr
    invalid = subprocess.run(
        [cli, "-i", str(invalid_path), str(schema_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert invalid.returncode != 0


def test_canonical_json_is_stable_and_strict() -> None:
    first = ArtifactBallotV1.model_validate(ballot_payload())
    reordered = dict(reversed(list(ballot_payload().items())))
    second = ArtifactBallotV1.model_validate(reordered)
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.canonical_sha256() == second.canonical_sha256()
    with pytest.raises(ValidationError):
        ArtifactBallotV1.model_validate({**ballot_payload(), "extra": "forbidden"})


def test_case_binds_exact_signed_bytes_and_nine_seat_roster() -> None:
    valid = case_payload()
    ArtifactCaseV1.model_validate(valid)
    corrupted = copy.deepcopy(valid)
    corrupted["signed_artifact_b64"] = base64.b64encode(b"different").decode("ascii")
    with pytest.raises(ValidationError, match="signed artifact hash mismatch"):
        ArtifactCaseV1.model_validate(corrupted)
    short_roster = copy.deepcopy(valid)
    short_roster["frozen_roster"].pop()
    with pytest.raises(ValidationError):
        ArtifactCaseV1.model_validate(short_roster)


def test_ballot_requires_source_self_binding_finding_and_round_one() -> None:
    valid = ballot_payload()
    ArtifactBallotV1.model_validate(valid)
    for missing in ("ballot_source", "self_binding_weakening_finding"):
        invalid = copy.deepcopy(valid)
        invalid.pop(missing)
        with pytest.raises(ValidationError):
            ArtifactBallotV1.model_validate(invalid)
    invalid_round = copy.deepcopy(valid)
    invalid_round["round_no"] = 2
    with pytest.raises(ValidationError):
        ArtifactBallotV1.model_validate(invalid_round)
    for repaired_round in ("1", 1.0, True):
        coerced_round = copy.deepcopy(valid)
        coerced_round["round_no"] = repaired_round
        with pytest.raises(ValidationError, match="exact integer"):
            ArtifactBallotV1.model_validate(coerced_round)


@pytest.mark.parametrize("malformed", ["1", 1.0, True])
def test_verdict_round_rejects_scalar_repair(malformed: object) -> None:
    valid = verdict_payload()
    invalid_round = copy.deepcopy(valid)
    invalid_round["round_no"] = malformed
    with pytest.raises(ValidationError, match="exact integer"):
        CouncilVerdictV1.model_validate(invalid_round)


@pytest.mark.parametrize("malformed", ["9", 9.0, True, -1])
def test_verdict_tallies_reject_scalar_repair_or_negative_counts(
    malformed: object,
) -> None:
    valid = verdict_payload()
    for field in ("raw_tally", "clean_routing_tally"):
        invalid_tally = copy.deepcopy(valid)
        first_key = next(iter(invalid_tally[field]))
        invalid_tally[field][first_key] = malformed
        with pytest.raises(ValidationError):
            CouncilVerdictV1.model_validate(invalid_tally)


def test_appeal_ends_round_one_without_effect() -> None:
    appeal = verdict_payload()
    appeal.update(
        decision="appeal_required",
        terminality="appeal_required",
        appeal_reasons=["correlation removal changed terminality"],
        requested_effects=[],
    )
    CouncilVerdictV1.model_validate(appeal)
    appeal["requested_effects"] = ["seed:supersede"]
    with pytest.raises(ValidationError, match="cannot request effects"):
        CouncilVerdictV1.model_validate(appeal)


def test_cluster_is_lineage_based_and_transport_correlation_forces_smear() -> None:
    invalid = ballot_payload()
    invalid["transport_correlation_refs"] = ["shared-transport:gateway"]
    invalid["correlation_smeared"] = False
    with pytest.raises(ValidationError, match="smear"):
        ArtifactBallotV1.model_validate(invalid)
    invalid_basis = ballot_payload()
    invalid_basis["cluster_basis"] = "transport"
    with pytest.raises(ValidationError):
        ArtifactBallotV1.model_validate(invalid_basis)


def test_countersign_hashes_effect_and_exact_allowlist() -> None:
    valid = countersign_payload()
    OperatorCountersignV1.model_validate(valid)
    invalid_effect = copy.deepcopy(valid)
    invalid_effect["effect_payload"]["seed"] = "canon"
    with pytest.raises(ValidationError, match="effect_payload_sha256"):
        OperatorCountersignV1.model_validate(invalid_effect)
    wildcard = copy.deepcopy(valid)
    wildcard["allowed_operations"] = [{"method": "POST", "path": "/api/v1/*"}]
    with pytest.raises(ValidationError):
        OperatorCountersignV1.model_validate(wildcard)


def test_preview_contract_proves_exact_59_plus_2_and_no_write() -> None:
    valid = preview_payload()
    CompostBatchPreviewV1.model_validate(valid)
    changed = copy.deepcopy(valid)
    changed["after_lifecycle_fingerprint"] = "f" * 64
    with pytest.raises(ValidationError, match="lifecycle fingerprint"):
        CompostBatchPreviewV1.model_validate(changed)
    wrong_actor = copy.deepcopy(valid)
    wrong_actor["records"][58]["actor_slot"] = "Dharma-cron"
    with pytest.raises(ValidationError, match="59 Hermes"):
        CompostBatchPreviewV1.model_validate(wrong_actor)


if __name__ == "__main__":
    write_fixture_corpus()
