from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from pydantic import ValidationError

from agora.sab_artifact_verdict import (
    ArtifactBallotV1,
    FrozenSeatV1,
    SignedDispositionPolicyV1,
    TrustedPolicyIssuerV1,
    canonical_json_bytes,
    canonical_sha256,
    evaluate_disposition_authority,
)
from agora.sab_first_verdict_compiler import (
    AppealReceiptV1,
    CompiledVerdictV1,
    CouncilCompilationError,
    CouncilTerminalityRuleV1,
    PreUnsealSeatV1,
    RefusalReceiptV1,
    assess_pre_unseal_feasibility,
    compile_council_outcome,
    compute_council_terminality_rule_sha256,
    verify_compiled_outcome,
)

NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
CASE_ID = "sab_case_build_b_synthetic"
CASE_SHA256 = "a" * 64
STATE_SHA256 = "b" * 64
EFFECTS = ("challenge:resolve", "seed:supersede")
SEATS = tuple(f"seat-{index}" for index in range(9))
BALLOT_KEYS = tuple(SigningKey.generate() for _ in range(9))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _contract_signature(
    key: SigningKey, message: bytes, *, signer: str
) -> dict[str, str]:
    return {
        "alg": "ed25519",
        "signer": signer,
        "public_key": key.verify_key.encode(encoder=HexEncoder).decode(),
        "signature": key.sign(message).signature.hex(),
        "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
        "canonicalization": "json-sort-keys-compact-v1",
    }


def _evaluated_authority(
    mode: str = "authorized",
    *,
    effects: tuple[str, ...] = EFFECTS,
):
    if mode == "no_jurisdiction":
        return evaluate_disposition_authority(
            artifact_id="sab_seed_build_b_synthetic",
            artifact_sha256=CASE_SHA256,
            requested_scope="Copy",
            requested_effects=effects,
            evaluated_state_hash=STATE_SHA256,
            signed_policy=None,
            now=NOW,
        )

    key = SigningKey(b"\x17" * 32)
    signer = "fixture:build-b-policy-issuer"
    source_fixture_id = "fixture:build-b-compiler"
    copied_database_id = "copy:build-b-compiler"
    body: dict[str, Any] = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": f"sab_policy_build_b_{mode}",
        "artifact_id": "sab_seed_build_b_synthetic",
        "artifact_sha256": CASE_SHA256,
        "disposition_mode": mode,
        "scope": "Copy",
        "permitted_effects": sorted(effects) if mode == "authorized" else [],
        "forbidden_effects": sorted(effects) if mode == "advisory_only" else [],
        "preconditions": ["challenge_state=pending", "seed_state=challenged"],
        "evaluated_state_hash": STATE_SHA256,
        "source_fixture_id": source_fixture_id,
        "copied_database_id": copied_database_id,
        "test_issuer": True,
        "live_eligible": False,
        "standing_effect": "none",
        "authority_refs": ["fixture:signed-build-b-policy"],
        "issued_at": (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "issuer": signer,
    }
    unsigned = {**body, "policy_sha256": canonical_sha256(body)}
    policy = SignedDispositionPolicyV1.model_validate(
        {
            **unsigned,
            "signature": _contract_signature(
                key,
                canonical_json_bytes(unsigned),
                signer=signer,
            ),
        }
    )
    trusted = TrustedPolicyIssuerV1(
        issuer_identity=signer,
        issuer_public_key=key.verify_key.encode(encoder=HexEncoder).decode(),
        source_fixture_id=source_fixture_id,
        copied_database_id=copied_database_id,
        authority_basis="founder_bootstrap_self_declared",
    )
    return evaluate_disposition_authority(
        artifact_id="sab_seed_build_b_synthetic",
        artifact_sha256=CASE_SHA256,
        requested_scope="Copy",
        requested_effects=() if mode == "advisory_only" else effects,
        evaluated_state_hash=STATE_SHA256,
        signed_policy=policy,
        trusted_policy_issuer=trusted,
        now=NOW,
    )


def _rule(
    *,
    minimum_raw_votes: int = 5,
    minimum_clean_clusters: int = 5,
) -> CouncilTerminalityRuleV1:
    body = {
        "schema": "sab.council_terminality_rule.v1",
        "rule_id": (
            f"fixture:rule:{minimum_raw_votes}-of-9:{minimum_clean_clusters}-clusters"
        ),
        "council_size": 9,
        "minimum_raw_votes": minimum_raw_votes,
        "minimum_clean_clusters": minimum_clean_clusters,
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


def _evidence(index: int) -> dict[str, str]:
    return {
        "ref": f"fixture:evidence:{index}",
        "content_sha256": _digest(f"evidence:{index}"),
        "proof_class": "signed_fixture",
    }


def _ballot(
    index: int,
    decision: str,
    *,
    cluster: str | None = None,
    smeared: bool = False,
    stage: str = "final",
    seat_id: str | None = None,
    ballot_id: str | None = None,
    signature_fault: str | None = None,
) -> ArtifactBallotV1:
    actual_seat_id = seat_id or f"seat-{index}"
    payload: dict[str, Any] = {
        "schema": "sab.artifact_ballot.v1",
        "ballot_id": ballot_id or f"sab_ballot_build_b_{index}",
        "case_id": CASE_ID,
        "case_sha256": CASE_SHA256,
        "seat_id": actual_seat_id,
        "round_no": 1,
        "stage": stage,
        "decision": decision,
        "ballot_source": "fixture_model",
        "claim_findings": [
            {
                "claim_ref": "fixture:claim:build-b",
                "finding": "supported",
                "rationale": "Synthetic evidence supports this fixture finding.",
                "evidence_refs": [_evidence(index)],
            }
        ],
        "self_binding_weakening_finding": {
            "weakens_self_binding_constraint": False,
            "affected_constraints": [],
            "evidence_refs": [_evidence(index + 20)],
            "explanation": "The synthetic decision preserves self-binding.",
        },
        "strongest_case_against_decision": "The fixture may be incomplete.",
        "unresolved_objections": [],
        "raw_model_output_sha256": _digest(f"raw:{index}"),
        "transcript_ref": _evidence(index + 40),
        "requested_model": f"fixture-model-{index}",
        "requested_route": f"fixture/requested/{index}",
        "served_provider": "fixture-provider",
        "served_model": f"fixture-model-{index}",
        "served_route": f"fixture/served/{index}",
        "credited_cluster": cluster or f"cluster-{index}",
        "cluster_basis": "evidenced_base_model_or_training_lineage",
        "model_lineage_evidence_refs": [_evidence(index + 60)],
        "transport_correlation_refs": (["fixture:shared-transport"] if smeared else []),
        "correlation_smeared": smeared,
        "signature_role": "operator_controlled_execution_attestation",
        "vendor_signature_claimed": False,
        "execution_signature": {
            "alg": "ed25519",
            "signer": actual_seat_id,
            "public_key": BALLOT_KEYS[index]
            .verify_key.encode(encoder=HexEncoder)
            .decode(),
            "signature": "0" * 128,
            "signed_payload_sha256": "0" * 64,
            "canonicalization": "json-sort-keys-compact-v1",
        },
    }
    provisional = ArtifactBallotV1.model_validate(payload)
    unsigned = provisional.canonical_bytes(exclude={"execution_signature"})
    signing_key = BALLOT_KEYS[index]
    claimed_key = signing_key.verify_key.encode(encoder=HexEncoder).decode()
    signer = actual_seat_id
    if signature_fault in {"invalid", "key_mismatch"}:
        signing_key = BALLOT_KEYS[(index + 1) % len(BALLOT_KEYS)]
    if signature_fault == "key_mismatch":
        claimed_key = signing_key.verify_key.encode(encoder=HexEncoder).decode()
    elif signature_fault == "signer_mismatch":
        signer = f"{actual_seat_id}:substituted"
    elif signature_fault not in {None, "invalid"}:
        raise ValueError(f"unknown signature fault: {signature_fault}")
    payload["execution_signature"] = _contract_signature(
        signing_key,
        unsigned,
        signer=signer,
    )
    payload["execution_signature"]["public_key"] = claimed_key
    return ArtifactBallotV1.model_validate(payload)


def _frozen_roster(
    *,
    smeared_index: int | None = None,
) -> tuple[FrozenSeatV1, ...]:
    return tuple(
        FrozenSeatV1(
            seat_id=f"seat-{index}",
            requested_lab=f"fixture-lab-{index}",
            requested_model=f"fixture-model-{index}",
            adapter="fixture-adapter",
            transport="fixture-transport",
            requested_route=f"fixture/requested/{index}",
            served_provider="fixture-provider",
            served_model=f"fixture-model-{index}",
            model_family=f"fixture-family-{index}",
            credited_cluster=f"cluster-{index}",
            model_lineage_evidence_refs=(_evidence(index + 60),),
            possible_underlying_routes=(f"fixture/served/{index}",),
            transport_correlation_refs=(
                ("fixture:shared-transport",) if index == smeared_index else ()
            ),
            correlation_smeared=index == smeared_index,
            execution_public_key=BALLOT_KEYS[index]
            .verify_key.encode(encoder=HexEncoder)
            .decode(),
            common_operator_backing="single disclosed fixture operator",
            liveness_receipt_sha256=_digest(f"liveness:{index}"),
        )
        for index in range(9)
    )


def _terminal_ballots(*, smeared_index: int | None = None) -> list[ArtifactBallotV1]:
    return [
        _ballot(
            index,
            "correct_and_supersede" if index < 5 else "compost",
            smeared=index == smeared_index,
        )
        for index in range(9)
    ]


def _compile_kwargs(
    authority: Any,
    ballots: Any,
    *,
    rule: Any | None = None,
    frozen_roster: Any | None = None,
) -> dict[str, Any]:
    return {
        "authority": authority,
        "case_id": CASE_ID,
        "case_sha256": CASE_SHA256,
        "ballots": ballots,
        "rule": rule or _rule(),
        "frozen_roster": (_frozen_roster() if frozen_roster is None else frozen_roster),
        "requested_scope": "Copy",
        "requested_effects": EFFECTS,
        "compiled_at": NOW,
    }


def test_rule_is_explicit_self_hashed_and_has_no_implicit_default() -> None:
    rule = _rule()
    assert rule.minimum_raw_votes == 5
    assert rule.minimum_clean_clusters == 5
    assert rule.rule_sha256 == rule.canonical_sha256(exclude={"rule_sha256"})

    missing_hash = rule.canonical_payload(exclude={"rule_sha256"})
    with pytest.raises(ValidationError):
        CouncilTerminalityRuleV1.model_validate(missing_hash)
    with pytest.raises(ValidationError, match="rule_sha256"):
        CouncilTerminalityRuleV1.model_validate(
            {**rule.canonical_payload(), "minimum_raw_votes": 6}
        )

    bypassed_model = rule.model_copy(update={"minimum_raw_votes": 6})
    with pytest.raises(CouncilCompilationError) as bypass_error:
        compile_council_outcome(
            **_compile_kwargs(
                _evaluated_authority(),
                _terminal_ballots(),
                rule=bypassed_model,
            )
        )
    assert bypass_error.value.code == "terminality_rule_invalid"

    wrong_size = rule.canonical_payload(exclude={"rule_sha256"})
    wrong_size["council_size"] = 8
    with pytest.raises(ValidationError, match="council_size"):
        CouncilTerminalityRuleV1.model_validate(
            {
                **wrong_size,
                "rule_sha256": compute_council_terminality_rule_sha256(wrong_size),
            }
        )


@pytest.mark.parametrize(
    "malformed_effects",
    [
        ("challenge:resolve", "challenge:resolve", "seed:supersede"),
        (" challenge:resolve", "seed:supersede"),
        ("seed:supersede", "challenge:resolve"),
    ],
)
def test_rule_rejects_noncanonical_effect_lists(
    malformed_effects: tuple[str, ...],
) -> None:
    body = _rule().canonical_payload(exclude={"rule_sha256"})
    body["effects_by_decision"] = {"correct_and_supersede": list(malformed_effects)}
    with pytest.raises(ValidationError):
        CouncilTerminalityRuleV1.model_validate(
            {**body, "rule_sha256": _digest("malformed-rule")}
        )


def test_five_of_nine_and_five_clean_clusters_compile_terminal_verdict() -> None:
    authority = _evaluated_authority()
    outcome = compile_council_outcome(**_compile_kwargs(authority, _terminal_ballots()))

    assert isinstance(outcome, CompiledVerdictV1)
    assert outcome.terminality == "terminal"
    assert outcome.winner == "correct_and_supersede"
    assert outcome.raw_tally == {"compost": 4, "correct_and_supersede": 5}
    assert outcome.clean_routing_tally == {
        "compost": 4,
        "correct_and_supersede": 5,
    }
    assert outcome.requested_effects == EFFECTS
    assert outcome.correlation_smear_removals == ()
    assert outcome.pre_unseal_feasibility.result == "feasible"
    assert outcome.frozen_roster_sha256 == canonical_sha256(
        [seat.canonical_payload() for seat in _frozen_roster()]
    )


def test_ballots_must_follow_exact_frozen_roster_order() -> None:
    authority = _evaluated_authority()
    ballots = _terminal_ballots()
    with pytest.raises(CouncilCompilationError) as error:
        compile_council_outcome(**_compile_kwargs(authority, list(reversed(ballots))))
    assert error.value.code == "ballot_roster_order_mismatch"


@pytest.mark.parametrize(
    ("fault", "expected_code"),
    [
        ("invalid", "ballot_signature_invalid"),
        ("key_mismatch", "ballot_signature_key_mismatch"),
        ("signer_mismatch", "ballot_signature_signer_mismatch"),
    ],
)
def test_compiler_independently_rejects_ballot_signature_failures(
    fault: str,
    expected_code: str,
) -> None:
    ballots = _terminal_ballots()
    ballots[0] = _ballot(
        0,
        "correct_and_supersede",
        signature_fault=fault,
    )
    with pytest.raises(CouncilCompilationError) as error:
        compile_council_outcome(**_compile_kwargs(_evaluated_authority(), ballots))
    assert error.value.code == expected_code


def test_trusted_roster_key_and_order_cannot_be_substituted() -> None:
    authority = _evaluated_authority()
    ballots = _terminal_ballots()
    roster = list(_frozen_roster())
    roster[0] = roster[0].model_copy(
        update={
            "execution_public_key": BALLOT_KEYS[1]
            .verify_key.encode(encoder=HexEncoder)
            .decode()
        }
    )
    with pytest.raises(CouncilCompilationError) as key_error:
        compile_council_outcome(
            **_compile_kwargs(authority, ballots, frozen_roster=roster)
        )
    assert key_error.value.code == "ballot_signature_key_mismatch"

    with pytest.raises(CouncilCompilationError) as order_error:
        compile_council_outcome(
            **_compile_kwargs(
                authority,
                ballots,
                frozen_roster=tuple(reversed(_frozen_roster())),
            )
        )
    assert order_error.value.code == "ballot_roster_order_mismatch"


def test_compiler_requires_exactly_nine_frozen_seats_and_matching_facts() -> None:
    authority = _evaluated_authority()
    ballots = _terminal_ballots()
    with pytest.raises(CouncilCompilationError) as size_error:
        compile_council_outcome(
            **_compile_kwargs(
                authority,
                ballots,
                frozen_roster=_frozen_roster()[:-1],
            )
        )
    assert size_error.value.code == "frozen_roster_size_mismatch"

    roster = list(_frozen_roster())
    roster[0] = roster[0].model_copy(update={"credited_cluster": "substituted"})
    with pytest.raises(CouncilCompilationError) as facts_error:
        compile_council_outcome(
            **_compile_kwargs(authority, ballots, frozen_roster=roster)
        )
    assert facts_error.value.code == "ballot_frozen_seat_mismatch"


def test_smear_that_destroys_five_cluster_terminality_forces_appeal() -> None:
    authority = _evaluated_authority()
    outcome = compile_council_outcome(
        **_compile_kwargs(
            authority,
            _terminal_ballots(smeared_index=0),
            frozen_roster=_frozen_roster(smeared_index=0),
        )
    )

    assert isinstance(outcome, AppealReceiptV1)
    assert outcome.terminality == "appeal_required"
    assert outcome.correlation_removal_result == "terminality_changed"
    assert outcome.appeal_reasons == ("correlation_smear_changed_terminality",)
    assert outcome.requested_effects == ()
    assert outcome.effects == ()
    assert tuple(removal.seat_id for removal in outcome.correlation_smear_removals) == (
        "seat-0",
    )


def test_plurality_below_five_of_nine_is_a_nonterminal_zero_effect_outcome() -> None:
    authority = _evaluated_authority()
    decisions = [
        "correct_and_supersede",
        "correct_and_supersede",
        "correct_and_supersede",
        "correct_and_supersede",
        "compost",
        "compost",
        "compost",
        "abstain",
        "abstain",
    ]
    outcome = compile_council_outcome(
        **_compile_kwargs(
            authority,
            [_ballot(index, decision) for index, decision in enumerate(decisions)],
        )
    )

    assert isinstance(outcome, CompiledVerdictV1)
    assert outcome.winner == "correct_and_supersede"
    assert outcome.decision == "no_terminal_verdict"
    assert outcome.terminality == "no_terminal_verdict"
    assert outcome.requested_effects == ()


def test_pre_unseal_result_uses_only_seat_cluster_and_smear_metadata() -> None:
    rule = _rule()
    exactly_five_clusters = [
        PreUnsealSeatV1(
            seat_id=seat_id,
            credited_cluster=f"cluster-{index % 5}",
            correlation_smeared=False,
        )
        for index, seat_id in enumerate(SEATS)
    ]
    feasible = assess_pre_unseal_feasibility(
        rule=rule,
        expected_seat_ids=SEATS,
        seats=exactly_five_clusters,
    )
    assert feasible.result == "feasible"
    assert feasible.maximum_clean_clusters == 5

    only_four_clusters = [
        seat.model_copy(update={"credited_cluster": f"cluster-{index % 4}"})
        for index, seat in enumerate(exactly_five_clusters)
    ]
    infeasible = assess_pre_unseal_feasibility(
        rule=rule,
        expected_seat_ids=SEATS,
        seats=only_four_clusters,
    )
    assert infeasible.result == "infeasible"
    assert infeasible.reason_codes == ("insufficient_clean_cluster_capacity",)


def test_verifier_rederives_and_rejects_caller_tally_tampering() -> None:
    authority = _evaluated_authority()
    ballots = _terminal_ballots()
    kwargs = _compile_kwargs(authority, ballots)
    outcome = compile_council_outcome(**kwargs)

    assert verify_compiled_outcome(outcome, **kwargs)
    tampered = outcome.canonical_payload()
    tampered["raw_tally"] = {"correct_and_supersede": 9}
    assert not verify_compiled_outcome(tampered, **kwargs)


def test_nonfinal_duplicate_and_missing_ballots_fail_closed() -> None:
    authority = _evaluated_authority()
    nonfinal = _terminal_ballots()
    nonfinal[0] = _ballot(0, "correct_and_supersede", stage="sealed_first_pass")
    with pytest.raises(CouncilCompilationError) as nonfinal_error:
        compile_council_outcome(**_compile_kwargs(authority, nonfinal))
    assert nonfinal_error.value.code == "ballot_not_final"

    duplicate_seat = _terminal_ballots()
    duplicate_seat[8] = _ballot(8, "compost", seat_id="seat-7")
    with pytest.raises(CouncilCompilationError) as duplicate_seat_error:
        compile_council_outcome(**_compile_kwargs(authority, duplicate_seat))
    assert duplicate_seat_error.value.code == "duplicate_seat"

    duplicate_id = _terminal_ballots()
    duplicate_id[8] = _ballot(8, "compost", ballot_id="sab_ballot_build_b_7")
    with pytest.raises(CouncilCompilationError) as duplicate_id_error:
        compile_council_outcome(**_compile_kwargs(authority, duplicate_id))
    assert duplicate_id_error.value.code == "duplicate_ballot_id"

    with pytest.raises(CouncilCompilationError) as missing_error:
        compile_council_outcome(**_compile_kwargs(authority, _terminal_ballots()[:-1]))
    assert missing_error.value.code == "missing_seat"


class _MeritsBomb:
    def __iter__(self):
        raise AssertionError("authority refusal touched merit-bearing input")

    def __len__(self):
        raise AssertionError("authority refusal measured merit-bearing input")


@pytest.mark.parametrize(
    "malformed_effects",
    [
        ("challenge:resolve", "challenge:resolve", "seed:supersede"),
        ("challenge:resolve ", "seed:supersede"),
        ("seed:supersede", "challenge:resolve"),
    ],
)
def test_malformed_requested_effects_refuse_before_merit_parsing(
    malformed_effects: tuple[str, ...],
) -> None:
    outcome = compile_council_outcome(
        authority=_evaluated_authority(),
        case_id=_MeritsBomb(),
        case_sha256=_MeritsBomb(),
        ballots=_MeritsBomb(),
        rule=_MeritsBomb(),
        frozen_roster=_MeritsBomb(),
        requested_scope="Copy",
        requested_effects=malformed_effects,
        compiled_at=_MeritsBomb(),
    )
    assert isinstance(outcome, RefusalReceiptV1)
    assert outcome.reason == "requested_effects_malformed"
    assert outcome.effects == ()
    assert outcome.authority_inspected is False
    assert outcome.terminality_rule_inspected is False
    assert outcome.ballots_inspected is False
    assert outcome.merits_parsed is False


def test_every_authority_denial_short_circuits_deliberately_malformed_merits() -> None:
    authorized = _evaluated_authority()
    cases = (
        (None, "Copy", EFFECTS, "authority_missing"),
        ({"result": "Authorized"}, "Copy", EFFECTS, "authority_malformed"),
        (
            _evaluated_authority("advisory_only"),
            "Copy",
            EFFECTS,
            "authority_advisory_only",
        ),
        (
            _evaluated_authority("no_jurisdiction"),
            "Copy",
            EFFECTS,
            "authority_no_jurisdiction",
        ),
        (
            authorized.canonical_payload(),
            "Copy",
            EFFECTS,
            "authority_not_evaluator_capability",
        ),
        (object(), "Copy", EFFECTS, "authority_malformed"),
        (authorized, "Copy", (EFFECTS[0],), "authority_effect_mismatch"),
        (authorized, "Live", EFFECTS, "live_scope_unsupported"),
    )
    for authority, scope, effects, reason in cases:
        outcome = compile_council_outcome(
            authority=authority,
            case_id=_MeritsBomb(),
            case_sha256=_MeritsBomb(),
            ballots=_MeritsBomb(),
            rule=_MeritsBomb(),
            frozen_roster=_MeritsBomb(),
            requested_scope=scope,
            requested_effects=effects,
            compiled_at=_MeritsBomb(),
        )
        assert isinstance(outcome, RefusalReceiptV1)
        assert outcome.reason == reason
        assert outcome.effects == ()
        assert outcome.ballots_inspected is False
        assert outcome.merits_parsed is False
        assert outcome.terminality_rule_inspected is False
        assert outcome.standing_effect == "none"
        assert outcome.live_eligible is False


def test_rule_effect_mismatch_refuses_before_ballot_parsing() -> None:
    extra_effects = tuple(sorted(EFFECTS + ("seed:canon",)))
    authority = _evaluated_authority(effects=extra_effects)
    outcome = compile_council_outcome(
        authority=authority,
        case_id=_MeritsBomb(),
        case_sha256=_MeritsBomb(),
        ballots=_MeritsBomb(),
        rule=_rule(),
        frozen_roster=_MeritsBomb(),
        requested_scope="Copy",
        requested_effects=extra_effects,
        compiled_at=_MeritsBomb(),
    )
    assert isinstance(outcome, RefusalReceiptV1)
    assert outcome.reason == "authority_effect_mismatch"
    assert outcome.terminality_rule_inspected is True
    assert outcome.ballots_inspected is False
    assert outcome.merits_parsed is False
