from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from pydantic import ValidationError

import agora.sab_first_verdict_transcript as transcript_module
from agora.sab_artifact_verdict import (
    ArtifactBallotV1,
    FrozenSeatV1,
    canonical_sha256,
)
from agora.sab_first_verdict_storage import (
    DatabaseSafetyError,
    init_first_verdict_storage,
)
from agora.sab_first_verdict_transcript import (
    CEREMONY_STAGES,
    EMPTY_REVEAL_SET_SHA256,
    TRANSCRIPT_MIGRATION_STATEMENTS,
    BallotCommitmentV1,
    BallotExecutionFactsV1,
    BallotRevealV1,
    CeremonyStageEnvelopeV1,
    FinalDeliberationSubjectV1,
    TranscriptForeignKeysRequired,
    TranscriptImmutableConflict,
    TranscriptMigrationError,
    TranscriptStoredRecordError,
    TranscriptValidationFailure,
    ballot_commitment_preimage_sha256,
    ballot_commitment_signing_bytes,
    canonical_commitment_set_sha256,
    canonical_reveal_set_sha256,
    init_transcript_storage,
    read_ballot_commitment,
    read_ballot_reveal,
    read_ceremony_transcript,
    read_stage_envelope,
    store_ballot_commitment,
    store_ballot_reveal,
    store_ceremony_transcript,
    store_stage_envelope,
    verify_ceremony_transcript,
    verify_commit_reveal,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sab_first_verdict" / "valid"
CASE_TEMPLATE = json.loads((FIXTURES / "sab.artifact_case.v1.json").read_text())
BALLOT_TEMPLATE = json.loads((FIXTURES / "sab.artifact_ballot.v1.json").read_text())
CASE_ID = "case:build-b-transcript"
CASE_SHA256 = hashlib.sha256(b"build-b-case").hexdigest()
AUTHORITY_DIGEST = hashlib.sha256(b"non-authorizing-authority-input").hexdigest()
RULE_DIGEST = hashlib.sha256(b"frozen-rule-input").hexdigest()
RECORDED_AT = "2026-08-01T00:00:00Z"
SIGNING_KEYS = tuple(SigningKey.generate() for _ in range(9))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _dummy_signature(seat: FrozenSeatV1) -> dict[str, str]:
    return {
        "alg": "ed25519",
        "signer": seat.seat_id,
        "public_key": seat.execution_public_key,
        "signature": "0" * 128,
        "signed_payload_sha256": "0" * 64,
        "canonicalization": "json-sort-keys-compact-v1",
    }


def _seat_signature(
    message: bytes,
    *,
    position: int,
    seat: FrozenSeatV1,
) -> dict[str, str]:
    return {
        "alg": "ed25519",
        "signer": seat.seat_id,
        "public_key": seat.execution_public_key,
        "signature": SIGNING_KEYS[position].sign(message).signature.hex(),
        "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
        "canonicalization": "json-sort-keys-compact-v1",
    }


def _resign_commitment(
    commitment: BallotCommitmentV1,
    *,
    updates: Mapping[str, Any] | None = None,
) -> BallotCommitmentV1:
    unsigned = commitment.canonical_payload(exclude={"commitment_signature"})
    unsigned.update(updates or {})
    seat = _roster()[commitment.seat_position]
    return BallotCommitmentV1(
        **unsigned,
        commitment_signature=_seat_signature(
            ballot_commitment_signing_bytes(unsigned),
            position=commitment.seat_position,
            seat=seat,
        ),
    )


def _roster() -> tuple[FrozenSeatV1, ...]:
    roster: list[FrozenSeatV1] = []
    for position, source in enumerate(CASE_TEMPLATE["frozen_roster"]):
        item = deepcopy(source)
        item["execution_public_key"] = (
            SIGNING_KEYS[position].verify_key.encode(encoder=HexEncoder).decode()
        )
        for reference_index, reference in enumerate(
            item["model_lineage_evidence_refs"]
        ):
            if reference["content_sha256"] == "0" * 64:
                reference["content_sha256"] = _digest(
                    f"lineage-evidence:{position}:{reference_index}"
                )
        roster.append(FrozenSeatV1.model_validate(item))
    return tuple(roster)


def _ballot(
    stage: str,
    position: int,
    seat: FrozenSeatV1,
    *,
    served_route: str | None = None,
    signature_fault: str | None = None,
) -> ArtifactBallotV1:
    payload = deepcopy(BALLOT_TEMPLATE)
    payload.update(
        {
            "ballot_id": f"ballot:{stage}:{position}",
            "case_id": CASE_ID,
            "case_sha256": CASE_SHA256,
            "seat_id": seat.seat_id,
            "stage": stage,
            "requested_model": seat.requested_model,
            "requested_route": seat.requested_route,
            "served_provider": seat.served_provider,
            "served_model": seat.served_model,
            "served_route": served_route or seat.possible_underlying_routes[0],
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
            "execution_signature": _dummy_signature(seat),
        }
    )
    provisional = ArtifactBallotV1.model_validate(payload)
    unsigned = provisional.canonical_bytes(exclude={"execution_signature"})
    signing_key = SIGNING_KEYS[position]
    claimed_key = seat.execution_public_key
    signer = seat.seat_id
    if signature_fault in {"invalid", "key_mismatch"}:
        signing_key = SIGNING_KEYS[(position + 1) % len(SIGNING_KEYS)]
    if signature_fault == "key_mismatch":
        claimed_key = signing_key.verify_key.encode(encoder=HexEncoder).decode()
    elif signature_fault == "signer_mismatch":
        signer = f"{seat.seat_id}:substituted"
    elif signature_fault not in {None, "invalid"}:
        raise ValueError(f"unknown signature fault: {signature_fault}")
    payload["execution_signature"] = {
        "alg": "ed25519",
        "signer": signer,
        "public_key": claimed_key,
        "signature": signing_key.sign(unsigned).signature.hex(),
        "signed_payload_sha256": hashlib.sha256(unsigned).hexdigest(),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return ArtifactBallotV1.model_validate(payload)


def _stage(
    stage: str,
    preceding_reveal_set_sha256: str,
    *,
    roster: tuple[FrozenSeatV1, ...],
    stage_input_sha256: str | None = None,
    served_route_override: str | None = None,
    signature_fault: str | None = None,
) -> CeremonyStageEnvelopeV1:
    stage_index = CEREMONY_STAGES.index(stage)  # type: ignore[arg-type]
    stage_input = stage_input_sha256 or _digest(f"stage-input:{stage}")
    roster_sha = canonical_sha256([seat.canonical_payload() for seat in roster])
    subject = None
    subject_sha = None
    if stage == "final":
        subject = FinalDeliberationSubjectV1(
            case_id=CASE_ID,
            case_sha256=CASE_SHA256,
            frozen_roster_sha256=roster_sha,
            authority_digest=AUTHORITY_DIGEST,
            rule_digest=RULE_DIGEST,
            cross_examination_reveal_set_sha256=preceding_reveal_set_sha256,
            stage_input_sha256=stage_input,
            question="Render a final ballot over the exact cross-examination record.",
            deliberation_material_sha256=_digest("final-deliberation-material"),
        )
        subject_sha = subject.canonical_sha256()

    commitments: list[BallotCommitmentV1] = []
    ballots: list[ArtifactBallotV1] = []
    nonces: list[str] = []
    for position, seat in enumerate(roster):
        ballot = _ballot(
            stage,
            position,
            seat,
            served_route=served_route_override if position == 0 else None,
            signature_fault=signature_fault if position == 0 else None,
        )
        facts = BallotExecutionFactsV1.from_ballot(ballot)
        nonce = f"offline-public-nonce:{stage}:{position:02d}"
        draft: dict[str, Any] = {
            "commitment_id": f"commitment:{stage}:{position}",
            "case_id": CASE_ID,
            "case_sha256": CASE_SHA256,
            "frozen_roster_sha256": roster_sha,
            "frozen_seat_sha256": seat.canonical_sha256(),
            "authority_digest": AUTHORITY_DIGEST,
            "rule_digest": RULE_DIGEST,
            "stage": stage,
            "stage_index": stage_index,
            "stage_input_sha256": stage_input,
            "preceding_reveal_set_sha256": preceding_reveal_set_sha256,
            "final_deliberation_subject_sha256": subject_sha,
            "seat_id": seat.seat_id,
            "seat_position": position,
            "execution_facts": facts,
        }
        unsigned_commitment = {
            **draft,
            "committed_preimage_sha256": ballot_commitment_preimage_sha256(
                draft,
                nonce=nonce,
                ballot=ballot,
            ),
        }
        commitments.append(
            BallotCommitmentV1(
                **unsigned_commitment,
                commitment_signature=_seat_signature(
                    ballot_commitment_signing_bytes(unsigned_commitment),
                    position=position,
                    seat=seat,
                ),
            )
        )
        ballots.append(ballot)
        nonces.append(nonce)

    commitment_set_sha = canonical_commitment_set_sha256(commitments)
    reveals = tuple(
        BallotRevealV1(
            reveal_id=f"reveal:{stage}:{position}",
            commitment_id=commitment.commitment_id,
            commitment_sha256=commitment.canonical_sha256(),
            commitment_set_sha256=commitment_set_sha,
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
        frozen_roster_sha256=roster_sha,
        expected_seat_ids=tuple(seat.seat_id for seat in roster),
        authority_digest=AUTHORITY_DIGEST,
        rule_digest=RULE_DIGEST,
        stage=stage,
        stage_index=stage_index,
        stage_input_sha256=stage_input,
        preceding_reveal_set_sha256=preceding_reveal_set_sha256,
        final_deliberation_subject=subject,
        final_deliberation_subject_sha256=subject_sha,
        commitments=tuple(commitments),
        commitment_set_sha256=commitment_set_sha,
        reveals=reveals,
        reveal_set_sha256=canonical_reveal_set_sha256(reveals),
    )


def _ceremony(
    *,
    cross_predecessor: str | None = None,
    stage_input: Callable[[str], str] | None = None,
    signature_fault_stage: str | None = None,
    signature_fault: str | None = None,
) -> tuple[CeremonyStageEnvelopeV1, ...]:
    roster = _roster()
    first = _stage(
        "sealed_first_pass",
        EMPTY_REVEAL_SET_SHA256,
        roster=roster,
        stage_input_sha256=stage_input("sealed_first_pass") if stage_input else None,
        signature_fault=(
            signature_fault if signature_fault_stage == "sealed_first_pass" else None
        ),
    )
    cross = _stage(
        "cross_examination",
        cross_predecessor or first.reveal_set_sha256,
        roster=roster,
        stage_input_sha256=stage_input("cross_examination") if stage_input else None,
        signature_fault=(
            signature_fault if signature_fault_stage == "cross_examination" else None
        ),
    )
    final = _stage(
        "final",
        cross.reveal_set_sha256,
        roster=roster,
        stage_input_sha256=stage_input("final") if stage_input else None,
        signature_fault=signature_fault if signature_fault_stage == "final" else None,
    )
    return first, cross, final


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@pytest.fixture(scope="module")
def ceremony() -> tuple[CeremonyStageEnvelopeV1, ...]:
    return _ceremony()


def _codes(result: Any) -> set[str]:
    return {error.code for error in result.errors}


def test_commitment_and_reveal_are_stable_strict_canonical_contracts(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    commitment = ceremony[0].commitments[0]
    payload = commitment.canonical_payload()
    reversed_payload = dict(reversed(tuple(payload.items())))
    reparsed = BallotCommitmentV1.model_validate(reversed_payload)
    assert reparsed.canonical_bytes() == commitment.canonical_bytes()
    assert reparsed.canonical_sha256() == commitment.canonical_sha256()
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        BallotCommitmentV1.model_validate({**payload, "authority": "forbidden"})
    with pytest.raises(ValidationError, match="frozen"):
        commitment.case_id = "mutated"  # type: ignore[misc]


@pytest.mark.parametrize("malformed", ["0", 0.0, False])
def test_transcript_indices_reject_scalar_type_coercion(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
    malformed: object,
) -> None:
    first = ceremony[0]
    for model, value, field in (
        (BallotCommitmentV1, first.commitments[0], "stage_index"),
        (BallotCommitmentV1, first.commitments[0], "seat_position"),
        (BallotRevealV1, first.reveals[0], "stage_index"),
        (BallotRevealV1, first.reveals[0], "seat_position"),
        (CeremonyStageEnvelopeV1, first, "stage_index"),
    ):
        payload = value.canonical_payload()
        payload[field] = malformed
        with pytest.raises(ValidationError):
            model.model_validate(payload)


def test_fully_rehashed_and_resigned_zero_context_roots_are_rejected(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    commitment = ceremony[2].commitments[0]
    reveal = ceremony[2].reveals[0]
    payload = commitment.canonical_payload()
    for field in (
        "case_sha256",
        "frozen_roster_sha256",
        "frozen_seat_sha256",
        "authority_digest",
        "rule_digest",
        "stage_input_sha256",
        "final_deliberation_subject_sha256",
    ):
        payload[field] = "0" * 64
    payload["committed_preimage_sha256"] = ballot_commitment_preimage_sha256(
        payload,
        nonce=reveal.nonce,
        ballot=reveal.ballot,
    )
    unsigned = {
        key: value for key, value in payload.items() if key != "commitment_signature"
    }
    payload["commitment_signature"] = _seat_signature(
        ballot_commitment_signing_bytes(unsigned),
        position=0,
        seat=ceremony[2].frozen_roster[0],
    )

    with pytest.raises(ValidationError, match="all-zero placeholder digest"):
        BallotCommitmentV1.model_validate(payload)

    subject_payload = ceremony[2].final_deliberation_subject.canonical_payload()  # type: ignore[union-attr]
    for field in (
        "case_sha256",
        "frozen_roster_sha256",
        "authority_digest",
        "rule_digest",
        "cross_examination_reveal_set_sha256",
        "stage_input_sha256",
        "deliberation_material_sha256",
    ):
        subject_payload[field] = "0" * 64
    with pytest.raises(ValidationError, match="all-zero placeholder digest"):
        FinalDeliberationSubjectV1.model_validate(subject_payload)


def test_nested_zero_roots_in_imported_evidence_ballot_and_roster_are_rejected(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    first = ceremony[0]
    facts_payload = first.commitments[0].execution_facts.canonical_payload()
    facts_payload["model_lineage_evidence_refs"][0]["content_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="all-zero placeholder digest"):
        BallotExecutionFactsV1.model_validate(facts_payload)

    ballot_payload = first.reveals[0].ballot.canonical_payload()
    ballot_payload["raw_model_output_sha256"] = "0" * 64
    provisional_ballot = ArtifactBallotV1.model_validate(ballot_payload)
    ballot_payload["execution_signature"] = _seat_signature(
        provisional_ballot.canonical_bytes(exclude={"execution_signature"}),
        position=0,
        seat=first.frozen_roster[0],
    )
    zero_ballot = ArtifactBallotV1.model_validate(ballot_payload)
    reveal_payload = first.reveals[0].canonical_payload()
    reveal_payload.update(
        {
            "ballot": zero_ballot.canonical_payload(),
            "ballot_sha256": zero_ballot.canonical_sha256(),
        }
    )
    with pytest.raises(ValidationError, match="all-zero placeholder digest"):
        BallotRevealV1.model_validate(reveal_payload)

    envelope_payload = first.canonical_payload()
    envelope_payload["frozen_roster"][0]["liveness_receipt_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="all-zero placeholder digest"):
        CeremonyStageEnvelopeV1.model_validate(envelope_payload)


def test_verify_commit_reveal_accepts_exact_preimage_but_grants_no_authority(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    commitment = ceremony[0].commitments[0]
    reveal = ceremony[0].reveals[0]
    result = verify_commit_reveal(commitment, reveal, frozen_seat=_roster()[0])
    assert result.ok is True
    assert result.readiness == "structurally_ready_awaiting_authority"
    assert result.errors == ()
    assert result.authority_effect == "none"
    assert result.standing_effect == "none"
    assert result.live_eligible is False
    assert result.frozen_roster_sha256 == commitment.frozen_roster_sha256
    assert result.rule_digest == RULE_DIGEST


def test_verify_commit_reveal_requires_the_trusted_frozen_seat(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    result = verify_commit_reveal(
        ceremony[0].commitments[0],
        ceremony[0].reveals[0],
    )
    assert _codes(result) == {"frozen_seat_required"}


def test_full_transcript_cryptographically_checks_all_ballots_and_commitments(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    original = transcript_module.verify_contract_signature

    def recording_verifier(message: bytes, signature: Any) -> bool:
        calls.append(signature.signer)
        return original(message, signature)

    monkeypatch.setattr(
        transcript_module,
        "verify_contract_signature",
        recording_verifier,
    )
    result = verify_ceremony_transcript(ceremony, expected_roster=_roster())
    assert result.ok is True
    assert len(calls) == 54


@pytest.mark.parametrize(
    ("stage_index", "context_updates", "new_nonce"),
    [
        (0, {}, "attacker-selected-public-nonce"),
        (0, {"authority_digest": _digest("attacker-authority")}, None),
        (0, {"rule_digest": _digest("attacker-rule")}, None),
        (0, {"frozen_roster_sha256": _digest("attacker-roster")}, None),
        (0, {"stage_input_sha256": _digest("attacker-stage-input")}, None),
        (
            1,
            {"preceding_reveal_set_sha256": _digest("attacker-predecessor")},
            None,
        ),
        (
            2,
            {"final_deliberation_subject_sha256": _digest("attacker-final-subject")},
            None,
        ),
    ],
)
def test_signed_ballot_cannot_be_rewrapped_in_new_commitment_context(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
    stage_index: int,
    context_updates: Mapping[str, Any],
    new_nonce: str | None,
) -> None:
    commitment = ceremony[stage_index].commitments[0]
    reveal = ceremony[stage_index].reveals[0]
    nonce = new_nonce or reveal.nonce
    unsigned = commitment.canonical_payload(exclude={"commitment_signature"})
    unsigned.update(context_updates)
    unsigned["committed_preimage_sha256"] = ballot_commitment_preimage_sha256(
        unsigned,
        nonce=nonce,
        ballot=reveal.ballot,
    )
    rewrapped_commitment = BallotCommitmentV1(
        **unsigned,
        commitment_signature=commitment.commitment_signature,
    )
    reveal_payload = reveal.canonical_payload()
    reveal_payload.update(context_updates)
    reveal_payload.update(
        {
            "nonce": nonce,
            "commitment_sha256": rewrapped_commitment.canonical_sha256(),
        }
    )
    rewrapped_reveal = BallotRevealV1.model_validate(reveal_payload)

    result = verify_commit_reveal(
        rewrapped_commitment,
        rewrapped_reveal,
        frozen_seat=ceremony[stage_index].frozen_roster[0],
    )

    assert _codes(result) == {"commitment_signature_invalid"}


@pytest.mark.parametrize(
    ("signature_update", "expected_code"),
    [
        (
            {"signer": "seat:substituted"},
            "commitment_signature_signer_mismatch",
        ),
        (
            {
                "public_key": SIGNING_KEYS[1]
                .verify_key.encode(encoder=HexEncoder)
                .decode()
            },
            "commitment_signature_key_mismatch",
        ),
    ],
)
def test_commitment_signature_identity_must_match_exact_frozen_seat(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
    signature_update: Mapping[str, str],
    expected_code: str,
) -> None:
    commitment = ceremony[0].commitments[0]
    signature = commitment.commitment_signature.model_copy(update=signature_update)
    substituted = commitment.model_copy(update={"commitment_signature": signature})
    reveal = (
        ceremony[0]
        .reveals[0]
        .model_copy(update={"commitment_sha256": substituted.canonical_sha256()})
    )
    result = verify_commit_reveal(
        substituted,
        reveal,
        frozen_seat=ceremony[0].frozen_roster[0],
    )
    assert expected_code in _codes(result)


@pytest.mark.parametrize(
    ("stage", "fault", "expected_code"),
    [
        ("sealed_first_pass", "invalid", "ballot_signature_invalid"),
        ("cross_examination", "invalid", "ballot_signature_invalid"),
        ("final", "invalid", "ballot_signature_invalid"),
        ("final", "key_mismatch", "ballot_signature_key_mismatch"),
        ("final", "signer_mismatch", "ballot_signature_signer_mismatch"),
    ],
)
def test_ballot_signature_failures_have_stable_typed_errors(
    stage: str,
    fault: str,
    expected_code: str,
) -> None:
    ceremony = _ceremony(signature_fault_stage=stage, signature_fault=fault)
    result = verify_ceremony_transcript(ceremony, expected_roster=_roster())
    assert result.ok is False
    assert expected_code in _codes(result)


def test_verify_commit_reveal_returns_typed_errors_for_bad_contracts(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    commitment = ceremony[0].commitments[0]
    invalid = {
        **commitment.canonical_payload(),
        "unexpected": "must-not-appear-in-error-detail",
    }
    result = verify_commit_reveal(invalid, ceremony[0].reveals[0])
    assert result.ok is False
    assert result.readiness == "blocked"
    assert _codes(result) == {"invalid_commitment_contract"}
    assert result.transcript_sha256 is None
    assert result.frozen_roster_sha256 is None
    assert result.rule_digest is None
    assert result.ordered_final_ballots == ()
    assert "must-not-appear" not in result.errors[0].detail
    with pytest.raises(ValidationError, match="blocked validation"):
        type(result).model_validate(
            {
                **result.canonical_payload(),
                "frozen_roster_sha256": "a" * 64,
                "rule_digest": "b" * 64,
            }
        )


def test_transcript_verifier_returns_typed_error_for_non_sequence_input() -> None:
    result = verify_ceremony_transcript(None)  # type: ignore[arg-type]
    assert result.ok is False
    assert _codes(result) == {"invalid_transcript_contract"}


def test_nonce_or_ballot_substitution_cannot_open_commitment(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    commitment = ceremony[0].commitments[0]
    reveal = ceremony[0].reveals[0]
    wrong_nonce = reveal.model_copy(update={"nonce": "different-public-nonce-value"})
    assert "commitment_preimage_mismatch" in _codes(
        verify_commit_reveal(commitment, wrong_nonce, frozen_seat=_roster()[0])
    )

    ballot_payload = reveal.ballot.canonical_payload()
    ballot_payload["served_route"] = "offline/substituted-route"
    substituted_ballot = ArtifactBallotV1.model_validate(ballot_payload)
    substituted = reveal.model_copy(
        update={
            "ballot": substituted_ballot,
            "ballot_sha256": substituted_ballot.canonical_sha256(),
            "execution_facts": BallotExecutionFactsV1.from_ballot(substituted_ballot),
        }
    )
    result = verify_commit_reveal(
        commitment,
        substituted,
        frozen_seat=_roster()[0],
    )
    assert "commit_reveal_binding_mismatch" in _codes(result)
    assert "commitment_preimage_mismatch" in _codes(result)


def test_seat_substitution_and_commitment_reference_mismatch_are_blocked(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    result = verify_commit_reveal(
        ceremony[0].commitments[0],
        ceremony[0].reveals[1],
        frozen_seat=_roster()[0],
    )
    assert {
        "commitment_reference_mismatch",
        "commitment_digest_mismatch",
        "commit_reveal_binding_mismatch",
        "commitment_preimage_mismatch",
    }.issubset(_codes(result))


def test_full_transcript_is_exactly_ordered_and_exposes_final_ballots_only(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    result = verify_ceremony_transcript(ceremony, expected_roster=_roster())
    assert result.ok is True
    assert result.validated_stages == CEREMONY_STAGES
    assert result.expected_seat_ids == tuple(seat.seat_id for seat in _roster())
    assert len(result.ordered_final_ballots) == 9
    assert (
        tuple(ballot.stage for ballot in result.ordered_final_ballots) == ("final",) * 9
    )
    assert tuple(ballot.seat_id for ballot in result.ordered_final_ballots) == (
        result.expected_seat_ids
    )
    assert result.final_ballot_payloads[0]["stage"] == "final"
    assert result.transcript_sha256 == canonical_sha256(
        [envelope.canonical_payload() for envelope in ceremony]
    )
    assert result.frozen_roster_sha256 == ceremony[0].frozen_roster_sha256
    assert result.rule_digest == RULE_DIGEST
    assert result.authority_effect == "none"


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (lambda stages: (stages[1], stages[0], stages[2]), "stage_order_mismatch"),
        (lambda stages: (stages[0], stages[2]), "final_requires_cross_examination"),
        (lambda stages: stages[:2], "stage_count_mismatch"),
        (
            lambda stages: (stages[0], stages[1], stages[1]),
            "duplicate_stage_envelope",
        ),
    ],
)
def test_missing_reordered_or_duplicated_stages_are_blocked(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
    mutate: Callable[[tuple[CeremonyStageEnvelopeV1, ...]], tuple[Any, ...]],
    expected_code: str,
) -> None:
    result = verify_ceremony_transcript(mutate(ceremony))
    assert result.ok is False
    assert expected_code in _codes(result)


def test_cross_examination_must_bind_first_pass_reveal_set() -> None:
    ceremony = _ceremony(cross_predecessor=_digest("unrelated-reveal-set"))
    result = verify_ceremony_transcript(ceremony)
    assert result.ok is False
    assert "preceding_reveal_set_mismatch" in _codes(result)


def test_equal_stage_input_digests_remain_bound_without_inventing_extra_policy() -> (
    None
):
    ceremony = _ceremony(stage_input=lambda _stage_name: _digest("replayed-input"))
    result = verify_ceremony_transcript(ceremony)
    assert result.ok is True
    assert {stage.stage_input_sha256 for stage in ceremony} == {
        _digest("replayed-input")
    }


def test_roster_substitution_reordering_and_in_stage_reordering_are_blocked(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    swapped_roster = list(_roster())
    swapped_roster[0], swapped_roster[1] = swapped_roster[1], swapped_roster[0]
    explicit = verify_ceremony_transcript(ceremony, expected_roster=swapped_roster)
    assert "frozen_roster_digest_mismatch" in _codes(explicit)

    reordered = ceremony[0].model_copy(
        update={"commitments": tuple(reversed(ceremony[0].commitments))}
    )
    result = verify_ceremony_transcript((reordered, ceremony[1], ceremony[2]))
    assert result.ok is False
    assert "invalid_stage_envelope_contract" in _codes(result)


def test_final_subject_cannot_be_removed_or_rebound(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    removed = ceremony[2].model_copy(
        update={
            "final_deliberation_subject": None,
            "final_deliberation_subject_sha256": None,
        }
    )
    result = verify_ceremony_transcript((ceremony[0], ceremony[1], removed))
    assert result.ok is False
    assert "invalid_stage_envelope_contract" in _codes(result)

    subject = ceremony[2].final_deliberation_subject
    assert subject is not None
    rebound = subject.model_copy(update={"question": "A substituted final question."})
    changed = ceremony[2].model_copy(update={"final_deliberation_subject": rebound})
    result = verify_ceremony_transcript((ceremony[0], ceremony[1], changed))
    assert "invalid_stage_envelope_contract" in _codes(result)


def test_envelope_rejects_open_reveal_set_or_route_fact_substitution(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    wrong_set_reveal = (
        ceremony[0]
        .reveals[0]
        .model_copy(update={"commitment_set_sha256": _digest("not-the-closed-set")})
    )
    wrong_set = ceremony[0].model_copy(
        update={"reveals": (wrong_set_reveal, *ceremony[0].reveals[1:])}
    )
    result = verify_ceremony_transcript((wrong_set, ceremony[1], ceremony[2]))
    assert result.ok is False
    assert "invalid_stage_envelope_contract" in _codes(result)

    facts = (
        ceremony[0]
        .commitments[0]
        .execution_facts.model_copy(update={"served_model": "substituted-model"})
    )
    changed_commitment = (
        ceremony[0].commitments[0].model_copy(update={"execution_facts": facts})
    )
    changed = ceremony[0].model_copy(
        update={"commitments": (changed_commitment, *ceremony[0].commitments[1:])}
    )
    result = verify_ceremony_transcript((changed, ceremony[1], ceremony[2]))
    assert "invalid_stage_envelope_contract" in _codes(result)

    with pytest.raises(
        ValidationError, match="execution facts differ from frozen bench"
    ):
        _stage(
            "sealed_first_pass",
            EMPTY_REVEAL_SET_SHA256,
            roster=_roster(),
            served_route_override="unfrozen/substituted-route",
        )

    multi_route_roster = list(_roster())
    multi_route_roster[0] = multi_route_roster[0].model_copy(
        update={
            "possible_underlying_routes": (
                multi_route_roster[0].possible_underlying_routes[0],
                "unprobed/listed-substitute",
            )
        }
    )
    with pytest.raises(
        ValidationError, match="execution facts differ from frozen bench"
    ):
        _stage(
            "sealed_first_pass",
            EMPTY_REVEAL_SET_SHA256,
            roster=tuple(multi_route_roster),
            served_route_override="unprobed/listed-substitute",
        )


def test_storage_migration_is_additive_and_preserves_build_a_ballot_uniqueness() -> (
    None
):
    conn = _connect()
    init_first_verdict_storage(conn, applied_at=RECORDED_AT)
    build_a_sql = str(
        conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'sab_artifact_ballots_v1'"
        ).fetchone()[0]
    )
    digest = init_transcript_storage(conn, applied_at=RECORDED_AT)
    assert len(digest) == 64
    assert init_transcript_storage(conn, applied_at="later") == digest
    assert "UNIQUE (case_id, round_no, seat_id)" in build_a_sql
    after_sql = str(
        conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'sab_artifact_ballots_v1'"
        ).fetchone()[0]
    )
    assert after_sql == build_a_sql
    assert {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name IN ('sab_ballot_commitments_v1', 'sab_ballot_reveals_v1', "
            "'sab_ceremony_stage_envelopes_v1')"
        )
    } == {
        "sab_ballot_commitments_v1",
        "sab_ballot_reveals_v1",
        "sab_ceremony_stage_envelopes_v1",
    }
    conn.close()


def test_migration_requires_foreign_keys_and_rolls_back_every_boundary() -> None:
    conn = sqlite3.connect(":memory:")
    with pytest.raises(TranscriptForeignKeysRequired, match="foreign_keys=ON"):
        init_transcript_storage(conn)
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'sab_%transcript%'"
        ).fetchone()[0]
        == 0
    )
    conn.close()

    for boundary in (
        "migration:0",
        f"migration:{len(TRANSCRIPT_MIGRATION_STATEMENTS) - 1}",
        "migration:schema_verified",
        "migration:recorded",
    ):
        conn = _connect()
        conn.execute("CREATE TABLE legacy_marker (value TEXT NOT NULL)")
        conn.execute("INSERT INTO legacy_marker VALUES ('preserved')")
        conn.commit()

        def fail(actual: str, *, selected: str = boundary) -> None:
            if actual == selected:
                raise RuntimeError(selected)

        with pytest.raises(RuntimeError, match=boundary):
            init_transcript_storage(conn, failure_hook=fail)
        assert [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ] == ["legacy_marker"]
        assert (
            conn.execute("SELECT value FROM legacy_marker").fetchone()[0] == "preserved"
        )
        assert not conn.in_transaction
        conn.close()


def test_migration_rejects_conflicting_same_named_schema() -> None:
    conn = _connect()
    conn.execute(
        "CREATE TABLE sab_first_verdict_transcript_migrations_v1 "
        "(migration_id TEXT PRIMARY KEY)"
    )
    conn.commit()
    with pytest.raises(
        TranscriptMigrationError, match="differs from the frozen schema"
    ):
        init_transcript_storage(conn)
    assert {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )
    } == {"sab_first_verdict_transcript_migrations_v1"}
    conn.close()


def test_ordinary_file_backed_database_is_rejected_as_non_offline(
    tmp_path: Path,
) -> None:
    conn = sqlite3.connect(tmp_path / "live-like.db")
    conn.execute("PRAGMA foreign_keys = ON")
    with pytest.raises(DatabaseSafetyError, match="attested copy"):
        init_transcript_storage(conn)
    conn.close()


def test_store_read_replay_and_three_stage_coexistence(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn, applied_at=RECORDED_AT)
    receipt = store_ceremony_transcript(
        conn,
        ceremony,
        expected_roster=_roster(),
        recorded_at=RECORDED_AT,
    )
    assert receipt.replayed is False
    assert receipt.authority_effect == "none"
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_ballot_commitments_v1").fetchone()[0]
        == 27
    )
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_ballot_reveals_v1").fetchone()[0] == 27
    )
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_ceremony_stage_envelopes_v1").fetchone()[
            0
        ]
        == 3
    )
    assert (
        conn.execute(
            "SELECT COUNT(DISTINCT stage) FROM sab_ballot_reveals_v1 WHERE seat_id = ?",
            (ceremony[0].expected_seat_ids[0],),
        ).fetchone()[0]
        == 3
    )
    assert (
        read_ballot_commitment(conn, ceremony[1].commitments[4].commitment_id)
        == ceremony[1].commitments[4]
    )
    assert (
        read_ballot_reveal(conn, ceremony[2].reveals[8].reveal_id)
        == ceremony[2].reveals[8]
    )
    assert read_stage_envelope(conn, CASE_ID, "cross_examination") == ceremony[1]
    persisted = read_ceremony_transcript(conn, CASE_ID)
    assert persisted == ceremony
    assert (
        verify_ceremony_transcript(persisted).transcript_sha256
        == receipt.transcript_sha256
    )

    replay = store_ceremony_transcript(conn, ceremony, recorded_at="ignored-on-replay")
    assert replay == receipt.model_copy(update={"replayed": True})
    conn.close()


def test_commit_before_reveal_and_final_after_cross_are_enforced(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)
    store_ballot_commitment(
        conn,
        ceremony[0].commitments[0],
        frozen_seat=ceremony[0].frozen_roster[0],
    )
    with pytest.raises(
        TranscriptImmutableConflict, match="all nine ordered commitments"
    ):
        store_ballot_reveal(
            conn,
            ceremony[0].reveals[0],
            frozen_seat=ceremony[0].frozen_roster[0],
        )
    with pytest.raises(TranscriptImmutableConflict, match="predecessor"):
        store_ballot_commitment(
            conn,
            ceremony[2].commitments[0],
            frozen_seat=ceremony[2].frozen_roster[0],
        )
    assert conn.execute("SELECT COUNT(*) FROM sab_ballot_reveals_v1").fetchone()[0] == 0
    conn.close()


def test_direct_commitment_storage_rejects_rewrapped_signed_ballot_context(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    commitment = ceremony[0].commitments[0]
    reveal = ceremony[0].reveals[0]
    unsigned = commitment.canonical_payload(exclude={"commitment_signature"})
    unsigned["authority_digest"] = _digest("storage-attacker-authority")
    unsigned["committed_preimage_sha256"] = ballot_commitment_preimage_sha256(
        unsigned,
        nonce=reveal.nonce,
        ballot=reveal.ballot,
    )
    rewrapped = BallotCommitmentV1(
        **unsigned,
        commitment_signature=commitment.commitment_signature,
    )
    conn = _connect()
    init_transcript_storage(conn)

    with pytest.raises(TranscriptValidationFailure) as caught:
        store_ballot_commitment(
            conn,
            rewrapped,
            frozen_seat=ceremony[0].frozen_roster[0],
        )

    assert _codes(caught.value.result) == {"commitment_signature_invalid"}
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_ballot_commitments_v1").fetchone()[0]
        == 0
    )
    conn.close()


def test_direct_stage_storage_rejects_cross_stage_binding_substitution(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)
    for seat, commitment in zip(
        ceremony[0].frozen_roster, ceremony[0].commitments, strict=True
    ):
        store_ballot_commitment(conn, commitment, frozen_seat=seat)
    for seat, reveal in zip(ceremony[0].frozen_roster, ceremony[0].reveals):
        store_ballot_reveal(conn, reveal, frozen_seat=seat)
    store_stage_envelope(conn, ceremony[0])

    substituted = _resign_commitment(
        ceremony[1].commitments[0],
        updates={"authority_digest": _digest("substituted-authority")},
    )
    with pytest.raises(TranscriptImmutableConflict, match="substitutes"):
        store_ballot_commitment(
            conn,
            substituted,
            frozen_seat=ceremony[1].frozen_roster[0],
        )
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM sab_ballot_commitments_v1 "
            "WHERE stage = 'cross_examination'"
        ).fetchone()[0]
        == 0
    )
    conn.close()


def test_immutable_identity_and_stage_slot_conflicts_are_rejected(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)
    original = ceremony[0].commitments[0]
    frozen_seat = ceremony[0].frozen_roster[0]
    store_ballot_commitment(conn, original, frozen_seat=frozen_seat)
    conflict = _resign_commitment(
        original,
        updates={"committed_preimage_sha256": _digest("different-preimage")},
    )
    with pytest.raises(
        TranscriptImmutableConflict, match="different transcript content"
    ):
        store_ballot_commitment(conn, conflict, frozen_seat=frozen_seat)
    slot_conflict = _resign_commitment(
        original,
        updates={"commitment_id": "different-identity"},
    )
    with pytest.raises(TranscriptImmutableConflict, match="already has different"):
        store_ballot_commitment(conn, slot_conflict, frozen_seat=frozen_seat)
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_ballot_commitments_v1").fetchone()[0]
        == 1
    )
    conn.close()


def test_transcript_tables_reject_update_and_delete(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)
    store_ceremony_transcript(conn, ceremony)
    with pytest.raises(sqlite3.IntegrityError, match="cannot be updated"):
        conn.execute(
            "UPDATE sab_ballot_reveals_v1 SET recorded_at = 'changed' WHERE reveal_id = ?",
            (ceremony[0].reveals[0].reveal_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
        conn.execute(
            "DELETE FROM sab_ceremony_stage_envelopes_v1 WHERE envelope_id = ?",
            (ceremony[2].envelope_id,),
        )
    conn.close()


def test_atomic_store_rolls_back_all_stages_on_injected_failure(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)

    def fail(boundary: str) -> None:
        if boundary == "reveal:cross_examination:4":
            raise RuntimeError(boundary)

    with pytest.raises(RuntimeError, match="reveal:cross_examination:4"):
        store_ceremony_transcript(conn, ceremony, failure_hook=fail)
    for table in (
        "sab_ballot_commitments_v1",
        "sab_ballot_reveals_v1",
        "sab_ceremony_stage_envelopes_v1",
    ):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    assert not conn.in_transaction
    conn.close()


def test_failed_nested_store_preserves_callers_outer_transaction(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)
    conn.execute("CREATE TABLE caller_state (value TEXT NOT NULL)")
    conn.commit()
    conn.execute("BEGIN")
    conn.execute("INSERT INTO caller_state VALUES ('outer-change')")

    def fail(boundary: str) -> None:
        if boundary == "commitment:cross_examination:2":
            raise RuntimeError(boundary)

    with pytest.raises(RuntimeError, match="commitment:cross_examination:2"):
        store_ceremony_transcript(conn, ceremony, failure_hook=fail)
    assert conn.in_transaction
    assert (
        conn.execute("SELECT value FROM caller_state").fetchone()[0] == "outer-change"
    )
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_ballot_commitments_v1").fetchone()[0]
        == 0
    )
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM caller_state").fetchone()[0] == 0
    conn.close()


def test_store_rejects_invalid_transcript_before_mutation(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)
    with pytest.raises(TranscriptValidationFailure) as raised:
        store_ceremony_transcript(conn, (ceremony[0], ceremony[2]))
    assert "final_requires_cross_examination" in _codes(raised.value.result)
    assert (
        conn.execute("SELECT COUNT(*) FROM sab_ballot_commitments_v1").fetchone()[0]
        == 0
    )
    conn.close()


def test_read_detects_digest_tampering_even_if_append_only_trigger_is_removed(
    ceremony: tuple[CeremonyStageEnvelopeV1, ...],
) -> None:
    conn = _connect()
    init_transcript_storage(conn)
    store_ceremony_transcript(conn, ceremony)
    conn.execute("DROP TRIGGER sab_ballot_reveals_v1_reject_update")
    conn.execute(
        "UPDATE sab_ballot_reveals_v1 SET reveal_sha256 = ? WHERE reveal_id = ?",
        (_digest("tampered"), ceremony[0].reveals[0].reveal_id),
    )
    with pytest.raises(TranscriptStoredRecordError, match="digest mismatch"):
        read_ballot_reveal(conn, ceremony[0].reveals[0].reveal_id)
    conn.close()
