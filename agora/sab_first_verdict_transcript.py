"""Offline commitment/reveal transcript contracts for first-verdict Build B.

The module deliberately has no provider, network, service, secret, or database
discovery surface.  Pure verification functions return structural readiness,
never disposition authority.  Persistence is additive and accepts only an
explicit SQLite connection already proven by Build A to be an in-memory
fixture or attested copy.

Build A stores one terminal ballot per ``(case, round, seat)``.  Build B does
not alter that uniqueness rule.  Its three-stage evidence lives in separate,
append-only, content-addressed tables keyed by ``(case, stage, seat)`` so the
sealed first pass, cross-examination, and final reveal can coexist.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Mapping, Sequence, TypeVar

from pydantic import (
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .sab_artifact_verdict import (
    SHA256_PATTERN,
    ArtifactBallotV1,
    EvidenceRefV1,
    FrozenSeatV1,
    StrictCanonicalModel,
    canonical_sha256,
    verify_contract_signature,
)
from .sab_first_verdict_storage import require_copy_or_fixture_connection

CeremonyStage = Literal["sealed_first_pass", "cross_examination", "final"]
CEREMONY_STAGES: tuple[CeremonyStage, ...] = (
    "sealed_first_pass",
    "cross_examination",
    "final",
)
STAGE_INDEX: dict[str, int] = {
    stage: index for index, stage in enumerate(CEREMONY_STAGES)
}
EMPTY_REVEAL_SET_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
COMMITMENT_DOMAIN = "sab.ballot_commitment.preimage.v1"
TRANSCRIPT_MIGRATION_ID = "20260801_first_verdict_transcript_v1"


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _exact_nonblank(value: str, *, field: str) -> str:
    if value != value.strip() or not value:
        raise ValueError(f"{field} must be nonblank canonical text")
    if any(ord(character) < 0x20 for character in value):
        raise ValueError(f"{field} cannot contain control characters")
    return value


def _stage_rules(
    *,
    stage: CeremonyStage,
    stage_index: int,
    preceding_reveal_set_sha256: str,
    final_deliberation_subject_sha256: str | None,
) -> None:
    if stage_index != STAGE_INDEX[stage]:
        raise ValueError("stage_index does not match the canonical stage order")
    if stage == "sealed_first_pass":
        if preceding_reveal_set_sha256 != EMPTY_REVEAL_SET_SHA256:
            raise ValueError(
                "sealed_first_pass must use the empty reveal-set predecessor"
            )
        if final_deliberation_subject_sha256 is not None:
            raise ValueError("only the final stage may bind a deliberation subject")
    elif stage == "cross_examination":
        if preceding_reveal_set_sha256 == EMPTY_REVEAL_SET_SHA256:
            raise ValueError("cross_examination must bind the first-pass reveal set")
        if final_deliberation_subject_sha256 is not None:
            raise ValueError("only the final stage may bind a deliberation subject")
    else:
        if preceding_reveal_set_sha256 == EMPTY_REVEAL_SET_SHA256:
            raise ValueError("final must bind the cross-examination reveal set")
        if final_deliberation_subject_sha256 is None:
            raise ValueError("final must bind a deliberation subject")


class TranscriptCanonicalModel(StrictCanonicalModel):
    """Build B's strict, immutable specialization of Build A canonical JSON."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        use_enum_values=True,
    )


class BallotExecutionFactsV1(TranscriptCanonicalModel):
    """Requested and observed execution facts committed before a reveal."""

    requested_model: str = Field(min_length=1, max_length=200)
    requested_route: str = Field(min_length=1, max_length=240)
    served_provider: str = Field(min_length=1, max_length=120)
    served_model: str = Field(min_length=1, max_length=200)
    served_route: str = Field(min_length=1, max_length=240)
    credited_cluster: str = Field(min_length=1, max_length=160)
    cluster_basis: Literal["evidenced_base_model_or_training_lineage"] = (
        "evidenced_base_model_or_training_lineage"
    )
    model_lineage_evidence_refs: tuple[EvidenceRefV1, ...] = Field(min_length=1)
    transport_correlation_refs: tuple[str, ...]
    correlation_smeared: bool

    @field_validator(
        "requested_model",
        "requested_route",
        "served_provider",
        "served_model",
        "served_route",
        "credited_cluster",
    )
    @classmethod
    def canonical_text(cls, value: str, info: Any) -> str:
        return _exact_nonblank(value, field=str(info.field_name))

    @field_validator("transport_correlation_refs")
    @classmethod
    def exact_correlation_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(
            _exact_nonblank(item, field="transport_correlation_refs") for item in value
        )
        if len(set(normalized)) != len(normalized):
            raise ValueError("transport_correlation_refs must be unique")
        if normalized != tuple(sorted(normalized)):
            raise ValueError("transport_correlation_refs must be canonically sorted")
        return normalized

    @model_validator(mode="after")
    def correlation_disclosure(self) -> "BallotExecutionFactsV1":
        if self.transport_correlation_refs and not self.correlation_smeared:
            raise ValueError("transport correlation must trigger smear disclosure")
        return self

    @classmethod
    def from_ballot(
        cls, ballot: ArtifactBallotV1 | Mapping[str, Any]
    ) -> "BallotExecutionFactsV1":
        parsed = (
            ballot
            if isinstance(ballot, ArtifactBallotV1)
            else ArtifactBallotV1.model_validate(ballot)
        )
        return cls.model_validate(
            {
                "requested_model": parsed.requested_model,
                "requested_route": parsed.requested_route,
                "served_provider": parsed.served_provider,
                "served_model": parsed.served_model,
                "served_route": parsed.served_route,
                "credited_cluster": parsed.credited_cluster,
                "cluster_basis": parsed.cluster_basis,
                "model_lineage_evidence_refs": parsed.model_lineage_evidence_refs,
                "transport_correlation_refs": parsed.transport_correlation_refs,
                "correlation_smeared": parsed.correlation_smeared,
            }
        )


class FinalDeliberationSubjectV1(TranscriptCanonicalModel):
    """The exact question/material handed to every final-stage seat."""

    schema_: Literal["sab.final_deliberation_subject.v1"] = Field(
        "sab.final_deliberation_subject.v1", alias="schema"
    )
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_digest: str = Field(pattern=SHA256_PATTERN)
    rule_digest: str = Field(pattern=SHA256_PATTERN)
    cross_examination_reveal_set_sha256: str = Field(pattern=SHA256_PATTERN)
    stage_input_sha256: str = Field(pattern=SHA256_PATTERN)
    question: str = Field(min_length=1, max_length=12_000)
    deliberation_material_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("case_id", "question")
    @classmethod
    def canonical_text(cls, value: str, info: Any) -> str:
        return _exact_nonblank(value, field=str(info.field_name))


class BallotCommitmentV1(TranscriptCanonicalModel):
    """A seat's context-bound commitment, published before any stage reveal."""

    schema_: Literal["sab.ballot_commitment.v1"] = Field(
        "sab.ballot_commitment.v1", alias="schema"
    )
    commitment_id: str = Field(min_length=1, max_length=240)
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_seat_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_digest: str = Field(pattern=SHA256_PATTERN)
    rule_digest: str = Field(pattern=SHA256_PATTERN)
    stage: CeremonyStage
    stage_index: int = Field(ge=0, le=2)
    stage_input_sha256: str = Field(pattern=SHA256_PATTERN)
    preceding_reveal_set_sha256: str = Field(pattern=SHA256_PATTERN)
    final_deliberation_subject_sha256: str | None = Field(
        default=None, pattern=SHA256_PATTERN
    )
    seat_id: str = Field(min_length=1, max_length=120)
    seat_position: int = Field(ge=0, le=8)
    execution_facts: BallotExecutionFactsV1
    committed_preimage_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("commitment_id", "case_id", "seat_id")
    @classmethod
    def canonical_ids(cls, value: str, info: Any) -> str:
        return _exact_nonblank(value, field=str(info.field_name))

    @model_validator(mode="after")
    def canonical_stage(self) -> "BallotCommitmentV1":
        _stage_rules(
            stage=self.stage,
            stage_index=self.stage_index,
            preceding_reveal_set_sha256=self.preceding_reveal_set_sha256,
            final_deliberation_subject_sha256=self.final_deliberation_subject_sha256,
        )
        return self


class BallotRevealV1(TranscriptCanonicalModel):
    """The public preimage and ballot corresponding to one commitment."""

    schema_: Literal["sab.ballot_reveal.v1"] = Field(
        "sab.ballot_reveal.v1", alias="schema"
    )
    reveal_id: str = Field(min_length=1, max_length=240)
    commitment_id: str = Field(min_length=1, max_length=240)
    commitment_sha256: str = Field(pattern=SHA256_PATTERN)
    commitment_set_sha256: str = Field(pattern=SHA256_PATTERN)
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_seat_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_digest: str = Field(pattern=SHA256_PATTERN)
    rule_digest: str = Field(pattern=SHA256_PATTERN)
    stage: CeremonyStage
    stage_index: int = Field(ge=0, le=2)
    stage_input_sha256: str = Field(pattern=SHA256_PATTERN)
    preceding_reveal_set_sha256: str = Field(pattern=SHA256_PATTERN)
    final_deliberation_subject_sha256: str | None = Field(
        default=None, pattern=SHA256_PATTERN
    )
    seat_id: str = Field(min_length=1, max_length=120)
    seat_position: int = Field(ge=0, le=8)
    execution_facts: BallotExecutionFactsV1
    nonce: str = Field(min_length=16, max_length=512)
    ballot: ArtifactBallotV1
    ballot_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("reveal_id", "commitment_id", "case_id", "seat_id", "nonce")
    @classmethod
    def canonical_ids(cls, value: str, info: Any) -> str:
        return _exact_nonblank(value, field=str(info.field_name))

    @model_validator(mode="after")
    def ballot_and_stage_are_bound(self) -> "BallotRevealV1":
        _stage_rules(
            stage=self.stage,
            stage_index=self.stage_index,
            preceding_reveal_set_sha256=self.preceding_reveal_set_sha256,
            final_deliberation_subject_sha256=self.final_deliberation_subject_sha256,
        )
        if self.ballot_sha256 != self.ballot.canonical_sha256():
            raise ValueError("ballot_sha256 does not bind the canonical ballot")
        if (
            self.ballot.case_id != self.case_id
            or self.ballot.case_sha256 != self.case_sha256
            or self.ballot.seat_id != self.seat_id
            or self.ballot.stage != self.stage
        ):
            raise ValueError("revealed ballot case, seat, or stage binding differs")
        if BallotExecutionFactsV1.from_ballot(self.ballot) != self.execution_facts:
            raise ValueError(
                "revealed ballot execution facts differ from the commitment facts"
            )
        return self


_COMMITMENT_PREIMAGE_FIELDS = (
    "commitment_id",
    "case_id",
    "case_sha256",
    "frozen_roster_sha256",
    "frozen_seat_sha256",
    "authority_digest",
    "rule_digest",
    "stage",
    "stage_index",
    "stage_input_sha256",
    "preceding_reveal_set_sha256",
    "final_deliberation_subject_sha256",
    "seat_id",
    "seat_position",
    "execution_facts",
)


def ballot_commitment_preimage_payload(
    commitment: BallotCommitmentV1 | Mapping[str, Any],
    *,
    nonce: str,
    ballot: ArtifactBallotV1 | Mapping[str, Any],
) -> dict[str, Any]:
    """Return the exact domain-separated preimage committed by Build B."""

    source = (
        commitment.canonical_payload()
        if isinstance(commitment, BallotCommitmentV1)
        else dict(commitment)
    )
    missing = [field for field in _COMMITMENT_PREIMAGE_FIELDS if field not in source]
    if missing:
        raise ValueError(f"commitment context is missing fields: {', '.join(missing)}")
    parsed_ballot = (
        ballot
        if isinstance(ballot, ArtifactBallotV1)
        else ArtifactBallotV1.model_validate(ballot)
    )
    canonical_nonce = _exact_nonblank(nonce, field="nonce")
    if not 16 <= len(canonical_nonce) <= 512:
        raise ValueError("nonce must contain between 16 and 512 characters")
    bindings: dict[str, Any] = {}
    for field in _COMMITMENT_PREIMAGE_FIELDS:
        value = source[field]
        if isinstance(value, StrictCanonicalModel):
            value = value.canonical_payload()
        bindings[field] = value
    return {
        "domain": COMMITMENT_DOMAIN,
        "bindings": bindings,
        "nonce": canonical_nonce,
        "ballot": parsed_ballot.canonical_payload(),
    }


def ballot_commitment_preimage_sha256(
    commitment: BallotCommitmentV1 | Mapping[str, Any],
    *,
    nonce: str,
    ballot: ArtifactBallotV1 | Mapping[str, Any],
) -> str:
    return canonical_sha256(
        ballot_commitment_preimage_payload(commitment, nonce=nonce, ballot=ballot)
    )


def canonical_commitment_set_sha256(
    commitments: Sequence[BallotCommitmentV1],
) -> str:
    members = [
        {
            "seat_position": item.seat_position,
            "seat_id": item.seat_id,
            "commitment_id": item.commitment_id,
            "commitment_sha256": item.canonical_sha256(),
        }
        for item in commitments
    ]
    return canonical_sha256(members)


def canonical_reveal_set_sha256(reveals: Sequence[BallotRevealV1]) -> str:
    members = [
        {
            "seat_position": item.seat_position,
            "seat_id": item.seat_id,
            "reveal_id": item.reveal_id,
            "reveal_sha256": item.canonical_sha256(),
            "ballot_sha256": item.ballot_sha256,
        }
        for item in reveals
    ]
    return canonical_sha256(members)


class TranscriptValidationErrorV1(TranscriptCanonicalModel):
    code: str = Field(min_length=1, max_length=120)
    path: str = Field(min_length=1, max_length=500)
    detail: str = Field(min_length=1, max_length=2000)


class TranscriptValidationResultV1(TranscriptCanonicalModel):
    """Structural readiness only; this type cannot carry disposition authority."""

    schema_: Literal["sab.transcript_validation_result.v1"] = Field(
        "sab.transcript_validation_result.v1", alias="schema"
    )
    ok: bool
    readiness: Literal["structurally_ready_awaiting_authority", "blocked"]
    errors: tuple[TranscriptValidationErrorV1, ...]
    expected_seat_ids: tuple[str, ...]
    validated_stages: tuple[CeremonyStage, ...]
    ordered_final_ballots: tuple[ArtifactBallotV1, ...]
    transcript_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    frozen_roster_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    rule_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    authority_effect: Literal["none"] = "none"
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False

    @model_validator(mode="after")
    def readiness_matches_errors(self) -> "TranscriptValidationResultV1":
        if self.ok != (not self.errors):
            raise ValueError("ok must be the inverse of errors")
        expected = "structurally_ready_awaiting_authority" if self.ok else "blocked"
        if self.readiness != expected:
            raise ValueError("readiness does not match validation errors")
        if not self.ok and (
            self.ordered_final_ballots
            or self.transcript_sha256
            or self.frozen_roster_sha256
            or self.rule_digest
        ):
            raise ValueError(
                "blocked validation cannot expose ballots or trusted transcript digests"
            )
        if self.ok and (self.frozen_roster_sha256 is None or self.rule_digest is None):
            raise ValueError(
                "successful validation must expose frozen-roster and rule digests"
            )
        return self

    @property
    def final_ballot_payloads(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            ballot.canonical_payload() for ballot in self.ordered_final_ballots
        )


def _error(code: str, path: str, detail: str) -> TranscriptValidationErrorV1:
    return TranscriptValidationErrorV1(code=code, path=path, detail=detail)


def _safe_validation_detail(exc: Exception) -> str:
    """Describe invalid structure without echoing submitted values or secrets."""

    if isinstance(exc, ValidationError):
        parts = []
        for item in exc.errors(
            include_url=False, include_context=False, include_input=False
        ):
            location = ".".join(str(part) for part in item.get("loc", ())) or "record"
            parts.append(f"{location}: {item.get('msg', 'invalid value')}")
        detail = "; ".join(parts) or "contract validation failed"
    else:
        detail = f"{type(exc).__name__}: {exc}"
    return detail[:2000]


def _result(
    errors: Sequence[TranscriptValidationErrorV1],
    *,
    expected_seat_ids: Sequence[str] = (),
    validated_stages: Sequence[CeremonyStage] = (),
    final_ballots: Sequence[ArtifactBallotV1] = (),
    transcript_sha256: str | None = None,
    frozen_roster_sha256: str | None = None,
    rule_digest: str | None = None,
) -> TranscriptValidationResultV1:
    unique: list[TranscriptValidationErrorV1] = []
    seen: set[tuple[str, str, str]] = set()
    for issue in errors:
        identity = (issue.code, issue.path, issue.detail)
        if identity not in seen:
            unique.append(issue)
            seen.add(identity)
    ok = not unique
    return TranscriptValidationResultV1(
        ok=ok,
        readiness=("structurally_ready_awaiting_authority" if ok else "blocked"),
        errors=tuple(unique),
        expected_seat_ids=tuple(expected_seat_ids),
        validated_stages=tuple(validated_stages),
        ordered_final_ballots=tuple(final_ballots) if ok else (),
        transcript_sha256=transcript_sha256 if ok else None,
        frozen_roster_sha256=frozen_roster_sha256 if ok else None,
        rule_digest=rule_digest if ok else None,
    )


_PAIR_BINDING_FIELDS = (
    "case_id",
    "case_sha256",
    "frozen_roster_sha256",
    "frozen_seat_sha256",
    "authority_digest",
    "rule_digest",
    "stage",
    "stage_index",
    "stage_input_sha256",
    "preceding_reveal_set_sha256",
    "final_deliberation_subject_sha256",
    "seat_id",
    "seat_position",
    "execution_facts",
)


def _verify_commit_reveal_models(
    commitment: BallotCommitmentV1,
    reveal: BallotRevealV1,
    *,
    path: str,
) -> list[TranscriptValidationErrorV1]:
    errors: list[TranscriptValidationErrorV1] = []
    if reveal.commitment_id != commitment.commitment_id:
        errors.append(
            _error(
                "commitment_reference_mismatch",
                f"{path}.commitment_id",
                "reveal references a different commitment identity",
            )
        )
    if reveal.commitment_sha256 != commitment.canonical_sha256():
        errors.append(
            _error(
                "commitment_digest_mismatch",
                f"{path}.commitment_sha256",
                "reveal does not bind the canonical commitment record",
            )
        )
    for field in _PAIR_BINDING_FIELDS:
        if getattr(reveal, field) != getattr(commitment, field):
            errors.append(
                _error(
                    "commit_reveal_binding_mismatch",
                    f"{path}.{field}",
                    f"commitment and reveal disagree on {field}",
                )
            )
    expected_preimage = ballot_commitment_preimage_sha256(
        commitment,
        nonce=reveal.nonce,
        ballot=reveal.ballot,
    )
    if expected_preimage != commitment.committed_preimage_sha256:
        errors.append(
            _error(
                "commitment_preimage_mismatch",
                f"{path}.committed_preimage_sha256",
                "revealed nonce and ballot do not open the commitment",
            )
        )
    return errors


def verify_commit_reveal(
    commitment: BallotCommitmentV1 | Mapping[str, Any],
    reveal: BallotRevealV1 | Mapping[str, Any],
    *,
    frozen_seat: FrozenSeatV1 | Mapping[str, Any] | None = None,
) -> TranscriptValidationResultV1:
    """Verify one pair and its frozen-seat signature without producing authority."""

    try:
        parsed_commitment = BallotCommitmentV1.model_validate(
            commitment.canonical_payload()
            if isinstance(commitment, BallotCommitmentV1)
            else commitment
        )
    except Exception as exc:
        return _result(
            [
                _error(
                    "invalid_commitment_contract",
                    "commitment",
                    _safe_validation_detail(exc),
                )
            ]
        )
    try:
        parsed_reveal = BallotRevealV1.model_validate(
            reveal.canonical_payload() if isinstance(reveal, BallotRevealV1) else reveal
        )
    except Exception as exc:
        return _result(
            [
                _error(
                    "invalid_reveal_contract",
                    "reveal",
                    _safe_validation_detail(exc),
                )
            ]
        )
    errors = _verify_commit_reveal_models(parsed_commitment, parsed_reveal, path="pair")
    if frozen_seat is None:
        errors.append(
            _error(
                "frozen_seat_required",
                "frozen_seat",
                "signature verification requires the trusted frozen seat",
            )
        )
    else:
        try:
            parsed_seat = (
                FrozenSeatV1.model_validate(frozen_seat.canonical_payload())
                if isinstance(frozen_seat, FrozenSeatV1)
                else FrozenSeatV1.model_validate(frozen_seat)
            )
        except Exception as exc:
            errors.append(
                _error(
                    "frozen_seat_invalid",
                    "frozen_seat",
                    _safe_validation_detail(exc),
                )
            )
        else:
            if (
                parsed_commitment.seat_id != parsed_seat.seat_id
                or parsed_reveal.seat_id != parsed_seat.seat_id
                or parsed_commitment.frozen_seat_sha256
                != parsed_seat.canonical_sha256()
                or parsed_reveal.frozen_seat_sha256 != parsed_seat.canonical_sha256()
                or not _facts_match_frozen_seat(
                    parsed_commitment.execution_facts, parsed_seat
                )
                or not _facts_match_frozen_seat(
                    parsed_reveal.execution_facts, parsed_seat
                )
            ):
                errors.append(
                    _error(
                        "frozen_seat_mismatch",
                        "frozen_seat",
                        "commitment or reveal differs from the trusted frozen seat",
                    )
                )
            errors.extend(
                _verify_ballot_authenticity(
                    parsed_reveal.ballot,
                    parsed_seat,
                    path="pair.ballot.execution_signature",
                )
            )
    return _result(
        errors,
        expected_seat_ids=(parsed_commitment.seat_id,),
        validated_stages=(parsed_commitment.stage,),
        final_ballots=(parsed_reveal.ballot,) if parsed_reveal.stage == "final" else (),
        frozen_roster_sha256=parsed_commitment.frozen_roster_sha256,
        rule_digest=parsed_commitment.rule_digest,
    )


def _facts_match_frozen_seat(facts: BallotExecutionFactsV1, seat: FrozenSeatV1) -> bool:
    return (
        facts.requested_model == seat.requested_model
        and facts.requested_route == seat.requested_route
        and facts.served_provider == seat.served_provider
        and facts.served_model == seat.served_model
        and facts.served_route in seat.possible_underlying_routes
        and facts.credited_cluster == seat.credited_cluster
        and facts.cluster_basis == seat.cluster_basis
        and facts.model_lineage_evidence_refs == seat.model_lineage_evidence_refs
        and facts.transport_correlation_refs == seat.transport_correlation_refs
        and facts.correlation_smeared == seat.correlation_smeared
    )


def _verify_ballot_authenticity(
    ballot: ArtifactBallotV1,
    seat: FrozenSeatV1,
    *,
    path: str,
) -> list[TranscriptValidationErrorV1]:
    """Bind an execution signature to the exact frozen seat before verifying it."""

    errors: list[TranscriptValidationErrorV1] = []
    signature = ballot.execution_signature
    if signature.signer != seat.seat_id:
        errors.append(
            _error(
                "ballot_signature_signer_mismatch",
                f"{path}.signer",
                "ballot signature signer differs from the frozen seat identity",
            )
        )
    if signature.public_key != seat.execution_public_key:
        errors.append(
            _error(
                "ballot_signature_key_mismatch",
                f"{path}.public_key",
                "ballot signature key differs from the frozen seat key",
            )
        )
    if not errors and not verify_contract_signature(
        ballot.canonical_bytes(exclude={"execution_signature"}), signature
    ):
        errors.append(
            _error(
                "ballot_signature_invalid",
                path,
                "ballot execution signature does not verify over canonical "
                "unsigned bytes",
            )
        )
    return errors


class CeremonyStageEnvelopeV1(TranscriptCanonicalModel):
    """A closed commit-then-reveal stage for the exact frozen nine-seat bench."""

    schema_: Literal["sab.ceremony_stage_envelope.v1"] = Field(
        "sab.ceremony_stage_envelope.v1", alias="schema"
    )
    envelope_id: str = Field(min_length=1, max_length=240)
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster: tuple[FrozenSeatV1, ...] = Field(min_length=9, max_length=9)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_seat_ids: tuple[str, ...] = Field(min_length=9, max_length=9)
    authority_digest: str = Field(pattern=SHA256_PATTERN)
    rule_digest: str = Field(pattern=SHA256_PATTERN)
    stage: CeremonyStage
    stage_index: int = Field(ge=0, le=2)
    stage_input_sha256: str = Field(pattern=SHA256_PATTERN)
    preceding_reveal_set_sha256: str = Field(pattern=SHA256_PATTERN)
    final_deliberation_subject: FinalDeliberationSubjectV1 | None = None
    final_deliberation_subject_sha256: str | None = Field(
        default=None, pattern=SHA256_PATTERN
    )
    commitments: tuple[BallotCommitmentV1, ...] = Field(min_length=9, max_length=9)
    commitment_set_sha256: str = Field(pattern=SHA256_PATTERN)
    commitments_closed_before_reveals: Literal[True] = True
    reveals: tuple[BallotRevealV1, ...] = Field(min_length=9, max_length=9)
    reveal_set_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_effect: Literal["none"] = "none"
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False

    @field_validator("envelope_id", "case_id")
    @classmethod
    def canonical_ids(cls, value: str, info: Any) -> str:
        return _exact_nonblank(value, field=str(info.field_name))

    @field_validator("expected_seat_ids")
    @classmethod
    def exact_seat_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(
            _exact_nonblank(item, field="expected_seat_ids") for item in value
        )
        if len(set(normalized)) != 9:
            raise ValueError("expected_seat_ids must contain nine unique seats")
        return normalized

    @model_validator(mode="after")
    def closed_stage_bindings(self) -> "CeremonyStageEnvelopeV1":
        _stage_rules(
            stage=self.stage,
            stage_index=self.stage_index,
            preceding_reveal_set_sha256=self.preceding_reveal_set_sha256,
            final_deliberation_subject_sha256=self.final_deliberation_subject_sha256,
        )
        roster_ids = tuple(seat.seat_id for seat in self.frozen_roster)
        if len(set(roster_ids)) != 9 or roster_ids != self.expected_seat_ids:
            raise ValueError(
                "frozen roster must exactly match ordered expected_seat_ids"
            )
        if (
            canonical_sha256([seat.canonical_payload() for seat in self.frozen_roster])
            != self.frozen_roster_sha256
        ):
            raise ValueError("frozen_roster_sha256 does not bind the ordered roster")
        if tuple(item.seat_id for item in self.commitments) != self.expected_seat_ids:
            raise ValueError("commitments must appear once in frozen seat order")
        if tuple(item.seat_position for item in self.commitments) != tuple(range(9)):
            raise ValueError("commitment seat positions must be exactly 0 through 8")
        if tuple(item.seat_id for item in self.reveals) != self.expected_seat_ids:
            raise ValueError("reveals must appear once in frozen seat order")
        if tuple(item.seat_position for item in self.reveals) != tuple(range(9)):
            raise ValueError("reveal seat positions must be exactly 0 through 8")
        if len({item.commitment_id for item in self.commitments}) != 9:
            raise ValueError("commitment identities must be unique")
        if len({item.reveal_id for item in self.reveals}) != 9:
            raise ValueError("reveal identities must be unique")
        if (
            canonical_commitment_set_sha256(self.commitments)
            != self.commitment_set_sha256
        ):
            raise ValueError(
                "commitment_set_sha256 does not bind the ordered commitments"
            )
        if canonical_reveal_set_sha256(self.reveals) != self.reveal_set_sha256:
            raise ValueError("reveal_set_sha256 does not bind the ordered reveals")

        common = (
            "case_id",
            "case_sha256",
            "frozen_roster_sha256",
            "authority_digest",
            "rule_digest",
            "stage",
            "stage_index",
            "stage_input_sha256",
            "preceding_reveal_set_sha256",
            "final_deliberation_subject_sha256",
        )
        for position, (seat, commitment, reveal) in enumerate(
            zip(self.frozen_roster, self.commitments, self.reveals)
        ):
            for item in (commitment, reveal):
                if any(
                    getattr(item, field) != getattr(self, field) for field in common
                ):
                    raise ValueError(f"seat {position} differs from envelope bindings")
                if item.frozen_seat_sha256 != seat.canonical_sha256():
                    raise ValueError(f"seat {position} does not bind its frozen seat")
                if not _facts_match_frozen_seat(item.execution_facts, seat):
                    raise ValueError(
                        f"seat {position} execution facts differ from frozen bench"
                    )
            if reveal.commitment_set_sha256 != self.commitment_set_sha256:
                raise ValueError("every reveal must bind the closed commitment set")
            pair_errors = _verify_commit_reveal_models(
                commitment, reveal, path=f"seats[{position}]"
            )
            if pair_errors:
                raise ValueError(pair_errors[0].detail)

        if self.stage == "final":
            if self.final_deliberation_subject is None:
                raise ValueError("final stage requires its deliberation subject")
            subject = self.final_deliberation_subject
            if subject.canonical_sha256() != self.final_deliberation_subject_sha256:
                raise ValueError("final deliberation subject digest mismatch")
            subject_bindings = (
                subject.case_id == self.case_id,
                subject.case_sha256 == self.case_sha256,
                subject.frozen_roster_sha256 == self.frozen_roster_sha256,
                subject.authority_digest == self.authority_digest,
                subject.rule_digest == self.rule_digest,
                subject.cross_examination_reveal_set_sha256
                == self.preceding_reveal_set_sha256,
                subject.stage_input_sha256 == self.stage_input_sha256,
            )
            if not all(subject_bindings):
                raise ValueError(
                    "final deliberation subject differs from final bindings"
                )
        elif (
            self.final_deliberation_subject is not None
            or self.final_deliberation_subject_sha256 is not None
        ):
            raise ValueError("non-final stage cannot contain a deliberation subject")
        return self


def _parse_envelopes(
    envelopes: Sequence[CeremonyStageEnvelopeV1 | Mapping[str, Any]],
) -> tuple[list[CeremonyStageEnvelopeV1], list[TranscriptValidationErrorV1]]:
    parsed: list[CeremonyStageEnvelopeV1] = []
    errors: list[TranscriptValidationErrorV1] = []
    if isinstance(envelopes, (str, bytes, bytearray)) or not isinstance(
        envelopes, Sequence
    ):
        return [], [
            _error(
                "invalid_transcript_contract",
                "envelopes",
                "envelopes must be an ordered sequence",
            )
        ]
    for index, envelope in enumerate(envelopes):
        try:
            parsed.append(
                CeremonyStageEnvelopeV1.model_validate(
                    envelope.canonical_payload()
                    if isinstance(envelope, CeremonyStageEnvelopeV1)
                    else envelope
                )
            )
        except Exception as exc:
            errors.append(
                _error(
                    "invalid_stage_envelope_contract",
                    f"envelopes[{index}]",
                    _safe_validation_detail(exc),
                )
            )
    return parsed, errors


def _parse_expected_roster(
    expected_roster: Sequence[FrozenSeatV1 | Mapping[str, Any] | str] | None,
) -> tuple[tuple[str, ...], str | None, list[TranscriptValidationErrorV1]]:
    if expected_roster is None:
        return (), None, []
    if isinstance(expected_roster, (str, bytes, bytearray)) or not isinstance(
        expected_roster, Sequence
    ):
        return (
            (),
            None,
            [
                _error(
                    "invalid_expected_roster",
                    "expected_roster",
                    "expected_roster must be an ordered sequence",
                )
            ],
        )
    if len(expected_roster) != 9:
        return (
            (),
            None,
            [
                _error(
                    "expected_roster_size_mismatch",
                    "expected_roster",
                    "the ceremony requires exactly nine expected seats",
                )
            ],
        )
    if all(isinstance(item, str) for item in expected_roster):
        try:
            ids = tuple(
                _exact_nonblank(str(item), field="expected_roster")
                for item in expected_roster
            )
        except ValueError as exc:
            return (
                (),
                None,
                [
                    _error(
                        "invalid_expected_roster",
                        "expected_roster",
                        _safe_validation_detail(exc),
                    )
                ],
            )
        if len(set(ids)) != 9:
            return (
                (),
                None,
                [
                    _error(
                        "duplicate_expected_seat",
                        "expected_roster",
                        "expected roster contains duplicate seat identities",
                    )
                ],
            )
        return ids, None, []
    try:
        seats = tuple(
            item
            if isinstance(item, FrozenSeatV1)
            else FrozenSeatV1.model_validate(item)
            for item in expected_roster
        )
    except Exception as exc:
        return (
            (),
            None,
            [
                _error(
                    "invalid_expected_roster",
                    "expected_roster",
                    _safe_validation_detail(exc),
                )
            ],
        )
    ids = tuple(seat.seat_id for seat in seats)
    if len(set(ids)) != 9:
        return (
            (),
            None,
            [
                _error(
                    "duplicate_expected_seat",
                    "expected_roster",
                    "expected roster contains duplicate seat identities",
                )
            ],
        )
    digest = canonical_sha256([seat.canonical_payload() for seat in seats])
    return ids, digest, []


def verify_ceremony_transcript(
    envelopes: Sequence[CeremonyStageEnvelopeV1 | Mapping[str, Any]],
    *,
    expected_roster: Sequence[FrozenSeatV1 | Mapping[str, Any] | str] | None = None,
    expected_seat_ids: Sequence[str] | None = None,
) -> TranscriptValidationResultV1:
    """Validate the exact three-stage ceremony as non-authorizing evidence.

    ``expected_roster`` may be the full frozen roster or an ordered tuple of
    seat IDs.  ``expected_seat_ids`` is a convenience alias; supplying both is
    rejected so there is only one external source of roster truth.
    """

    if expected_roster is not None and expected_seat_ids is not None:
        return _result(
            [
                _error(
                    "ambiguous_expected_roster",
                    "expected_roster",
                    "provide expected_roster or expected_seat_ids, not both",
                )
            ]
        )
    if isinstance(envelopes, (str, bytes, bytearray)) or not isinstance(
        envelopes, Sequence
    ):
        return _result(
            [
                _error(
                    "invalid_transcript_contract",
                    "envelopes",
                    "envelopes must be an ordered sequence",
                )
            ]
        )
    roster_input: Sequence[FrozenSeatV1 | Mapping[str, Any] | str] | None = (
        expected_roster if expected_roster is not None else expected_seat_ids
    )
    external_ids, external_digest, roster_errors = _parse_expected_roster(roster_input)
    parsed, errors = _parse_envelopes(envelopes)
    errors = [*roster_errors, *errors]
    if len(envelopes) != 3:
        errors.append(
            _error(
                "stage_count_mismatch",
                "envelopes",
                "transcript must contain exactly three stage envelopes",
            )
        )
    if len(parsed) != len(envelopes):
        return _result(errors, expected_seat_ids=external_ids)
    if not parsed:
        return _result(errors, expected_seat_ids=external_ids)

    observed_stages = tuple(envelope.stage for envelope in parsed)
    if observed_stages != CEREMONY_STAGES:
        errors.append(
            _error(
                "stage_order_mismatch",
                "envelopes",
                "stage order must be sealed_first_pass, cross_examination, final",
            )
        )
    final_positions = [
        index for index, envelope in enumerate(parsed) if envelope.stage == "final"
    ]
    if final_positions and not any(
        index > 0 and parsed[index - 1].stage == "cross_examination"
        for index in final_positions
    ):
        errors.append(
            _error(
                "final_requires_cross_examination",
                f"envelopes[{final_positions[0]}]",
                "final cannot exist without an immediately preceding cross-examination stage",
            )
        )
    first = parsed[0]
    expected_ids = external_ids or first.expected_seat_ids
    if len(expected_ids) != 9 or len(set(expected_ids)) != 9:
        errors.append(
            _error(
                "expected_roster_size_mismatch",
                "expected_roster",
                "the ceremony requires nine unique expected seats",
            )
        )
    if external_digest is not None and first.frozen_roster_sha256 != external_digest:
        errors.append(
            _error(
                "frozen_roster_digest_mismatch",
                "envelopes[0].frozen_roster_sha256",
                "transcript frozen roster differs from the explicit roster",
            )
        )

    shared_fields = (
        "case_id",
        "case_sha256",
        "frozen_roster_sha256",
        "authority_digest",
        "rule_digest",
        "expected_seat_ids",
    )
    for index, envelope in enumerate(parsed):
        if envelope.expected_seat_ids != tuple(expected_ids):
            errors.append(
                _error(
                    "roster_substitution_or_reordering",
                    f"envelopes[{index}].expected_seat_ids",
                    "stage roster differs from the exact expected seat order",
                )
            )
        for field in shared_fields:
            if getattr(envelope, field) != getattr(first, field):
                errors.append(
                    _error(
                        "stage_binding_mismatch",
                        f"envelopes[{index}].{field}",
                        f"stage differs from sealed_first_pass on {field}",
                    )
                )
        if envelope.stage_index != index:
            errors.append(
                _error(
                    "stage_order_mismatch",
                    f"envelopes[{index}].stage_index",
                    "stage index differs from transcript position",
                )
            )
        for position, (seat, reveal) in enumerate(
            zip(envelope.frozen_roster, envelope.reveals)
        ):
            errors.extend(
                _verify_ballot_authenticity(
                    reveal.ballot,
                    seat,
                    path=(
                        f"envelopes[{index}].reveals[{position}]"
                        ".ballot.execution_signature"
                    ),
                )
            )

    if len({envelope.envelope_id for envelope in parsed}) != len(parsed):
        errors.append(
            _error(
                "duplicate_stage_envelope",
                "envelopes",
                "stage envelope identities must be unique",
            )
        )
    if len(parsed) >= 2 and (
        parsed[1].preceding_reveal_set_sha256 != parsed[0].reveal_set_sha256
    ):
        errors.append(
            _error(
                "preceding_reveal_set_mismatch",
                "envelopes[1].preceding_reveal_set_sha256",
                "cross-examination does not bind the sealed first-pass reveal set",
            )
        )
    if len(parsed) >= 3 and (
        parsed[2].preceding_reveal_set_sha256 != parsed[1].reveal_set_sha256
    ):
        errors.append(
            _error(
                "final_requires_cross_examination",
                "envelopes[2].preceding_reveal_set_sha256",
                "final does not bind the immediately preceding cross-examination reveals",
            )
        )
    if len(parsed) >= 3:
        subject = parsed[2].final_deliberation_subject
        if (
            subject is None
            or subject.cross_examination_reveal_set_sha256
            != parsed[1].reveal_set_sha256
        ):
            errors.append(
                _error(
                    "final_deliberation_subject_mismatch",
                    "envelopes[2].final_deliberation_subject",
                    "final subject does not bind the cross-examination reveal set",
                )
            )

    commitments = [item for envelope in parsed for item in envelope.commitments]
    reveals = [item for envelope in parsed for item in envelope.reveals]
    ballots = [item.ballot for item in reveals]
    for values, code, detail in (
        (
            [item.commitment_id for item in commitments],
            "duplicate_commitment_identity",
            "commitment identities cannot be reused across stages",
        ),
        (
            [item.reveal_id for item in reveals],
            "duplicate_reveal_identity",
            "reveal identities cannot be reused across stages",
        ),
        (
            [item.ballot_id for item in ballots],
            "duplicate_ballot_identity",
            "ballot identities cannot be reused across stages",
        ),
    ):
        if len(set(values)) != len(values):
            errors.append(_error(code, "envelopes", detail))

    complete = len(parsed) == 3 and observed_stages == CEREMONY_STAGES
    transcript_digest = (
        canonical_sha256([envelope.canonical_payload() for envelope in parsed])
        if complete and not errors
        else None
    )
    final_ballots = parsed[2].reveals if complete and not errors else ()
    return _result(
        errors,
        expected_seat_ids=expected_ids,
        validated_stages=observed_stages if not errors else (),
        final_ballots=tuple(reveal.ballot for reveal in final_ballots),
        transcript_sha256=transcript_digest,
        frozen_roster_sha256=first.frozen_roster_sha256,
        rule_digest=first.rule_digest,
    )


class TranscriptStorageError(RuntimeError):
    """Base class for deterministic offline transcript storage failures."""


class TranscriptMigrationError(TranscriptStorageError):
    pass


class TranscriptForeignKeysRequired(TranscriptStorageError):
    pass


class TranscriptImmutableConflict(TranscriptStorageError):
    pass


class TranscriptValidationFailure(TranscriptStorageError):
    def __init__(self, result: TranscriptValidationResultV1) -> None:
        self.result = result
        codes = ", ".join(error.code for error in result.errors)
        super().__init__(f"transcript validation blocked: {codes}")


class TranscriptStoredRecordError(TranscriptStorageError):
    pass


_LEDGER_STATEMENT = """
CREATE TABLE IF NOT EXISTS sab_first_verdict_transcript_migrations_v1 (
    migration_id TEXT PRIMARY KEY,
    migration_digest TEXT NOT NULL CHECK (length(migration_digest) = 64),
    applied_at TEXT NOT NULL
)
"""

_TABLE_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS sab_ballot_commitments_v1 (
        commitment_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        stage TEXT NOT NULL CHECK (
            stage IN ('sealed_first_pass', 'cross_examination', 'final')
        ),
        stage_index INTEGER NOT NULL CHECK (
            (stage = 'sealed_first_pass' AND stage_index = 0) OR
            (stage = 'cross_examination' AND stage_index = 1) OR
            (stage = 'final' AND stage_index = 2)
        ),
        seat_id TEXT NOT NULL,
        seat_position INTEGER NOT NULL CHECK (seat_position BETWEEN 0 AND 8),
        preceding_reveal_set_sha256 TEXT NOT NULL
            CHECK (length(preceding_reveal_set_sha256) = 64),
        committed_preimage_sha256 TEXT NOT NULL
            CHECK (length(committed_preimage_sha256) = 64),
        commitment_json TEXT NOT NULL,
        commitment_sha256 TEXT NOT NULL UNIQUE
            CHECK (length(commitment_sha256) = 64),
        recorded_at TEXT NOT NULL,
        UNIQUE (case_id, stage, seat_id),
        UNIQUE (case_id, stage, seat_position),
        UNIQUE (
            commitment_id, commitment_sha256, case_id, stage, seat_id, seat_position
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_ballot_reveals_v1 (
        reveal_id TEXT PRIMARY KEY,
        commitment_id TEXT NOT NULL,
        commitment_sha256 TEXT NOT NULL,
        commitment_set_sha256 TEXT NOT NULL
            CHECK (length(commitment_set_sha256) = 64),
        case_id TEXT NOT NULL,
        stage TEXT NOT NULL CHECK (
            stage IN ('sealed_first_pass', 'cross_examination', 'final')
        ),
        stage_index INTEGER NOT NULL CHECK (
            (stage = 'sealed_first_pass' AND stage_index = 0) OR
            (stage = 'cross_examination' AND stage_index = 1) OR
            (stage = 'final' AND stage_index = 2)
        ),
        seat_id TEXT NOT NULL,
        seat_position INTEGER NOT NULL CHECK (seat_position BETWEEN 0 AND 8),
        ballot_sha256 TEXT NOT NULL CHECK (length(ballot_sha256) = 64),
        reveal_json TEXT NOT NULL,
        reveal_sha256 TEXT NOT NULL UNIQUE CHECK (length(reveal_sha256) = 64),
        recorded_at TEXT NOT NULL,
        UNIQUE (case_id, stage, seat_id),
        UNIQUE (case_id, stage, seat_position),
        FOREIGN KEY (
            commitment_id, commitment_sha256, case_id, stage, seat_id, seat_position
        ) REFERENCES sab_ballot_commitments_v1 (
            commitment_id, commitment_sha256, case_id, stage, seat_id, seat_position
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_ceremony_stage_envelopes_v1 (
        envelope_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        stage TEXT NOT NULL CHECK (
            stage IN ('sealed_first_pass', 'cross_examination', 'final')
        ),
        stage_index INTEGER NOT NULL CHECK (
            (stage = 'sealed_first_pass' AND stage_index = 0) OR
            (stage = 'cross_examination' AND stage_index = 1) OR
            (stage = 'final' AND stage_index = 2)
        ),
        preceding_reveal_set_sha256 TEXT NOT NULL
            CHECK (length(preceding_reveal_set_sha256) = 64),
        commitment_set_sha256 TEXT NOT NULL
            CHECK (length(commitment_set_sha256) = 64),
        reveal_set_sha256 TEXT NOT NULL UNIQUE CHECK (length(reveal_set_sha256) = 64),
        final_deliberation_subject_sha256 TEXT
            CHECK (
                final_deliberation_subject_sha256 IS NULL OR
                length(final_deliberation_subject_sha256) = 64
            ),
        envelope_json TEXT NOT NULL,
        envelope_sha256 TEXT NOT NULL UNIQUE CHECK (length(envelope_sha256) = 64),
        recorded_at TEXT NOT NULL,
        UNIQUE (case_id, stage),
        UNIQUE (case_id, stage_index),
        CHECK (
            (stage = 'final' AND final_deliberation_subject_sha256 IS NOT NULL) OR
            (stage != 'final' AND final_deliberation_subject_sha256 IS NULL)
        )
    )
    """,
)


def _immutable_triggers() -> tuple[str, ...]:
    statements: list[str] = []
    for table in (
        "sab_first_verdict_transcript_migrations_v1",
        "sab_ballot_commitments_v1",
        "sab_ballot_reveals_v1",
        "sab_ceremony_stage_envelopes_v1",
    ):
        statements.extend(
            (
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_reject_update
                BEFORE UPDATE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'Build B transcript records cannot be updated');
                END
                """,
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_reject_delete
                BEFORE DELETE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'Build B transcript records cannot be deleted');
                END
                """,
            )
        )
    statements.extend(
        (
            """
            CREATE TRIGGER IF NOT EXISTS sab_ballot_commitments_v1_require_predecessor
            BEFORE INSERT ON sab_ballot_commitments_v1
            WHEN (
                NEW.stage = 'sealed_first_pass'
                AND NEW.preceding_reveal_set_sha256 !=
                    '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
            ) OR (
                NEW.stage = 'cross_examination'
                AND NOT EXISTS (
                    SELECT 1 FROM sab_ceremony_stage_envelopes_v1
                    WHERE case_id = NEW.case_id
                      AND stage = 'sealed_first_pass'
                      AND reveal_set_sha256 = NEW.preceding_reveal_set_sha256
                )
            ) OR (
                NEW.stage = 'final'
                AND NOT EXISTS (
                    SELECT 1 FROM sab_ceremony_stage_envelopes_v1
                    WHERE case_id = NEW.case_id
                      AND stage = 'cross_examination'
                      AND reveal_set_sha256 = NEW.preceding_reveal_set_sha256
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'Build B stage predecessor is missing or mismatched');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS sab_ballot_reveals_v1_require_closed_commitments
            BEFORE INSERT ON sab_ballot_reveals_v1
            WHEN (
                SELECT COUNT(*) FROM sab_ballot_commitments_v1
                WHERE case_id = NEW.case_id AND stage = NEW.stage
            ) != 9
            BEGIN
                SELECT RAISE(ABORT, 'all nine commitments must precede every reveal');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS sab_ceremony_stage_envelopes_v1_require_members
            BEFORE INSERT ON sab_ceremony_stage_envelopes_v1
            WHEN (
                SELECT COUNT(*) FROM sab_ballot_commitments_v1
                WHERE case_id = NEW.case_id AND stage = NEW.stage
            ) != 9 OR (
                SELECT COUNT(*) FROM sab_ballot_reveals_v1
                WHERE case_id = NEW.case_id AND stage = NEW.stage
            ) != 9
            BEGIN
                SELECT RAISE(ABORT, 'stage envelope requires nine commitments and reveals');
            END
            """,
        )
    )
    return tuple(statements)


TRANSCRIPT_MIGRATION_STATEMENTS = (
    _LEDGER_STATEMENT,
    *_TABLE_STATEMENTS,
    *_immutable_triggers(),
)
TRANSCRIPT_MIGRATION_DIGEST = hashlib.sha256(
    "\n".join(
        statement.strip() for statement in TRANSCRIPT_MIGRATION_STATEMENTS
    ).encode("utf-8")
).hexdigest()

_SCHEMA_OBJECT = re.compile(
    r"^CREATE\s+(?:TABLE|TRIGGER)\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


def _normalized_sql(statement: str) -> str:
    return re.sub(r"\s+", " ", statement.strip()).replace(" IF NOT EXISTS ", " ")


def _verify_migration_schema(conn: sqlite3.Connection) -> None:
    for statement in TRANSCRIPT_MIGRATION_STATEMENTS:
        match = _SCHEMA_OBJECT.match(statement.strip())
        if match is None:
            raise TranscriptMigrationError(
                "unrecognized transcript migration statement"
            )
        name = match.group(1)
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = ?", (name,)
        ).fetchone()
        actual = "" if row is None or row[0] is None else _normalized_sql(str(row[0]))
        if actual != _normalized_sql(statement):
            raise TranscriptMigrationError(
                f"transcript migration object {name} differs from the frozen schema"
            )


def _transaction_start(conn: sqlite3.Connection, savepoint: str) -> bool:
    owns_transaction = not conn.in_transaction
    if owns_transaction:
        conn.execute("BEGIN IMMEDIATE")
    else:
        conn.execute(f"SAVEPOINT {savepoint}")
    return owns_transaction


def _transaction_finish(
    conn: sqlite3.Connection, savepoint: str, owns_transaction: bool
) -> None:
    if owns_transaction:
        conn.commit()
    else:
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")


def _transaction_rollback(
    conn: sqlite3.Connection, savepoint: str, owns_transaction: bool
) -> None:
    if owns_transaction:
        conn.rollback()
    else:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")


def init_transcript_storage(
    conn: sqlite3.Connection,
    *,
    applied_at: str | None = None,
    failure_hook: Callable[[str], None] | None = None,
) -> str:
    """Install the append-only transcript schema in one rollback-safe transaction."""

    require_copy_or_fixture_connection(conn)
    if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        raise TranscriptForeignKeysRequired(
            "PRAGMA foreign_keys=ON is required for transcript persistence"
        )
    savepoint = "sab_build_b_transcript_migration"
    owns_transaction = _transaction_start(conn, savepoint)
    try:
        for index, statement in enumerate(TRANSCRIPT_MIGRATION_STATEMENTS):
            conn.execute(statement)
            if failure_hook is not None:
                failure_hook(f"migration:{index}")
        _verify_migration_schema(conn)
        existing = conn.execute(
            "SELECT migration_digest FROM sab_first_verdict_transcript_migrations_v1 "
            "WHERE migration_id = ?",
            (TRANSCRIPT_MIGRATION_ID,),
        ).fetchone()
        if existing is not None and str(existing[0]) != TRANSCRIPT_MIGRATION_DIGEST:
            raise TranscriptMigrationError("transcript migration digest mismatch")
        if failure_hook is not None:
            failure_hook("migration:schema_verified")
        conn.execute(
            "INSERT OR IGNORE INTO sab_first_verdict_transcript_migrations_v1 "
            "(migration_id, migration_digest, applied_at) VALUES (?, ?, ?)",
            (
                TRANSCRIPT_MIGRATION_ID,
                TRANSCRIPT_MIGRATION_DIGEST,
                applied_at or _utc_now_text(),
            ),
        )
        if failure_hook is not None:
            failure_hook("migration:recorded")
    except Exception:
        _transaction_rollback(conn, savepoint, owns_transaction)
        raise
    _transaction_finish(conn, savepoint, owns_transaction)
    return TRANSCRIPT_MIGRATION_DIGEST


# Stable integration spelling.
init_ceremony_transcript_storage = init_transcript_storage


ModelT = TypeVar("ModelT", bound=TranscriptCanonicalModel)

_IMMUTABLE_RECORD_QUERIES = {
    (
        "sab_ballot_commitments_v1",
        "commitment_id",
        "commitment_sha256",
    ): (
        "SELECT commitment_sha256 FROM sab_ballot_commitments_v1 "
        "WHERE commitment_id = ?"
    ),
    ("sab_ballot_reveals_v1", "reveal_id", "reveal_sha256"): (
        "SELECT reveal_sha256 FROM sab_ballot_reveals_v1 WHERE reveal_id = ?"
    ),
    (
        "sab_ceremony_stage_envelopes_v1",
        "envelope_id",
        "envelope_sha256",
    ): (
        "SELECT envelope_sha256 FROM sab_ceremony_stage_envelopes_v1 "
        "WHERE envelope_id = ?"
    ),
}

_STAGE_SLOT_QUERIES = {
    (
        "sab_ballot_commitments_v1",
        "commitment_id",
        "commitment_sha256",
    ): (
        "SELECT commitment_id, commitment_sha256 FROM sab_ballot_commitments_v1 "
        "WHERE case_id = ? AND stage = ? AND seat_id = ?"
    ),
    ("sab_ballot_reveals_v1", "reveal_id", "reveal_sha256"): (
        "SELECT reveal_id, reveal_sha256 FROM sab_ballot_reveals_v1 "
        "WHERE case_id = ? AND stage = ? AND seat_id = ?"
    ),
}


def _record_replay(
    conn: sqlite3.Connection,
    *,
    table: str,
    id_column: str,
    digest_column: str,
    object_id: str,
    digest: str,
) -> bool:
    try:
        query = _IMMUTABLE_RECORD_QUERIES[(table, id_column, digest_column)]
    except KeyError:
        raise ValueError("unsupported transcript immutable lookup") from None
    row = conn.execute(query, (object_id,)).fetchone()
    if row is None:
        return False
    if str(row[0]) != digest:
        raise TranscriptImmutableConflict(
            f"{object_id} already exists with different transcript content"
        )
    return True


def _stage_slot_conflict(
    conn: sqlite3.Connection,
    *,
    table: Literal["sab_ballot_commitments_v1", "sab_ballot_reveals_v1"],
    id_column: Literal["commitment_id", "reveal_id"],
    digest_column: Literal["commitment_sha256", "reveal_sha256"],
    case_id: str,
    stage: CeremonyStage,
    seat_id: str,
    object_id: str,
    digest: str,
) -> None:
    try:
        query = _STAGE_SLOT_QUERIES[(table, id_column, digest_column)]
    except KeyError:
        raise ValueError("unsupported transcript stage-slot lookup") from None
    row = conn.execute(query, (case_id, stage, seat_id)).fetchone()
    if row is not None and (str(row[0]), str(row[1])) != (object_id, digest):
        raise TranscriptImmutableConflict(
            f"{case_id}/{stage}/{seat_id} already has different transcript content"
        )


def _stored_commitments_for_stage(
    conn: sqlite3.Connection, case_id: str, stage: CeremonyStage
) -> tuple[BallotCommitmentV1, ...]:
    rows = conn.execute(
        "SELECT commitment_json, commitment_sha256 FROM sab_ballot_commitments_v1 "
        "WHERE case_id = ? AND stage = ? ORDER BY seat_position",
        (case_id, stage),
    ).fetchall()
    records: list[BallotCommitmentV1] = []
    for payload_json, expected_digest in rows:
        try:
            model = BallotCommitmentV1.model_validate(json.loads(str(payload_json)))
        except Exception as exc:
            raise TranscriptStoredRecordError(
                "stored commitment is not a valid canonical contract"
            ) from exc
        if model.canonical_sha256() != str(expected_digest):
            raise TranscriptStoredRecordError("stored commitment digest mismatch")
        records.append(model)
    return tuple(records)


def _stored_stage_envelope_by_index(
    conn: sqlite3.Connection, case_id: str, stage_index: int
) -> CeremonyStageEnvelopeV1 | None:
    row = conn.execute(
        "SELECT envelope_json, envelope_sha256 "
        "FROM sab_ceremony_stage_envelopes_v1 "
        "WHERE case_id = ? AND stage_index = ?",
        (case_id, stage_index),
    ).fetchone()
    if row is None:
        return None
    try:
        model = CeremonyStageEnvelopeV1.model_validate(json.loads(str(row[0])))
    except Exception as exc:
        raise TranscriptStoredRecordError(
            "stored stage envelope is not a valid canonical contract"
        ) from exc
    if model.canonical_sha256() != str(row[1]):
        raise TranscriptStoredRecordError("stored stage envelope digest mismatch")
    return model


def _require_commitment_predecessor_binding(
    conn: sqlite3.Connection, commitment: BallotCommitmentV1
) -> None:
    if commitment.stage_index == 0:
        return
    prior = _stored_stage_envelope_by_index(
        conn, commitment.case_id, commitment.stage_index - 1
    )
    if (
        prior is None
        or prior.reveal_set_sha256 != commitment.preceding_reveal_set_sha256
    ):
        raise TranscriptImmutableConflict(
            "commitment stage predecessor is missing or mismatched"
        )
    shared_fields = (
        "case_id",
        "case_sha256",
        "frozen_roster_sha256",
        "authority_digest",
        "rule_digest",
    )
    if any(
        getattr(prior, field) != getattr(commitment, field) for field in shared_fields
    ):
        raise TranscriptImmutableConflict(
            "commitment substitutes case, frozen bench, authority, or rule bindings"
        )
    seat = prior.frozen_roster[commitment.seat_position]
    if (
        seat.seat_id != commitment.seat_id
        or seat.canonical_sha256() != commitment.frozen_seat_sha256
        or not _facts_match_frozen_seat(commitment.execution_facts, seat)
    ):
        raise TranscriptImmutableConflict(
            "commitment substitutes a frozen seat or its execution facts"
        )


def store_ballot_commitment(
    conn: sqlite3.Connection,
    commitment: BallotCommitmentV1 | Mapping[str, Any],
    *,
    recorded_at: str | None = None,
) -> tuple[BallotCommitmentV1, str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        model = BallotCommitmentV1.model_validate(
            commitment.canonical_payload()
            if isinstance(commitment, BallotCommitmentV1)
            else commitment
        )
    except Exception as exc:
        raise TranscriptImmutableConflict(
            f"invalid ballot commitment: {_safe_validation_detail(exc)}"
        ) from exc
    _require_commitment_predecessor_binding(conn, model)
    digest = model.canonical_sha256()
    replay = _record_replay(
        conn,
        table="sab_ballot_commitments_v1",
        id_column="commitment_id",
        digest_column="commitment_sha256",
        object_id=model.commitment_id,
        digest=digest,
    )
    _stage_slot_conflict(
        conn,
        table="sab_ballot_commitments_v1",
        id_column="commitment_id",
        digest_column="commitment_sha256",
        case_id=model.case_id,
        stage=model.stage,
        seat_id=model.seat_id,
        object_id=model.commitment_id,
        digest=digest,
    )
    if not replay:
        try:
            conn.execute(
                "INSERT INTO sab_ballot_commitments_v1 "
                "(commitment_id, case_id, stage, stage_index, seat_id, seat_position, "
                "preceding_reveal_set_sha256, committed_preimage_sha256, "
                "commitment_json, commitment_sha256, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    model.commitment_id,
                    model.case_id,
                    model.stage,
                    model.stage_index,
                    model.seat_id,
                    model.seat_position,
                    model.preceding_reveal_set_sha256,
                    model.committed_preimage_sha256,
                    model.canonical_json(),
                    digest,
                    recorded_at or _utc_now_text(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise TranscriptImmutableConflict(str(exc)) from exc
    return model, digest, replay


def store_ballot_reveal(
    conn: sqlite3.Connection,
    reveal: BallotRevealV1 | Mapping[str, Any],
    *,
    frozen_seat: FrozenSeatV1 | Mapping[str, Any],
    recorded_at: str | None = None,
) -> tuple[BallotRevealV1, str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        model = BallotRevealV1.model_validate(
            reveal.canonical_payload() if isinstance(reveal, BallotRevealV1) else reveal
        )
    except Exception as exc:
        raise TranscriptImmutableConflict(
            f"invalid ballot reveal: {_safe_validation_detail(exc)}"
        ) from exc
    commitments = _stored_commitments_for_stage(conn, model.case_id, model.stage)
    if len(commitments) != 9 or tuple(
        item.seat_position for item in commitments
    ) != tuple(range(9)):
        raise TranscriptImmutableConflict(
            "all nine ordered commitments must be stored before any reveal"
        )
    expected_set = canonical_commitment_set_sha256(commitments)
    if model.commitment_set_sha256 != expected_set:
        raise TranscriptImmutableConflict(
            "reveal commitment-set digest differs from stored commitments"
        )
    commitment = next(
        (item for item in commitments if item.commitment_id == model.commitment_id),
        None,
    )
    if commitment is None:
        raise TranscriptImmutableConflict("reveal references an unknown commitment")
    pair_result = verify_commit_reveal(
        commitment,
        model,
        frozen_seat=frozen_seat,
    )
    if not pair_result.ok:
        raise TranscriptValidationFailure(pair_result)
    digest = model.canonical_sha256()
    replay = _record_replay(
        conn,
        table="sab_ballot_reveals_v1",
        id_column="reveal_id",
        digest_column="reveal_sha256",
        object_id=model.reveal_id,
        digest=digest,
    )
    _stage_slot_conflict(
        conn,
        table="sab_ballot_reveals_v1",
        id_column="reveal_id",
        digest_column="reveal_sha256",
        case_id=model.case_id,
        stage=model.stage,
        seat_id=model.seat_id,
        object_id=model.reveal_id,
        digest=digest,
    )
    if not replay:
        try:
            conn.execute(
                "INSERT INTO sab_ballot_reveals_v1 "
                "(reveal_id, commitment_id, commitment_sha256, commitment_set_sha256, "
                "case_id, stage, stage_index, seat_id, seat_position, ballot_sha256, "
                "reveal_json, reveal_sha256, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    model.reveal_id,
                    model.commitment_id,
                    model.commitment_sha256,
                    model.commitment_set_sha256,
                    model.case_id,
                    model.stage,
                    model.stage_index,
                    model.seat_id,
                    model.seat_position,
                    model.ballot_sha256,
                    model.canonical_json(),
                    digest,
                    recorded_at or _utc_now_text(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise TranscriptImmutableConflict(str(exc)) from exc
    return model, digest, replay


def _stored_reveals_for_stage(
    conn: sqlite3.Connection, case_id: str, stage: CeremonyStage
) -> tuple[BallotRevealV1, ...]:
    rows = conn.execute(
        "SELECT reveal_json, reveal_sha256 FROM sab_ballot_reveals_v1 "
        "WHERE case_id = ? AND stage = ? ORDER BY seat_position",
        (case_id, stage),
    ).fetchall()
    records: list[BallotRevealV1] = []
    for payload_json, expected_digest in rows:
        try:
            model = BallotRevealV1.model_validate(json.loads(str(payload_json)))
        except Exception as exc:
            raise TranscriptStoredRecordError(
                "stored reveal is not a valid canonical contract"
            ) from exc
        if model.canonical_sha256() != str(expected_digest):
            raise TranscriptStoredRecordError("stored reveal digest mismatch")
        records.append(model)
    return tuple(records)


def store_stage_envelope(
    conn: sqlite3.Connection,
    envelope: CeremonyStageEnvelopeV1 | Mapping[str, Any],
    *,
    recorded_at: str | None = None,
) -> tuple[CeremonyStageEnvelopeV1, str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        model = CeremonyStageEnvelopeV1.model_validate(
            envelope.canonical_payload()
            if isinstance(envelope, CeremonyStageEnvelopeV1)
            else envelope
        )
    except Exception as exc:
        raise TranscriptImmutableConflict(
            f"invalid ceremony stage envelope: {_safe_validation_detail(exc)}"
        ) from exc
    stored_commitments = _stored_commitments_for_stage(conn, model.case_id, model.stage)
    stored_reveals = _stored_reveals_for_stage(conn, model.case_id, model.stage)
    if stored_commitments != model.commitments or stored_reveals != model.reveals:
        raise TranscriptImmutableConflict(
            "stage envelope members differ from the stored commitment/reveal records"
        )
    prior_index = model.stage_index - 1
    if prior_index >= 0:
        prior = _stored_stage_envelope_by_index(conn, model.case_id, prior_index)
        if (
            prior is None
            or prior.reveal_set_sha256 != model.preceding_reveal_set_sha256
        ):
            raise TranscriptImmutableConflict(
                "stage envelope is missing its exact preceding reveal set"
            )
        shared_fields = (
            "case_id",
            "case_sha256",
            "frozen_roster",
            "frozen_roster_sha256",
            "expected_seat_ids",
            "authority_digest",
            "rule_digest",
        )
        if any(
            getattr(prior, field) != getattr(model, field) for field in shared_fields
        ):
            raise TranscriptImmutableConflict(
                "stage envelope substitutes case, frozen bench, authority, or rule bindings"
            )
    digest = model.canonical_sha256()
    replay = _record_replay(
        conn,
        table="sab_ceremony_stage_envelopes_v1",
        id_column="envelope_id",
        digest_column="envelope_sha256",
        object_id=model.envelope_id,
        digest=digest,
    )
    slot = conn.execute(
        "SELECT envelope_id, envelope_sha256 FROM sab_ceremony_stage_envelopes_v1 "
        "WHERE case_id = ? AND stage = ?",
        (model.case_id, model.stage),
    ).fetchone()
    if slot is not None and (str(slot[0]), str(slot[1])) != (model.envelope_id, digest):
        raise TranscriptImmutableConflict(
            f"{model.case_id}/{model.stage} already has a different stage envelope"
        )
    if not replay:
        try:
            conn.execute(
                "INSERT INTO sab_ceremony_stage_envelopes_v1 "
                "(envelope_id, case_id, stage, stage_index, "
                "preceding_reveal_set_sha256, commitment_set_sha256, "
                "reveal_set_sha256, final_deliberation_subject_sha256, "
                "envelope_json, envelope_sha256, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    model.envelope_id,
                    model.case_id,
                    model.stage,
                    model.stage_index,
                    model.preceding_reveal_set_sha256,
                    model.commitment_set_sha256,
                    model.reveal_set_sha256,
                    model.final_deliberation_subject_sha256,
                    model.canonical_json(),
                    digest,
                    recorded_at or _utc_now_text(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise TranscriptImmutableConflict(str(exc)) from exc
    return model, digest, replay


class TranscriptStorageReceiptV1(TranscriptCanonicalModel):
    schema_: Literal["sab.transcript_storage_receipt.v1"] = Field(
        "sab.transcript_storage_receipt.v1", alias="schema"
    )
    case_id: str = Field(min_length=1, max_length=200)
    transcript_sha256: str = Field(pattern=SHA256_PATTERN)
    stage_envelope_sha256s: tuple[str, str, str]
    replayed: bool
    authority_effect: Literal["none"] = "none"
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False


def store_ceremony_transcript(
    conn: sqlite3.Connection,
    envelopes: Sequence[CeremonyStageEnvelopeV1 | Mapping[str, Any]],
    *,
    expected_roster: Sequence[FrozenSeatV1 | Mapping[str, Any] | str] | None = None,
    recorded_at: str | None = None,
    failure_hook: Callable[[str], None] | None = None,
) -> TranscriptStorageReceiptV1:
    """Atomically persist all 54 pair records and three stage envelopes."""

    require_copy_or_fixture_connection(conn)
    validation = verify_ceremony_transcript(
        envelopes,
        expected_roster=expected_roster,
    )
    if not validation.ok or validation.transcript_sha256 is None:
        raise TranscriptValidationFailure(validation)
    parsed = tuple(
        CeremonyStageEnvelopeV1.model_validate(
            envelope.canonical_payload()
            if isinstance(envelope, CeremonyStageEnvelopeV1)
            else envelope
        )
        for envelope in envelopes
    )
    savepoint = "sab_build_b_transcript_store"
    owns_transaction = _transaction_start(conn, savepoint)
    replays: list[bool] = []
    try:
        for envelope in parsed:
            for commitment in envelope.commitments:
                _, _, replay = store_ballot_commitment(
                    conn, commitment, recorded_at=recorded_at
                )
                replays.append(replay)
                if failure_hook is not None:
                    failure_hook(
                        f"commitment:{envelope.stage}:{commitment.seat_position}"
                    )
            for seat, reveal in zip(envelope.frozen_roster, envelope.reveals):
                _, _, replay = store_ballot_reveal(
                    conn,
                    reveal,
                    frozen_seat=seat,
                    recorded_at=recorded_at,
                )
                replays.append(replay)
                if failure_hook is not None:
                    failure_hook(f"reveal:{envelope.stage}:{reveal.seat_position}")
            _, _, replay = store_stage_envelope(conn, envelope, recorded_at=recorded_at)
            replays.append(replay)
            if failure_hook is not None:
                failure_hook(f"envelope:{envelope.stage}")
    except Exception:
        _transaction_rollback(conn, savepoint, owns_transaction)
        raise
    _transaction_finish(conn, savepoint, owns_transaction)
    return TranscriptStorageReceiptV1(
        case_id=parsed[0].case_id,
        transcript_sha256=validation.transcript_sha256,
        stage_envelope_sha256s=tuple(  # type: ignore[arg-type]
            envelope.canonical_sha256() for envelope in parsed
        ),
        replayed=all(replays),
    )


def _read_record(
    conn: sqlite3.Connection,
    *,
    query: str,
    params: tuple[Any, ...],
    model_type: type[ModelT],
) -> ModelT | None:
    row = conn.execute(query, params).fetchone()
    if row is None:
        return None
    try:
        model = model_type.model_validate(json.loads(str(row[0])))
    except Exception as exc:
        raise TranscriptStoredRecordError("stored transcript JSON is invalid") from exc
    if model.canonical_sha256() != str(row[1]):
        raise TranscriptStoredRecordError("stored transcript digest mismatch")
    return model


def read_ballot_commitment(
    conn: sqlite3.Connection, commitment_id: str
) -> BallotCommitmentV1 | None:
    return _read_record(
        conn,
        query=(
            "SELECT commitment_json, commitment_sha256 "
            "FROM sab_ballot_commitments_v1 WHERE commitment_id = ?"
        ),
        params=(commitment_id,),
        model_type=BallotCommitmentV1,
    )


def read_ballot_reveal(
    conn: sqlite3.Connection, reveal_id: str
) -> BallotRevealV1 | None:
    return _read_record(
        conn,
        query=(
            "SELECT reveal_json, reveal_sha256 "
            "FROM sab_ballot_reveals_v1 WHERE reveal_id = ?"
        ),
        params=(reveal_id,),
        model_type=BallotRevealV1,
    )


def read_stage_envelope(
    conn: sqlite3.Connection, case_id: str, stage: CeremonyStage
) -> CeremonyStageEnvelopeV1 | None:
    if stage not in CEREMONY_STAGES:
        raise ValueError("unsupported ceremony stage")
    return _read_record(
        conn,
        query=(
            "SELECT envelope_json, envelope_sha256 "
            "FROM sab_ceremony_stage_envelopes_v1 WHERE case_id = ? AND stage = ?"
        ),
        params=(case_id, stage),
        model_type=CeremonyStageEnvelopeV1,
    )


def read_ceremony_transcript(
    conn: sqlite3.Connection, case_id: str
) -> tuple[CeremonyStageEnvelopeV1, ...]:
    records: list[CeremonyStageEnvelopeV1] = []
    for stage in CEREMONY_STAGES:
        envelope = read_stage_envelope(conn, case_id, stage)
        if envelope is not None:
            records.append(envelope)
    return tuple(records)


__all__ = [
    "BallotCommitmentV1",
    "BallotExecutionFactsV1",
    "BallotRevealV1",
    "CEREMONY_STAGES",
    "COMMITMENT_DOMAIN",
    "CeremonyStageEnvelopeV1",
    "EMPTY_REVEAL_SET_SHA256",
    "FinalDeliberationSubjectV1",
    "TRANSCRIPT_MIGRATION_DIGEST",
    "TRANSCRIPT_MIGRATION_ID",
    "TRANSCRIPT_MIGRATION_STATEMENTS",
    "TranscriptForeignKeysRequired",
    "TranscriptImmutableConflict",
    "TranscriptMigrationError",
    "TranscriptStorageError",
    "TranscriptStorageReceiptV1",
    "TranscriptStoredRecordError",
    "TranscriptValidationErrorV1",
    "TranscriptValidationFailure",
    "TranscriptValidationResultV1",
    "ballot_commitment_preimage_payload",
    "ballot_commitment_preimage_sha256",
    "canonical_commitment_set_sha256",
    "canonical_reveal_set_sha256",
    "init_ceremony_transcript_storage",
    "init_transcript_storage",
    "read_ballot_commitment",
    "read_ballot_reveal",
    "read_ceremony_transcript",
    "read_stage_envelope",
    "store_ballot_commitment",
    "store_ballot_reveal",
    "store_ceremony_transcript",
    "store_stage_envelope",
    "verify_ceremony_transcript",
    "verify_commit_reveal",
]
