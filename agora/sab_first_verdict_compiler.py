"""Pure, authority-first council compiler for SAB First Verdict Build B.

The compiler accepts no implicit terminality policy.  A caller must provide a
fully specified, self-hashed :class:`CouncilTerminalityRuleV1`.  More
importantly, the authority gate runs before that rule, the roster, or any
ballot is parsed.  A refusal receipt therefore carries typed evidence that no
merit-bearing input was inspected.

This module performs no I/O, persistence, provider calls, key loading, or
service mutation.  It can compile fixture-derived ``Copy`` outcomes only;
``Authorized<Live>`` is neither represented nor constructible here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Union

from pydantic import Field, TypeAdapter, field_validator, model_validator

from agora.sab_artifact_verdict import (
    DISPOSITION_AUTHORITY_ADAPTER,
    SHA256_PATTERN,
    AdvisoryOnlyDispositionAuthorityV1,
    ArtifactBallotV1,
    AuthorityDenied,
    AuthorizedDispositionAuthorityV1,
    BallotSource,
    CouncilVerdictV1,
    DispositionScope,
    EvidenceProvenance,
    FrozenSeatV1,
    NoJurisdictionDispositionAuthorityV1,
    StrictCanonicalModel,
    canonical_sha256,
    require_rehearsal_authority,
    verify_contract_signature,
)

TerminalDecision = Literal["canon", "compost", "correct_and_supersede"]
BallotDecision = Literal[
    "canon",
    "compost",
    "correct_and_supersede",
    "no_terminal_verdict",
    "appeal",
    "abstain",
]
AuthorityResult = Literal["Authorized", "AdvisoryOnly", "NoJurisdiction"]
RefusalReason = Literal[
    "authority_missing",
    "authority_malformed",
    "authority_advisory_only",
    "authority_no_jurisdiction",
    "authority_not_evaluator_capability",
    "authority_scope_mismatch",
    "authority_effect_mismatch",
    "requested_scope_malformed",
    "requested_effects_malformed",
    "live_scope_unsupported",
]


class CouncilCompilationError(ValueError):
    """A post-authority council input cannot be compiled safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _nonblank(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a nonblank string")
    if value != value.strip():
        raise ValueError(f"{field} must not contain surrounding whitespace")
    return value


def _exact_strings(
    values: Any,
    *,
    field: str,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ValueError(f"{field} must be a sequence of strings")
    if any(not isinstance(value, str) for value in values):
        raise ValueError(f"{field} must contain strings only")
    normalized = tuple(_nonblank(value, field=field) for value in values)
    if not normalized and not allow_empty:
        raise ValueError(f"{field} cannot be empty")
    if any("*" in value for value in normalized):
        raise ValueError(f"{field} cannot contain wildcard values")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} cannot contain duplicate values")
    if normalized != tuple(sorted(normalized)):
        raise ValueError(f"{field} must use canonical sorted order")
    return normalized


class CouncilTerminalityRuleV1(StrictCanonicalModel):
    """Explicit, synthetic council policy; this module supplies no default rule."""

    schema_: Literal["sab.council_terminality_rule.v1"] = Field(
        "sab.council_terminality_rule.v1", alias="schema"
    )
    rule_id: str = Field(min_length=1, max_length=200)
    council_size: Literal[9] = 9
    minimum_raw_votes: int = Field(ge=1, le=9, strict=True)
    minimum_clean_clusters: int = Field(ge=1, le=9, strict=True)
    terminal_decisions: tuple[TerminalDecision, ...] = Field(min_length=1)
    effects_by_decision: dict[TerminalDecision, tuple[str, ...]]
    correlation_policy: Literal["remove_smeared_and_appeal_on_change"]
    tie_policy: Literal["no_terminal_verdict"]
    rule_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("council_size", mode="before")
    @classmethod
    def exact_council_size_type(cls, value: Any) -> int:
        if type(value) is not int:
            raise ValueError("council_size must be an exact integer")
        return value

    @field_validator("terminal_decisions", mode="before")
    @classmethod
    def exact_terminal_decisions(cls, value: Any) -> tuple[str, ...]:
        return _exact_strings(value, field="terminal_decisions")

    @field_validator("effects_by_decision", mode="before")
    @classmethod
    def exact_effect_map(cls, value: Any) -> dict[str, tuple[str, ...]]:
        if not isinstance(value, Mapping):
            raise ValueError(
                "effects_by_decision must be a decision-to-effects mapping"
            )
        normalized: dict[str, tuple[str, ...]] = {}
        for decision, effects in value.items():
            key = _nonblank(decision, field="effects_by_decision key")
            normalized[key] = _exact_strings(
                effects,
                field=f"effects_by_decision[{key}]",
            )
        return dict(sorted(normalized.items()))

    @model_validator(mode="after")
    def thresholds_effects_and_hash_are_exact(self) -> "CouncilTerminalityRuleV1":
        if self.minimum_raw_votes > self.council_size:
            raise ValueError("minimum_raw_votes cannot exceed council_size")
        if self.minimum_clean_clusters > self.council_size:
            raise ValueError("minimum_clean_clusters cannot exceed council_size")
        if set(self.effects_by_decision) != set(self.terminal_decisions):
            raise ValueError(
                "effects_by_decision must exactly cover terminal_decisions"
            )
        expected = self.canonical_sha256(exclude={"rule_sha256"})
        if self.rule_sha256 != expected:
            raise ValueError("rule_sha256 does not bind the canonical rule body")
        return self

    @property
    def all_requested_effects(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    effect
                    for effects in self.effects_by_decision.values()
                    for effect in effects
                }
            )
        )


def compute_council_terminality_rule_sha256(payload: Mapping[str, Any]) -> str:
    """Hash an explicit rule body using the same normalization as the model."""

    if not isinstance(payload, Mapping):
        raise TypeError("rule payload must be a mapping")
    material = dict(payload)
    material.pop("rule_sha256", None)
    if "schema_" in material and "schema" not in material:
        material["schema"] = material.pop("schema_")
    material.setdefault("schema", "sab.council_terminality_rule.v1")
    if "terminal_decisions" in material:
        material["terminal_decisions"] = list(
            _exact_strings(material["terminal_decisions"], field="terminal_decisions")
        )
    if "effects_by_decision" in material:
        material["effects_by_decision"] = {
            decision: list(effects)
            for decision, effects in CouncilTerminalityRuleV1.exact_effect_map(
                material["effects_by_decision"]
            ).items()
        }
    return canonical_sha256(material)


class PreUnsealSeatV1(StrictCanonicalModel):
    """Non-merit metadata available before final ballots are unsealed."""

    seat_id: str = Field(min_length=1, max_length=120)
    credited_cluster: str = Field(min_length=1, max_length=160)
    correlation_smeared: bool


class PreUnsealFeasibilityV1(StrictCanonicalModel):
    """Whether the committed metadata can still satisfy the explicit rule."""

    schema_: Literal["sab.pre_unseal_feasibility.v1"] = Field(
        "sab.pre_unseal_feasibility.v1", alias="schema"
    )
    result: Literal["feasible", "infeasible"]
    rule_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_seat_count: int = Field(ge=0, strict=True)
    committed_seat_count: int = Field(ge=0, strict=True)
    distinct_committed_seat_count: int = Field(ge=0, strict=True)
    maximum_terminal_votes: int = Field(ge=0, strict=True)
    maximum_clean_clusters: int = Field(ge=0, strict=True)
    required_terminal_votes: int = Field(ge=1, strict=True)
    required_clean_clusters: int = Field(ge=1, strict=True)
    missing_seats: tuple[str, ...]
    duplicate_seats: tuple[str, ...]
    unknown_seats: tuple[str, ...]
    reason_codes: tuple[str, ...]

    @field_validator(
        "missing_seats",
        "duplicate_seats",
        "unknown_seats",
        "reason_codes",
        mode="before",
    )
    @classmethod
    def exact_sets(cls, value: Any, info: Any) -> tuple[str, ...]:
        return _exact_strings(
            value,
            field=str(info.field_name),
            allow_empty=True,
        )

    @model_validator(mode="after")
    def result_matches_reasons(self) -> "PreUnsealFeasibilityV1":
        if (self.result == "feasible") != (not self.reason_codes):
            raise ValueError("pre-unseal feasibility result must match reason_codes")
        return self


# Slightly longer spelling for integrations that name the value as a result.
PreUnsealFeasibilityResultV1 = PreUnsealFeasibilityV1


class CorrelationSmearRemovalV1(StrictCanonicalModel):
    seat_id: str = Field(min_length=1, max_length=120)
    ballot_id: str = Field(min_length=1, max_length=200)
    decision: BallotDecision
    credited_cluster: str = Field(min_length=1, max_length=160)
    transport_correlation_refs: tuple[str, ...]

    @field_validator("transport_correlation_refs", mode="before")
    @classmethod
    def exact_refs(cls, value: Any) -> tuple[str, ...]:
        return _exact_strings(
            value,
            field="transport_correlation_refs",
            allow_empty=True,
        )


class RefusalReceiptV1(StrictCanonicalModel):
    """Effect-free proof that authority failed before merit parsing."""

    schema_: Literal["sab.council_refusal_receipt.v1"] = Field(
        "sab.council_refusal_receipt.v1", alias="schema"
    )
    result: Literal["refused"] = "refused"
    refusal_id: str = Field(min_length=1, max_length=200)
    reason: RefusalReason
    requested_scope: Literal["Copy", "Live", "All", "invalid"]
    authority_result: AuthorityResult | None
    authority_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    effects: tuple[()] = ()
    authority_inspected: bool
    terminality_rule_inspected: bool
    ballots_inspected: Literal[False] = False
    merits_parsed: Literal[False] = False
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False


class CompiledVerdictV1(CouncilVerdictV1):
    """Deterministically re-derived terminal or nonterminal Copy verdict."""

    schema_: Literal["sab.compiled_verdict.v1"] = Field(
        "sab.compiled_verdict.v1", alias="schema"
    )
    result: Literal["compiled_verdict"] = "compiled_verdict"
    decision: Literal[
        "canon", "compost", "correct_and_supersede", "no_terminal_verdict"
    ]
    terminality: Literal["terminal", "no_terminal_verdict"]
    scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    evidence_provenance: Literal[EvidenceProvenance.FIXTURE_MODELS] = (
        EvidenceProvenance.FIXTURE_MODELS
    )
    ballot_set_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    terminality_rule_sha256: str = Field(pattern=SHA256_PATTERN)
    winner: BallotDecision | None
    clean_cluster_winner: BallotDecision | None
    correlation_smear_removals: tuple[CorrelationSmearRemovalV1, ...]
    pre_unseal_feasibility: PreUnsealFeasibilityV1

    @model_validator(mode="after")
    def compiled_shape(self) -> "CompiledVerdictV1":
        if self.terminality == "terminal":
            if self.decision == "no_terminal_verdict":
                raise ValueError("terminal verdict must name a terminal decision")
            if self.winner != self.decision or not self.requested_effects:
                raise ValueError("terminal verdict must bind its winner and effects")
        elif self.decision != "no_terminal_verdict":
            raise ValueError("nonterminal verdict must use no_terminal_verdict")
        return self


class AppealReceiptV1(CouncilVerdictV1):
    """Effect-free end of the one-round slice when appeal is required."""

    schema_: Literal["sab.council_appeal_receipt.v1"] = Field(
        "sab.council_appeal_receipt.v1", alias="schema"
    )
    result: Literal["appeal_required"] = "appeal_required"
    appeal_id: str = Field(min_length=1, max_length=200)
    decision: Literal["appeal_required"] = "appeal_required"
    terminality: Literal["appeal_required"] = "appeal_required"
    appeal_reasons: tuple[str, ...] = Field(min_length=1)
    requested_effects: tuple[()] = ()
    scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    evidence_provenance: Literal[EvidenceProvenance.FIXTURE_MODELS] = (
        EvidenceProvenance.FIXTURE_MODELS
    )
    ballot_set_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    terminality_rule_sha256: str = Field(pattern=SHA256_PATTERN)
    winner: BallotDecision | None
    clean_cluster_winner: BallotDecision | None
    correlation_smear_removals: tuple[CorrelationSmearRemovalV1, ...]
    pre_unseal_feasibility: PreUnsealFeasibilityV1
    effects: tuple[()] = ()
    live_eligible: Literal[False] = False


CeremonyOutcome = Annotated[
    Union[CompiledVerdictV1, RefusalReceiptV1, AppealReceiptV1],
    Field(discriminator="result"),
]
CEREMONY_OUTCOME_ADAPTER = TypeAdapter(CeremonyOutcome)


def _parse_rule(value: Any) -> CouncilTerminalityRuleV1:
    try:
        payload = (
            value.canonical_payload()
            if isinstance(value, CouncilTerminalityRuleV1)
            else value
        )
        return CouncilTerminalityRuleV1.model_validate(payload)
    except Exception as exc:
        raise CouncilCompilationError(
            "terminality_rule_invalid",
            "an explicit, canonically hashed terminality rule is required",
        ) from exc


def _parse_pre_unseal_seats(value: Any) -> tuple[PreUnsealSeatV1, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise CouncilCompilationError(
            "pre_unseal_metadata_invalid",
            "pre-unseal seats must be a sequence",
        )
    parsed: list[PreUnsealSeatV1] = []
    for item in value:
        try:
            payload = (
                item.canonical_payload() if isinstance(item, PreUnsealSeatV1) else item
            )
            parsed.append(PreUnsealSeatV1.model_validate(payload))
        except Exception as exc:
            raise CouncilCompilationError(
                "pre_unseal_metadata_invalid",
                "pre-unseal seat metadata is malformed",
            ) from exc
    return tuple(parsed)


def _assess_pre_unseal(
    *,
    rule: CouncilTerminalityRuleV1,
    expected_seat_ids: tuple[str, ...],
    seats: tuple[PreUnsealSeatV1, ...],
) -> PreUnsealFeasibilityV1:
    expected = set(expected_seat_ids)
    counts = Counter(seat.seat_id for seat in seats)
    duplicates = tuple(
        sorted(seat_id for seat_id, count in counts.items() if count > 1)
    )
    committed = set(counts)
    missing = tuple(sorted(expected - committed))
    unknown = tuple(sorted(committed - expected))
    usable_seats = {
        seat.seat_id: seat
        for seat in seats
        if seat.seat_id in expected and counts[seat.seat_id] == 1
    }
    maximum_votes = len(usable_seats)
    maximum_clean_clusters = len(
        {
            seat.credited_cluster
            for seat in usable_seats.values()
            if not seat.correlation_smeared
        }
    )
    reasons: list[str] = []
    if len(expected_seat_ids) != rule.council_size:
        reasons.append("expected_roster_size_mismatch")
    if missing:
        reasons.append("commitment_set_incomplete")
    if duplicates:
        reasons.append("duplicate_seat_commitments")
    if unknown:
        reasons.append("unknown_seat_commitments")
    if maximum_votes < rule.minimum_raw_votes:
        reasons.append("insufficient_terminal_vote_capacity")
    if maximum_clean_clusters < rule.minimum_clean_clusters:
        reasons.append("insufficient_clean_cluster_capacity")
    return PreUnsealFeasibilityV1(
        result="infeasible" if reasons else "feasible",
        rule_sha256=rule.rule_sha256,
        expected_seat_count=len(expected_seat_ids),
        committed_seat_count=len(seats),
        distinct_committed_seat_count=len(committed),
        maximum_terminal_votes=maximum_votes,
        maximum_clean_clusters=maximum_clean_clusters,
        required_terminal_votes=rule.minimum_raw_votes,
        required_clean_clusters=rule.minimum_clean_clusters,
        missing_seats=missing,
        duplicate_seats=duplicates,
        unknown_seats=unknown,
        reason_codes=tuple(reasons),
    )


def assess_pre_unseal_feasibility(
    *,
    rule: CouncilTerminalityRuleV1 | Mapping[str, Any],
    expected_seat_ids: Sequence[str],
    seats: Sequence[PreUnsealSeatV1 | Mapping[str, Any]],
) -> PreUnsealFeasibilityV1:
    """Evaluate commitment metadata without accepting or inspecting decisions."""

    parsed_rule = _parse_rule(rule)
    try:
        expected = _exact_strings(expected_seat_ids, field="expected_seat_ids")
    except ValueError as exc:
        raise CouncilCompilationError(
            "expected_roster_invalid", "expected roster is malformed"
        ) from exc
    parsed_seats = _parse_pre_unseal_seats(seats)
    return _assess_pre_unseal(
        rule=parsed_rule,
        expected_seat_ids=expected,
        seats=parsed_seats,
    )


def _scope_label(value: Any) -> Literal["Copy", "Live", "All", "invalid"]:
    try:
        return DispositionScope(value).value
    except Exception:
        return "invalid"


def _refusal(
    *,
    reason: RefusalReason,
    requested_scope: Any,
    authority: (
        AuthorizedDispositionAuthorityV1
        | AdvisoryOnlyDispositionAuthorityV1
        | NoJurisdictionDispositionAuthorityV1
        | None
    ),
    authority_inspected: bool,
    terminality_rule_inspected: bool = False,
) -> RefusalReceiptV1:
    authority_result: AuthorityResult | None = None
    authority_digest: str | None = None
    if authority is not None:
        authority_result = authority.result
        authority_digest = authority.authority_digest
    identity = canonical_sha256(
        {
            "reason": reason,
            "requested_scope": _scope_label(requested_scope),
            "authority_result": authority_result,
            "authority_digest": authority_digest,
            "terminality_rule_inspected": terminality_rule_inspected,
        }
    )
    return RefusalReceiptV1(
        refusal_id=f"sab_council_refusal_{identity[:24]}",
        reason=reason,
        requested_scope=_scope_label(requested_scope),
        authority_result=authority_result,
        authority_digest=authority_digest,
        authority_inspected=authority_inspected,
        terminality_rule_inspected=terminality_rule_inspected,
    )


def _authority_first(
    *,
    authority: Any,
    requested_scope: Any,
    requested_effects: Any,
) -> tuple[AuthorizedDispositionAuthorityV1 | RefusalReceiptV1, tuple[str, ...]]:
    """Gate authority without receiving any merit-bearing arguments."""

    try:
        scope = DispositionScope(requested_scope)
    except Exception:
        return (
            _refusal(
                reason="requested_scope_malformed",
                requested_scope=requested_scope,
                authority=None,
                authority_inspected=False,
            ),
            (),
        )
    if scope != DispositionScope.COPY:
        return (
            _refusal(
                reason=(
                    "live_scope_unsupported"
                    if scope == DispositionScope.LIVE
                    else "authority_scope_mismatch"
                ),
                requested_scope=scope,
                authority=None,
                authority_inspected=False,
            ),
            (),
        )
    try:
        effects = _exact_strings(
            requested_effects,
            field="requested_effects",
            allow_empty=True,
        )
    except ValueError:
        return (
            _refusal(
                reason="requested_effects_malformed",
                requested_scope=scope,
                authority=None,
                authority_inspected=False,
            ),
            (),
        )
    if authority is None:
        return (
            _refusal(
                reason="authority_missing",
                requested_scope=scope,
                authority=None,
                authority_inspected=True,
            ),
            effects,
        )
    parsed: (
        AuthorizedDispositionAuthorityV1
        | AdvisoryOnlyDispositionAuthorityV1
        | NoJurisdictionDispositionAuthorityV1
    )
    if isinstance(
        authority,
        (
            AuthorizedDispositionAuthorityV1,
            AdvisoryOnlyDispositionAuthorityV1,
            NoJurisdictionDispositionAuthorityV1,
        ),
    ):
        parsed = authority
    elif isinstance(authority, Mapping):
        try:
            parsed = DISPOSITION_AUTHORITY_ADAPTER.validate_python(authority)
        except Exception:
            return (
                _refusal(
                    reason="authority_malformed",
                    requested_scope=scope,
                    authority=None,
                    authority_inspected=True,
                ),
                effects,
            )
    else:
        return (
            _refusal(
                reason="authority_malformed",
                requested_scope=scope,
                authority=None,
                authority_inspected=True,
            ),
            effects,
        )
    if isinstance(parsed, AdvisoryOnlyDispositionAuthorityV1):
        return (
            _refusal(
                reason="authority_advisory_only",
                requested_scope=scope,
                authority=parsed,
                authority_inspected=True,
            ),
            effects,
        )
    if isinstance(parsed, NoJurisdictionDispositionAuthorityV1):
        return (
            _refusal(
                reason="authority_no_jurisdiction",
                requested_scope=scope,
                authority=parsed,
                authority_inspected=True,
            ),
            effects,
        )
    if parsed.scope != scope:
        return (
            _refusal(
                reason="authority_scope_mismatch",
                requested_scope=scope,
                authority=parsed,
                authority_inspected=True,
            ),
            effects,
        )
    if set(parsed.allowed_effects) != set(effects):
        return (
            _refusal(
                reason="authority_effect_mismatch",
                requested_scope=scope,
                authority=parsed,
                authority_inspected=True,
            ),
            effects,
        )
    try:
        require_rehearsal_authority(parsed, effects=effects)
    except (AuthorityDenied, ValueError, TypeError):
        return (
            _refusal(
                reason="authority_not_evaluator_capability",
                requested_scope=scope,
                authority=parsed,
                authority_inspected=True,
            ),
            effects,
        )
    return parsed, effects


def _parse_frozen_roster(value: Any) -> tuple[FrozenSeatV1, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise CouncilCompilationError(
            "frozen_roster_invalid", "frozen_roster must be an ordered sequence"
        )
    if len(value) != 9:
        raise CouncilCompilationError(
            "frozen_roster_size_mismatch",
            "the trusted frozen roster must contain exactly nine seats",
        )
    seats: list[FrozenSeatV1] = []
    for item in value:
        try:
            payload = (
                item.canonical_payload() if isinstance(item, FrozenSeatV1) else item
            )
            seats.append(FrozenSeatV1.model_validate(payload))
        except Exception as exc:
            raise CouncilCompilationError(
                "frozen_roster_invalid", "a trusted frozen seat is malformed"
            ) from exc
    seat_ids = [seat.seat_id for seat in seats]
    if len(set(seat_ids)) != 9:
        raise CouncilCompilationError(
            "duplicate_frozen_seat",
            "the trusted frozen roster must contain nine unique seat identities",
        )
    return tuple(seats)


def _ballot_matches_frozen_seat(
    ballot: ArtifactBallotV1,
    seat: FrozenSeatV1,
) -> bool:
    return (
        ballot.seat_id == seat.seat_id
        and ballot.requested_model == seat.requested_model
        and ballot.requested_route == seat.requested_route
        and ballot.served_provider == seat.served_provider
        and ballot.served_model == seat.served_model
        and seat.possible_underlying_routes == (ballot.served_route,)
        and ballot.credited_cluster == seat.credited_cluster
        and ballot.cluster_basis == seat.cluster_basis
        and ballot.model_lineage_evidence_refs == seat.model_lineage_evidence_refs
        and ballot.transport_correlation_refs == seat.transport_correlation_refs
        and ballot.correlation_smeared == seat.correlation_smeared
        and ballot.signature_role == seat.key_role
    )


def _require_ballot_authenticity(
    ballot: ArtifactBallotV1,
    seat: FrozenSeatV1,
) -> None:
    signature = ballot.execution_signature
    if signature.signer != seat.seat_id:
        raise CouncilCompilationError(
            "ballot_signature_signer_mismatch",
            "ballot signature signer differs from the trusted frozen seat",
        )
    if signature.public_key != seat.execution_public_key:
        raise CouncilCompilationError(
            "ballot_signature_key_mismatch",
            "ballot signature key differs from the trusted frozen seat",
        )
    if not verify_contract_signature(
        ballot.canonical_bytes(exclude={"execution_signature"}), signature
    ):
        raise CouncilCompilationError(
            "ballot_signature_invalid",
            "ballot execution signature does not verify over canonical unsigned bytes",
        )


def _parse_final_ballots(
    value: Any,
    *,
    case_id: str,
    case_sha256: str,
    frozen_roster: tuple[FrozenSeatV1, ...],
) -> tuple[ArtifactBallotV1, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise CouncilCompilationError(
            "ballot_set_invalid", "ballots must be a sequence"
        )
    ballots: list[ArtifactBallotV1] = []
    for item in value:
        try:
            payload = (
                item.canonical_payload() if isinstance(item, ArtifactBallotV1) else item
            )
            ballot = ArtifactBallotV1.model_validate(payload)
        except Exception as exc:
            raise CouncilCompilationError(
                "ballot_malformed", "a final ballot is malformed"
            ) from exc
        if ballot.stage != "final":
            raise CouncilCompilationError(
                "ballot_not_final", "only final ballots may be compiled"
            )
        if ballot.case_id != case_id or ballot.case_sha256 != case_sha256:
            raise CouncilCompilationError(
                "ballot_case_mismatch", "ballot case binding differs from the ceremony"
            )
        if ballot.ballot_source != BallotSource.FIXTURE_MODEL:
            raise CouncilCompilationError(
                "ballot_source_not_fixture",
                "Build B offline compilation accepts Copy fixture ballots only",
            )
        ballots.append(ballot)
    ballot_ids = [ballot.ballot_id for ballot in ballots]
    duplicate_ballot_ids = sorted(
        ballot_id for ballot_id, count in Counter(ballot_ids).items() if count > 1
    )
    if duplicate_ballot_ids:
        raise CouncilCompilationError(
            "duplicate_ballot_id", "final ballot identifiers must be unique"
        )
    seat_ids = [ballot.seat_id for ballot in ballots]
    duplicate_seats = sorted(
        seat_id for seat_id, count in Counter(seat_ids).items() if count > 1
    )
    if duplicate_seats:
        raise CouncilCompilationError(
            "duplicate_seat", "each expected seat must contribute exactly one ballot"
        )
    expected_seat_ids = tuple(seat.seat_id for seat in frozen_roster)
    expected = set(expected_seat_ids)
    actual = set(seat_ids)
    if actual - expected:
        raise CouncilCompilationError(
            "unknown_seat", "a ballot seat is outside the expected roster"
        )
    if expected - actual:
        raise CouncilCompilationError(
            "missing_seat", "the final ballot set does not cover the expected roster"
        )
    if len(ballots) != len(frozen_roster):
        raise CouncilCompilationError(
            "ballot_count_mismatch",
            "the final ballot count differs from the explicit council rule",
        )
    if tuple(seat_ids) != expected_seat_ids:
        raise CouncilCompilationError(
            "ballot_roster_order_mismatch",
            "final ballots must appear in the exact trusted frozen-roster order",
        )
    for ballot, seat in zip(ballots, frozen_roster):
        if not _ballot_matches_frozen_seat(ballot, seat):
            raise CouncilCompilationError(
                "ballot_frozen_seat_mismatch",
                "ballot execution facts differ from the trusted frozen seat",
            )
        _require_ballot_authenticity(ballot, seat)
    return tuple(ballots)


def _ballot_set_sha256(ballots: Sequence[ArtifactBallotV1]) -> str:
    members = [
        {
            "seat_position": position,
            "seat_id": ballot.seat_id,
            "ballot_id": ballot.ballot_id,
            "ballot_sha256": ballot.canonical_sha256(),
        }
        for position, ballot in enumerate(ballots)
    ]
    return canonical_sha256(members)


def _unique_winner(tally: Mapping[str, int]) -> BallotDecision | None:
    if not tally:
        return None
    highest = max(tally.values())
    winners = sorted(decision for decision, count in tally.items() if count == highest)
    return winners[0] if len(winners) == 1 else None  # type: ignore[return-value]


def _normalize_time(value: Any) -> datetime:
    try:
        parsed = TypeAdapter(datetime).validate_python(value)
    except Exception as exc:
        raise CouncilCompilationError(
            "compiled_at_invalid", "compiled_at must be a timezone-aware timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise CouncilCompilationError(
            "compiled_at_invalid", "compiled_at must be a timezone-aware timestamp"
        )
    return parsed.astimezone(timezone.utc)


def _derived_verdict_id(
    *,
    case_id: str,
    case_sha256: str,
    ballot_set_sha256: str,
    frozen_roster_sha256: str,
    authority_digest: str,
    rule_sha256: str,
    compiled_at: datetime,
) -> str:
    digest = canonical_sha256(
        {
            "case_id": case_id,
            "case_sha256": case_sha256,
            "ballot_set_sha256": ballot_set_sha256,
            "frozen_roster_sha256": frozen_roster_sha256,
            "authority_digest": authority_digest,
            "terminality_rule_sha256": rule_sha256,
            "compiled_at": compiled_at.isoformat().replace("+00:00", "Z"),
        }
    )
    return f"sab_compiled_verdict_{digest[:24]}"


def compile_council_outcome(
    *,
    authority: Any,
    case_id: Any,
    case_sha256: Any,
    ballots: Any,
    rule: Any,
    frozen_roster: Any,
    requested_scope: Any,
    requested_effects: Any,
    compiled_at: Any,
    verdict_id: str | None = None,
) -> CeremonyOutcome:
    """Compile one deterministic Copy outcome, checking authority first."""

    authority_or_refusal, authorized_effects = _authority_first(
        authority=authority,
        requested_scope=requested_scope,
        requested_effects=requested_effects,
    )
    if isinstance(authority_or_refusal, RefusalReceiptV1):
        return authority_or_refusal
    authorized = authority_or_refusal

    parsed_rule = _parse_rule(rule)
    if set(parsed_rule.all_requested_effects) != set(authorized_effects):
        return _refusal(
            reason="authority_effect_mismatch",
            requested_scope=DispositionScope.COPY,
            authority=authorized,
            authority_inspected=True,
            terminality_rule_inspected=True,
        )

    try:
        normalized_case_id = _nonblank(case_id, field="case_id")
        normalized_case_sha256 = _nonblank(case_sha256, field="case_sha256")
        if len(normalized_case_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in normalized_case_sha256
        ):
            raise ValueError("case_sha256 must be lowercase SHA-256")
    except ValueError as exc:
        raise CouncilCompilationError(
            "ceremony_binding_invalid", "case binding is malformed"
        ) from exc
    parsed_roster = _parse_frozen_roster(frozen_roster)
    expected = tuple(seat.seat_id for seat in parsed_roster)
    if len(parsed_roster) != parsed_rule.council_size:
        raise CouncilCompilationError(
            "expected_roster_size_mismatch",
            "expected roster size differs from the explicit council rule",
        )
    frozen_roster_sha256 = canonical_sha256(
        [seat.canonical_payload() for seat in parsed_roster]
    )

    parsed_ballots = _parse_final_ballots(
        ballots,
        case_id=normalized_case_id,
        case_sha256=normalized_case_sha256,
        frozen_roster=parsed_roster,
    )
    ballot_set_sha256 = _ballot_set_sha256(parsed_ballots)
    pre_unseal = _assess_pre_unseal(
        rule=parsed_rule,
        expected_seat_ids=expected,
        seats=tuple(
            PreUnsealSeatV1(
                seat_id=ballot.seat_id,
                credited_cluster=ballot.credited_cluster,
                correlation_smeared=ballot.correlation_smeared,
            )
            for ballot in parsed_ballots
        ),
    )

    raw_tally = dict(
        sorted(Counter(str(ballot.decision) for ballot in parsed_ballots).items())
    )
    all_clusters: defaultdict[str, set[str]] = defaultdict(set)
    clean_clusters: defaultdict[str, set[str]] = defaultdict(set)
    removals: list[CorrelationSmearRemovalV1] = []
    for ballot in parsed_ballots:
        decision = str(ballot.decision)
        all_clusters[decision].add(ballot.credited_cluster)
        if ballot.correlation_smeared:
            removals.append(
                CorrelationSmearRemovalV1(
                    seat_id=ballot.seat_id,
                    ballot_id=ballot.ballot_id,
                    decision=decision,
                    credited_cluster=ballot.credited_cluster,
                    transport_correlation_refs=ballot.transport_correlation_refs,
                )
            )
        else:
            clean_clusters[decision].add(ballot.credited_cluster)
    clusters_by_result = {
        decision: tuple(sorted(clusters))
        for decision, clusters in sorted(all_clusters.items())
    }
    all_cluster_tally = {
        decision: len(clusters) for decision, clusters in sorted(all_clusters.items())
    }
    clean_cluster_tally = {
        decision: len(clusters) for decision, clusters in sorted(clean_clusters.items())
    }
    raw_winner = _unique_winner(raw_tally)
    all_cluster_winner = _unique_winner(all_cluster_tally)
    clean_cluster_winner = _unique_winner(clean_cluster_tally)

    def qualifies(cluster_tally: Mapping[str, int], cluster_winner: str | None) -> bool:
        return bool(
            raw_winner in parsed_rule.terminal_decisions
            and raw_tally.get(str(raw_winner), 0) >= parsed_rule.minimum_raw_votes
            and cluster_tally.get(str(raw_winner), 0)
            >= parsed_rule.minimum_clean_clusters
            and cluster_winner == raw_winner
        )

    before_removal_terminal = qualifies(all_cluster_tally, all_cluster_winner)
    after_removal_terminal = qualifies(clean_cluster_tally, clean_cluster_winner)
    correlation_result: Literal["stable", "winner_changed", "terminality_changed"]
    if removals and before_removal_terminal != after_removal_terminal:
        correlation_result = "terminality_changed"
    elif removals and all_cluster_winner != clean_cluster_winner:
        correlation_result = "winner_changed"
    else:
        correlation_result = "stable"

    compiled_time = _normalize_time(compiled_at)
    normalized_verdict_id = (
        _nonblank(verdict_id, field="verdict_id")
        if verdict_id is not None
        else _derived_verdict_id(
            case_id=normalized_case_id,
            case_sha256=normalized_case_sha256,
            ballot_set_sha256=ballot_set_sha256,
            frozen_roster_sha256=frozen_roster_sha256,
            authority_digest=authorized.authority_digest,
            rule_sha256=parsed_rule.rule_sha256,
            compiled_at=compiled_time,
        )
    )
    base: dict[str, Any] = {
        "verdict_id": normalized_verdict_id,
        "case_id": normalized_case_id,
        "case_sha256": normalized_case_sha256,
        "round_no": 1,
        "raw_tally": raw_tally,
        "clean_routing_tally": clean_cluster_tally,
        "credited_clusters_by_result": clusters_by_result,
        "smeared_seats": tuple(sorted(removal.seat_id for removal in removals)),
        "correlation_removal_result": correlation_result,
        "ballot_sources": (BallotSource.FIXTURE_MODEL,),
        "evidence_provenance": EvidenceProvenance.FIXTURE_MODELS,
        "authority_digest": authorized.authority_digest,
        "scope": DispositionScope.COPY,
        "operator_independence": "single_operator_bootstrap",
        "effect_domain": "artifact",
        "standing_effect": "none",
        "compiled_at": compiled_time,
        "ballot_set_sha256": ballot_set_sha256,
        "frozen_roster_sha256": frozen_roster_sha256,
        "terminality_rule_sha256": parsed_rule.rule_sha256,
        "winner": raw_winner,
        "clean_cluster_winner": clean_cluster_winner,
        "correlation_smear_removals": tuple(
            sorted(removals, key=lambda removal: (removal.seat_id, removal.ballot_id))
        ),
        "pre_unseal_feasibility": pre_unseal,
    }

    appeal_reasons: list[str] = []
    if correlation_result == "winner_changed":
        appeal_reasons.append("correlation_smear_changed_winner")
    elif correlation_result == "terminality_changed":
        appeal_reasons.append("correlation_smear_changed_terminality")
    appeal_vote_succeeds = bool(
        raw_winner == "appeal"
        and raw_tally.get("appeal", 0) >= parsed_rule.minimum_raw_votes
        and clean_cluster_tally.get("appeal", 0) >= parsed_rule.minimum_clean_clusters
        and clean_cluster_winner == "appeal"
    )
    if appeal_vote_succeeds:
        appeal_reasons.append("council_vote_requires_appeal")
    if appeal_reasons:
        appeal_identity = canonical_sha256(
            {
                "verdict_id": normalized_verdict_id,
                "ballot_set_sha256": ballot_set_sha256,
                "appeal_reasons": sorted(appeal_reasons),
            }
        )
        return AppealReceiptV1(
            **base,
            appeal_id=f"sab_council_appeal_{appeal_identity[:24]}",
            decision="appeal_required",
            terminality="appeal_required",
            appeal_reasons=tuple(appeal_reasons),
            requested_effects=(),
        )

    if after_removal_terminal and raw_winner is not None:
        terminal_effects = parsed_rule.effects_by_decision[raw_winner]  # type: ignore[index]
        return CompiledVerdictV1(
            **base,
            decision=raw_winner,
            terminality="terminal",
            appeal_reasons=(),
            requested_effects=terminal_effects,
        )
    return CompiledVerdictV1(
        **base,
        decision="no_terminal_verdict",
        terminality="no_terminal_verdict",
        appeal_reasons=(),
        requested_effects=(),
    )


def verify_compiled_outcome(
    outcome: CeremonyOutcome | Mapping[str, Any],
    *,
    authority: Any,
    case_id: Any,
    case_sha256: Any,
    ballots: Any,
    rule: Any,
    frozen_roster: Any,
    requested_scope: Any,
    requested_effects: Any,
    compiled_at: Any,
    verdict_id: str | None = None,
) -> bool:
    """Recompile from source inputs and reject any caller-supplied derived field."""

    try:
        expected = compile_council_outcome(
            authority=authority,
            case_id=case_id,
            case_sha256=case_sha256,
            ballots=ballots,
            rule=rule,
            frozen_roster=frozen_roster,
            requested_scope=requested_scope,
            requested_effects=requested_effects,
            compiled_at=compiled_at,
            verdict_id=verdict_id,
        )
        actual = CEREMONY_OUTCOME_ADAPTER.validate_python(outcome)
    except Exception:
        return False
    return actual.canonical_bytes() == expected.canonical_bytes()


__all__ = [
    "AppealReceiptV1",
    "CEREMONY_OUTCOME_ADAPTER",
    "CeremonyOutcome",
    "CompiledVerdictV1",
    "CorrelationSmearRemovalV1",
    "CouncilCompilationError",
    "CouncilTerminalityRuleV1",
    "PreUnsealFeasibilityResultV1",
    "PreUnsealFeasibilityV1",
    "PreUnsealSeatV1",
    "RefusalReceiptV1",
    "assess_pre_unseal_feasibility",
    "compile_council_outcome",
    "compute_council_terminality_rule_sha256",
    "verify_compiled_outcome",
]
