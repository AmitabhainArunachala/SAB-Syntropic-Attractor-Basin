"""Evidence-derived, unsigned operator packets for an attended SAB ceremony.

The public constructor in this module does not accept a JSON envelope or a set
of caller-chosen digests.  It consumes the typed objects emitted by the
ceremony, transcript, and compiler lanes, re-verifies their cross-bindings,
and returns a locally sealed :class:`CeremonyApprovalEvidence` value.  Only
that in-memory value can be turned into an unsigned operator packet.

The resulting packet remains non-authorizing.  A persisted packet can be
checked for canonical integrity and rendered for human inspection, but that
check cannot recreate the local verifier seals, an operator signature, or an
evaluator capability.  The CLI therefore verifies and renders existing
packets only; it cannot synthesize one from arbitrary JSON.

Expected ceremony inputs are the v1 typed objects from
``sab_first_verdict_ceremony``.  Signed founder/provider/maintenance/control/
lease observations expose ``attestor_*``, ``attestation_signature``, and
``signing_bytes()``.  Both readiness values must be the exact locally sealed
objects returned by the ceremony verifiers.  The Live lease is evidence in
``prepared_for_attended_activation`` state and explicitly permits no effect.
"""

from __future__ import annotations

import hashlib
import json
import re
import weakref
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .sab_artifact_verdict import (
    AuthorizedDispositionAuthorityV1,
    canonical_json,
    canonical_sha256,
    verify_contract_signature,
)
from .sab_first_verdict_ceremony import (
    AttendedCeremonyManifestV1,
    BenchCostEnvelopeV1,
    FounderDecisionReceiptV1,
    FrozenBenchManifestV1,
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
)
from .sab_first_verdict_compiler import (
    CompiledVerdictV1,
    CouncilTerminalityRuleV1,
    verify_compiled_outcome,
)
from .sab_first_verdict_transcript import (
    CEREMONY_STAGES,
    CeremonyStageEnvelopeV1,
    TranscriptValidationResultV1,
    verify_ceremony_transcript,
)


SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_OBJECT_PATTERN = r"^[0-9a-f]{40}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SIGNING_INSTRUCTION = (
    "Only inside an attended controller that has re-derived current source "
    "evidence, inspect every full evidence digest and the attended-window state; "
    "then sign the full approval_payload_sha256 only. Never sign from a persisted "
    "integrity-only view; the short checksum and this unsigned packet are "
    "non-authorizing."
)
SIGNING_INSTRUCTION_SHA256 = hashlib.sha256(SIGNING_INSTRUCTION.encode()).hexdigest()
BUILD_A_MERGE_COMMIT = "6ad237af3414288cee52148a5f0dec7c69f32b71"
BUILD_A_MERGE_TREE = "92e523eec91c8dc52573835625bf1fb2ddc30b3a"
BUILD_A_CLOSEOUT_SHA256 = (
    "a19ebdc01d6d487239f213f6cfe539ad159a0bdb1c286984a0600f16182e890e"
)
BUILD_A_CLOSEOUT_CANONICAL_SHA256 = (
    "4fe873c21aab72d5079211988f803c6bc51022c4dfc37196f33223b9fada7a06"
)
_FORBIDDEN_KEY_PARTS = frozenset(
    {
        "api_key",
        "credential",
        "private_key",
        "secret",
        "seed_phrase",
        "token",
    }
)


class ApprovalPacketError(ValueError):
    """Fail-closed approval-packet error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _CeremonyCodeBindingV2(_StrictModel):
    runtime_commit_sha: str = Field(pattern=GIT_OBJECT_PATTERN)
    build_a_merge_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    build_a_merge_tree: str = Field(pattern=GIT_OBJECT_PATTERN)
    build_a_closeout_sha256: str = Field(pattern=SHA256_PATTERN)
    build_a_closeout_canonical_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _known_build_a_roots_are_distinct(self) -> "_CeremonyCodeBindingV2":
        if (
            self.build_a_merge_commit != BUILD_A_MERGE_COMMIT
            or self.build_a_merge_tree != BUILD_A_MERGE_TREE
            or self.build_a_closeout_sha256 != BUILD_A_CLOSEOUT_SHA256
            or self.build_a_closeout_canonical_sha256
            != BUILD_A_CLOSEOUT_CANONICAL_SHA256
            or self.runtime_commit_sha == self.build_a_merge_commit
        ):
            raise ValueError("code roots do not bind the pinned Build A closeout")
        return self


class _BuildAPullRequestV1(_StrictModel):
    number: int = Field(gt=0)
    url: str = Field(min_length=1)
    state: Literal["MERGED"] = "MERGED"
    head: str = Field(pattern=GIT_OBJECT_PATTERN)
    head_tree: str = Field(pattern=GIT_OBJECT_PATTERN)
    merge_commit: str = Field(pattern=GIT_OBJECT_PATTERN)
    merge_tree: str = Field(pattern=GIT_OBJECT_PATTERN)
    merged_at_utc: str

    @field_validator("merged_at_utc")
    @classmethod
    def _merged_at_is_utc(cls, value: str) -> str:
        if not UTC_PATTERN.fullmatch(value):
            raise ValueError("merged_at_utc must use exact UTC Z form")
        return value


class _BuildAGitHubCIV1(_StrictModel):
    run_id: int = Field(gt=0)
    test_python_3_10: Literal["PASS"] = "PASS"
    test_python_3_11: Literal["PASS"] = "PASS"
    test_python_3_12: Literal["PASS"] = "PASS"
    security: Literal["PASS"] = "PASS"
    lint: Literal["PASS"] = "PASS"
    docker: Literal["PASS"] = "PASS"


class _BuildALocalVerificationV1(_StrictModel):
    full_pytest: str = Field(
        pattern=r"^[1-9][0-9]* passed(?:, [0-9]+ warnings)? in .+$"
    )
    atomic_pytest: str = Field(pattern=r"^[1-9][0-9]* passed$")
    bandit: str = Field(pattern=r"^0 high, 0 medium, 0 low$")
    ruff_check: Literal["PASS"] = "PASS"
    ruff_format_check: Literal["PASS"] = "PASS"
    compileall: Literal["PASS"] = "PASS"
    governance_and_orientation: Literal["PASS"] = "PASS"
    worktree_clean: Literal[True] = True


class _BuildAPriorReceiptsV1(_StrictModel):
    integration_replay: str = Field(min_length=1)
    integration_replay_sha256: str = Field(pattern=SHA256_PATTERN)
    linux_portability: str = Field(min_length=1)
    linux_portability_sha256: str = Field(pattern=SHA256_PATTERN)


class _BuildATerminalClaimV1(_StrictModel):
    engineering_status: Literal["proven_on_copy_and_merged"] = (
        "proven_on_copy_and_merged"
    )
    historic_live_win: Literal[False] = False
    live_mutations: Literal[0] = 0
    service_mutations: Literal[0] = 0
    provider_calls: Literal[0] = 0
    standing_effect: Literal["none"] = "none"
    master_vision_effect: Literal["none"] = "none"
    build_b: Literal["not_run_at_build_a_merge"] = "not_run_at_build_a_merge"


class _BuildAMergeCloseoutV1(_StrictModel):
    schema_: Literal["sab.first_verdict.build_a_merge_closeout.v1"] = Field(
        "sab.first_verdict.build_a_merge_closeout.v1", alias="schema"
    )
    created_at_utc: str
    repository: Literal["AmitabhainArunachala/SAB-Syntropic-Attractor-Basin"]
    pull_request: _BuildAPullRequestV1
    github_ci: _BuildAGitHubCIV1
    final_local_verification: _BuildALocalVerificationV1
    ci_repairs: dict[str, str]
    prior_receipts: _BuildAPriorReceiptsV1
    terminal_claim: _BuildATerminalClaimV1

    @field_validator("created_at_utc")
    @classmethod
    def _created_at_is_utc(cls, value: str) -> str:
        if not UTC_PATTERN.fullmatch(value):
            raise ValueError("created_at_utc must use exact UTC Z form")
        return value

    @field_validator("ci_repairs")
    @classmethod
    def _repair_commits_are_exact(cls, value: dict[str, str]) -> dict[str, str]:
        if not value or any(
            re.fullmatch(GIT_OBJECT_PATTERN, commit) is None or not detail
            for commit, detail in value.items()
        ):
            raise ValueError("ci_repairs must bind nonempty Git commits and details")
        return value

    @model_validator(mode="after")
    def _merged_tree_and_time_are_bound(self) -> "_BuildAMergeCloseoutV1":
        if (
            self.pull_request.head_tree != self.pull_request.merge_tree
            or self.created_at_utc != self.pull_request.merged_at_utc
            or self.pull_request.url
            != (f"https://github.com/{self.repository}/pull/{self.pull_request.number}")
        ):
            raise ValueError(
                "Build A closeout merge tree, completion time, or pull request differs"
            )
        return self


class _CeremonyAuthorityEvidenceV2(_StrictModel):
    case_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_id: str = Field(pattern=IDENTIFIER_PATTERN)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_evaluated_state_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_effects: tuple[Literal["challenge:resolve", "seed:supersede"], ...] = (
        Field(min_length=1)
    )
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    founder_decision_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    founder_decision: Literal["alternate_artifact_terminal_disposition"] = (
        "alternate_artifact_terminal_disposition"
    )
    authority_evaluation_sha256: str = Field(pattern=SHA256_PATTERN)
    compiler_copy_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_semantics: Literal["signed_receipts_not_capabilities"] = (
        "signed_receipts_not_capabilities"
    )
    live_authority_created: Literal[False] = False

    @field_validator("requested_effects", mode="before")
    @classmethod
    def _requested_effects_are_canonical(cls, value: Any) -> tuple[Any, ...]:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError("requested effects must be a sequence")
        normalized = tuple(value)
        if normalized != tuple(sorted(set(normalized))):
            raise ValueError("requested effects must be unique and canonically sorted")
        return normalized


class _CeremonyBenchBindingV2(_StrictModel):
    attended_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_bench_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    terminality_rule_sha256: str = Field(pattern=SHA256_PATTERN)
    provider_probe_bundle_sha256: str = Field(pattern=SHA256_PATTERN)
    cost_envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    transcript_head_sha256: str = Field(pattern=SHA256_PATTERN)
    final_ballot_set_sha256: str = Field(pattern=SHA256_PATTERN)
    compiled_outcome_sha256: str = Field(pattern=SHA256_PATTERN)
    compiled_outcome_scope: Literal["Copy"] = "Copy"
    compiled_decision: Literal["correct_and_supersede"] = "correct_and_supersede"
    live_promotion_claimed: Literal[False] = False


class _CeremonyCostBindingV2(_StrictModel):
    currency: Literal["USD"] = "USD"
    total_maximum_cost_microusd: int = Field(ge=0)
    spend_cap_microusd: int = Field(ge=0)
    automatic_top_up: Literal[False] = False
    operator_public_key_fingerprint: str = Field(pattern=SHA256_PATTERN)


class _CeremonyTrustAnchorBindingV2(_StrictModel):
    frozen_trust_anchor_set_sha256s: tuple[str, ...] = Field(min_length=1)
    live_trust_anchor_set_sha256s: tuple[str, ...] = Field(min_length=1)

    @field_validator(
        "frozen_trust_anchor_set_sha256s",
        "live_trust_anchor_set_sha256s",
        mode="before",
    )
    @classmethod
    def _trust_anchor_digests_are_exact(cls, value: Any) -> tuple[str, ...]:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError("trust-anchor digests must be a sequence")
        normalized = tuple(value)
        if (
            len(set(normalized)) != len(normalized)
            or normalized != tuple(sorted(normalized))
            or any(
                not isinstance(item, str) or re.fullmatch(SHA256_PATTERN, item) is None
                for item in normalized
            )
        ):
            raise ValueError("trust-anchor digests must be unique canonical SHA-256s")
        return normalized


class _CeremonyMaintenanceBindingV2(_StrictModel):
    runtime_attestation_sha256: str = Field(pattern=SHA256_PATTERN)
    service_state_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_exclusion_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    restoration_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    service_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    write_lease_sha256: str = Field(pattern=SHA256_PATTERN)
    write_lease_scope: Literal["Live"] = "Live"
    write_lease_state: Literal["prepared_for_attended_activation"] = (
        "prepared_for_attended_activation"
    )
    write_lease_permits_live_effect: Literal[False] = False


class CeremonyEffectProposalV1(_StrictModel):
    """Closed, deterministic proposal; it is evidence and never an effect."""

    schema_version: Literal["sab.ceremony_effect_proposal.v1"] = (
        "sab.ceremony_effect_proposal.v1"
    )
    effect_type: Literal["challenge:resolve", "seed:supersede"]
    action: Literal["resolve_terminal_challenge", "supersede_terminal_artifact"]
    target_kind: Literal["case", "artifact"]
    target_id: str = Field(pattern=IDENTIFIER_PATTERN)
    ceremony_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_id: str = Field(pattern=IDENTIFIER_PATTERN)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_evaluated_state_sha256: str = Field(pattern=SHA256_PATTERN)
    compiled_outcome_sha256: str = Field(pattern=SHA256_PATTERN)
    transcript_sha256: str = Field(pattern=SHA256_PATTERN)
    standing_effect: Literal["none"] = "none"
    effect_executable: Literal[False] = False

    @model_validator(mode="after")
    def _action_target_is_exact(self) -> "CeremonyEffectProposalV1":
        expected = {
            "challenge:resolve": (
                "resolve_terminal_challenge",
                "case",
                self.case_id,
            ),
            "seed:supersede": (
                "supersede_terminal_artifact",
                "artifact",
                self.artifact_id,
            ),
        }[self.effect_type]
        if (self.action, self.target_kind, self.target_id) != expected:
            raise ValueError("effect action and target do not match the closed effect")
        return self


class _CeremonyEffectBindingV2(_StrictModel):
    proposal: CeremonyEffectProposalV1
    proposal_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)

    @model_validator(mode="after")
    def _proposal_digest_is_exact(self) -> "_CeremonyEffectBindingV2":
        expected = canonical_sha256(self.proposal.model_dump(mode="json"))
        if self.proposal_sha256 != expected:
            raise ValueError("proposal_sha256 does not bind the closed proposal")
        return self


class _CeremonyApprovalPayloadV2(_StrictModel):
    """Closed evidence summary; callers cannot use it to construct packets."""

    schema_version: Literal["sab.ceremony_approval_payload.v2"]
    ceremony_id: str = Field(pattern=IDENTIFIER_PATTERN)
    prepared_at: str
    source_evidence_valid_until: str
    requested_scope: Literal["Live"] = "Live"
    evidence_derivation: Literal["typed_objects_rederived_in_memory_v1"] = (
        "typed_objects_rederived_in_memory_v1"
    )
    code: _CeremonyCodeBindingV2
    authority_evidence: _CeremonyAuthorityEvidenceV2
    bench: _CeremonyBenchBindingV2
    cost: _CeremonyCostBindingV2
    trust_anchors: _CeremonyTrustAnchorBindingV2
    maintenance: _CeremonyMaintenanceBindingV2
    proposed_effects: tuple[_CeremonyEffectBindingV2, ...] = Field(min_length=1)
    operator_signature_state: Literal["awaiting_operator_countersign"] = (
        "awaiting_operator_countersign"
    )
    effect_executable: Literal[False] = False
    live_authority_created: Literal[False] = False

    @field_validator("prepared_at", "source_evidence_valid_until")
    @classmethod
    def _evidence_times_are_exact_utc(cls, value: str) -> str:
        if not UTC_PATTERN.fullmatch(value):
            raise ValueError(
                "evidence times must use exact second-resolution UTC Z form"
            )
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.tzinfo is None or parsed.astimezone(timezone.utc) != parsed:
            raise ValueError("evidence times must be UTC")
        return value

    @field_validator("proposed_effects", mode="before")
    @classmethod
    def _proposed_effects_are_a_tuple(cls, value: Any) -> tuple[Any, ...]:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError("proposed effects must be a sequence")
        return tuple(value)

    @field_validator("proposed_effects")
    @classmethod
    def _effects_are_canonical(
        cls, value: tuple[_CeremonyEffectBindingV2, ...]
    ) -> tuple[_CeremonyEffectBindingV2, ...]:
        names = tuple(item.proposal.effect_type for item in value)
        if len(set(names)) != len(names) or names != tuple(sorted(names)):
            raise ValueError("proposed effects must be unique and canonically sorted")
        return value

    @model_validator(mode="after")
    def _all_persisted_cross_bindings_are_exact(
        self,
    ) -> "_CeremonyApprovalPayloadV2":
        prepared_at = datetime.fromisoformat(self.prepared_at[:-1] + "+00:00")
        valid_until = datetime.fromisoformat(
            self.source_evidence_valid_until[:-1] + "+00:00"
        )
        if prepared_at >= valid_until:
            raise ValueError(
                "source evidence has no positive persisted validity window"
            )
        if self.cost.total_maximum_cost_microusd > self.cost.spend_cap_microusd:
            raise ValueError("maximum cost exceeds the persisted spend cap")
        if not set(self.trust_anchors.frozen_trust_anchor_set_sha256s).issubset(
            self.trust_anchors.live_trust_anchor_set_sha256s
        ):
            raise ValueError("live trust anchors do not preserve frozen trust anchors")
        proposal_effects = tuple(
            item.proposal.effect_type for item in self.proposed_effects
        )
        if proposal_effects != self.authority_evidence.requested_effects:
            raise ValueError(
                "proposal effects differ from persisted authority requested effects"
            )
        expected_effects = {"challenge:resolve", "seed:supersede"}
        if set(proposal_effects) != expected_effects:
            raise ValueError("proposal set differs from the closed Build B effect set")
        for item in self.proposed_effects:
            proposal = item.proposal
            if not all(
                (
                    proposal.ceremony_id == self.ceremony_id,
                    proposal.case_id == self.authority_evidence.case_id,
                    proposal.case_sha256 == self.authority_evidence.case_sha256,
                    proposal.artifact_id == self.authority_evidence.artifact_id,
                    proposal.artifact_sha256 == self.authority_evidence.artifact_sha256,
                    proposal.expected_evaluated_state_sha256
                    == self.authority_evidence.expected_evaluated_state_sha256,
                    proposal.compiled_outcome_sha256
                    == self.bench.compiled_outcome_sha256,
                    proposal.transcript_sha256 == self.bench.transcript_head_sha256,
                )
            ):
                raise ValueError(
                    "effect proposal differs from persisted evidence roots"
                )
            expected_idempotency = canonical_sha256(
                {
                    "ceremony_id": self.ceremony_id,
                    "effect_type": proposal.effect_type,
                    "proposal_sha256": item.proposal_sha256,
                    "write_lease_sha256": self.maintenance.write_lease_sha256,
                }
            )
            if item.idempotency_key != f"sab-{expected_idempotency[:32]}":
                raise ValueError(
                    "proposal idempotency key does not bind the write lease"
                )
        return self


class CeremonyApprovalEvidence:
    """Locally sealed evidence derivation; it is intentionally not serializable."""

    __slots__ = ("_payload", "_payload_sha256", "__weakref__")

    def __new__(cls) -> "CeremonyApprovalEvidence":
        raise TypeError("CeremonyApprovalEvidence is evaluator-constructed only")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("CeremonyApprovalEvidence is immutable")


_EVIDENCE_REGISTRY: weakref.WeakKeyDictionary[CeremonyApprovalEvidence, str] = (
    weakref.WeakKeyDictionary()
)


def _seal_approval_evidence(
    payload: _CeremonyApprovalPayloadV2,
    payload_sha256: str,
) -> CeremonyApprovalEvidence:
    evidence = object.__new__(CeremonyApprovalEvidence)
    object.__setattr__(evidence, "_payload", payload)
    object.__setattr__(evidence, "_payload_sha256", payload_sha256)
    _EVIDENCE_REGISTRY[evidence] = payload_sha256
    return evidence


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def _reject_secret_bearing_keys(value: Any) -> None:
    """Reject secret-shaped fields without ever echoing their values."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = _normalized_key(key)
            if any(
                normalized == forbidden
                or normalized.startswith(forbidden + "_")
                or normalized.endswith("_" + forbidden)
                for forbidden in _FORBIDDEN_KEY_PARTS
            ):
                raise ApprovalPacketError(
                    "secret_field_forbidden",
                    "approval material contains a forbidden secret-bearing field",
                )
            _reject_secret_bearing_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_secret_bearing_keys(child)


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise ApprovalPacketError(code, detail)


def _require_signed_observation(value: Any, *, label: str) -> None:
    signature = getattr(value, "attestation_signature", None)
    signing_bytes = getattr(value, "signing_bytes", None)
    _require(
        callable(signing_bytes) and signature is not None,
        f"{label}_unsigned",
        f"{label} must be a typed signed observation",
    )
    _require(
        getattr(value, "authority_semantics", None)
        == "persisted_receipt_not_capability",
        f"{label}_semantics_invalid",
        f"{label} must remain persisted evidence rather than a capability",
    )
    _require(
        getattr(value, "standing_effect", None) == "none",
        f"{label}_standing_invalid",
        f"{label} cannot carry standing",
    )
    _require(
        verify_contract_signature(signing_bytes(), signature),
        f"{label}_signature_invalid",
        f"{label} signature failed verification",
    )


def _require_local_readiness(
    value: Any,
    *,
    phase: Literal["frozen_execution_facts", "live_maintenance_preflight"],
    manifest_sha256: str,
    expected_receipts: set[str],
    prepared_at: datetime,
) -> None:
    _require(
        isinstance(value, StructurallyCompleteAwaitingAuthority)
        and readiness_is_locally_verified(value, phase=phase),
        f"{phase}_not_locally_verified",
        f"{phase} must be the exact locally verified readiness value",
    )
    _require(
        value.manifest_sha256 == manifest_sha256,
        f"{phase}_manifest_mismatch",
        f"{phase} belongs to another manifest",
    )
    _require(
        set(value.verified_receipt_sha256s) == expected_receipts,
        f"{phase}_receipt_set_mismatch",
        f"{phase} does not bind the exact evidence set",
    )
    _require(
        value.checked_at <= prepared_at < value.valid_until,
        f"{phase}_outside_validity",
        f"{phase} is not valid at packet preparation time",
    )
    _require(
        value.live_authority_state == "absent"
        and value.permits_live_effect is False
        and value.standing_effect == "none",
        f"{phase}_authority_claim_invalid",
        f"{phase} cannot carry live authority",
    )


def _ballot_set_sha256(ballots: Sequence[Any]) -> str:
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


def _prepared_at(value: datetime) -> tuple[datetime, str]:
    _require(
        isinstance(value, datetime) and value.tzinfo is not None,
        "prepared_at_invalid",
        "prepared_at must be a timezone-aware datetime",
    )
    normalized = value.astimezone(timezone.utc)
    _require(
        normalized.microsecond == 0,
        "prepared_at_invalid",
        "prepared_at must use exact second resolution",
    )
    return normalized, normalized.isoformat().replace("+00:00", "Z")


def _build_a_closeout_binding(
    value: bytes,
) -> tuple[_BuildAMergeCloseoutV1, str, str]:
    _require(
        isinstance(value, bytes) and bool(value),
        "build_a_closeout_invalid",
        "Build A closeout must be supplied as non-empty receipt bytes",
    )

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise ApprovalPacketError(
                    "build_a_closeout_duplicate_key",
                    "Build A closeout contains a duplicate JSON key",
                )
            result[key] = child
        return result

    try:
        payload = json.loads(value, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApprovalPacketError(
            "build_a_closeout_invalid", "Build A closeout is not JSON receipt bytes"
        ) from exc
    _require(
        isinstance(payload, Mapping),
        "build_a_closeout_invalid",
        "Build A closeout must be a JSON object",
    )
    _reject_secret_bearing_keys(payload)
    raw_digest = hashlib.sha256(value).hexdigest()
    canonical_digest = canonical_sha256(payload)
    _require(
        raw_digest == BUILD_A_CLOSEOUT_SHA256
        and canonical_digest == BUILD_A_CLOSEOUT_CANONICAL_SHA256,
        "build_a_closeout_provenance_mismatch",
        "Build A closeout differs from the pinned immutable receipt",
    )
    try:
        closeout = _BuildAMergeCloseoutV1.model_validate(payload)
    except Exception as exc:
        raise ApprovalPacketError(
            "build_a_closeout_invalid",
            "Build A closeout fails the exact merged, green, non-live contract",
        ) from exc
    return closeout, raw_digest, canonical_digest


def bind_operator_approval_evidence(
    *,
    manifest: AttendedCeremonyManifestV1,
    frozen_readiness: StructurallyCompleteAwaitingAuthority,
    live_readiness: StructurallyCompleteAwaitingAuthority,
    founder_decision_receipt: FounderDecisionReceiptV1,
    authority_evaluation: SignedAuthorityEvaluationEnvelopeV1,
    compiler_authority: AuthorizedDispositionAuthorityV1,
    provider_probes: Sequence[ProviderProbeReceiptV1],
    bench_manifest: FrozenBenchManifestV1,
    cost_envelope: BenchCostEnvelopeV1,
    transcript: Sequence[CeremonyStageEnvelopeV1],
    transcript_validation: TranscriptValidationResultV1,
    terminality_rule: CouncilTerminalityRuleV1,
    compiled_outcome: CompiledVerdictV1,
    runtime_attestation: MaintenanceRuntimeAttestationV1,
    service_state_snapshot: ServiceStateSnapshotV1,
    tick_exclusion_receipt: TickExclusionReceiptV1,
    restoration_plan: RestorationPlanV1,
    service_control_authority: MaintenanceControlAuthorityReceiptV1,
    tick_control_authority: MaintenanceControlAuthorityReceiptV1,
    live_write_lease: LiveWriteLeaseEnvelopeV1,
    build_a_closeout_bytes: bytes,
    prepared_at: datetime,
) -> CeremonyApprovalEvidence:
    """Re-derive one non-authorizing operator packet from typed evidence.

    No digest, authority result, cost, roster, effect name, or idempotency key
    is accepted from the caller.  Digest literals in the returned payload are
    derived from the supplied typed objects or raw Build A closeout bytes.
    """

    typed_inputs = (
        (manifest, AttendedCeremonyManifestV1, "manifest"),
        (founder_decision_receipt, FounderDecisionReceiptV1, "founder_decision"),
        (
            authority_evaluation,
            SignedAuthorityEvaluationEnvelopeV1,
            "authority_evaluation",
        ),
        (
            compiler_authority,
            AuthorizedDispositionAuthorityV1,
            "compiler_authority",
        ),
        (bench_manifest, FrozenBenchManifestV1, "bench_manifest"),
        (cost_envelope, BenchCostEnvelopeV1, "cost_envelope"),
        (transcript_validation, TranscriptValidationResultV1, "transcript_validation"),
        (terminality_rule, CouncilTerminalityRuleV1, "terminality_rule"),
        (compiled_outcome, CompiledVerdictV1, "compiled_outcome"),
        (
            runtime_attestation,
            MaintenanceRuntimeAttestationV1,
            "runtime_attestation",
        ),
        (
            service_state_snapshot,
            ServiceStateSnapshotV1,
            "service_state_snapshot",
        ),
        (
            tick_exclusion_receipt,
            TickExclusionReceiptV1,
            "tick_exclusion_receipt",
        ),
        (restoration_plan, RestorationPlanV1, "restoration_plan"),
        (
            service_control_authority,
            MaintenanceControlAuthorityReceiptV1,
            "service_control_authority",
        ),
        (
            tick_control_authority,
            MaintenanceControlAuthorityReceiptV1,
            "tick_control_authority",
        ),
        (live_write_lease, LiveWriteLeaseEnvelopeV1, "live_write_lease"),
    )
    for value, expected, label in typed_inputs:
        _require(
            isinstance(value, expected),
            f"{label}_type_invalid",
            f"{label} must be the exact typed object",
        )
    _require(
        isinstance(provider_probes, Sequence)
        and not isinstance(provider_probes, (str, bytes, bytearray))
        and all(isinstance(item, ProviderProbeReceiptV1) for item in provider_probes),
        "provider_probes_type_invalid",
        "provider probes must be typed receipt objects",
    )
    _require(
        isinstance(transcript, Sequence)
        and not isinstance(transcript, (str, bytes, bytearray))
        and all(isinstance(item, CeremonyStageEnvelopeV1) for item in transcript),
        "transcript_type_invalid",
        "transcript must contain typed stage envelopes",
    )
    normalized_time, prepared_text = _prepared_at(prepared_at)

    for value, label in (
        (founder_decision_receipt, "founder_decision"),
        *[
            (probe, f"provider_probe_{index}")
            for index, probe in enumerate(provider_probes)
        ],
        (runtime_attestation, "runtime_attestation"),
        (service_state_snapshot, "service_state_snapshot"),
        (tick_exclusion_receipt, "tick_exclusion_receipt"),
        (restoration_plan, "restoration_plan"),
        (service_control_authority, "service_control_authority"),
        (tick_control_authority, "tick_control_authority"),
        (live_write_lease, "live_write_lease"),
    ):
        _require_signed_observation(value, label=label)
    _require(
        verify_contract_signature(
            authority_evaluation.signing_bytes(), authority_evaluation.signature
        ),
        "authority_evaluation_signature_invalid",
        "authority evaluation signature failed verification",
    )
    _require(
        authority_evaluation.authority_semantics == "persisted_receipt_not_capability"
        and authority_evaluation.standing_effect == "none",
        "authority_evaluation_semantics_invalid",
        "authority evaluation must remain persisted evidence without standing",
    )
    _require(
        verify_contract_signature(
            cost_envelope.signing_bytes(), cost_envelope.approval_signature
        ),
        "cost_approval_signature_invalid",
        "cost envelope approval signature failed verification",
    )

    manifest_sha256 = manifest.canonical_sha256()
    probe_by_digest = {probe.canonical_sha256(): probe for probe in provider_probes}
    _require(
        len(provider_probes) == len(probe_by_digest) == 9,
        "provider_probe_set_invalid",
        "exactly nine unique provider probe receipts are required",
    )
    ordered_probes = []
    for bench_seat in bench_manifest.seats:
        probe = probe_by_digest.get(bench_seat.provider_probe_sha256)
        _require(
            probe is not None
            and probe.frozen_seat.canonical_bytes()
            == bench_seat.frozen_seat.canonical_bytes(),
            "provider_bench_binding_mismatch",
            "provider receipt differs from the exact frozen bench seat",
        )
        ordered_probes.append(probe)

    frozen_expected = {
        manifest_sha256,
        founder_decision_receipt.canonical_sha256(),
        authority_evaluation.canonical_sha256(),
        bench_manifest.canonical_sha256(),
        cost_envelope.canonical_sha256(),
        *probe_by_digest,
    }
    live_expected = {
        *frozen_expected,
        runtime_attestation.canonical_sha256(),
        service_state_snapshot.canonical_sha256(),
        tick_exclusion_receipt.canonical_sha256(),
        restoration_plan.canonical_sha256(),
        service_control_authority.canonical_sha256(),
        tick_control_authority.canonical_sha256(),
        live_write_lease.canonical_sha256(),
    }
    _require_local_readiness(
        frozen_readiness,
        phase="frozen_execution_facts",
        manifest_sha256=manifest_sha256,
        expected_receipts=frozen_expected,
        prepared_at=normalized_time,
    )
    _require_local_readiness(
        live_readiness,
        phase="live_maintenance_preflight",
        manifest_sha256=manifest_sha256,
        expected_receipts=live_expected,
        prepared_at=normalized_time,
    )
    _require(
        set(frozen_readiness.trust_anchor_set_sha256s).issubset(
            live_readiness.trust_anchor_set_sha256s
        ),
        "readiness_trust_anchor_set_mismatch",
        "live readiness does not preserve every frozen-facts trust anchor",
    )

    _require(
        manifest.founder_decision_receipt_sha256
        == founder_decision_receipt.canonical_sha256()
        and manifest.founder_decision
        == founder_decision_receipt.decision
        == "alternate_artifact_terminal_disposition"
        and founder_decision_receipt.ceremony_id == manifest.ceremony_id
        and founder_decision_receipt.case_id == manifest.case_id
        and founder_decision_receipt.case_sha256 == manifest.case_sha256
        and founder_decision_receipt.artifact_id == manifest.artifact_id
        and founder_decision_receipt.artifact_sha256 == manifest.artifact_sha256
        and founder_decision_receipt.requested_effects == manifest.requested_effects,
        "founder_decision_binding_mismatch",
        "founder decision does not bind the exact ceremony manifest",
    )
    _require(
        manifest.authority_evaluation_sha256 == authority_evaluation.canonical_sha256()
        and authority_evaluation.ceremony_id == manifest.ceremony_id
        and authority_evaluation.case_id == manifest.case_id
        and authority_evaluation.case_sha256 == manifest.case_sha256
        and authority_evaluation.artifact_id == manifest.artifact_id
        and authority_evaluation.artifact_sha256 == manifest.artifact_sha256
        and authority_evaluation.policy_sha256 == manifest.policy_sha256
        and authority_evaluation.evaluated_state_sha256
        == manifest.expected_evaluated_state_sha256
        and authority_evaluation.requested_effects == manifest.requested_effects
        and authority_evaluation.reported_result == "Authorized"
        and authority_evaluation.reported_allowed_effects == manifest.requested_effects
        and authority_evaluation.reported_forbidden_effects == ()
        and authority_evaluation.reported_live_eligible is True,
        "authority_evaluation_binding_mismatch",
        "authority evaluation receipt does not bind the exact manifest",
    )
    _require(
        compiler_authority.scope == "Copy"
        and compiler_authority.live_eligible is False
        and compiler_authority.standing_effect == "none"
        and compiler_authority.artifact_id == manifest.artifact_id
        and compiler_authority.content_sha256 == manifest.artifact_sha256
        and compiler_authority.policy_sha256 == manifest.policy_sha256
        and compiler_authority.evaluated_state_hash
        == manifest.expected_evaluated_state_sha256
        and compiler_authority.allowed_effects == manifest.requested_effects,
        "compiler_authority_binding_mismatch",
        "compiler Copy authority differs from the exact ceremony evidence",
    )
    _require(
        manifest.bench_manifest_sha256 == bench_manifest.canonical_sha256()
        and bench_manifest.ceremony_id == manifest.ceremony_id
        and bench_manifest.case_id == manifest.case_id
        and bench_manifest.case_sha256 == manifest.case_sha256
        and bench_manifest.roster_sha256 == manifest.frozen_roster_sha256
        and bench_manifest.terminality_rule_sha256
        == manifest.terminality_rule_sha256
        == terminality_rule.rule_sha256,
        "bench_rule_binding_mismatch",
        "bench roster or rule differs from the exact ceremony manifest",
    )
    _require(
        tuple(sorted(probe_by_digest)) == manifest.provider_probe_sha256s,
        "provider_probe_manifest_mismatch",
        "provider probe set differs from the ceremony manifest",
    )
    _require(
        manifest.bench_cost_envelope_sha256 == cost_envelope.canonical_sha256()
        and cost_envelope.bench_manifest_sha256 == bench_manifest.canonical_sha256()
        and cost_envelope.ceremony_id == manifest.ceremony_id
        and cost_envelope.approved_by == manifest.operator_identity
        and cost_envelope.approver_public_key == manifest.operator_public_key
        and cost_envelope.approver_fingerprint == manifest.operator_fingerprint,
        "cost_binding_mismatch",
        "cost envelope differs from the bench, manifest, or operator rail",
    )
    costs_by_seat = {item.seat_id: item for item in cost_envelope.seat_costs}
    _require(
        set(costs_by_seat) == {seat.seat_id for seat in bench_manifest.seats},
        "cost_roster_mismatch",
        "cost envelope does not cover the exact nine-seat roster",
    )
    for seat in bench_manifest.seats:
        item = costs_by_seat[seat.seat_id]
        probe = probe_by_digest[seat.provider_probe_sha256]
        _require(
            item.provider_probe_sha256 == seat.provider_probe_sha256
            and item.pricing_catalog_sha256 == probe.catalog_sha256,
            "cost_source_mismatch",
            "seat cost does not bind its exact provider and catalog receipt",
        )

    rederived_transcript = verify_ceremony_transcript(
        transcript,
        expected_roster=bench_manifest.transcript_roster,
    )
    _require(
        rederived_transcript.canonical_bytes()
        == transcript_validation.canonical_bytes()
        and transcript_validation.ok
        and transcript_validation.transcript_sha256 is not None
        and transcript_validation.validated_stages == CEREMONY_STAGES,
        "transcript_validation_mismatch",
        "transcript validation cannot be re-derived exactly",
    )
    first_stage = transcript[0]
    _require(
        first_stage.case_id == manifest.case_id
        and first_stage.case_sha256 == manifest.case_sha256
        and first_stage.frozen_roster_sha256 == manifest.frozen_roster_sha256
        and first_stage.rule_digest == terminality_rule.rule_sha256
        and first_stage.authority_digest == compiled_outcome.authority_digest,
        "transcript_binding_mismatch",
        "transcript differs from the manifest, rule, or compiled authority input",
    )
    _require(
        compiled_outcome.case_id == manifest.case_id
        and compiled_outcome.case_sha256 == manifest.case_sha256
        and compiled_outcome.terminality == "terminal"
        and compiled_outcome.decision != "no_terminal_verdict"
        and compiled_outcome.scope == "Copy"
        and compiled_outcome.terminality_rule_sha256 == terminality_rule.rule_sha256
        and compiled_outcome.ballot_set_sha256
        == _ballot_set_sha256(transcript_validation.ordered_final_ballots),
        "compiled_outcome_binding_mismatch",
        "compiled outcome is nonterminal or differs from the exact transcript/rule",
    )
    _require(
        transcript_validation.frozen_roster_sha256 == bench_manifest.roster_sha256
        and transcript_validation.rule_digest == terminality_rule.rule_sha256
        and compiled_outcome.frozen_roster_sha256 == bench_manifest.roster_sha256
        and verify_compiled_outcome(
            compiled_outcome,
            authority=compiler_authority,
            case_id=manifest.case_id,
            case_sha256=manifest.case_sha256,
            ballots=transcript_validation.ordered_final_ballots,
            rule=terminality_rule,
            frozen_roster=bench_manifest.transcript_roster,
            requested_scope="Copy",
            requested_effects=manifest.requested_effects,
            compiled_at=compiled_outcome.compiled_at,
        ),
        "compiled_outcome_reverification_failed",
        "compiled outcome cannot be re-derived from the exact authority, roster, and ballots",
    )
    rule_effects = terminality_rule.effects_by_decision.get(compiled_outcome.decision)
    _require(
        rule_effects is not None
        and tuple(rule_effects)
        == compiled_outcome.requested_effects
        == manifest.requested_effects
        == live_write_lease.allowed_effects,
        "effect_binding_mismatch",
        "rule, outcome, manifest, and Live lease effect sets differ",
    )

    maintenance_bindings = (
        manifest.maintenance_runtime_attestation_sha256
        == runtime_attestation.canonical_sha256(),
        manifest.service_state_snapshot_sha256
        == service_state_snapshot.canonical_sha256(),
        manifest.tick_exclusion_receipt_sha256
        == tick_exclusion_receipt.canonical_sha256(),
        manifest.restoration_plan_sha256 == restoration_plan.canonical_sha256(),
        manifest.service_control_authority_sha256
        == service_control_authority.canonical_sha256(),
        manifest.tick_control_authority_sha256
        == tick_control_authority.canonical_sha256(),
        manifest.live_write_lease_sha256 == live_write_lease.canonical_sha256(),
        runtime_attestation.ceremony_id == manifest.ceremony_id,
        runtime_attestation.runtime_id == manifest.expected_runtime_id,
        runtime_attestation.writer_id == manifest.expected_writer_id,
        runtime_attestation.code_commit == manifest.expected_code_commit,
        runtime_attestation.database_sha256 == manifest.expected_database_sha256,
        runtime_attestation.lifecycle_fingerprint
        == manifest.expected_lifecycle_fingerprint,
        service_state_snapshot.ceremony_id == manifest.ceremony_id,
        service_state_snapshot.maintenance_runtime_id == manifest.expected_runtime_id,
        service_state_snapshot.database_sha256 == manifest.expected_database_sha256,
        tick_exclusion_receipt.ceremony_id == manifest.ceremony_id,
        restoration_plan.ceremony_id == manifest.ceremony_id,
        service_control_authority.ceremony_id == manifest.ceremony_id,
        service_control_authority.control_kind == "service",
        service_control_authority.target_id == manifest.expected_service_name,
        service_control_authority.authority_scope == manifest.service_control_scope,
        tick_control_authority.ceremony_id == manifest.ceremony_id,
        tick_control_authority.control_kind == "tick",
        tick_control_authority.target_id == manifest.expected_tick_id,
        tick_control_authority.authority_scope == manifest.tick_control_scope,
        live_write_lease.ceremony_id == manifest.ceremony_id,
        live_write_lease.scope == "Live",
        live_write_lease.runtime_id == manifest.expected_runtime_id,
        live_write_lease.writer_id == manifest.expected_writer_id,
        live_write_lease.database_sha256 == manifest.expected_database_sha256,
        live_write_lease.lifecycle_fingerprint
        == manifest.expected_lifecycle_fingerprint,
        live_write_lease.lease_state == "prepared_for_attended_activation",
        live_write_lease.permits_live_effect is False,
    )
    _require(
        all(maintenance_bindings),
        "maintenance_binding_mismatch",
        "maintenance receipts, control evidence, or Live lease differ from manifest",
    )
    _require(
        manifest.maintenance_window_start
        <= normalized_time
        < manifest.maintenance_window_end
        and live_write_lease.issued_at <= normalized_time < live_write_lease.expires_at
        and service_control_authority.authorized_from
        <= normalized_time
        < service_control_authority.authorized_until
        and tick_control_authority.authorized_from
        <= normalized_time
        < tick_control_authority.authorized_until,
        "attended_window_mismatch",
        "packet preparation is outside the exact lease or control window",
    )

    proposal_shapes = {
        "challenge:resolve": (
            "resolve_terminal_challenge",
            "case",
            manifest.case_id,
        ),
        "seed:supersede": (
            "supersede_terminal_artifact",
            "artifact",
            manifest.artifact_id,
        ),
    }
    _require(
        set(compiled_outcome.requested_effects).issubset(proposal_shapes),
        "unsupported_effect_proposal",
        "compiled outcome requests an effect without a closed proposal contract",
    )
    effect_bindings = []
    for effect_type in compiled_outcome.requested_effects:
        action, target_kind, target_id = proposal_shapes[effect_type]
        proposal = CeremonyEffectProposalV1(
            effect_type=effect_type,
            action=action,
            target_kind=target_kind,
            target_id=target_id,
            ceremony_id=manifest.ceremony_id,
            case_id=manifest.case_id,
            case_sha256=manifest.case_sha256,
            artifact_id=manifest.artifact_id,
            artifact_sha256=manifest.artifact_sha256,
            expected_evaluated_state_sha256=(manifest.expected_evaluated_state_sha256),
            compiled_outcome_sha256=compiled_outcome.canonical_sha256(),
            transcript_sha256=transcript_validation.transcript_sha256,
        )
        proposal_sha256 = canonical_sha256(proposal.model_dump(mode="json"))
        idempotency_sha256 = canonical_sha256(
            {
                "ceremony_id": manifest.ceremony_id,
                "effect_type": effect_type,
                "proposal_sha256": proposal_sha256,
                "write_lease_sha256": live_write_lease.canonical_sha256(),
            }
        )
        effect_bindings.append(
            _CeremonyEffectBindingV2(
                proposal=proposal,
                proposal_sha256=proposal_sha256,
                idempotency_key=f"sab-{idempotency_sha256[:32]}",
            )
        )

    (
        build_a_closeout,
        closeout_sha256,
        closeout_canonical_sha256,
    ) = _build_a_closeout_binding(build_a_closeout_bytes)
    _require(
        build_a_closeout.pull_request.merge_commit != manifest.expected_code_commit,
        "build_a_build_b_commit_not_distinct",
        "Build A merge and Build B runtime commits must remain distinct",
    )
    provider_bundle_sha256 = canonical_sha256(
        [probe.canonical_payload() for probe in ordered_probes]
    )
    payload = _CeremonyApprovalPayloadV2(
        schema_version="sab.ceremony_approval_payload.v2",
        ceremony_id=manifest.ceremony_id,
        prepared_at=prepared_text,
        source_evidence_valid_until=min(
            frozen_readiness.valid_until,
            live_readiness.valid_until,
        )
        .astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        code=_CeremonyCodeBindingV2(
            runtime_commit_sha=manifest.expected_code_commit,
            build_a_merge_commit=build_a_closeout.pull_request.merge_commit,
            build_a_merge_tree=build_a_closeout.pull_request.merge_tree,
            build_a_closeout_sha256=closeout_sha256,
            build_a_closeout_canonical_sha256=closeout_canonical_sha256,
        ),
        authority_evidence=_CeremonyAuthorityEvidenceV2(
            case_id=manifest.case_id,
            case_sha256=manifest.case_sha256,
            artifact_id=manifest.artifact_id,
            artifact_sha256=manifest.artifact_sha256,
            expected_evaluated_state_sha256=(manifest.expected_evaluated_state_sha256),
            requested_effects=manifest.requested_effects,
            policy_sha256=manifest.policy_sha256,
            founder_decision_receipt_sha256=(
                founder_decision_receipt.canonical_sha256()
            ),
            founder_decision=founder_decision_receipt.decision,
            authority_evaluation_sha256=authority_evaluation.canonical_sha256(),
            compiler_copy_authority_sha256=compiler_authority.authority_digest,
        ),
        bench=_CeremonyBenchBindingV2(
            attended_manifest_sha256=manifest_sha256,
            frozen_bench_manifest_sha256=bench_manifest.canonical_sha256(),
            frozen_roster_sha256=bench_manifest.roster_sha256,
            terminality_rule_sha256=terminality_rule.rule_sha256,
            provider_probe_bundle_sha256=provider_bundle_sha256,
            cost_envelope_sha256=cost_envelope.canonical_sha256(),
            transcript_head_sha256=transcript_validation.transcript_sha256,
            final_ballot_set_sha256=compiled_outcome.ballot_set_sha256,
            compiled_outcome_sha256=compiled_outcome.canonical_sha256(),
            compiled_decision=compiled_outcome.decision,
        ),
        cost=_CeremonyCostBindingV2(
            total_maximum_cost_microusd=cost_envelope.total_maximum_cost_microusd,
            spend_cap_microusd=cost_envelope.spend_cap_microusd,
            operator_public_key_fingerprint=manifest.operator_fingerprint,
        ),
        trust_anchors=_CeremonyTrustAnchorBindingV2(
            frozen_trust_anchor_set_sha256s=(frozen_readiness.trust_anchor_set_sha256s),
            live_trust_anchor_set_sha256s=live_readiness.trust_anchor_set_sha256s,
        ),
        maintenance=_CeremonyMaintenanceBindingV2(
            runtime_attestation_sha256=runtime_attestation.canonical_sha256(),
            service_state_snapshot_sha256=service_state_snapshot.canonical_sha256(),
            tick_exclusion_receipt_sha256=tick_exclusion_receipt.canonical_sha256(),
            restoration_plan_sha256=restoration_plan.canonical_sha256(),
            service_control_authority_sha256=(
                service_control_authority.canonical_sha256()
            ),
            tick_control_authority_sha256=tick_control_authority.canonical_sha256(),
            write_lease_sha256=live_write_lease.canonical_sha256(),
        ),
        proposed_effects=tuple(effect_bindings),
    )
    digest = canonical_sha256(payload.model_dump(mode="json"))
    return _seal_approval_evidence(payload, digest)


def short_display_checksum(full_sha256: str) -> str:
    """Return a display aid which is explicitly never an authority token."""

    if not re.fullmatch(SHA256_PATTERN, full_sha256):
        raise ApprovalPacketError(
            "digest_invalid", "full approval digest must be lowercase SHA-256"
        )
    return f"SAB-{full_sha256[:8].upper()}-{full_sha256[-8:].upper()}"


def build_operator_approval_packet(
    evidence: CeremonyApprovalEvidence,
) -> dict[str, Any]:
    """Turn only a locally sealed evidence derivation into an unsigned packet."""

    _require(
        isinstance(evidence, CeremonyApprovalEvidence)
        and _EVIDENCE_REGISTRY.get(evidence) == evidence._payload_sha256
        and evidence._payload_sha256
        == canonical_sha256(evidence._payload.model_dump(mode="json")),
        "approval_evidence_not_locally_bound",
        "approval packet construction requires locally re-derived evidence",
    )
    payload = evidence._payload.model_dump(mode="json")
    digest = evidence._payload_sha256
    return {
        "schema_version": "sab.operator_approval_packet.v2",
        "status": "awaiting_operator_countersign",
        "proof_class": "unsigned_non_authorizing_evidence_summary",
        "canonicalization": "json-sort-keys-compact-v1",
        "approval_payload": payload,
        "approval_payload_sha256": digest,
        "short_display_checksum": short_display_checksum(digest),
        "operator_signature": None,
        "effect_executable": False,
        "live_authority_created": False,
        "signing_instruction": SIGNING_INSTRUCTION,
        "signing_instruction_sha256": SIGNING_INSTRUCTION_SHA256,
    }


def verify_operator_approval_packet(
    packet: Mapping[str, Any],
    *,
    checked_at: datetime | None = None,
) -> dict[str, Any]:
    """Verify persisted integrity while keeping freshness explicitly non-positive."""

    _reject_secret_bearing_keys(packet)
    required = {
        "schema_version",
        "status",
        "proof_class",
        "canonicalization",
        "approval_payload",
        "approval_payload_sha256",
        "short_display_checksum",
        "operator_signature",
        "effect_executable",
        "live_authority_created",
        "signing_instruction",
        "signing_instruction_sha256",
    }
    if set(packet) != required:
        raise ApprovalPacketError(
            "packet_shape_invalid", "approval packet has missing or unknown fields"
        )
    if (
        packet.get("schema_version") != "sab.operator_approval_packet.v2"
        or packet.get("status") != "awaiting_operator_countersign"
        or packet.get("proof_class") != "unsigned_non_authorizing_evidence_summary"
        or packet.get("canonicalization") != "json-sort-keys-compact-v1"
        or packet.get("operator_signature") is not None
        or packet.get("effect_executable") is not False
        or packet.get("live_authority_created") is not False
    ):
        raise ApprovalPacketError(
            "packet_state_invalid",
            "unsigned approval packet state or proof class is invalid",
        )
    if (
        packet.get("signing_instruction") != SIGNING_INSTRUCTION
        or packet.get("signing_instruction_sha256") != SIGNING_INSTRUCTION_SHA256
    ):
        raise ApprovalPacketError(
            "signing_instruction_mismatch",
            "packet signing instruction differs from the immutable instruction",
        )
    try:
        payload = _CeremonyApprovalPayloadV2.model_validate(packet["approval_payload"])
    except Exception as exc:
        raise ApprovalPacketError(
            "approval_payload_invalid",
            "approval payload does not satisfy the closed evidence summary contract",
        ) from exc
    payload_dict = payload.model_dump(mode="json")
    digest = canonical_sha256(payload_dict)
    if packet.get("approval_payload_sha256") != digest:
        raise ApprovalPacketError(
            "packet_digest_mismatch", "approval payload digest does not verify"
        )
    if packet.get("short_display_checksum") != short_display_checksum(digest):
        raise ApprovalPacketError(
            "display_checksum_mismatch", "short display checksum does not verify"
        )
    observed_at = checked_at or datetime.now(timezone.utc)
    if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
        raise ApprovalPacketError(
            "verification_time_invalid", "verification time must be timezone-aware"
        )
    observed_at = observed_at.astimezone(timezone.utc)
    prepared_at = datetime.fromisoformat(payload.prepared_at[:-1] + "+00:00")
    valid_until = datetime.fromisoformat(
        payload.source_evidence_valid_until[:-1] + "+00:00"
    )
    if observed_at < prepared_at:
        evidence_time_state = "not_yet_prepared"
    elif observed_at >= valid_until:
        evidence_time_state = "expired"
    else:
        evidence_time_state = "within_recorded_window_unreverified"
    return {
        "packet_integrity_valid": True,
        "schema_version": "sab.operator_approval_packet_verification.v2",
        "status": "awaiting_operator_countersign",
        "proof_class": "unsigned_non_authorizing_evidence_summary",
        "approval_payload_sha256": digest,
        "short_display_checksum": short_display_checksum(digest),
        "evidence_reverified": False,
        "evidence_freshness_reverified": False,
        "evidence_time_state": evidence_time_state,
        "source_evidence_valid_until": payload.source_evidence_valid_until,
        "operator_signing_eligible": False,
        "effect_executable": False,
        "live_authority_created": False,
    }


def _format_microusd(value: int) -> str:
    dollars, micros = divmod(value, 1_000_000)
    return f"{dollars}.{micros:06d}"


def _sha256_inventory_lines(value: Any, *, path: str = "approval_payload") -> list[str]:
    """List every persisted SHA-256 leaf with its unambiguous payload path."""

    lines: list[str] = []
    if isinstance(value, Mapping):
        for key in sorted(value):
            lines.extend(_sha256_inventory_lines(value[key], path=f"{path}.{key}"))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            lines.extend(_sha256_inventory_lines(child, path=f"{path}[{index}]"))
    elif isinstance(value, str) and re.fullmatch(SHA256_PATTERN, value):
        lines.append(f"- `{path}`: `{value}`")
    return lines


def render_operator_approval_markdown(
    packet: Mapping[str, Any],
    *,
    checked_at: datetime | None = None,
) -> str:
    """Render a complete but deliberately non-signable persisted inspection view."""

    verified = verify_operator_approval_packet(packet, checked_at=checked_at)
    payload = _CeremonyApprovalPayloadV2.model_validate(packet["approval_payload"])
    effects = ", ".join(
        f"{item.proposal.effect_type} -> "
        f"{item.proposal.target_kind}:{item.proposal.target_id} "
        f"({item.proposal_sha256})"
        for item in payload.proposed_effects
    )
    frozen_anchors = "\n".join(
        f"- Frozen trust anchor: `{digest}`"
        for digest in payload.trust_anchors.frozen_trust_anchor_set_sha256s
    )
    live_anchors = "\n".join(
        f"- Live-preflight trust anchor: `{digest}`"
        for digest in payload.trust_anchors.live_trust_anchor_set_sha256s
    )
    digest_inventory = "\n".join(
        _sha256_inventory_lines(payload.model_dump(mode="json"))
    )
    return "\n".join(
        [
            "# SAB attended ceremony approval — unsigned",
            "",
            "**Persisted-view status:** `integrity_only_not_signable`",
            f"**Evidence time state:** `{verified['evidence_time_state']}`",
            "**Operator signing eligible from this view:** `false`",
            "",
            "This is a non-authorizing evidence summary. Persisted verification "
            "checks canonical integrity only; it does not recreate verifier seals, "
            "fresh source evidence, human presence, or current control authority. "
            "Re-derive the packet inside the attended controller before signing.",
            "",
            f"- Ceremony: `{payload.ceremony_id}`",
            f"- Build B runtime commit: `{payload.code.runtime_commit_sha}`",
            f"- Build A merge commit: `{payload.code.build_a_merge_commit}`",
            f"- Build A merge tree: `{payload.code.build_a_merge_tree}`",
            f"- Build A closeout SHA-256: `{payload.code.build_a_closeout_sha256}`",
            "- Pinned Build A closeout canonical SHA-256: "
            f"`{payload.code.build_a_closeout_canonical_sha256}`",
            f"- Case: `{payload.authority_evidence.case_id}`",
            f"- Artifact: `{payload.authority_evidence.artifact_id}`",
            "- Expected evaluated state: "
            f"`{payload.authority_evidence.expected_evaluated_state_sha256}`",
            f"- Operator key fingerprint: `{payload.cost.operator_public_key_fingerprint}`",
            f"- Prepared at: `{payload.prepared_at}`",
            f"- Source evidence valid until: `{payload.source_evidence_valid_until}`",
            f"- Compiler scope: `{payload.bench.compiled_outcome_scope}`",
            f"- Compiled decision: `{payload.bench.compiled_decision}`",
            f"- Proposed effects: `{effects}`",
            f"- Maximum spend: `${_format_microusd(payload.cost.spend_cap_microusd)}`",
            "- Automatic top-up: `false`",
            "- Live authority created: `false`",
            "- Effect executable: `false`",
            "",
            "## Out-of-band trust-anchor set digests",
            "",
            frozen_anchors,
            live_anchors,
            "",
            "## Complete persisted SHA-256 inventory",
            "",
            digest_inventory,
            "",
            "## Canonical payload digest — do not sign from this persisted view",
            "",
            f"`{verified['approval_payload_sha256']}`",
            "",
            "## Display checksum (non-authorizing)",
            "",
            f"`{verified['short_display_checksum']}`",
            "",
            SIGNING_INSTRUCTION,
            "",
        ]
    )


def canonical_packet_json(packet: Mapping[str, Any]) -> str:
    """Return stable packet JSON after the non-authorizing integrity check."""

    verify_operator_approval_packet(packet)
    return canonical_json(dict(packet))


__all__ = [
    "ApprovalPacketError",
    "BUILD_A_CLOSEOUT_CANONICAL_SHA256",
    "BUILD_A_CLOSEOUT_SHA256",
    "BUILD_A_MERGE_COMMIT",
    "BUILD_A_MERGE_TREE",
    "CeremonyApprovalEvidence",
    "CeremonyEffectProposalV1",
    "SIGNING_INSTRUCTION",
    "SIGNING_INSTRUCTION_SHA256",
    "bind_operator_approval_evidence",
    "build_operator_approval_packet",
    "canonical_packet_json",
    "render_operator_approval_markdown",
    "short_display_checksum",
    "verify_operator_approval_packet",
]
