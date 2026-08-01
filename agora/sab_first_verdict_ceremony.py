"""Offline Build B contracts for an attended first-verdict ceremony.

This module validates *persisted receipts*.  It deliberately has no adapters
for providers, processes, services, databases, files, environment variables,
or signing keys.  A valid signature authenticates receipt bytes; it does not
recreate the evaluator capability which produced those bytes.  Consequently,
the strongest value returned here is ``StructurallyCompleteAwaitingAuthority``.

The distinction is intentional type/evaluator semantics: evidence can prove
that a packet is structurally ready to be presented to an operator, while the
authority to perform a live effect remains absent from this module.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import weakref
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Collection, Literal, Mapping, Sequence, Union, cast

from pydantic import Field, TypeAdapter, field_validator, model_validator

from agora.sab_artifact_verdict import (
    ContractSignatureV1,
    FROZEN_MAINTENANCE_OPERATIONS,
    FrozenSeatV1,
    GIT_SHA_PATTERN,
    HEX_PUBLIC_KEY_PATTERN,
    MASTER_VISION_SEED_ID,
    SHA256_PATTERN,
    StrictCanonicalModel,
    allowed_operations_digest,
    canonical_sha256,
    verify_contract_signature,
)


PROVIDER_PROBE_MAX_AGE = timedelta(minutes=10)
AUTHORITY_EVALUATION_MAX_AGE = timedelta(minutes=15)
MAINTENANCE_RECEIPT_MAX_AGE = timedelta(minutes=10)
MAX_FUTURE_CLOCK_SKEW = timedelta(seconds=30)
ZERO_SHA256 = "0" * 64
ZERO_GIT_SHA = "0" * 40
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$"
ISSUE_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,119}$"
CEREMONY_COUNCIL_SIZE = 9
_READINESS_REGISTRY: dict[int, tuple[weakref.ReferenceType[Any], str]] = {}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _exact_strings(
    values: Sequence[str], *, field: str, allow_empty: bool = False
) -> tuple[str, ...]:
    """Return a deterministic set-like tuple without silently repairing input."""

    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ValueError(f"{field} must be a sequence of strings")
    if any(not isinstance(value, str) for value in values):
        raise ValueError(f"{field} must contain strings only")
    if any(not value or value != value.strip() for value in values):
        raise ValueError(f"{field} cannot contain blank or padded values")
    if any("*" in value for value in values):
        raise ValueError(f"{field} cannot contain wildcards")
    if len(set(values)) != len(values):
        raise ValueError(f"{field} cannot contain duplicates")
    if not values and not allow_empty:
        raise ValueError(f"{field} cannot be empty")
    return tuple(sorted(values))


def _key_fingerprint(public_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key)).hexdigest()


def _contains_zero_sha256(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            (str(key).endswith("sha256") and child == ZERO_SHA256)
            or _contains_zero_sha256(child)
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_zero_sha256(child) for child in value)
    return False


def _safe_digest(value: Any) -> str:
    try:
        if isinstance(value, StrictCanonicalModel):
            return value.canonical_sha256()
        return canonical_sha256(value)
    except (TypeError, ValueError):
        return ZERO_SHA256


def _maintenance_operations_sha256() -> str:
    operations = [
        {"method": method, "path": path}
        for method, path in sorted(FROZEN_MAINTENANCE_OPERATIONS)
    ]
    return allowed_operations_digest(operations)


FROZEN_MAINTENANCE_OPERATIONS_SHA256 = _maintenance_operations_sha256()


class _SignedObservationV1(StrictCanonicalModel):
    """Common authenticated evidence shape; a signature is not a live capability."""

    attestor_identity: str = Field(pattern=ID_PATTERN)
    attestor_public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    attestor_fingerprint: str = Field(pattern=SHA256_PATTERN)
    attestation_signature: ContractSignatureV1
    authority_semantics: Literal["persisted_receipt_not_capability"] = (
        "persisted_receipt_not_capability"
    )

    @model_validator(mode="after")
    def attestor_identity_is_bound(self) -> "_SignedObservationV1":
        if self.attestor_fingerprint != _key_fingerprint(self.attestor_public_key):
            raise ValueError("attestor fingerprint does not bind attestor public key")
        if (
            self.attestation_signature.signer != self.attestor_identity
            or self.attestation_signature.public_key != self.attestor_public_key
        ):
            raise ValueError("attestation signature does not bind named attestor")
        if _contains_zero_sha256(
            self.canonical_payload(exclude={"attestation_signature"})
        ):
            raise ValueError("signed evidence cannot contain zero SHA-256 placeholders")
        return self

    def signing_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"attestation_signature"})


class SignedAuthorityEvaluationEnvelopeV1(StrictCanonicalModel):
    """Signed serialization of an evaluation, never an authority capability."""

    schema_: Literal["sab.signed_authority_evaluation_envelope.v1"] = Field(
        "sab.signed_authority_evaluation_envelope.v1", alias="schema"
    )
    evaluation_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    case_id: str = Field(pattern=ID_PATTERN)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_id: str = Field(pattern=ID_PATTERN)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    evaluated_state_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_scope: Literal["Live"] = "Live"
    requested_effects: tuple[str, ...] = Field(min_length=1)
    reported_result: Literal["Authorized", "AdvisoryOnly", "NoJurisdiction"]
    reported_allowed_effects: tuple[str, ...] = ()
    reported_forbidden_effects: tuple[str, ...] = ()
    reported_live_eligible: bool
    evaluator_identity: str = Field(pattern=ID_PATTERN)
    evaluator_public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    evaluator_fingerprint: str = Field(pattern=SHA256_PATTERN)
    evaluated_at: datetime
    expires_at: datetime
    signature: ContractSignatureV1
    authority_semantics: Literal["persisted_receipt_not_capability"] = (
        "persisted_receipt_not_capability"
    )
    standing_effect: Literal["none"] = "none"

    @field_validator(
        "requested_effects",
        "reported_allowed_effects",
        "reported_forbidden_effects",
        mode="before",
    )
    @classmethod
    def exact_effects(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(
            value,
            field=str(info.field_name),
            allow_empty=str(info.field_name) != "requested_effects",
        )

    @field_validator("evaluated_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def coherent_evaluation_receipt(self) -> "SignedAuthorityEvaluationEnvelopeV1":
        if _contains_zero_sha256(self.canonical_payload(exclude={"signature"})):
            raise ValueError(
                "authority evaluation cannot contain zero hash placeholders"
            )
        if not (
            self.evaluated_at < self.expires_at
            and self.expires_at - self.evaluated_at <= AUTHORITY_EVALUATION_MAX_AGE
        ):
            raise ValueError("authority evaluation validity window is invalid")
        if self.evaluator_fingerprint != _key_fingerprint(self.evaluator_public_key):
            raise ValueError("evaluator fingerprint does not bind evaluator public key")
        if (
            self.signature.signer != self.evaluator_identity
            or self.signature.public_key != self.evaluator_public_key
        ):
            raise ValueError("signature identity does not bind evaluator identity")
        if self.reported_result == "Authorized":
            if (
                self.reported_allowed_effects != self.requested_effects
                or self.reported_forbidden_effects
                or not self.reported_live_eligible
            ):
                raise ValueError(
                    "reported Authorized result has incoherent effect bounds"
                )
        elif self.reported_result == "AdvisoryOnly":
            if (
                self.reported_allowed_effects
                or not self.reported_forbidden_effects
                or self.reported_live_eligible
            ):
                raise ValueError("reported AdvisoryOnly result has incoherent bounds")
        elif (
            self.reported_allowed_effects
            or self.reported_forbidden_effects
            or self.reported_live_eligible
        ):
            raise ValueError("reported NoJurisdiction result cannot carry effects")
        return self

    def signing_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"signature"})


class FounderDecisionReceiptV1(_SignedObservationV1):
    """Founder-signed jurisdiction choice; still only persisted evidence."""

    schema_: Literal["sab.founder_decision_receipt.v1"] = Field(
        "sab.founder_decision_receipt.v1", alias="schema"
    )
    decision_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    case_id: str = Field(pattern=ID_PATTERN)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_id: str = Field(pattern=ID_PATTERN)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    decision: Literal[
        "jurisdictional_refusal", "alternate_artifact_terminal_disposition"
    ]
    requested_effects: tuple[str, ...] = Field(min_length=1)
    decided_at: datetime
    expires_at: datetime
    standing_effect: Literal["none"] = "none"

    @field_validator("requested_effects", mode="before")
    @classmethod
    def exact_effects(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="requested_effects")

    @field_validator("decided_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def coherent_founder_decision(self) -> "FounderDecisionReceiptV1":
        if not (
            self.decided_at < self.expires_at
            and self.expires_at - self.decided_at <= AUTHORITY_EVALUATION_MAX_AGE
        ):
            raise ValueError("founder decision receipt validity window is invalid")
        if self.decision == "jurisdictional_refusal":
            if self.requested_effects != ("record_jurisdictional_refusal",):
                raise ValueError("jurisdictional refusal has an inexact effect")
        elif self.requested_effects == ("record_jurisdictional_refusal",):
            raise ValueError("alternate artifact decision requires a terminal effect")
        return self


class ProviderProbeReceiptV1(_SignedObservationV1):
    """Persisted response facts from a probe performed outside this module."""

    schema_: Literal["sab.provider_probe_receipt.v1"] = Field(
        "sab.provider_probe_receipt.v1", alias="schema"
    )
    probe_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    provider: str = Field(pattern=ID_PATTERN)
    requested_route: str = Field(pattern=ID_PATTERN)
    served_route: str = Field(pattern=ID_PATTERN)
    requested_model: str = Field(pattern=ID_PATTERN)
    served_model: str = Field(pattern=ID_PATTERN)
    requested_lineage: str = Field(pattern=ID_PATTERN)
    served_lineage: str = Field(pattern=ID_PATTERN)
    requested_correlation_id: str = Field(pattern=ID_PATTERN)
    served_correlation_id: str = Field(pattern=ID_PATTERN)
    frozen_seat: FrozenSeatV1
    catalog_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)
    balance_known: Literal[True] = True
    available_balance_microusd: int = Field(ge=0, strict=True)
    route_available: Literal[True] = True
    probe_status: Literal["passed"] = "passed"
    probed_at: datetime
    expires_at: datetime
    receipt_source: Literal["persisted_external_probe"] = "persisted_external_probe"
    standing_effect: Literal["none"] = "none"

    @field_validator("probed_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def exact_requested_and_served_facts(self) -> "ProviderProbeReceiptV1":
        if not (
            self.probed_at < self.expires_at
            and self.expires_at - self.probed_at <= PROVIDER_PROBE_MAX_AGE
        ):
            raise ValueError("provider probe validity window is invalid")
        substitutions = (
            self.requested_route != self.served_route,
            self.requested_model != self.served_model,
            self.requested_lineage != self.served_lineage,
            self.requested_correlation_id != self.served_correlation_id,
        )
        if any(substitutions):
            raise ValueError("provider probe contains requested/served substitution")
        seat = self.frozen_seat
        if (
            self.provider != seat.served_provider
            or self.requested_route != seat.requested_route
            or seat.possible_underlying_routes != (self.served_route,)
            or self.requested_model != seat.requested_model
            or self.served_model != seat.served_model
            or self.requested_lineage != seat.model_family
            or self.served_lineage != seat.model_family
        ):
            raise ValueError("provider probe differs from its exact frozen seat")
        return self


class FrozenBenchSeatV1(StrictCanonicalModel):
    role: str = Field(pattern=ID_PATTERN)
    frozen_seat: FrozenSeatV1
    probe_correlation_id: str = Field(pattern=ID_PATTERN)
    provider_probe_sha256: str = Field(pattern=SHA256_PATTERN)
    terminal_capable: Literal[True] = True

    @property
    def seat_id(self) -> str:
        return self.frozen_seat.seat_id


class FrozenBenchManifestV1(StrictCanonicalModel):
    schema_: Literal["sab.frozen_bench_manifest.v1"] = Field(
        "sab.frozen_bench_manifest.v1", alias="schema"
    )
    bench_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    case_id: str = Field(pattern=ID_PATTERN)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    seats: tuple[FrozenBenchSeatV1, ...] = Field(
        min_length=CEREMONY_COUNCIL_SIZE, max_length=CEREMONY_COUNCIL_SIZE
    )
    roster_sha256: str = Field(pattern=SHA256_PATTERN)
    terminality_rule_sha256: str = Field(pattern=SHA256_PATTERN)
    terminal_rule: Literal["every_frozen_seat_must_return_a_final_ballot"] = (
        "every_frozen_seat_must_return_a_final_ballot"
    )
    terminally_feasible: Literal[True] = True
    frozen_at: datetime
    standing_effect: Literal["none"] = "none"

    @field_validator("frozen_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("seats", mode="before")
    @classmethod
    def canonical_seat_order(cls, value: Sequence[Any]) -> tuple[Any, ...]:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError("seats must be a sequence")
        items = tuple(value)
        seat_ids = tuple(
            str(item.get("frozen_seat", {}).get("seat_id", ""))
            if isinstance(item, Mapping)
            else item.seat_id
            for item in items
        )
        if seat_ids != tuple(sorted(seat_ids)):
            raise ValueError("seats must already be in canonical seat-id order")
        return items

    @model_validator(mode="after")
    def exact_roster(self) -> "FrozenBenchManifestV1":
        if _contains_zero_sha256(self.canonical_payload()):
            raise ValueError("frozen bench cannot contain zero hash placeholders")
        seat_ids = [seat.seat_id for seat in self.seats]
        roles = [seat.role for seat in self.seats]
        correlations = [seat.probe_correlation_id for seat in self.seats]
        probes = [seat.provider_probe_sha256 for seat in self.seats]
        if any(
            len(set(items)) != len(items)
            for items in (seat_ids, roles, correlations, probes)
        ):
            raise ValueError(
                "bench seats, roles, correlations, and probes must be unique"
            )
        if len(seat_ids) != CEREMONY_COUNCIL_SIZE:
            raise ValueError("frozen bench must contain exactly nine seats")
        expected = canonical_sha256(
            [seat.frozen_seat.canonical_payload() for seat in self.seats]
        )
        if self.roster_sha256 != expected:
            raise ValueError("roster_sha256 does not bind the exact frozen seats")
        return self

    @property
    def transcript_roster(self) -> tuple[FrozenSeatV1, ...]:
        return tuple(seat.frozen_seat for seat in self.seats)


class BenchSeatCostV1(StrictCanonicalModel):
    seat_id: str = Field(pattern=ID_PATTERN)
    provider_probe_sha256: str = Field(pattern=SHA256_PATTERN)
    pricing_catalog_sha256: str = Field(pattern=SHA256_PATTERN)
    maximum_cost_microusd: int = Field(ge=0, strict=True)


class BenchCostEnvelopeV1(StrictCanonicalModel):
    schema_: Literal["sab.bench_cost_envelope.v1"] = Field(
        "sab.bench_cost_envelope.v1", alias="schema"
    )
    cost_envelope_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    bench_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    currency: Literal["USD"] = "USD"
    seat_costs: tuple[BenchSeatCostV1, ...] = Field(
        min_length=CEREMONY_COUNCIL_SIZE, max_length=CEREMONY_COUNCIL_SIZE
    )
    total_maximum_cost_microusd: int = Field(ge=0, strict=True)
    spend_cap_microusd: int = Field(ge=0, strict=True)
    costs_known: Literal[True] = True
    unpriced_items: tuple[str, ...] = Field(default=(), max_length=0)
    automatic_top_up: Literal[False] = False
    approved_by: str = Field(pattern=ID_PATTERN)
    approver_public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    approver_fingerprint: str = Field(pattern=SHA256_PATTERN)
    approved_at: datetime
    expires_at: datetime
    approval_signature: ContractSignatureV1
    standing_effect: Literal["none"] = "none"

    @field_validator("approved_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("seat_costs", mode="before")
    @classmethod
    def canonical_cost_order(cls, value: Sequence[Any]) -> tuple[Any, ...]:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError("seat_costs must be a sequence")
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    str(item.get("seat_id", ""))
                    if isinstance(item, Mapping)
                    else item.seat_id
                ),
            )
        )

    @model_validator(mode="after")
    def bounded_known_cost(self) -> "BenchCostEnvelopeV1":
        if _contains_zero_sha256(
            self.canonical_payload(exclude={"approval_signature"})
        ):
            raise ValueError("cost envelope cannot contain zero hash placeholders")
        if not (
            self.approved_at < self.expires_at
            and self.expires_at - self.approved_at <= MAINTENANCE_RECEIPT_MAX_AGE
        ):
            raise ValueError("cost approval validity window is invalid")
        if len({item.seat_id for item in self.seat_costs}) != len(self.seat_costs):
            raise ValueError("each bench seat must have exactly one cost")
        if sum(item.maximum_cost_microusd for item in self.seat_costs) != (
            self.total_maximum_cost_microusd
        ):
            raise ValueError("declared total does not equal exact seat costs")
        if self.total_maximum_cost_microusd > self.spend_cap_microusd:
            raise ValueError("known maximum cost exceeds approved spend cap")
        if self.approver_fingerprint != _key_fingerprint(self.approver_public_key):
            raise ValueError("approver fingerprint does not bind approver public key")
        if (
            self.approval_signature.signer != self.approved_by
            or self.approval_signature.public_key != self.approver_public_key
        ):
            raise ValueError("approval signature does not bind the named approver")
        return self

    def signing_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"approval_signature"})


class AttendedCeremonyManifestV1(StrictCanonicalModel):
    """Root digest manifest for a packet which remains non-authorizing."""

    schema_: Literal["sab.attended_ceremony_manifest.v1"] = Field(
        "sab.attended_ceremony_manifest.v1", alias="schema"
    )
    ceremony_id: str = Field(pattern=ID_PATTERN)
    case_id: str = Field(pattern=ID_PATTERN)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_id: str = Field(pattern=ID_PATTERN)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_effects: tuple[str, ...] = Field(min_length=1)
    founder_decision: Literal[
        "jurisdictional_refusal", "alternate_artifact_terminal_disposition"
    ]
    founder_decision_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_evaluation_sha256: str = Field(pattern=SHA256_PATTERN)
    bench_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    terminality_rule_sha256: str = Field(pattern=SHA256_PATTERN)
    bench_cost_envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    provider_probe_sha256s: tuple[str, ...] = Field(
        min_length=CEREMONY_COUNCIL_SIZE, max_length=CEREMONY_COUNCIL_SIZE
    )
    maintenance_runtime_attestation_sha256: str = Field(pattern=SHA256_PATTERN)
    service_state_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_exclusion_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    restoration_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_code_commit: str = Field(pattern=GIT_SHA_PATTERN)
    expected_openapi_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_runtime_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_maintenance_operations_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_database_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    expected_evaluated_state_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_runtime_id: str = Field(pattern=ID_PATTERN)
    expected_writer_id: str = Field(pattern=ID_PATTERN)
    expected_service_name: str = Field(pattern=ID_PATTERN)
    expected_tick_id: str = Field(pattern=ID_PATTERN)
    service_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    live_write_lease_sha256: str = Field(pattern=SHA256_PATTERN)
    service_control_scope: Literal["pause_and_restore_exact_prior_service"] = (
        "pause_and_restore_exact_prior_service"
    )
    tick_control_scope: Literal["exclude_and_restore_exact_prior_tick"] = (
        "exclude_and_restore_exact_prior_tick"
    )
    operator_identity: str = Field(pattern=ID_PATTERN)
    operator_public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    operator_fingerprint: str = Field(pattern=SHA256_PATTERN)
    frozen_at: datetime
    expires_at: datetime
    maintenance_window_start: datetime
    maintenance_window_end: datetime
    operator_presence_required: Literal[True] = True
    operator_signing_rail_state: Literal["approval_required"] = "approval_required"
    operator_signature_state: Literal["not_yet_signed"] = "not_yet_signed"
    live_authority_state: Literal["awaiting_evaluator_capability"] = (
        "awaiting_evaluator_capability"
    )
    permits_live_effect: Literal[False] = False
    standing_effect: Literal["none"] = "none"

    @field_validator("requested_effects", "provider_probe_sha256s", mode="before")
    @classmethod
    def exact_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name))

    @field_validator(
        "frozen_at", "expires_at", "maintenance_window_start", "maintenance_window_end"
    )
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("expected_code_commit")
    @classmethod
    def nonzero_expected_commit(cls, value: str) -> str:
        if value == ZERO_GIT_SHA:
            raise ValueError("expected code commit must not be the all-zero Git object")
        return value

    @model_validator(mode="after")
    def coherent_non_authorizing_manifest(self) -> "AttendedCeremonyManifestV1":
        if (
            _contains_zero_sha256(self.canonical_payload())
            or ZERO_SHA256 in self.provider_probe_sha256s
        ):
            raise ValueError("manifest cannot contain zero hash placeholders")
        if not (
            self.frozen_at < self.expires_at
            and self.maintenance_window_start < self.maintenance_window_end
            and self.frozen_at <= self.maintenance_window_start
            and self.expires_at >= self.maintenance_window_start
        ):
            raise ValueError("manifest and maintenance windows are incoherent")
        if self.operator_fingerprint != _key_fingerprint(self.operator_public_key):
            raise ValueError("operator fingerprint does not bind operator public key")
        if (
            self.expected_maintenance_operations_sha256
            != FROZEN_MAINTENANCE_OPERATIONS_SHA256
        ):
            raise ValueError("manifest does not bind the frozen maintenance inventory")
        if self.founder_decision == "jurisdictional_refusal":
            if self.requested_effects != ("record_jurisdictional_refusal",):
                raise ValueError(
                    "jurisdictional refusal may request only its exact record"
                )
        elif self.requested_effects == ("record_jurisdictional_refusal",):
            raise ValueError("alternate artifact decision requires a terminal effect")
        if (
            self.artifact_id == MASTER_VISION_SEED_ID
            and self.founder_decision != "jurisdictional_refusal"
        ):
            raise ValueError(
                "Master Vision signed terms permit a jurisdictional refusal only"
            )
        return self


class MaintenanceRuntimeAttestationV1(_SignedObservationV1):
    schema_: Literal["sab.maintenance_runtime_attestation.v1"] = Field(
        "sab.maintenance_runtime_attestation.v1", alias="schema"
    )
    attestation_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    runtime_id: str = Field(pattern=ID_PATTERN)
    writer_id: str = Field(pattern=ID_PATTERN)
    active_writer_ids: tuple[str, ...] = Field(min_length=1, max_length=1)
    code_commit: str = Field(pattern=GIT_SHA_PATTERN)
    openapi_sha256: str = Field(pattern=SHA256_PATTERN)
    runtime_sha256: str = Field(pattern=SHA256_PATTERN)
    maintenance_operations_sha256: str = Field(pattern=SHA256_PATTERN)
    database_sha256: str = Field(pattern=SHA256_PATTERN)
    lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    bind_host: str = Field(min_length=2, max_length=64)
    bind_port: int = Field(ge=1, le=65535, strict=True)
    process_evidence_sha256: str = Field(pattern=SHA256_PATTERN)
    maintenance_only: Literal[True] = True
    legacy_mutations_exposed: Literal[False] = False
    started_at: datetime
    attested_at: datetime
    expires_at: datetime
    standing_effect: Literal["none"] = "none"

    @field_validator("active_writer_ids", mode="before")
    @classmethod
    def exact_writers(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="active_writer_ids")

    @field_validator("code_commit")
    @classmethod
    def nonzero_code_commit(cls, value: str) -> str:
        if value == ZERO_GIT_SHA:
            raise ValueError("runtime code commit must not be the all-zero Git object")
        return value

    @field_validator("started_at", "attested_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("bind_host")
    @classmethod
    def numeric_loopback_only(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("bind_host must be a numeric loopback address") from exc
        if not address.is_loopback:
            raise ValueError("maintenance runtime must bind only to loopback")
        return address.compressed

    @model_validator(mode="after")
    def exact_runtime_attestation(self) -> "MaintenanceRuntimeAttestationV1":
        if self.active_writer_ids != (self.writer_id,):
            raise ValueError("maintenance runtime is not the sole active writer")
        if self.maintenance_operations_sha256 != FROZEN_MAINTENANCE_OPERATIONS_SHA256:
            raise ValueError("runtime exposes the wrong maintenance inventory")
        if not (
            self.started_at <= self.attested_at < self.expires_at
            and self.expires_at - self.attested_at <= MAINTENANCE_RECEIPT_MAX_AGE
        ):
            raise ValueError("runtime attestation validity window is invalid")
        return self


class ServiceStateSnapshotV1(_SignedObservationV1):
    schema_: Literal["sab.service_state_snapshot.v1"] = Field(
        "sab.service_state_snapshot.v1", alias="schema"
    )
    snapshot_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    service_name: str = Field(pattern=ID_PATTERN)
    maintenance_runtime_id: str = Field(pattern=ID_PATTERN)
    active_writer_ids: tuple[str, ...] = Field(min_length=1, max_length=1)
    old_service_paused: Literal[True] = True
    prior_service_state: Literal["running", "stopped"]
    prior_service_instance_id: str | None = Field(default=None, pattern=ID_PATTERN)
    prior_service_definition_sha256: str = Field(pattern=SHA256_PATTERN)
    prior_writer_ids: tuple[str, ...]
    tick_id: str = Field(pattern=ID_PATTERN)
    prior_tick_state: Literal["enabled", "disabled"]
    prior_tick_definition_sha256: str = Field(pattern=SHA256_PATTERN)
    service_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    database_sha256: str = Field(pattern=SHA256_PATTERN)
    lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    backup_sha256: str = Field(pattern=SHA256_PATTERN)
    backup_completed_at: datetime
    database_integrity: Literal["ok"] = "ok"
    captured_at: datetime
    expires_at: datetime
    standing_effect: Literal["none"] = "none"

    @field_validator("active_writer_ids", "prior_writer_ids", mode="before")
    @classmethod
    def exact_writers(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(
            value,
            field=str(info.field_name),
            allow_empty=str(info.field_name) == "prior_writer_ids",
        )

    @field_validator("backup_completed_at", "captured_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def complete_prior_state(self) -> "ServiceStateSnapshotV1":
        if self.prior_service_state == "running":
            if not self.prior_service_instance_id or not self.prior_writer_ids:
                raise ValueError("running prior service state is incomplete")
        elif self.prior_service_instance_id is not None or self.prior_writer_ids:
            raise ValueError("stopped prior service cannot claim live process state")
        if not (
            self.backup_completed_at <= self.captured_at < self.expires_at
            and self.expires_at - self.captured_at <= MAINTENANCE_RECEIPT_MAX_AGE
            and self.captured_at - self.backup_completed_at
            <= MAINTENANCE_RECEIPT_MAX_AGE
        ):
            raise ValueError("service snapshot freshness window is invalid")
        return self


class TickExclusionReceiptV1(_SignedObservationV1):
    schema_: Literal["sab.tick_exclusion_receipt.v1"] = Field(
        "sab.tick_exclusion_receipt.v1", alias="schema"
    )
    receipt_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    tick_id: str = Field(pattern=ID_PATTERN)
    tick_definition_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    exclusion_active: Literal[True] = True
    excluded_from: datetime
    excluded_until: datetime
    ceremony_window_start: datetime
    ceremony_window_end: datetime
    last_tick_completed_at: datetime | None = None
    next_tick_not_before: datetime
    overlapping_tick_ids: tuple[str, ...] = Field(default=(), max_length=0)
    observed_at: datetime
    expires_at: datetime
    standing_effect: Literal["none"] = "none"

    @field_validator("overlapping_tick_ids", mode="before")
    @classmethod
    def exact_overlaps(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="overlapping_tick_ids", allow_empty=True)

    @field_validator(
        "excluded_from",
        "excluded_until",
        "ceremony_window_start",
        "ceremony_window_end",
        "last_tick_completed_at",
        "next_tick_not_before",
        "observed_at",
        "expires_at",
    )
    @classmethod
    def aware_times(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value)

    @model_validator(mode="after")
    def no_tick_overlap(self) -> "TickExclusionReceiptV1":
        if not (
            self.excluded_from
            <= self.ceremony_window_start
            < self.ceremony_window_end
            <= self.excluded_until
        ):
            raise ValueError("tick exclusion does not cover the ceremony window")
        if (
            self.last_tick_completed_at
            and self.last_tick_completed_at > self.excluded_from
        ):
            raise ValueError("a prior tick overlaps the exclusion window")
        if self.next_tick_not_before < self.excluded_until:
            raise ValueError("next tick can start inside the exclusion window")
        if not (
            self.excluded_from <= self.observed_at < self.expires_at
            and self.expires_at - self.observed_at <= MAINTENANCE_RECEIPT_MAX_AGE
        ):
            raise ValueError("tick exclusion receipt freshness window is invalid")
        return self


class RestorationPlanV1(_SignedObservationV1):
    """Historical rollback-only plan which restores the pre-ceremony state.

    Version 1 can never describe a successful closeout: its database and
    lifecycle roots are checked against the captured pre-ceremony snapshot.
    The wire shape remains unchanged for historical receipt verification.
    """

    schema_: Literal["sab.restoration_plan.v1"] = Field(
        "sab.restoration_plan.v1", alias="schema"
    )
    plan_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    service_state_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    maintenance_runtime_id: str = Field(pattern=ID_PATTERN)
    stop_maintenance_runtime: Literal[True] = True
    restore_service_name: str = Field(pattern=ID_PATTERN)
    restore_service_state: Literal["running", "stopped"]
    restore_service_instance_id: str | None = Field(default=None, pattern=ID_PATTERN)
    restore_service_definition_sha256: str = Field(pattern=SHA256_PATTERN)
    restore_writer_ids: tuple[str, ...]
    restore_tick_id: str = Field(pattern=ID_PATTERN)
    restore_tick_state: Literal["enabled", "disabled"]
    restore_tick_definition_sha256: str = Field(pattern=SHA256_PATTERN)
    restore_database_sha256: str = Field(pattern=SHA256_PATTERN)
    restore_lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    service_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    generated_at: datetime
    apply_only_after_ceremony: Literal[True] = True
    standing_effect: Literal["none"] = "none"

    @field_validator("restore_writer_ids", mode="before")
    @classmethod
    def exact_writers(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="restore_writer_ids", allow_empty=True)

    @field_validator("generated_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def coherent_restore_target(self) -> "RestorationPlanV1":
        if self.restore_service_state == "running":
            if not self.restore_service_instance_id or not self.restore_writer_ids:
                raise ValueError("running restoration target is incomplete")
        elif self.restore_service_instance_id is not None or self.restore_writer_ids:
            raise ValueError("stopped restoration target cannot name live writers")
        return self

    @property
    def closeout_mode(self) -> Literal["rollback_to_pre_ceremony_state"]:
        """Expose the fixed historical semantics without changing v1 bytes."""

        return "rollback_to_pre_ceremony_state"

    @property
    def effect_executable(self) -> Literal[False]:
        return False


class SuccessfulCloseoutPlanV2(_SignedObservationV1):
    """Prospective, non-executable plan for a successful closeout.

    The plan is constructible before any effect occurs.  It declares which
    future evidence a separate closeout evaluator must verify, but deliberately
    contains no claimed effect receipt, post-effect root, or completion time.
    Service and tick controls still return to the exact pre-ceremony snapshot;
    database and lifecycle state must remain at the separately verified
    post-effect roots.
    """

    schema_: Literal["sab.successful_closeout_plan.v2"] = Field(
        "sab.successful_closeout_plan.v2", alias="schema"
    )
    plan_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    service_state_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    maintenance_runtime_id: str = Field(pattern=ID_PATTERN)
    closeout_mode: Literal["preserve_verified_post_effect_state"]
    database_disposition: Literal["preserve_separately_verified_post_effect_root"]
    lifecycle_disposition: Literal[
        "preserve_separately_verified_post_effect_fingerprint"
    ]
    successful_effect_receipt_requirement: Literal["required"]
    post_effect_state_verification_requirement: Literal[
        "database_sha256_and_lifecycle_fingerprint_required"
    ]
    success_branch_control_restore_precondition: Literal[
        "success_branch_successful_effect_receipt_and_post_effect_state_verification"
    ]
    success_branch_apply_precondition: Literal[
        "success_branch_only_after_successful_effect_receipt_and_post_effect_state_verification"
    ]
    failure_trigger: Literal["effect_failure_or_post_effect_state_verification_failure"]
    failure_disposition: Literal[
        "rollback_to_captured_pre_ceremony_database_and_lifecycle_roots"
    ]
    failure_database_sha256: str = Field(pattern=SHA256_PATTERN)
    failure_lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    failure_rollback_verification_requirement: Literal[
        "database_sha256_and_lifecycle_fingerprint_required_before_control_restore"
    ]
    failure_branch_apply_precondition: Literal[
        "failure_branch_effect_failure_or_post_effect_state_verification_failure_then_verified_snapshot_rollback_before_control_restore"
    ]
    control_and_runtime_completion_requirement: Literal[
        "restore_exact_prior_controls_and_stop_maintenance_runtime_on_success_or_failure"
    ]
    stop_maintenance_runtime: Literal[True]
    restore_service_name: str = Field(pattern=ID_PATTERN)
    restore_service_state: Literal["running", "stopped"]
    restore_service_instance_id: str | None = Field(default=None, pattern=ID_PATTERN)
    restore_service_definition_sha256: str = Field(pattern=SHA256_PATTERN)
    restore_writer_ids: tuple[str, ...]
    restore_tick_id: str = Field(pattern=ID_PATTERN)
    restore_tick_state: Literal["enabled", "disabled"]
    restore_tick_definition_sha256: str = Field(pattern=SHA256_PATTERN)
    service_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_control_authority_sha256: str = Field(pattern=SHA256_PATTERN)
    generated_at: datetime
    effect_executable: Literal[False]
    live_authority_created: Literal[False]
    permits_live_effect: Literal[False]
    standing_effect: Literal["none"]

    @field_validator("restore_writer_ids", mode="before")
    @classmethod
    def exact_writers(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="restore_writer_ids", allow_empty=True)

    @field_validator("generated_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def coherent_successful_closeout(self) -> "SuccessfulCloseoutPlanV2":
        if self.restore_service_state == "running":
            if not self.restore_service_instance_id or not self.restore_writer_ids:
                raise ValueError("running closeout target is incomplete")
        elif self.restore_service_instance_id is not None or self.restore_writer_ids:
            raise ValueError("stopped closeout target cannot name live writers")
        return self


CeremonyCloseoutPlan = RestorationPlanV1 | SuccessfulCloseoutPlanV2
_CLOSEOUT_PLAN_TYPES = (RestorationPlanV1, SuccessfulCloseoutPlanV2)


class MaintenanceControlAuthorityReceiptV1(_SignedObservationV1):
    """Signed proof of narrow service or tick control, not disposition authority."""

    schema_: Literal["sab.maintenance_control_authority_receipt.v1"] = Field(
        "sab.maintenance_control_authority_receipt.v1", alias="schema"
    )
    authority_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    control_kind: Literal["service", "tick"]
    target_id: str = Field(pattern=ID_PATTERN)
    authority_scope: Literal[
        "pause_and_restore_exact_prior_service",
        "exclude_and_restore_exact_prior_tick",
    ]
    authorized_from: datetime
    authorized_until: datetime
    issued_at: datetime
    expires_at: datetime
    standing_effect: Literal["none"] = "none"

    @field_validator("authorized_from", "authorized_until", "issued_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def narrow_control_scope(self) -> "MaintenanceControlAuthorityReceiptV1":
        expected = {
            "service": "pause_and_restore_exact_prior_service",
            "tick": "exclude_and_restore_exact_prior_tick",
        }[self.control_kind]
        if self.authority_scope != expected:
            raise ValueError("maintenance control kind has the wrong narrow scope")
        if not (
            self.issued_at <= self.authorized_from < self.authorized_until
            and self.issued_at < self.expires_at
            and self.authorized_until <= self.expires_at
            and self.expires_at - self.issued_at <= MAINTENANCE_RECEIPT_MAX_AGE
        ):
            raise ValueError("maintenance control authority window is invalid")
        return self


class LiveWriteLeaseEnvelopeV1(_SignedObservationV1):
    """Signed narrow lease evidence; never the evaluator's Live capability."""

    schema_: Literal["sab.live_write_lease_envelope.v1"] = Field(
        "sab.live_write_lease_envelope.v1", alias="schema"
    )
    lease_id: str = Field(pattern=ID_PATTERN)
    ceremony_id: str = Field(pattern=ID_PATTERN)
    scope: Literal["Live"] = "Live"
    runtime_id: str = Field(pattern=ID_PATTERN)
    writer_id: str = Field(pattern=ID_PATTERN)
    database_sha256: str = Field(pattern=SHA256_PATTERN)
    lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    allowed_effects: tuple[str, ...] = Field(min_length=1)
    lease_state: Literal["prepared_for_attended_activation"] = (
        "prepared_for_attended_activation"
    )
    issued_at: datetime
    expires_at: datetime
    permits_live_effect: Literal[False] = False
    standing_effect: Literal["none"] = "none"

    @field_validator("allowed_effects", mode="before")
    @classmethod
    def exact_effects(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="allowed_effects")

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def short_lived_lease(self) -> "LiveWriteLeaseEnvelopeV1":
        if not (
            self.issued_at < self.expires_at
            and self.expires_at - self.issued_at <= MAINTENANCE_RECEIPT_MAX_AGE
        ):
            raise ValueError("live write lease window is invalid")
        return self


ReceiptKind = Literal[
    "manifest",
    "founder_decision",
    "authority_evaluation",
    "provider_probe",
    "bench_manifest",
    "cost_envelope",
    "frozen_facts",
    "maintenance_runtime",
    "service_state",
    "tick_exclusion",
    "restoration_plan",
    "service_control_authority",
    "tick_control_authority",
    "write_lease",
]


class PreflightIssueV1(StrictCanonicalModel):
    code: str = Field(pattern=ISSUE_CODE_PATTERN)
    receipt: ReceiptKind
    detail: str = Field(min_length=1, max_length=500)


ReadinessPhase = Literal["frozen_execution_facts", "live_maintenance_preflight"]


class StructurallyCompleteAwaitingAuthority(StrictCanonicalModel):
    schema_: Literal["sab.ceremony_readiness.v1"] = Field(
        "sab.ceremony_readiness.v1", alias="schema"
    )
    status: Literal["StructurallyCompleteAwaitingAuthority"] = (
        "StructurallyCompleteAwaitingAuthority"
    )
    phase: ReadinessPhase
    checked_at: datetime
    valid_until: datetime
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    verified_receipt_sha256s: tuple[str, ...] = Field(min_length=1)
    trust_anchor_set_sha256s: tuple[str, ...] = Field(min_length=1)
    blockers: tuple[PreflightIssueV1, ...] = Field(default=(), max_length=0)
    live_authority_state: Literal["absent"] = "absent"
    permits_live_effect: Literal[False] = False
    next_requirement: Literal[
        "fresh_authority_capability_and_attended_operator_rail_approval"
    ] = "fresh_authority_capability_and_attended_operator_rail_approval"
    standing_effect: Literal["none"] = "none"

    @field_validator("checked_at", "valid_until")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator(
        "verified_receipt_sha256s", "trust_anchor_set_sha256s", mode="before"
    )
    @classmethod
    def exact_receipts(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="receipt_or_trust_anchor_digests")

    @model_validator(mode="after")
    def useful_readiness_window(self) -> "StructurallyCompleteAwaitingAuthority":
        if self.valid_until <= self.checked_at:
            raise ValueError("readiness must have a future validity boundary")
        return self


def _seal_readiness(
    value: StructurallyCompleteAwaitingAuthority,
) -> StructurallyCompleteAwaitingAuthority:
    """Attach evaluator-local provenance without serializing a forgeable bearer token."""

    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        current = _READINESS_REGISTRY.get(identity)
        if current is not None and current[0] is reference:
            _READINESS_REGISTRY.pop(identity, None)

    reference = weakref.ref(value, discard)
    _READINESS_REGISTRY[identity] = (reference, value.canonical_sha256())
    return value


def readiness_is_locally_verified(
    value: object, *, phase: ReadinessPhase | None = None
) -> bool:
    """Return whether this exact in-memory value was emitted by this evaluator."""

    if not isinstance(value, StructurallyCompleteAwaitingAuthority):
        return False
    registered = _READINESS_REGISTRY.get(id(value))
    return bool(
        registered is not None
        and registered[0]() is value
        and registered[1] == value.canonical_sha256()
        and (phase is None or value.phase == phase)
    )


class Blocked(StrictCanonicalModel):
    schema_: Literal["sab.ceremony_readiness.v1"] = Field(
        "sab.ceremony_readiness.v1", alias="schema"
    )
    status: Literal["Blocked"] = "Blocked"
    phase: ReadinessPhase
    checked_at: datetime
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    blockers: tuple[PreflightIssueV1, ...] = Field(min_length=1)
    live_authority_state: Literal["absent"] = "absent"
    permits_live_effect: Literal[False] = False
    standing_effect: Literal["none"] = "none"

    @field_validator("checked_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("blockers", mode="before")
    @classmethod
    def canonical_issues(cls, value: Sequence[Any]) -> tuple[Any, ...]:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError("blockers must be a sequence")
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    (
                        str(item.get("code", "")),
                        str(item.get("receipt", "")),
                        str(item.get("detail", "")),
                    )
                    if isinstance(item, Mapping)
                    else (item.code, item.receipt, item.detail)
                ),
            )
        )


CeremonyReadinessV1 = Annotated[
    Union[StructurallyCompleteAwaitingAuthority, Blocked],
    Field(discriminator="status"),
]
CEREMONY_READINESS_ADAPTER = TypeAdapter(CeremonyReadinessV1)


def _issue(code: str, receipt: ReceiptKind, detail: str) -> PreflightIssueV1:
    return PreflightIssueV1(code=code, receipt=receipt, detail=detail)


def _parse_receipt(
    model: type[StrictCanonicalModel],
    value: Any,
    *,
    code: str,
    receipt: ReceiptKind,
) -> tuple[StrictCanonicalModel | None, list[PreflightIssueV1]]:
    try:
        payload = (
            value.canonical_payload()
            if isinstance(value, StrictCanonicalModel)
            else value
        )
        return model.model_validate(payload), []
    except Exception:
        return None, [
            _issue(code, receipt, "receipt failed strict canonical validation")
        ]


def _parse_closeout_plan(
    value: Any,
) -> tuple[CeremonyCloseoutPlan | None, list[PreflightIssueV1]]:
    """Select the exact versioned closeout contract without union coercion."""

    payload = (
        value.canonical_payload() if isinstance(value, StrictCanonicalModel) else value
    )
    if not isinstance(payload, Mapping):
        return None, [
            _issue(
                "restoration_plan_invalid",
                "restoration_plan",
                "closeout plan failed strict canonical validation",
            )
        ]
    model = {
        "sab.restoration_plan.v1": RestorationPlanV1,
        "sab.successful_closeout_plan.v2": SuccessfulCloseoutPlanV2,
    }.get(payload.get("schema"))
    if model is None:
        return None, [
            _issue(
                "restoration_plan_invalid",
                "restoration_plan",
                "closeout plan schema is missing or unsupported",
            )
        ]
    parsed, issues = _parse_receipt(
        model,
        payload,
        code="restoration_plan_invalid",
        receipt="restoration_plan",
    )
    return cast(CeremonyCloseoutPlan | None, parsed), issues


def _freshness_issues(
    *,
    observed_at: datetime,
    expires_at: datetime,
    now: datetime,
    receipt: ReceiptKind,
    prefix: str,
) -> list[PreflightIssueV1]:
    issues: list[PreflightIssueV1] = []
    if observed_at > now + MAX_FUTURE_CLOCK_SKEW:
        issues.append(
            _issue(
                f"{prefix}_not_yet_valid",
                receipt,
                "receipt observation is in the future",
            )
        )
    if expires_at <= now:
        issues.append(_issue(f"{prefix}_stale", receipt, "receipt has expired"))
    return issues


def _trusted_fingerprint_set(
    values: Collection[str],
    *,
    receipt: ReceiptKind,
    code: str,
) -> tuple[set[str], list[PreflightIssueV1]]:
    try:
        trusted = set(values)
    except TypeError:
        trusted = set()
    if not trusted or any(
        not isinstance(item, str)
        or re.fullmatch(SHA256_PATTERN, item) is None
        or item == ZERO_SHA256
        for item in trusted
    ):
        return set(), [
            _issue(
                code,
                receipt,
                "trusted fingerprints must be a non-empty exact out-of-band set",
            )
        ]
    return trusted, []


def _signed_observation_issues(
    value: _SignedObservationV1,
    *,
    trusted: set[str],
    receipt: ReceiptKind,
    prefix: str,
) -> list[PreflightIssueV1]:
    issues: list[PreflightIssueV1] = []
    if value.attestor_fingerprint not in trusted:
        issues.append(
            _issue(
                f"{prefix}_attestor_untrusted",
                receipt,
                "receipt attestor is absent from the exact out-of-band trust set",
            )
        )
    if not verify_contract_signature(
        value.signing_bytes(), value.attestation_signature
    ):
        issues.append(
            _issue(
                f"{prefix}_signature_invalid",
                receipt,
                "receipt attestation signature failed verification",
            )
        )
    return issues


def _blocked(
    *,
    phase: ReadinessPhase,
    now: datetime,
    manifest_value: Any,
    issues: Sequence[PreflightIssueV1],
) -> Blocked:
    unique = {(issue.code, issue.receipt, issue.detail): issue for issue in issues}
    return Blocked(
        phase=phase,
        checked_at=now,
        manifest_sha256=_safe_digest(manifest_value),
        blockers=tuple(unique.values()),
    )


def verify_frozen_execution_facts(
    *,
    manifest: AttendedCeremonyManifestV1 | Mapping[str, Any],
    founder_decision_receipt: FounderDecisionReceiptV1 | Mapping[str, Any],
    authority_evaluation: SignedAuthorityEvaluationEnvelopeV1 | Mapping[str, Any],
    provider_probes: Sequence[ProviderProbeReceiptV1 | Mapping[str, Any]],
    bench_manifest: FrozenBenchManifestV1 | Mapping[str, Any],
    cost_envelope: BenchCostEnvelopeV1 | Mapping[str, Any],
    trusted_founder_fingerprints: Collection[str],
    trusted_evaluator_fingerprints: Collection[str],
    trusted_operator_fingerprints: Collection[str],
    trusted_provider_attestor_fingerprints: Collection[str],
    now: datetime,
) -> CeremonyReadinessV1:
    """Verify frozen facts without calling a provider or constructing authority."""

    checked_at = _utc(now)
    issues: list[PreflightIssueV1] = []
    parsed_manifest, new = _parse_receipt(
        AttendedCeremonyManifestV1,
        manifest,
        code="manifest_invalid",
        receipt="manifest",
    )
    issues.extend(new)
    parsed_founder, new = _parse_receipt(
        FounderDecisionReceiptV1,
        founder_decision_receipt,
        code="founder_decision_invalid",
        receipt="founder_decision",
    )
    issues.extend(new)
    parsed_authority, new = _parse_receipt(
        SignedAuthorityEvaluationEnvelopeV1,
        authority_evaluation,
        code="authority_evaluation_invalid",
        receipt="authority_evaluation",
    )
    issues.extend(new)
    parsed_bench, new = _parse_receipt(
        FrozenBenchManifestV1,
        bench_manifest,
        code="bench_manifest_invalid",
        receipt="bench_manifest",
    )
    issues.extend(new)
    parsed_cost, new = _parse_receipt(
        BenchCostEnvelopeV1,
        cost_envelope,
        code="cost_envelope_invalid",
        receipt="cost_envelope",
    )
    issues.extend(new)

    probes: list[ProviderProbeReceiptV1] = []
    if isinstance(provider_probes, (str, bytes, bytearray)) or not isinstance(
        provider_probes, Sequence
    ):
        issues.append(
            _issue("provider_probes_missing", "provider_probe", "probe set is absent")
        )
    else:
        if not provider_probes:
            issues.append(
                _issue(
                    "provider_probes_missing", "provider_probe", "probe set is empty"
                )
            )
        for raw_probe in provider_probes:
            parsed_probe, new = _parse_receipt(
                ProviderProbeReceiptV1,
                raw_probe,
                code="provider_probe_invalid",
                receipt="provider_probe",
            )
            issues.extend(new)
            if isinstance(parsed_probe, ProviderProbeReceiptV1):
                probes.append(parsed_probe)

    trusted_founders, new = _trusted_fingerprint_set(
        trusted_founder_fingerprints,
        receipt="founder_decision",
        code="trusted_founder_set_invalid",
    )
    issues.extend(new)
    trusted_evaluators, new = _trusted_fingerprint_set(
        trusted_evaluator_fingerprints,
        receipt="authority_evaluation",
        code="trusted_evaluator_set_invalid",
    )
    issues.extend(new)
    trusted_probe_attestors, new = _trusted_fingerprint_set(
        trusted_provider_attestor_fingerprints,
        receipt="provider_probe",
        code="trusted_provider_attestor_set_invalid",
    )
    issues.extend(new)
    trusted_operators, new = _trusted_fingerprint_set(
        trusted_operator_fingerprints,
        receipt="cost_envelope",
        code="trusted_operator_set_invalid",
    )
    issues.extend(new)

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_manifest.frozen_at,
                expires_at=parsed_manifest.expires_at,
                now=checked_at,
                receipt="manifest",
                prefix="manifest",
            )
        )

    if isinstance(parsed_founder, FounderDecisionReceiptV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_founder.decided_at,
                expires_at=parsed_founder.expires_at,
                now=checked_at,
                receipt="founder_decision",
                prefix="founder_decision",
            )
        )
        issues.extend(
            _signed_observation_issues(
                parsed_founder,
                trusted=trusted_founders,
                receipt="founder_decision",
                prefix="founder_decision",
            )
        )

    if isinstance(parsed_authority, SignedAuthorityEvaluationEnvelopeV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_authority.evaluated_at,
                expires_at=parsed_authority.expires_at,
                now=checked_at,
                receipt="authority_evaluation",
                prefix="authority_evaluation",
            )
        )
        if parsed_authority.evaluator_fingerprint not in trusted_evaluators:
            issues.append(
                _issue(
                    "evaluator_untrusted",
                    "authority_evaluation",
                    "evaluator fingerprint is not in the out-of-band trust set",
                )
            )

        if not verify_contract_signature(
            parsed_authority.signing_bytes(), parsed_authority.signature
        ):
            issues.append(
                _issue(
                    "authority_signature_invalid",
                    "authority_evaluation",
                    "authority evaluation signature failed verification",
                )
            )

    for probe in probes:
        issues.extend(
            _freshness_issues(
                observed_at=probe.probed_at,
                expires_at=probe.expires_at,
                now=checked_at,
                receipt="provider_probe",
                prefix="provider_probe",
            )
        )
        issues.extend(
            _signed_observation_issues(
                probe,
                trusted=trusted_probe_attestors,
                receipt="provider_probe",
                prefix="provider_probe",
            )
        )

    if isinstance(parsed_cost, BenchCostEnvelopeV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_cost.approved_at,
                expires_at=parsed_cost.expires_at,
                now=checked_at,
                receipt="cost_envelope",
                prefix="cost_envelope",
            )
        )
        if parsed_cost.approver_fingerprint not in trusted_operators:
            issues.append(
                _issue(
                    "cost_approver_untrusted",
                    "cost_envelope",
                    "cost approver is absent from the out-of-band operator trust set",
                )
            )
        if not verify_contract_signature(
            parsed_cost.signing_bytes(), parsed_cost.approval_signature
        ):
            issues.append(
                _issue(
                    "cost_approval_signature_invalid",
                    "cost_envelope",
                    "operator cost approval signature failed verification",
                )
            )

    # The bench commits to exact provider probes, and the signed cost envelope
    # in turn approves that exact bench digest.  Enforce that dependency order;
    # manifest.frozen_at is a planning boundary, not the assembly time for the
    # later live-state receipts which the manifest also hashes.
    if isinstance(parsed_bench, FrozenBenchManifestV1):
        if any(probe.probed_at > parsed_bench.frozen_at for probe in probes):
            issues.append(
                _issue(
                    "provider_probe_after_bench_freeze",
                    "provider_probe",
                    "a provider probe postdates the bench which commits to it",
                )
            )
        if (
            isinstance(parsed_cost, BenchCostEnvelopeV1)
            and parsed_cost.approved_at < parsed_bench.frozen_at
        ):
            issues.append(
                _issue(
                    "cost_approval_before_bench_freeze",
                    "cost_envelope",
                    "cost approval predates the bench whose digest it approves",
                )
            )
        if isinstance(parsed_cost, BenchCostEnvelopeV1) and any(
            parsed_cost.approved_at >= probe.expires_at for probe in probes
        ):
            issues.append(
                _issue(
                    "provider_probe_expired_before_cost_approval",
                    "cost_envelope",
                    "cost approval used provider facts at or after their expiry",
                )
            )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1) and isinstance(
        parsed_founder, FounderDecisionReceiptV1
    ):
        founder_bindings = (
            parsed_founder.ceremony_id == parsed_manifest.ceremony_id,
            parsed_founder.case_id == parsed_manifest.case_id,
            parsed_founder.case_sha256 == parsed_manifest.case_sha256,
            parsed_founder.artifact_id == parsed_manifest.artifact_id,
            parsed_founder.artifact_sha256 == parsed_manifest.artifact_sha256,
            parsed_founder.decision == parsed_manifest.founder_decision,
            parsed_founder.requested_effects == parsed_manifest.requested_effects,
            parsed_founder.canonical_sha256()
            == parsed_manifest.founder_decision_receipt_sha256,
        )
        if not all(founder_bindings):
            issues.append(
                _issue(
                    "founder_decision_binding_mismatch",
                    "founder_decision",
                    "founder receipt does not bind the exact ceremony decision",
                )
            )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1) and isinstance(
        parsed_authority, SignedAuthorityEvaluationEnvelopeV1
    ):
        authority_bindings = (
            parsed_authority.ceremony_id == parsed_manifest.ceremony_id,
            parsed_authority.case_id == parsed_manifest.case_id,
            parsed_authority.case_sha256 == parsed_manifest.case_sha256,
            parsed_authority.artifact_id == parsed_manifest.artifact_id,
            parsed_authority.artifact_sha256 == parsed_manifest.artifact_sha256,
            parsed_authority.policy_sha256 == parsed_manifest.policy_sha256,
            parsed_authority.evaluated_state_sha256
            == parsed_manifest.expected_evaluated_state_sha256,
            parsed_authority.requested_effects == parsed_manifest.requested_effects,
            parsed_authority.canonical_sha256()
            == parsed_manifest.authority_evaluation_sha256,
        )
        if not all(authority_bindings):
            issues.append(
                _issue(
                    "authority_binding_mismatch",
                    "authority_evaluation",
                    "evaluation does not bind the exact frozen ceremony facts",
                )
            )
        if (
            parsed_manifest.founder_decision == "jurisdictional_refusal"
            and parsed_authority.reported_result
            not in {"AdvisoryOnly", "NoJurisdiction"}
        ):
            issues.append(
                _issue(
                    "founder_decision_authority_mismatch",
                    "authority_evaluation",
                    "jurisdictional refusal cannot be represented as Authorized",
                )
            )
        if (
            parsed_manifest.founder_decision
            == "alternate_artifact_terminal_disposition"
            and parsed_authority.reported_result != "Authorized"
        ):
            issues.append(
                _issue(
                    "terminal_authority_evaluation_absent",
                    "authority_evaluation",
                    "alternate terminal case lacks a reported exact authorization",
                )
            )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1) and isinstance(
        parsed_bench, FrozenBenchManifestV1
    ):
        if (
            parsed_bench.ceremony_id != parsed_manifest.ceremony_id
            or parsed_bench.case_id != parsed_manifest.case_id
            or parsed_bench.case_sha256 != parsed_manifest.case_sha256
            or parsed_bench.roster_sha256 != parsed_manifest.frozen_roster_sha256
            or parsed_bench.terminality_rule_sha256
            != parsed_manifest.terminality_rule_sha256
            or parsed_bench.canonical_sha256() != parsed_manifest.bench_manifest_sha256
        ):
            issues.append(
                _issue(
                    "bench_binding_mismatch",
                    "bench_manifest",
                    "bench does not bind the exact ceremony and case",
                )
            )

    probe_by_digest = {probe.canonical_sha256(): probe for probe in probes}
    if len(probe_by_digest) != len(probes):
        issues.append(
            _issue(
                "duplicate_provider_probe",
                "provider_probe",
                "provider probe receipts are not unique",
            )
        )
    if isinstance(parsed_manifest, AttendedCeremonyManifestV1):
        if tuple(sorted(probe_by_digest)) != parsed_manifest.provider_probe_sha256s:
            issues.append(
                _issue(
                    "provider_probe_set_mismatch",
                    "provider_probe",
                    "manifest probe set is missing, extra, or substituted",
                )
            )
        if any(probe.ceremony_id != parsed_manifest.ceremony_id for probe in probes):
            issues.append(
                _issue(
                    "provider_probe_ceremony_mismatch",
                    "provider_probe",
                    "probe belongs to a different ceremony",
                )
            )

    if isinstance(parsed_bench, FrozenBenchManifestV1):
        if {seat.provider_probe_sha256 for seat in parsed_bench.seats} != set(
            probe_by_digest
        ):
            issues.append(
                _issue(
                    "bench_probe_set_mismatch",
                    "provider_probe",
                    "provider probe set must exactly cover the nine frozen seats",
                )
            )
        for seat in parsed_bench.seats:
            probe = probe_by_digest.get(seat.provider_probe_sha256)
            if probe is None:
                issues.append(
                    _issue(
                        "bench_probe_missing",
                        "provider_probe",
                        "a frozen seat lacks its exact persisted probe",
                    )
                )
                continue
            if (
                seat.frozen_seat != probe.frozen_seat
                or seat.probe_correlation_id != probe.requested_correlation_id
            ):
                issues.append(
                    _issue(
                        "bench_route_substitution",
                        "bench_manifest",
                        "bench seat differs from its requested/served probe facts",
                    )
                )

    if (
        isinstance(parsed_manifest, AttendedCeremonyManifestV1)
        and isinstance(parsed_bench, FrozenBenchManifestV1)
        and isinstance(parsed_cost, BenchCostEnvelopeV1)
    ):
        if (
            parsed_cost.ceremony_id != parsed_manifest.ceremony_id
            or parsed_cost.bench_manifest_sha256 != parsed_bench.canonical_sha256()
            or parsed_cost.canonical_sha256()
            != parsed_manifest.bench_cost_envelope_sha256
            or parsed_cost.approved_by != parsed_manifest.operator_identity
            or parsed_cost.approver_public_key != parsed_manifest.operator_public_key
            or parsed_cost.approver_fingerprint != parsed_manifest.operator_fingerprint
        ):
            issues.append(
                _issue(
                    "cost_binding_mismatch",
                    "cost_envelope",
                    "cost approval does not bind the bench and approved operator rail",
                )
            )
        seats_by_id = {seat.seat_id: seat for seat in parsed_bench.seats}
        costs_by_id = {cost.seat_id: cost for cost in parsed_cost.seat_costs}
        if set(seats_by_id) != set(costs_by_id):
            issues.append(
                _issue(
                    "seat_cost_coverage_mismatch",
                    "cost_envelope",
                    "cost envelope does not cover every frozen seat exactly",
                )
            )
        provider_costs: dict[str, int] = {}
        provider_balances: dict[str, list[int]] = {}
        for seat_id, cost in costs_by_id.items():
            seat = seats_by_id.get(seat_id)
            probe = probe_by_digest.get(cost.provider_probe_sha256)
            if (
                seat is None
                or probe is None
                or cost.provider_probe_sha256 != seat.provider_probe_sha256
                or cost.pricing_catalog_sha256 != probe.catalog_sha256
            ):
                issues.append(
                    _issue(
                        "seat_cost_source_mismatch",
                        "cost_envelope",
                        "seat cost lacks its exact probe and pricing catalog",
                    )
                )
                continue
            provider_costs[probe.provider] = (
                provider_costs.get(probe.provider, 0) + cost.maximum_cost_microusd
            )
            provider_balances.setdefault(probe.provider, []).append(
                probe.available_balance_microusd
            )
        for provider, maximum_cost in provider_costs.items():
            if maximum_cost > min(provider_balances[provider]):
                issues.append(
                    _issue(
                        "provider_balance_insufficient",
                        "cost_envelope",
                        "known provider balance cannot cover the frozen maximum",
                    )
                )

    if issues:
        return _blocked(
            phase="frozen_execution_facts",
            now=checked_at,
            manifest_value=manifest,
            issues=issues,
        )

    parsed_manifest = cast(AttendedCeremonyManifestV1, parsed_manifest)
    parsed_founder = cast(FounderDecisionReceiptV1, parsed_founder)
    parsed_authority = cast(SignedAuthorityEvaluationEnvelopeV1, parsed_authority)
    parsed_bench = cast(FrozenBenchManifestV1, parsed_bench)
    parsed_cost = cast(BenchCostEnvelopeV1, parsed_cost)
    valid_until = min(
        parsed_manifest.expires_at,
        parsed_founder.expires_at,
        parsed_authority.expires_at,
        parsed_cost.expires_at,
        *(probe.expires_at for probe in probes),
    )
    if valid_until <= checked_at:
        return _blocked(
            phase="frozen_execution_facts",
            now=checked_at,
            manifest_value=parsed_manifest,
            issues=(
                _issue(
                    "frozen_facts_stale",
                    "frozen_facts",
                    "no positive readiness interval remains",
                ),
            ),
        )
    return _seal_readiness(
        StructurallyCompleteAwaitingAuthority(
            phase="frozen_execution_facts",
            checked_at=checked_at,
            valid_until=valid_until,
            manifest_sha256=parsed_manifest.canonical_sha256(),
            verified_receipt_sha256s=tuple(
                sorted(
                    {
                        parsed_manifest.canonical_sha256(),
                        parsed_founder.canonical_sha256(),
                        parsed_authority.canonical_sha256(),
                        parsed_bench.canonical_sha256(),
                        parsed_cost.canonical_sha256(),
                        *(probe.canonical_sha256() for probe in probes),
                    }
                )
            ),
            trust_anchor_set_sha256s=tuple(
                sorted(
                    {
                        canonical_sha256(
                            {
                                "role": "founder",
                                "fingerprints": sorted(trusted_founders),
                            }
                        ),
                        canonical_sha256(
                            {
                                "role": "evaluator",
                                "fingerprints": sorted(trusted_evaluators),
                            }
                        ),
                        canonical_sha256(
                            {
                                "role": "provider_probe_attestor",
                                "fingerprints": sorted(trusted_probe_attestors),
                            }
                        ),
                        canonical_sha256(
                            {
                                "role": "operator",
                                "fingerprints": sorted(trusted_operators),
                            }
                        ),
                    }
                )
            ),
        )
    )


def validate_live_preflight_receipts(
    *,
    manifest: AttendedCeremonyManifestV1 | Mapping[str, Any],
    frozen_facts: CeremonyReadinessV1 | Mapping[str, Any] | None,
    runtime_attestation: MaintenanceRuntimeAttestationV1 | Mapping[str, Any],
    service_state_snapshot: ServiceStateSnapshotV1 | Mapping[str, Any],
    tick_exclusion_receipt: TickExclusionReceiptV1 | Mapping[str, Any],
    restoration_plan: CeremonyCloseoutPlan | Mapping[str, Any],
    service_control_authority_receipt: MaintenanceControlAuthorityReceiptV1
    | Mapping[str, Any],
    tick_control_authority_receipt: MaintenanceControlAuthorityReceiptV1
    | Mapping[str, Any],
    write_lease: LiveWriteLeaseEnvelopeV1 | Mapping[str, Any],
    trusted_maintenance_attestor_fingerprints: Collection[str],
    trusted_control_authority_fingerprints: Collection[str],
    trusted_write_lease_issuer_fingerprints: Collection[str],
    now: datetime,
) -> CeremonyReadinessV1:
    """Validate persisted maintenance evidence without inspecting live state."""

    checked_at = _utc(now)
    issues: list[PreflightIssueV1] = []
    parsed_manifest, new = _parse_receipt(
        AttendedCeremonyManifestV1,
        manifest,
        code="manifest_invalid",
        receipt="manifest",
    )
    issues.extend(new)
    parsed_runtime, new = _parse_receipt(
        MaintenanceRuntimeAttestationV1,
        runtime_attestation,
        code="maintenance_runtime_invalid",
        receipt="maintenance_runtime",
    )
    issues.extend(new)

    raw_snapshot = (
        service_state_snapshot.canonical_payload()
        if isinstance(service_state_snapshot, StrictCanonicalModel)
        else service_state_snapshot
    )
    required_prior = {
        "prior_service_state",
        "prior_service_definition_sha256",
        "prior_writer_ids",
        "prior_tick_state",
        "prior_tick_definition_sha256",
    }
    if isinstance(raw_snapshot, Mapping) and not required_prior.issubset(raw_snapshot):
        issues.append(
            _issue(
                "prior_state_missing",
                "service_state",
                "service or tick prior state is incomplete",
            )
        )
    parsed_snapshot, new = _parse_receipt(
        ServiceStateSnapshotV1,
        service_state_snapshot,
        code="service_state_invalid",
        receipt="service_state",
    )
    issues.extend(new)
    parsed_tick, new = _parse_receipt(
        TickExclusionReceiptV1,
        tick_exclusion_receipt,
        code="tick_exclusion_invalid",
        receipt="tick_exclusion",
    )
    issues.extend(new)
    parsed_restoration, new = _parse_closeout_plan(restoration_plan)
    issues.extend(new)
    parsed_service_control, new = _parse_receipt(
        MaintenanceControlAuthorityReceiptV1,
        service_control_authority_receipt,
        code="service_control_authority_invalid",
        receipt="service_control_authority",
    )
    issues.extend(new)
    parsed_tick_control, new = _parse_receipt(
        MaintenanceControlAuthorityReceiptV1,
        tick_control_authority_receipt,
        code="tick_control_authority_invalid",
        receipt="tick_control_authority",
    )
    issues.extend(new)
    parsed_lease, new = _parse_receipt(
        LiveWriteLeaseEnvelopeV1,
        write_lease,
        code="write_lease_invalid",
        receipt="write_lease",
    )
    issues.extend(new)

    trusted_maintenance, new = _trusted_fingerprint_set(
        trusted_maintenance_attestor_fingerprints,
        receipt="maintenance_runtime",
        code="trusted_maintenance_attestor_set_invalid",
    )
    issues.extend(new)
    trusted_controls, new = _trusted_fingerprint_set(
        trusted_control_authority_fingerprints,
        receipt="service_control_authority",
        code="trusted_control_authority_set_invalid",
    )
    issues.extend(new)
    trusted_lease_issuers, new = _trusted_fingerprint_set(
        trusted_write_lease_issuer_fingerprints,
        receipt="write_lease",
        code="trusted_write_lease_issuer_set_invalid",
    )
    issues.extend(new)

    parsed_frozen: CeremonyReadinessV1 | None = None
    if frozen_facts is None:
        issues.append(
            _issue(
                "frozen_facts_missing",
                "frozen_facts",
                "live preflight requires a frozen-facts readiness receipt",
            )
        )
    elif not readiness_is_locally_verified(
        frozen_facts, phase="frozen_execution_facts"
    ):
        issues.append(
            _issue(
                "frozen_facts_unverifiable",
                "frozen_facts",
                "frozen facts were not emitted by this evaluator from source receipts",
            )
        )
    else:
        parsed_frozen = cast(StructurallyCompleteAwaitingAuthority, frozen_facts)

    if isinstance(parsed_frozen, Blocked):
        issues.append(
            _issue(
                "frozen_facts_blocked",
                "frozen_facts",
                "frozen execution facts have unresolved blockers",
            )
        )
    elif isinstance(parsed_frozen, StructurallyCompleteAwaitingAuthority):
        if parsed_frozen.phase != "frozen_execution_facts":
            issues.append(
                _issue(
                    "frozen_facts_phase_mismatch",
                    "frozen_facts",
                    "readiness receipt is from the wrong validation phase",
                )
            )
        if parsed_frozen.valid_until <= checked_at:
            issues.append(
                _issue(
                    "frozen_facts_stale",
                    "frozen_facts",
                    "frozen execution fact readiness has expired",
                )
            )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_manifest.frozen_at,
                expires_at=parsed_manifest.expires_at,
                now=checked_at,
                receipt="manifest",
                prefix="manifest",
            )
        )
        if not (
            parsed_manifest.maintenance_window_start
            <= checked_at
            < parsed_manifest.maintenance_window_end
        ):
            issues.append(
                _issue(
                    "outside_maintenance_window",
                    "manifest",
                    "preflight check is outside the exact maintenance window",
                )
            )
        if (
            isinstance(parsed_frozen, StructurallyCompleteAwaitingAuthority)
            and parsed_frozen.manifest_sha256 != parsed_manifest.canonical_sha256()
        ):
            issues.append(
                _issue(
                    "frozen_manifest_mismatch",
                    "frozen_facts",
                    "frozen-facts receipt belongs to a different manifest",
                )
            )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1):
        controls = (
            (
                parsed_service_control,
                "service",
                parsed_manifest.expected_service_name,
                parsed_manifest.service_control_scope,
                parsed_manifest.service_control_authority_sha256,
                "service_control_authority",
            ),
            (
                parsed_tick_control,
                "tick",
                parsed_manifest.expected_tick_id,
                parsed_manifest.tick_control_scope,
                parsed_manifest.tick_control_authority_sha256,
                "tick_control_authority",
            ),
        )
        for (
            control,
            expected_kind,
            expected_target,
            expected_scope,
            expected_digest,
            receipt_name,
        ) in controls:
            if isinstance(control, MaintenanceControlAuthorityReceiptV1) and not all(
                (
                    control.ceremony_id == parsed_manifest.ceremony_id,
                    control.control_kind == expected_kind,
                    control.target_id == expected_target,
                    control.authority_scope == expected_scope,
                    control.authorized_from == parsed_manifest.maintenance_window_start,
                    control.authorized_until == parsed_manifest.maintenance_window_end,
                    control.canonical_sha256() == expected_digest,
                )
            ):
                issues.append(
                    _issue(
                        f"{expected_kind}_control_authority_binding_mismatch",
                        cast(ReceiptKind, receipt_name),
                        "control receipt does not bind the exact target and window",
                    )
                )

        if isinstance(parsed_lease, LiveWriteLeaseEnvelopeV1) and not all(
            (
                parsed_lease.canonical_sha256()
                == parsed_manifest.live_write_lease_sha256,
                parsed_lease.ceremony_id == parsed_manifest.ceremony_id,
                parsed_lease.runtime_id == parsed_manifest.expected_runtime_id,
                parsed_lease.writer_id == parsed_manifest.expected_writer_id,
                parsed_lease.database_sha256
                == parsed_manifest.expected_database_sha256,
                parsed_lease.lifecycle_fingerprint
                == parsed_manifest.expected_lifecycle_fingerprint,
                parsed_lease.allowed_effects == parsed_manifest.requested_effects,
                parsed_lease.issued_at <= parsed_manifest.maintenance_window_start,
                parsed_lease.expires_at >= parsed_manifest.maintenance_window_end,
            )
        ):
            issues.append(
                _issue(
                    "write_lease_binding_mismatch",
                    "write_lease",
                    "write lease does not bind exact runtime, state, effect, and window",
                )
            )

        if (
            isinstance(parsed_snapshot, ServiceStateSnapshotV1)
            and isinstance(parsed_service_control, MaintenanceControlAuthorityReceiptV1)
            and isinstance(parsed_tick_control, MaintenanceControlAuthorityReceiptV1)
            and not (
                parsed_service_control.authorized_from
                <= parsed_snapshot.captured_at
                < parsed_service_control.authorized_until
                and parsed_tick_control.authorized_from
                <= parsed_snapshot.captured_at
                < parsed_tick_control.authorized_until
            )
        ):
            issues.append(
                _issue(
                    "service_snapshot_outside_control_window",
                    "service_state",
                    "snapshot was not captured inside both exact control windows",
                )
            )

        if (
            isinstance(parsed_tick, TickExclusionReceiptV1)
            and isinstance(parsed_tick_control, MaintenanceControlAuthorityReceiptV1)
            and not (
                parsed_tick_control.authorized_from
                <= parsed_tick.excluded_from
                <= parsed_tick.observed_at
                <= parsed_tick.excluded_until
                <= parsed_tick_control.authorized_until
            )
        ):
            issues.append(
                _issue(
                    "tick_exclusion_outside_control_window",
                    "tick_exclusion",
                    "tick observation or exclusion interval exceeds its control window",
                )
            )

        if isinstance(parsed_restoration, _CLOSEOUT_PLAN_TYPES):
            if (
                isinstance(parsed_service_control, MaintenanceControlAuthorityReceiptV1)
                and isinstance(
                    parsed_tick_control, MaintenanceControlAuthorityReceiptV1
                )
                and not (
                    parsed_service_control.authorized_from
                    <= parsed_restoration.generated_at
                    < parsed_service_control.authorized_until
                    and parsed_tick_control.authorized_from
                    <= parsed_restoration.generated_at
                    < parsed_tick_control.authorized_until
                )
            ):
                issues.append(
                    _issue(
                        "restoration_plan_outside_control_window",
                        "restoration_plan",
                        "closeout plan was not generated inside both control windows",
                    )
                )

    if isinstance(parsed_runtime, MaintenanceRuntimeAttestationV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_runtime.attested_at,
                expires_at=parsed_runtime.expires_at,
                now=checked_at,
                receipt="maintenance_runtime",
                prefix="maintenance_runtime",
            )
        )
        issues.extend(
            _signed_observation_issues(
                parsed_runtime,
                trusted=trusted_maintenance,
                receipt="maintenance_runtime",
                prefix="maintenance_runtime",
            )
        )
    if isinstance(parsed_snapshot, ServiceStateSnapshotV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_snapshot.captured_at,
                expires_at=parsed_snapshot.expires_at,
                now=checked_at,
                receipt="service_state",
                prefix="service_state",
            )
        )
        issues.extend(
            _signed_observation_issues(
                parsed_snapshot,
                trusted=trusted_maintenance,
                receipt="service_state",
                prefix="service_state",
            )
        )
    if isinstance(parsed_tick, TickExclusionReceiptV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_tick.observed_at,
                expires_at=parsed_tick.expires_at,
                now=checked_at,
                receipt="tick_exclusion",
                prefix="tick_exclusion",
            )
        )
        issues.extend(
            _signed_observation_issues(
                parsed_tick,
                trusted=trusted_maintenance,
                receipt="tick_exclusion",
                prefix="tick_exclusion",
            )
        )
    if isinstance(parsed_restoration, _CLOSEOUT_PLAN_TYPES):
        if (
            parsed_restoration.generated_at > checked_at + MAX_FUTURE_CLOCK_SKEW
            or checked_at - parsed_restoration.generated_at
            > MAINTENANCE_RECEIPT_MAX_AGE
        ):
            issues.append(
                _issue(
                    "restoration_plan_stale",
                    "restoration_plan",
                    "restoration plan was not freshly generated",
                )
            )
        issues.extend(
            _signed_observation_issues(
                parsed_restoration,
                trusted=trusted_maintenance,
                receipt="restoration_plan",
                prefix="restoration_plan",
            )
        )
    for control, receipt_name, prefix in (
        (parsed_service_control, "service_control_authority", "service_control"),
        (parsed_tick_control, "tick_control_authority", "tick_control"),
    ):
        if isinstance(control, MaintenanceControlAuthorityReceiptV1):
            issues.extend(
                _freshness_issues(
                    observed_at=control.issued_at,
                    expires_at=control.expires_at,
                    now=checked_at,
                    receipt=cast(ReceiptKind, receipt_name),
                    prefix=prefix,
                )
            )
            issues.extend(
                _signed_observation_issues(
                    control,
                    trusted=trusted_controls,
                    receipt=cast(ReceiptKind, receipt_name),
                    prefix=prefix,
                )
            )
    if isinstance(parsed_lease, LiveWriteLeaseEnvelopeV1):
        issues.extend(
            _freshness_issues(
                observed_at=parsed_lease.issued_at,
                expires_at=parsed_lease.expires_at,
                now=checked_at,
                receipt="write_lease",
                prefix="write_lease",
            )
        )
        issues.extend(
            _signed_observation_issues(
                parsed_lease,
                trusted=trusted_lease_issuers,
                receipt="write_lease",
                prefix="write_lease",
            )
        )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1) and isinstance(
        parsed_runtime, MaintenanceRuntimeAttestationV1
    ):
        if parsed_runtime.canonical_sha256() != (
            parsed_manifest.maintenance_runtime_attestation_sha256
        ):
            issues.append(
                _issue(
                    "runtime_attestation_digest_mismatch",
                    "maintenance_runtime",
                    "runtime attestation differs from the frozen manifest",
                )
            )
        identity_checks = (
            parsed_runtime.ceremony_id == parsed_manifest.ceremony_id,
            parsed_runtime.runtime_id == parsed_manifest.expected_runtime_id,
            parsed_runtime.writer_id == parsed_manifest.expected_writer_id,
            parsed_runtime.code_commit == parsed_manifest.expected_code_commit,
            parsed_runtime.openapi_sha256 == parsed_manifest.expected_openapi_sha256,
            parsed_runtime.runtime_sha256 == parsed_manifest.expected_runtime_sha256,
            parsed_runtime.maintenance_operations_sha256
            == parsed_manifest.expected_maintenance_operations_sha256,
            parsed_runtime.database_sha256 == parsed_manifest.expected_database_sha256,
            parsed_runtime.lifecycle_fingerprint
            == parsed_manifest.expected_lifecycle_fingerprint,
        )
        if not all(identity_checks):
            issues.append(
                _issue(
                    "maintenance_runtime_identity_mismatch",
                    "maintenance_runtime",
                    "code, OpenAPI, runtime, writer, or database identity differs",
                )
            )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1) and isinstance(
        parsed_snapshot, ServiceStateSnapshotV1
    ):
        if parsed_snapshot.canonical_sha256() != (
            parsed_manifest.service_state_snapshot_sha256
        ):
            issues.append(
                _issue(
                    "service_snapshot_digest_mismatch",
                    "service_state",
                    "service snapshot differs from the frozen manifest",
                )
            )
        snapshot_checks = (
            parsed_snapshot.ceremony_id == parsed_manifest.ceremony_id,
            parsed_snapshot.service_name == parsed_manifest.expected_service_name,
            parsed_snapshot.maintenance_runtime_id
            == parsed_manifest.expected_runtime_id,
            parsed_snapshot.active_writer_ids == (parsed_manifest.expected_writer_id,),
            parsed_snapshot.tick_id == parsed_manifest.expected_tick_id,
            parsed_snapshot.service_control_authority_sha256
            == parsed_manifest.service_control_authority_sha256,
            parsed_snapshot.tick_control_authority_sha256
            == parsed_manifest.tick_control_authority_sha256,
            parsed_snapshot.database_sha256 == parsed_manifest.expected_database_sha256,
            parsed_snapshot.lifecycle_fingerprint
            == parsed_manifest.expected_lifecycle_fingerprint,
        )
        if not all(snapshot_checks):
            issues.append(
                _issue(
                    "service_state_binding_mismatch",
                    "service_state",
                    "service snapshot does not bind exact runtime and prior state",
                )
            )

    if isinstance(parsed_manifest, AttendedCeremonyManifestV1) and isinstance(
        parsed_tick, TickExclusionReceiptV1
    ):
        if (
            parsed_tick.canonical_sha256()
            != parsed_manifest.tick_exclusion_receipt_sha256
        ):
            issues.append(
                _issue(
                    "tick_exclusion_digest_mismatch",
                    "tick_exclusion",
                    "tick exclusion receipt differs from the frozen manifest",
                )
            )
        tick_checks = (
            parsed_tick.ceremony_id == parsed_manifest.ceremony_id,
            parsed_tick.tick_id == parsed_manifest.expected_tick_id,
            parsed_tick.tick_control_authority_sha256
            == parsed_manifest.tick_control_authority_sha256,
            parsed_tick.ceremony_window_start
            == parsed_manifest.maintenance_window_start,
            parsed_tick.ceremony_window_end == parsed_manifest.maintenance_window_end,
        )
        if not all(tick_checks):
            issues.append(
                _issue(
                    "tick_exclusion_binding_mismatch",
                    "tick_exclusion",
                    "tick exclusion does not bind the exact ceremony window",
                )
            )

    if (
        isinstance(parsed_snapshot, ServiceStateSnapshotV1)
        and isinstance(parsed_tick, TickExclusionReceiptV1)
        and parsed_tick.tick_definition_sha256
        != parsed_snapshot.prior_tick_definition_sha256
    ):
        issues.append(
            _issue(
                "tick_definition_mismatch",
                "tick_exclusion",
                "excluded tick definition differs from captured prior state",
            )
        )

    if (
        isinstance(parsed_manifest, AttendedCeremonyManifestV1)
        and isinstance(parsed_snapshot, ServiceStateSnapshotV1)
        and isinstance(parsed_restoration, _CLOSEOUT_PLAN_TYPES)
    ):
        if (
            parsed_restoration.canonical_sha256()
            != parsed_manifest.restoration_plan_sha256
        ):
            issues.append(
                _issue(
                    "restoration_plan_digest_mismatch",
                    "restoration_plan",
                    "restoration plan differs from the frozen manifest",
                )
            )
        expected_control_restore = (
            parsed_restoration.ceremony_id == parsed_manifest.ceremony_id,
            parsed_restoration.service_state_snapshot_sha256
            == parsed_snapshot.canonical_sha256(),
            parsed_restoration.maintenance_runtime_id
            == parsed_snapshot.maintenance_runtime_id,
            parsed_restoration.restore_service_name == parsed_snapshot.service_name,
            parsed_restoration.restore_service_state
            == parsed_snapshot.prior_service_state,
            parsed_restoration.restore_service_instance_id
            == parsed_snapshot.prior_service_instance_id,
            parsed_restoration.restore_service_definition_sha256
            == parsed_snapshot.prior_service_definition_sha256,
            parsed_restoration.restore_writer_ids == parsed_snapshot.prior_writer_ids,
            parsed_restoration.restore_tick_id == parsed_snapshot.tick_id,
            parsed_restoration.restore_tick_state == parsed_snapshot.prior_tick_state,
            parsed_restoration.restore_tick_definition_sha256
            == parsed_snapshot.prior_tick_definition_sha256,
            parsed_restoration.service_control_authority_sha256
            == parsed_snapshot.service_control_authority_sha256,
            parsed_restoration.tick_control_authority_sha256
            == parsed_snapshot.tick_control_authority_sha256,
        )
        disposition_roots_match = (
            parsed_restoration.restore_database_sha256
            == parsed_snapshot.database_sha256
            and parsed_restoration.restore_lifecycle_fingerprint
            == parsed_snapshot.lifecycle_fingerprint
            if isinstance(parsed_restoration, RestorationPlanV1)
            else parsed_restoration.failure_database_sha256
            == parsed_snapshot.database_sha256
            and parsed_restoration.failure_lifecycle_fingerprint
            == parsed_snapshot.lifecycle_fingerprint
        )
        if not all(expected_control_restore) or not disposition_roots_match:
            issues.append(
                _issue(
                    "restoration_drift",
                    "restoration_plan",
                    "closeout target differs from its exact captured prior controls",
                )
            )

    if (
        isinstance(parsed_restoration, SuccessfulCloseoutPlanV2)
        and isinstance(parsed_snapshot, ServiceStateSnapshotV1)
        and isinstance(parsed_tick, TickExclusionReceiptV1)
        and isinstance(parsed_lease, LiveWriteLeaseEnvelopeV1)
        and not (
            parsed_snapshot.captured_at
            <= parsed_tick.observed_at
            <= parsed_restoration.generated_at
            and parsed_tick.excluded_from
            <= parsed_restoration.generated_at
            < parsed_tick.excluded_until
            and parsed_lease.issued_at
            <= parsed_restoration.generated_at
            < parsed_lease.expires_at
        )
    ):
        issues.append(
            _issue(
                "successful_closeout_plan_chronology_invalid",
                "restoration_plan",
                "successful closeout plan does not follow snapshot, exclusion, and lease chronology",
            )
        )

    if issues:
        return _blocked(
            phase="live_maintenance_preflight",
            now=checked_at,
            manifest_value=manifest,
            issues=issues,
        )

    parsed_manifest = cast(AttendedCeremonyManifestV1, parsed_manifest)
    parsed_runtime = cast(MaintenanceRuntimeAttestationV1, parsed_runtime)
    parsed_snapshot = cast(ServiceStateSnapshotV1, parsed_snapshot)
    parsed_tick = cast(TickExclusionReceiptV1, parsed_tick)
    parsed_restoration = cast(CeremonyCloseoutPlan, parsed_restoration)
    parsed_service_control = cast(
        MaintenanceControlAuthorityReceiptV1, parsed_service_control
    )
    parsed_tick_control = cast(
        MaintenanceControlAuthorityReceiptV1, parsed_tick_control
    )
    parsed_lease = cast(LiveWriteLeaseEnvelopeV1, parsed_lease)
    parsed_frozen = cast(StructurallyCompleteAwaitingAuthority, parsed_frozen)
    valid_until = min(
        parsed_manifest.expires_at,
        parsed_manifest.maintenance_window_end,
        parsed_frozen.valid_until,
        parsed_runtime.expires_at,
        parsed_snapshot.expires_at,
        parsed_tick.expires_at,
        parsed_service_control.expires_at,
        parsed_tick_control.expires_at,
        parsed_lease.expires_at,
    )
    if valid_until <= checked_at:
        return _blocked(
            phase="live_maintenance_preflight",
            now=checked_at,
            manifest_value=parsed_manifest,
            issues=(
                _issue(
                    "live_preflight_stale",
                    "manifest",
                    "no positive maintenance readiness interval remains",
                ),
            ),
        )
    return _seal_readiness(
        StructurallyCompleteAwaitingAuthority(
            phase="live_maintenance_preflight",
            checked_at=checked_at,
            valid_until=valid_until,
            manifest_sha256=parsed_manifest.canonical_sha256(),
            verified_receipt_sha256s=tuple(
                sorted(
                    {
                        *parsed_frozen.verified_receipt_sha256s,
                        parsed_runtime.canonical_sha256(),
                        parsed_snapshot.canonical_sha256(),
                        parsed_tick.canonical_sha256(),
                        parsed_restoration.canonical_sha256(),
                        parsed_service_control.canonical_sha256(),
                        parsed_tick_control.canonical_sha256(),
                        parsed_lease.canonical_sha256(),
                    }
                )
            ),
            trust_anchor_set_sha256s=tuple(
                sorted(
                    {
                        *parsed_frozen.trust_anchor_set_sha256s,
                        canonical_sha256(
                            {
                                "role": "maintenance_attestor",
                                "fingerprints": sorted(trusted_maintenance),
                            }
                        ),
                        canonical_sha256(
                            {
                                "role": "maintenance_controller",
                                "fingerprints": sorted(trusted_controls),
                            }
                        ),
                        canonical_sha256(
                            {
                                "role": "write_lease_issuer",
                                "fingerprints": sorted(trusted_lease_issuers),
                            }
                        ),
                    }
                )
            ),
        )
    )


__all__ = [
    "AUTHORITY_EVALUATION_MAX_AGE",
    "AttendedCeremonyManifestV1",
    "BenchCostEnvelopeV1",
    "BenchSeatCostV1",
    "Blocked",
    "CEREMONY_READINESS_ADAPTER",
    "CeremonyCloseoutPlan",
    "CeremonyReadinessV1",
    "FROZEN_MAINTENANCE_OPERATIONS_SHA256",
    "FounderDecisionReceiptV1",
    "FrozenBenchManifestV1",
    "FrozenBenchSeatV1",
    "MAINTENANCE_RECEIPT_MAX_AGE",
    "LiveWriteLeaseEnvelopeV1",
    "MaintenanceControlAuthorityReceiptV1",
    "MaintenanceRuntimeAttestationV1",
    "PROVIDER_PROBE_MAX_AGE",
    "PreflightIssueV1",
    "ProviderProbeReceiptV1",
    "RestorationPlanV1",
    "ServiceStateSnapshotV1",
    "SignedAuthorityEvaluationEnvelopeV1",
    "StructurallyCompleteAwaitingAuthority",
    "SuccessfulCloseoutPlanV2",
    "TickExclusionReceiptV1",
    "validate_live_preflight_receipts",
    "readiness_is_locally_verified",
    "verify_frozen_execution_facts",
]
