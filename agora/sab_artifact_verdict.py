"""Strict, offline contracts for SAB's first-verdict Build A slice.

The central safety property is deliberately implemented as construction-time
semantics: a copy rehearsal contains ``Authorized<Copy>`` and a live effective
verdict contains ``Authorized<Live>``.  A ballot tally, lease, countersign, or
fixture is never accepted as a substitute for disposition authority.

This module is pure.  It performs no I/O, persistence, provider calls, or
service mutation.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, Mapping, Sequence, Union

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
    model_validator,
)


SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
HEX_PUBLIC_KEY_PATTERN = r"^[0-9a-f]{64}$"
HEX_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"
CANONICALIZATION = "json-sort-keys-compact-v1"
MASTER_VISION_SEED_ID = "sab_seed_master_vision_v1_ebe422aab149"

MASTER_VISION_FORBIDDEN_EFFECTS = (
    "alter_standing",
    "canon",
    "compost",
    "resolve_challenge",
    "submit_effective_successor",
    "supersede",
)

FROZEN_MAINTENANCE_OPERATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/health"),
        ("POST", "/api/v1/session-write-leases/activate"),
        ("POST", "/api/v1/session-write-leases/{lease_id}/release"),
        ("GET", "/api/v1/session-write-leases/{lease_id}"),
        ("POST", "/api/v1/artifact-cases"),
        ("GET", "/api/v1/artifact-cases/{case_id}"),
        ("POST", "/api/v1/artifact-cases/{case_id}/ballots"),
        ("POST", "/api/v1/artifact-cases/{case_id}/authority-evaluations"),
        ("POST", "/api/v1/artifact-cases/{case_id}/verdicts"),
        ("GET", "/api/v1/artifact-verdicts/{verdict_id}"),
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        ),
        ("GET", "/api/v1/rehearsal-dispositions/{disposition_id}"),
        ("GET", "/api/v1/seeds/{seed_id}/lineage"),
        ("POST", "/api/v1/compost-batches/preview"),
    }
)


def canonical_json_bytes(payload: Any) -> bytes:
    """Return SAB's stable v1 signing encoding."""

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def canonical_json(payload: Any) -> str:
    return canonical_json_bytes(payload).decode("utf-8")


def canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


# The longer name is the stable integration spelling used by storage/lifecycle.
canonical_json_sha256 = canonical_sha256


def bytes_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _nonblank(value: str, *, field: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} cannot be blank")
    return normalized


def _exact_strings(
    values: Sequence[str], *, field: str, allow_empty: bool = False
) -> tuple[str, ...]:
    normalized = tuple(sorted({_nonblank(str(value), field=field) for value in values}))
    if not normalized and not allow_empty:
        raise ValueError(f"{field} cannot be empty")
    if any("*" in value for value in normalized):
        raise ValueError(f"{field} cannot contain wildcard authority")
    return normalized


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


class StrictCanonicalModel(BaseModel):
    """Immutable strict model with one stable byte representation."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        use_enum_values=True,
    )

    def canonical_payload(self, *, exclude: set[str] | None = None) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude=exclude or set(),
            exclude_none=False,
        )

    def canonical_bytes(self, *, exclude: set[str] | None = None) -> bytes:
        return canonical_json_bytes(self.canonical_payload(exclude=exclude))

    def canonical_json(self, *, exclude: set[str] | None = None) -> str:
        return self.canonical_bytes(exclude=exclude).decode("utf-8")

    def canonical_sha256(self, *, exclude: set[str] | None = None) -> str:
        return hashlib.sha256(self.canonical_bytes(exclude=exclude)).hexdigest()


class DispositionScope(str, Enum):
    COPY = "Copy"
    LIVE = "Live"
    ALL = "All"


class BallotSource(str, Enum):
    REAL_EXTERNAL_MODEL = "real_external_model"
    FIXTURE_MODEL = "fixture_model"


class EvidenceProvenance(str, Enum):
    REAL_EXTERNAL_MODELS = "real_external_models"
    FIXTURE_MODELS = "fixture_models"


class ContractSignatureV1(StrictCanonicalModel):
    alg: Literal["ed25519"] = "ed25519"
    signer: str = Field(min_length=1, max_length=200)
    public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    signature: str = Field(pattern=HEX_SIGNATURE_PATTERN)
    signed_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    canonicalization: Literal["json-sort-keys-compact-v1"] = CANONICALIZATION


def verify_contract_signature(message: bytes, signature: ContractSignatureV1) -> bool:
    if bytes_sha256(message) != signature.signed_payload_sha256:
        return False
    try:
        key = VerifyKey(signature.public_key.encode("ascii"), encoder=HexEncoder)
        key.verify(message, bytes.fromhex(signature.signature))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


class EvidenceRefV1(StrictCanonicalModel):
    ref: str = Field(min_length=1, max_length=1000)
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    proof_class: str = Field(min_length=1, max_length=120)


class AllowedOperationV1(StrictCanonicalModel):
    method: Literal["GET", "POST"]
    path: str = Field(min_length=1, max_length=240, pattern=r"^/[^\s]*$")

    @model_validator(mode="after")
    def exact_frozen_operation(self) -> "AllowedOperationV1":
        if "*" in self.path:
            raise ValueError("wildcard paths are forbidden")
        if (self.method, self.path) not in FROZEN_MAINTENANCE_OPERATIONS:
            raise ValueError(
                "operation is outside the frozen Build A maintenance inventory"
            )
        return self


def allowed_operations_digest(
    operations: Sequence[AllowedOperationV1 | Mapping[str, Any]],
) -> str:
    parsed = [
        operation
        if isinstance(operation, AllowedOperationV1)
        else AllowedOperationV1.model_validate(operation)
        for operation in operations
    ]
    payload = sorted(
        (operation.canonical_payload() for operation in parsed),
        key=lambda item: (item["method"], item["path"]),
    )
    if len({(item["method"], item["path"]) for item in payload}) != len(payload):
        raise ValueError("allowed operations must be unique")
    return canonical_sha256(payload)


def validate_exact_allowed_operations(
    operations: Sequence[AllowedOperationV1 | Mapping[str, Any]],
) -> tuple[AllowedOperationV1, ...]:
    """Parse, deduplicate, sort, and freeze exact method/path pairs."""

    parsed = tuple(
        sorted(
            (
                operation
                if isinstance(operation, AllowedOperationV1)
                else AllowedOperationV1.model_validate(operation)
                for operation in operations
            ),
            key=lambda item: (item.method, item.path),
        )
    )
    if not parsed:
        raise ValueError("allowed operations cannot be empty")
    if len({(item.method, item.path) for item in parsed}) != len(parsed):
        raise ValueError("allowed operations must be unique")
    return parsed


class SignedDispositionPolicyV1(StrictCanonicalModel):
    """Signed policy input understood by the pure authority evaluator."""

    schema_: Literal["sab.signed_disposition_policy.v1"] = Field(
        "sab.signed_disposition_policy.v1", alias="schema"
    )
    policy_id: str = Field(min_length=1, max_length=200)
    artifact_id: str = Field(min_length=1, max_length=200)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    disposition_mode: Literal["authorized", "advisory_only", "no_jurisdiction"]
    scope: DispositionScope
    permitted_effects: tuple[str, ...]
    forbidden_effects: tuple[str, ...]
    preconditions: tuple[str, ...] = Field(min_length=1)
    evaluated_state_hash: str = Field(pattern=SHA256_PATTERN)
    source_fixture_id: str | None = Field(default=None, min_length=1, max_length=240)
    copied_database_id: str | None = Field(default=None, min_length=1, max_length=240)
    test_issuer: bool
    live_eligible: bool
    standing_effect: Literal["none"] = "none"
    authority_refs: tuple[str, ...] = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    issuer: str = Field(min_length=1, max_length=200)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    signature: ContractSignatureV1

    @field_validator("permitted_effects", "forbidden_effects", mode="before")
    @classmethod
    def exact_effect_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name), allow_empty=True)

    @field_validator("authority_refs", "preconditions", mode="before")
    @classmethod
    def exact_required_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name))

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def coherent_policy(self) -> "SignedDispositionPolicyV1":
        if self.expires_at <= self.issued_at:
            raise ValueError("policy must expire after issuance")
        if self.test_issuer:
            if self.scope != DispositionScope.COPY:
                raise ValueError("test issuers may authorize Copy scope only")
            if self.live_eligible:
                raise ValueError("test-issued policies cannot be live eligible")
            if not self.source_fixture_id or not self.copied_database_id:
                raise ValueError(
                    "test policy must bind source fixture and copied database"
                )
        if self.disposition_mode == "authorized":
            if not self.permitted_effects or self.forbidden_effects:
                raise ValueError("authorized policy needs permitted effects only")
        elif self.disposition_mode == "advisory_only":
            if self.permitted_effects or not self.forbidden_effects:
                raise ValueError("advisory policy needs forbidden effects only")
        elif self.permitted_effects or self.forbidden_effects:
            raise ValueError("no-jurisdiction policy cannot grant or forbid effects")
        expected = canonical_sha256(
            self.canonical_payload(exclude={"policy_sha256", "signature"})
        )
        if self.policy_sha256 != expected:
            raise ValueError("policy_sha256 does not bind the unsigned policy body")
        return self

    def signing_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"signature"})


class DispositionAuthorityBaseV1(StrictCanonicalModel):
    schema_: Literal["sab.disposition_authority.v1"] = Field(
        "sab.disposition_authority.v1", alias="schema"
    )
    evaluation_id: str = Field(min_length=1, max_length=200)
    artifact_id: str = Field(min_length=1, max_length=200)
    scope: DispositionScope
    authority_refs: tuple[str, ...]
    allowed_effects: tuple[str, ...] = ()
    forbidden_effects: tuple[str, ...] = ()
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    evaluated_state_hash: str = Field(pattern=SHA256_PATTERN)
    reason_codes: tuple[str, ...] = Field(min_length=1)
    live_eligible: bool
    standing_effect: Literal["none"] = "none"

    @field_validator(
        "authority_refs",
        "allowed_effects",
        "forbidden_effects",
        "reason_codes",
        mode="before",
    )
    @classmethod
    def exact_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(
            value,
            field=str(info.field_name),
            allow_empty=str(info.field_name)
            in {"authority_refs", "allowed_effects", "forbidden_effects"},
        )

    @property
    def authority_digest(self) -> str:
        return self.canonical_sha256()


class AuthorizedDispositionAuthorityV1(DispositionAuthorityBaseV1):
    result: Literal["Authorized"] = "Authorized"
    scope: Literal[DispositionScope.COPY, DispositionScope.LIVE]

    @model_validator(mode="after")
    def authorized_shape(self) -> "AuthorizedDispositionAuthorityV1":
        if not self.authority_refs:
            raise ValueError("Authorized requires authority references")
        if not self.allowed_effects or self.forbidden_effects:
            raise ValueError("Authorized requires allowed effects only")
        if self.scope == DispositionScope.COPY and self.live_eligible:
            raise ValueError("Authorized<Copy> cannot be live eligible")
        if self.scope == DispositionScope.LIVE and not self.live_eligible:
            raise ValueError("Authorized<Live> must be live eligible")
        return self


class AdvisoryOnlyDispositionAuthorityV1(DispositionAuthorityBaseV1):
    result: Literal["AdvisoryOnly"] = "AdvisoryOnly"

    @model_validator(mode="after")
    def advisory_shape(self) -> "AdvisoryOnlyDispositionAuthorityV1":
        if self.allowed_effects or not self.forbidden_effects:
            raise ValueError("AdvisoryOnly requires forbidden effects and grants none")
        if self.live_eligible:
            raise ValueError("AdvisoryOnly cannot be live eligible")
        return self


class NoJurisdictionDispositionAuthorityV1(DispositionAuthorityBaseV1):
    result: Literal["NoJurisdiction"] = "NoJurisdiction"

    @model_validator(mode="after")
    def refusal_shape(self) -> "NoJurisdictionDispositionAuthorityV1":
        if self.allowed_effects or self.forbidden_effects:
            raise ValueError("NoJurisdiction cannot grant or reserve effects")
        if self.live_eligible:
            raise ValueError("NoJurisdiction cannot be live eligible")
        return self


DispositionAuthorityV1 = Annotated[
    Union[
        AuthorizedDispositionAuthorityV1,
        AdvisoryOnlyDispositionAuthorityV1,
        NoJurisdictionDispositionAuthorityV1,
    ],
    Field(discriminator="result"),
]
DISPOSITION_AUTHORITY_ADAPTER = TypeAdapter(DispositionAuthorityV1)


class AuthorityDenied(ValueError):
    """A requested effect cannot be constructed from the supplied authority."""


def _evaluation_id(artifact_id: str, state_hash: str, scope: DispositionScope) -> str:
    digest = canonical_sha256(
        {
            "artifact_id": artifact_id,
            "evaluated_state_hash": state_hash,
            "scope": scope.value,
        }
    )
    return f"sab_authority_{digest[:24]}"


def _no_jurisdiction(
    *,
    artifact_id: str,
    artifact_sha256: str,
    requested_scope: DispositionScope,
    evaluated_state_hash: str,
    policy_sha256: str,
    authority_refs: Sequence[str],
    reasons: Sequence[str],
) -> NoJurisdictionDispositionAuthorityV1:
    return NoJurisdictionDispositionAuthorityV1(
        evaluation_id=_evaluation_id(
            artifact_id, evaluated_state_hash, requested_scope
        ),
        artifact_id=artifact_id,
        scope=requested_scope,
        authority_refs=tuple(authority_refs),
        policy_sha256=policy_sha256,
        content_sha256=artifact_sha256,
        evaluated_state_hash=evaluated_state_hash,
        reason_codes=tuple(reasons),
        live_eligible=False,
    )


def evaluate_disposition_authority(
    *,
    artifact_id: str,
    artifact_sha256: str,
    requested_scope: DispositionScope | str,
    requested_effects: Sequence[str],
    evaluated_state_hash: str,
    signed_policy: SignedDispositionPolicyV1 | Mapping[str, Any] | None,
    now: datetime | None = None,
) -> DispositionAuthorityV1:
    """Evaluate authority *before* any merit tally or effect construction.

    Invalid, missing, expired, ambiguous, mismatched, or unverifiable policy
    fails closed.  Master Vision v1.0 has a controlling explicit AdvisoryOnly
    ruling regardless of vote count or requested effect.
    """

    scope = DispositionScope(requested_scope)
    effects = _exact_strings(
        requested_effects, field="requested_effects", allow_empty=True
    )
    current_time = _utc(now or datetime.now(timezone.utc))
    zero_hash = "0" * 64

    if artifact_id == MASTER_VISION_SEED_ID:
        raw_policy = (
            signed_policy.canonical_payload()
            if isinstance(signed_policy, SignedDispositionPolicyV1)
            else dict(signed_policy or {})
        )
        return AdvisoryOnlyDispositionAuthorityV1(
            evaluation_id=_evaluation_id(artifact_id, evaluated_state_hash, scope),
            artifact_id=artifact_id,
            scope=DispositionScope.ALL,
            authority_refs=(
                "signed-seed:sab_seed_master_vision_v1_ebe422aab149",
                "signed-challenge:sab_challenge_master_vision_v1_ebe422aab149",
            ),
            forbidden_effects=MASTER_VISION_FORBIDDEN_EFFECTS,
            policy_sha256=canonical_sha256(raw_policy),
            content_sha256=artifact_sha256,
            evaluated_state_hash=evaluated_state_hash,
            reason_codes=(
                "independent_operator_resolution_required",
                "signed_compost_conditions_unmet",
            ),
            live_eligible=False,
        )

    if signed_policy is None:
        return _no_jurisdiction(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            requested_scope=scope,
            evaluated_state_hash=evaluated_state_hash,
            policy_sha256=zero_hash,
            authority_refs=(),
            reasons=("missing_signed_policy",),
        )

    try:
        policy = (
            signed_policy
            if isinstance(signed_policy, SignedDispositionPolicyV1)
            else SignedDispositionPolicyV1.model_validate(signed_policy)
        )
    except Exception:
        raw = dict(signed_policy) if isinstance(signed_policy, Mapping) else {}
        return _no_jurisdiction(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            requested_scope=scope,
            evaluated_state_hash=evaluated_state_hash,
            policy_sha256=canonical_sha256(raw),
            authority_refs=(),
            reasons=("invalid_policy_contract",),
        )

    base = dict(
        evaluation_id=_evaluation_id(artifact_id, evaluated_state_hash, scope),
        artifact_id=artifact_id,
        authority_refs=policy.authority_refs,
        policy_sha256=policy.policy_sha256,
        content_sha256=artifact_sha256,
        evaluated_state_hash=evaluated_state_hash,
    )
    mismatches: list[str] = []
    if policy.artifact_id != artifact_id or policy.artifact_sha256 != artifact_sha256:
        mismatches.append("artifact_binding_mismatch")
    if policy.evaluated_state_hash != evaluated_state_hash:
        mismatches.append("state_hash_mismatch")
    if policy.expires_at <= current_time:
        mismatches.append("policy_expired")
    if not verify_contract_signature(policy.signing_bytes(), policy.signature):
        mismatches.append("policy_signature_invalid")
    if policy.scope not in {scope, DispositionScope.ALL}:
        mismatches.append("scope_mismatch")
    if not set(effects).issubset(policy.permitted_effects):
        mismatches.append("effect_not_authorized")
    if scope == DispositionScope.LIVE and (
        policy.test_issuer or not policy.live_eligible
    ):
        mismatches.append("live_authority_absent")
    if mismatches:
        return _no_jurisdiction(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            requested_scope=scope,
            evaluated_state_hash=evaluated_state_hash,
            policy_sha256=policy.policy_sha256,
            authority_refs=policy.authority_refs,
            reasons=mismatches,
        )
    if policy.disposition_mode == "advisory_only":
        return AdvisoryOnlyDispositionAuthorityV1(
            **base,
            scope=scope,
            forbidden_effects=policy.forbidden_effects,
            reason_codes=("policy_advisory_only",),
            live_eligible=False,
        )
    if policy.disposition_mode == "no_jurisdiction":
        return NoJurisdictionDispositionAuthorityV1(
            **base,
            scope=scope,
            reason_codes=("policy_declines_jurisdiction",),
            live_eligible=False,
        )
    return AuthorizedDispositionAuthorityV1(
        **base,
        scope=scope,
        allowed_effects=policy.permitted_effects,
        reason_codes=("signed_policy_authorizes_exact_scope_and_effects",),
        live_eligible=policy.live_eligible,
    )


def require_authorized_effects(
    authority: DispositionAuthorityV1,
    *,
    scope: DispositionScope | str,
    effects: Sequence[str],
    evidence_provenance: EvidenceProvenance | str,
) -> AuthorizedDispositionAuthorityV1:
    requested_scope = DispositionScope(scope)
    provenance = EvidenceProvenance(evidence_provenance)
    requested_effects = set(_exact_strings(effects, field="effects"))
    if not isinstance(authority, AuthorizedDispositionAuthorityV1):
        raise AuthorityDenied(
            f"{authority.result} cannot construct an effective disposition"
        )
    if authority.scope != requested_scope:
        raise AuthorityDenied("authority scope does not match disposition scope")
    if not requested_effects.issubset(authority.allowed_effects):
        raise AuthorityDenied("effect is outside the exact authority set")
    if requested_scope == DispositionScope.LIVE:
        if not authority.live_eligible:
            raise AuthorityDenied("authority is not live eligible")
        if provenance != EvidenceProvenance.REAL_EXTERNAL_MODELS:
            raise AuthorityDenied(
                "EffectiveVerdict<Live> requires real evidence provenance"
            )
    if (
        requested_scope == DispositionScope.COPY
        and provenance != EvidenceProvenance.FIXTURE_MODELS
    ):
        raise AuthorityDenied("Build A rehearsal requires fixture evidence provenance")
    return authority


def require_rehearsal_authority(
    authority: DispositionAuthorityV1,
    *,
    effects: Sequence[str],
) -> AuthorizedDispositionAuthorityV1:
    """Construction gate for ``RehearsalDisposition<Copy>``."""

    return require_authorized_effects(
        authority,
        scope=DispositionScope.COPY,
        effects=effects,
        evidence_provenance=EvidenceProvenance.FIXTURE_MODELS,
    )


def require_live_authority(
    authority: DispositionAuthorityV1,
    *,
    effects: Sequence[str],
) -> AuthorizedDispositionAuthorityV1:
    """Construction gate for ``EffectiveVerdict<Live>``."""

    return require_authorized_effects(
        authority,
        scope=DispositionScope.LIVE,
        effects=effects,
        evidence_provenance=EvidenceProvenance.REAL_EXTERNAL_MODELS,
    )


class SessionWriteLeaseV1(StrictCanonicalModel):
    schema_: Literal["sab.session_write_lease.v1"] = Field(
        "sab.session_write_lease.v1", alias="schema"
    )
    lease_id: str = Field(min_length=1, max_length=200)
    session_id: str = Field(min_length=1, max_length=200)
    clerk_identity: str = Field(min_length=1, max_length=200)
    allowed_operations: tuple[AllowedOperationV1, ...] = Field(min_length=1)
    allowed_operations_sha256: str = Field(pattern=SHA256_PATTERN)
    accepted_code_sha: str = Field(pattern=GIT_SHA_PATTERN)
    expected_lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    source_backup_sha256: str = Field(pattern=SHA256_PATTERN)
    issuer_identity: str = Field(min_length=1, max_length=200)
    issuer_public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    issuer_fingerprint: str = Field(pattern=SHA256_PATTERN)
    authority_basis: Literal["founder_bootstrap_self_declared"]
    scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    issued_at: datetime
    activated_at: datetime
    expires_at: datetime
    lease_sha256: str = Field(pattern=SHA256_PATTERN)
    signature: ContractSignatureV1
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False

    @field_validator("issued_at", "activated_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("allowed_operations", mode="before")
    @classmethod
    def sort_operations(cls, value: Sequence[Any]) -> tuple[Any, ...]:
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    str(item.get("method", ""))
                    if isinstance(item, Mapping)
                    else item.method,
                    str(item.get("path", ""))
                    if isinstance(item, Mapping)
                    else item.path,
                ),
            )
        )

    @model_validator(mode="after")
    def lease_bindings(self) -> "SessionWriteLeaseV1":
        if not (self.issued_at <= self.activated_at < self.expires_at):
            raise ValueError("lease timestamps are not ordered")
        if len(set((op.method, op.path) for op in self.allowed_operations)) != len(
            self.allowed_operations
        ):
            raise ValueError("allowed operations must be unique")
        if self.allowed_operations_sha256 != allowed_operations_digest(
            self.allowed_operations
        ):
            raise ValueError("allowed_operations_sha256 mismatch")
        expected_fingerprint = hashlib.sha256(
            bytes.fromhex(self.issuer_public_key)
        ).hexdigest()
        if self.issuer_fingerprint != expected_fingerprint:
            raise ValueError("issuer_fingerprint does not bind issuer_public_key")
        expected_lease = self.canonical_sha256(exclude={"lease_sha256", "signature"})
        if self.lease_sha256 != expected_lease:
            raise ValueError("lease_sha256 does not bind unsigned lease")
        return self


class ChallengeSnapshotV1(StrictCanonicalModel):
    challenge_id: str = Field(min_length=1, max_length=200)
    challenge_packet_sha256: str = Field(pattern=SHA256_PATTERN)
    status: Literal["pending", "resolved", "withdrawn"]


class DocketRuleV1(StrictCanonicalModel):
    version: str = Field(min_length=1, max_length=120)
    rule_sha256: str = Field(pattern=SHA256_PATTERN)
    signed_conditions_satisfied: bool
    challenge_resolution_authorized: bool
    jurisdiction_established: bool


class ConflictFlagsV1(StrictCanonicalModel):
    clerk_is_case_author: bool
    clerk_is_challenger: bool
    author_is_challenger: bool


class FrozenSeatV1(StrictCanonicalModel):
    seat_id: str = Field(min_length=1, max_length=120)
    requested_lab: str = Field(min_length=1, max_length=120)
    requested_model: str = Field(min_length=1, max_length=200)
    adapter: str = Field(min_length=1, max_length=120)
    transport: str = Field(min_length=1, max_length=120)
    requested_route: str = Field(min_length=1, max_length=240)
    served_provider: str = Field(min_length=1, max_length=120)
    served_model: str = Field(min_length=1, max_length=200)
    model_family: str = Field(min_length=1, max_length=160)
    credited_cluster: str = Field(min_length=1, max_length=160)
    cluster_basis: Literal["evidenced_base_model_or_training_lineage"] = (
        "evidenced_base_model_or_training_lineage"
    )
    model_lineage_evidence_refs: tuple[EvidenceRefV1, ...] = Field(min_length=1)
    possible_underlying_routes: tuple[str, ...] = Field(min_length=1)
    transport_correlation_refs: tuple[str, ...] = ()
    correlation_smeared: bool
    execution_public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    key_role: Literal["operator_controlled_execution_attestation"] = (
        "operator_controlled_execution_attestation"
    )
    common_operator_backing: str = Field(min_length=1, max_length=500)
    liveness_receipt_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator(
        "possible_underlying_routes", "transport_correlation_refs", mode="before"
    )
    @classmethod
    def exact_route_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name), allow_empty=True)

    @model_validator(mode="after")
    def correlation_is_only_smear_trigger(self) -> "FrozenSeatV1":
        if self.transport_correlation_refs and not self.correlation_smeared:
            raise ValueError("transport correlation must trigger smear disclosure")
        return self


class ArtifactCaseV1(StrictCanonicalModel):
    schema_: Literal["sab.artifact_case.v1"] = Field(
        "sab.artifact_case.v1", alias="schema"
    )
    case_id: str = Field(min_length=1, max_length=200)
    target_seed_id: str = Field(min_length=1, max_length=200)
    target_seed_packet_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_seed_state: str = Field(min_length=1, max_length=80)
    expected_case_head: str = Field(pattern=SHA256_PATTERN)
    challenges: tuple[ChallengeSnapshotV1, ...]
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(min_length=1)
    docket_rule: DocketRuleV1
    canon_conditions: tuple[str, ...] = Field(min_length=1)
    compost_conditions: tuple[str, ...] = Field(min_length=1)
    anti_capture_rules: tuple[str, ...] = Field(min_length=1)
    independence_disclosure: str = Field(min_length=1, max_length=4000)
    demanded_correction: str = Field(min_length=1, max_length=4000)
    amendment_clause: str = Field(min_length=1, max_length=4000)
    conflict_flags: ConflictFlagsV1
    signed_artifact_b64: str = Field(min_length=1)
    signed_artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    frozen_roster: tuple[FrozenSeatV1, ...] = Field(min_length=9, max_length=9)
    frozen_roster_sha256: str = Field(pattern=SHA256_PATTERN)
    single_operator_adjudicated: Literal[True] = True
    clerk_identity: str = Field(min_length=1, max_length=200)
    lease_id: str = Field(min_length=1, max_length=200)
    frozen_at: datetime
    clerk_signature: ContractSignatureV1

    @field_validator(
        "canon_conditions", "compost_conditions", "anti_capture_rules", mode="before"
    )
    @classmethod
    def exact_conditions(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name))

    @field_validator("frozen_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def exact_artifact_and_roster(self) -> "ArtifactCaseV1":
        try:
            artifact_bytes = base64.b64decode(self.signed_artifact_b64, validate=True)
        except Exception as exc:
            raise ValueError("signed_artifact_b64 is not canonical base64") from exc
        if base64.b64encode(artifact_bytes).decode("ascii") != self.signed_artifact_b64:
            raise ValueError("signed_artifact_b64 must use canonical padded base64")
        if bytes_sha256(artifact_bytes) != self.signed_artifact_sha256:
            raise ValueError("signed artifact hash mismatch")
        if len({seat.seat_id for seat in self.frozen_roster}) != 9:
            raise ValueError("frozen roster must contain nine unique seats")
        roster_payload = [seat.canonical_payload() for seat in self.frozen_roster]
        if canonical_sha256(roster_payload) != self.frozen_roster_sha256:
            raise ValueError("frozen roster hash mismatch")
        return self


class SelfBindingWeakeningFindingV1(StrictCanonicalModel):
    weakens_self_binding_constraint: bool
    affected_constraints: tuple[str, ...]
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(min_length=1)
    explanation: str = Field(min_length=1, max_length=4000)

    @field_validator("affected_constraints", mode="before")
    @classmethod
    def exact_constraints(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="affected_constraints", allow_empty=True)

    @model_validator(mode="after")
    def finding_is_explicit(self) -> "SelfBindingWeakeningFindingV1":
        if self.weakens_self_binding_constraint and not self.affected_constraints:
            raise ValueError("weakening finding must name affected constraints")
        return self


class ClaimFindingV1(StrictCanonicalModel):
    claim_ref: str = Field(min_length=1, max_length=300)
    finding: Literal["supported", "refuted", "uncertain", "out_of_scope"]
    rationale: str = Field(min_length=1, max_length=4000)
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(min_length=1)


class ArtifactBallotV1(StrictCanonicalModel):
    schema_: Literal["sab.artifact_ballot.v1"] = Field(
        "sab.artifact_ballot.v1", alias="schema"
    )
    ballot_id: str = Field(min_length=1, max_length=200)
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    seat_id: str = Field(min_length=1, max_length=120)
    round_no: Literal[1] = 1
    stage: Literal["sealed_first_pass", "cross_examination", "final"]
    decision: Literal[
        "canon",
        "compost",
        "correct_and_supersede",
        "no_terminal_verdict",
        "appeal",
        "abstain",
    ]
    ballot_source: BallotSource
    claim_findings: tuple[ClaimFindingV1, ...] = Field(min_length=1)
    self_binding_weakening_finding: SelfBindingWeakeningFindingV1
    strongest_case_against_decision: str = Field(min_length=1, max_length=6000)
    unresolved_objections: tuple[str, ...]
    raw_model_output_sha256: str = Field(pattern=SHA256_PATTERN)
    transcript_ref: EvidenceRefV1
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
    signature_role: Literal["operator_controlled_execution_attestation"] = (
        "operator_controlled_execution_attestation"
    )
    vendor_signature_claimed: Literal[False] = False
    execution_signature: ContractSignatureV1

    @field_validator(
        "unresolved_objections", "transport_correlation_refs", mode="before"
    )
    @classmethod
    def exact_optional_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name), allow_empty=True)

    @model_validator(mode="after")
    def ballot_provenance_and_smear(self) -> "ArtifactBallotV1":
        if self.transport_correlation_refs and not self.correlation_smeared:
            raise ValueError("transport correlation is a required smear trigger")
        return self


class CouncilVerdictV1(StrictCanonicalModel):
    schema_: Literal["sab.council_verdict.v1"] = Field(
        "sab.council_verdict.v1", alias="schema"
    )
    verdict_id: str = Field(min_length=1, max_length=200)
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    round_no: Literal[1] = 1
    decision: Literal[
        "canon",
        "compost",
        "correct_and_supersede",
        "no_terminal_verdict",
        "appeal_required",
    ]
    raw_tally: dict[str, int]
    clean_routing_tally: dict[str, int]
    credited_clusters_by_result: dict[str, tuple[str, ...]]
    smeared_seats: tuple[str, ...]
    correlation_removal_result: Literal[
        "stable", "winner_changed", "terminality_changed"
    ]
    terminality: Literal["terminal", "no_terminal_verdict", "appeal_required"]
    appeal_reasons: tuple[str, ...]
    ballot_sources: tuple[BallotSource, ...] = Field(min_length=1)
    evidence_provenance: EvidenceProvenance
    requested_effects: tuple[str, ...]
    authority_digest: str = Field(pattern=SHA256_PATTERN)
    scope: Literal[DispositionScope.COPY, DispositionScope.LIVE]
    operator_independence: Literal["single_operator_bootstrap"] = (
        "single_operator_bootstrap"
    )
    effect_domain: Literal["artifact"] = "artifact"
    standing_effect: Literal["none"] = "none"
    compiled_at: datetime

    @field_validator(
        "smeared_seats", "appeal_reasons", "requested_effects", mode="before"
    )
    @classmethod
    def exact_verdict_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name), allow_empty=True)

    @field_validator("compiled_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def provenance_matches_ballots(self) -> "CouncilVerdictV1":
        sources = set(self.ballot_sources)
        expected = (
            EvidenceProvenance.FIXTURE_MODELS
            if sources == {BallotSource.FIXTURE_MODEL}
            else EvidenceProvenance.REAL_EXTERNAL_MODELS
        )
        if self.evidence_provenance != expected:
            raise ValueError(
                "verdict evidence_provenance does not match ballot sources"
            )
        if self.round_no != 1:
            raise ValueError("Build A has exactly one round")
        if (
            self.correlation_removal_result != "stable"
            and self.terminality == "terminal"
        ):
            raise ValueError("correlation-sensitive result must appeal")
        if self.terminality != "terminal" and self.requested_effects:
            raise ValueError("nonterminal or appeal verdict cannot request effects")
        if self.decision == "appeal_required" and self.terminality != "appeal_required":
            raise ValueError("appeal ends this one-round slice without effect")
        if (
            self.decision == "no_terminal_verdict"
            and self.terminality != "no_terminal_verdict"
        ):
            raise ValueError("nonterminal decision cannot be rendered terminal")
        return self


class OperatorCountersignV1(StrictCanonicalModel):
    schema_: Literal["sab.operator_countersign.v1"] = Field(
        "sab.operator_countersign.v1", alias="schema"
    )
    countersign_id: str = Field(min_length=1, max_length=200)
    verdict_id: str = Field(min_length=1, max_length=200)
    verdict_sha256: str = Field(pattern=SHA256_PATTERN)
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    target_seed_id: str = Field(min_length=1, max_length=200)
    decision: str = Field(min_length=1, max_length=80)
    expected_seed_state: str = Field(min_length=1, max_length=80)
    expected_case_head: str = Field(pattern=SHA256_PATTERN)
    expected_lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    effect_payload: dict[str, Any]
    effect_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    successor_envelope_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    write_lease_id: str = Field(min_length=1, max_length=200)
    lease_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_digest: str = Field(pattern=SHA256_PATTERN)
    allowed_operations: tuple[AllowedOperationV1, ...] = Field(min_length=1)
    allowed_operations_sha256: str = Field(pattern=SHA256_PATTERN)
    code_sha: str = Field(pattern=GIT_SHA_PATTERN)
    scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    signer_kind: Literal["fixture_ephemeral"] = "fixture_ephemeral"
    created_at: datetime
    expires_at: datetime
    signature: ContractSignatureV1
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False

    @field_validator("created_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def exact_bindings(self) -> "OperatorCountersignV1":
        if self.expires_at <= self.created_at:
            raise ValueError("countersign must expire after creation")
        if self.effect_payload_sha256 != canonical_sha256(self.effect_payload):
            raise ValueError("effect_payload_sha256 mismatch")
        if self.allowed_operations_sha256 != allowed_operations_digest(
            self.allowed_operations
        ):
            raise ValueError("allowed_operations_sha256 mismatch")
        return self


class RehearsalDispositionV1(StrictCanonicalModel):
    schema_: Literal["sab.rehearsal_disposition.v1"] = Field(
        "sab.rehearsal_disposition.v1", alias="schema"
    )
    disposition_id: str = Field(min_length=1, max_length=200)
    verdict_id: str = Field(min_length=1, max_length=200)
    verdict_sha256: str = Field(pattern=SHA256_PATTERN)
    case_id: str = Field(min_length=1, max_length=200)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    authority: AuthorizedDispositionAuthorityV1
    countersign_id: str = Field(min_length=1, max_length=200)
    countersign_sha256: str = Field(pattern=SHA256_PATTERN)
    effects: tuple[str, ...] = Field(min_length=1)
    ballot_source: Literal[BallotSource.FIXTURE_MODEL] = BallotSource.FIXTURE_MODEL
    evidence_provenance: Literal[EvidenceProvenance.FIXTURE_MODELS] = (
        EvidenceProvenance.FIXTURE_MODELS
    )
    scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    proof_class: Literal["copied_live_db_rehearsal"] = "copied_live_db_rehearsal"
    source_fixture_id: str = Field(min_length=1, max_length=240)
    copied_database_id: str = Field(min_length=1, max_length=240)
    before_state_hash: str = Field(pattern=SHA256_PATTERN)
    after_state_hash: str = Field(pattern=SHA256_PATTERN)
    applied_at: datetime
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False

    @field_validator("effects", mode="before")
    @classmethod
    def exact_effects(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="effects")

    @field_validator("applied_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def authorized_copy_constructor(self) -> "RehearsalDispositionV1":
        require_authorized_effects(
            self.authority,
            scope=DispositionScope.COPY,
            effects=self.effects,
            evidence_provenance=EvidenceProvenance.FIXTURE_MODELS,
        )
        return self


class EffectiveVerdictV1(StrictCanonicalModel):
    schema_: Literal["sab.effective_verdict.v1"] = Field(
        "sab.effective_verdict.v1", alias="schema"
    )
    effective_verdict_id: str = Field(min_length=1, max_length=200)
    verdict_id: str = Field(min_length=1, max_length=200)
    verdict_sha256: str = Field(pattern=SHA256_PATTERN)
    authority: AuthorizedDispositionAuthorityV1
    effects: tuple[str, ...] = Field(min_length=1)
    evidence_provenance: Literal[EvidenceProvenance.REAL_EXTERNAL_MODELS] = (
        EvidenceProvenance.REAL_EXTERNAL_MODELS
    )
    scope: Literal[DispositionScope.LIVE] = DispositionScope.LIVE
    fixture_derived: Literal[False] = False
    applied_at: datetime
    standing_effect: Literal["none"] = "none"

    @field_validator("effects", mode="before")
    @classmethod
    def exact_effects(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="effects")

    @field_validator("applied_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def authorized_live_constructor(self) -> "EffectiveVerdictV1":
        require_authorized_effects(
            self.authority,
            scope=DispositionScope.LIVE,
            effects=self.effects,
            evidence_provenance=EvidenceProvenance.REAL_EXTERNAL_MODELS,
        )
        return self


class SeedSupersessionV1(StrictCanonicalModel):
    schema_: Literal["sab.seed_supersession.v1"] = Field(
        "sab.seed_supersession.v1", alias="schema"
    )
    predecessor_seed_id: str = Field(min_length=1, max_length=200)
    predecessor_packet_sha256: str = Field(pattern=SHA256_PATTERN)
    successor_seed_id: str = Field(min_length=1, max_length=200)
    successor_packet_sha256: str = Field(pattern=SHA256_PATTERN)
    correction_summary: str = Field(min_length=1, max_length=6000)
    correction_artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    relation: Literal["superseded_by_correction"] = "superseded_by_correction"
    claimant_identity: str = Field(min_length=1, max_length=200)
    authority_lease_id: str = Field(min_length=1, max_length=200)
    scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    created_at: datetime
    claimant_signature: ContractSignatureV1
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def distinct_lineage_nodes(self) -> "SeedSupersessionV1":
        if self.predecessor_seed_id == self.successor_seed_id:
            raise ValueError("a seed cannot supersede itself")
        return self


class PreviewRecordV1(StrictCanonicalModel):
    record_id: str = Field(min_length=1, max_length=240)
    actor_slot: Literal["Hermes", "Dharma-cron", "other"]
    eligible: bool
    evidence_refs: tuple[EvidenceRefV1, ...] = Field(min_length=1)
    exclusion_reason: str | None = Field(default=None, min_length=1, max_length=1000)
    row_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def exact_exclusion(self) -> "PreviewRecordV1":
        if self.eligible and self.exclusion_reason is not None:
            raise ValueError("eligible preview record cannot have an exclusion reason")
        if not self.eligible and self.exclusion_reason is None:
            raise ValueError("excluded preview record must have an exact reason")
        return self


class CompostBatchPreviewV1(StrictCanonicalModel):
    schema_: Literal["sab.compost_batch_preview.v1"] = Field(
        "sab.compost_batch_preview.v1", alias="schema"
    )
    preview_id: str = Field(min_length=1, max_length=240)
    scanned_count: Literal[67] = 67
    hermes_count: Literal[59] = 59
    dharma_cron_count: Literal[2] = 2
    selected_count: Literal[61] = 61
    excluded_count: Literal[6] = 6
    actor_slot_parameterized: Literal[True] = True
    records: tuple[PreviewRecordV1, ...] = Field(min_length=67, max_length=67)
    before_database_sha256: str = Field(pattern=SHA256_PATTERN)
    after_database_sha256: str = Field(pattern=SHA256_PATTERN)
    before_lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    after_lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)
    before_head_sha256: str = Field(pattern=SHA256_PATTERN)
    after_head_sha256: str = Field(pattern=SHA256_PATTERN)
    before_file_mtime_ns: int = Field(ge=0)
    after_file_mtime_ns: int = Field(ge=0)
    execution_supported: Literal[False] = False
    mutation_count: Literal[0] = 0

    @model_validator(mode="after")
    def exact_counts_and_no_write(self) -> "CompostBatchPreviewV1":
        hermes = sum(
            record.eligible and record.actor_slot == "Hermes" for record in self.records
        )
        cron = sum(
            record.eligible and record.actor_slot == "Dharma-cron"
            for record in self.records
        )
        excluded = sum(not record.eligible for record in self.records)
        if (hermes, cron, excluded) != (59, 2, 6):
            raise ValueError(
                "preview must prove 59 Hermes + 2 Dharma-cron with 6 exclusions"
            )
        if any(
            record.eligible and record.actor_slot == "other" for record in self.records
        ):
            raise ValueError("eligible records must occupy an explicit actor slot")
        if self.before_database_sha256 != self.after_database_sha256:
            raise ValueError("preview changed database bytes")
        if self.before_lifecycle_fingerprint != self.after_lifecycle_fingerprint:
            raise ValueError("preview changed lifecycle fingerprint")
        if self.before_head_sha256 != self.after_head_sha256:
            raise ValueError("preview changed witness head")
        if self.before_file_mtime_ns != self.after_file_mtime_ns:
            raise ValueError("preview changed database file mtime")
        return self


class ReceiptAcceptedBaseV1(StrictCanonicalModel):
    integration_sha: str = Field(pattern=GIT_SHA_PATTERN)
    integration_tree: str = Field(pattern=GIT_SHA_PATTERN)
    current_head: str = Field(pattern=GIT_SHA_PATTERN)
    current_tree: str = Field(pattern=GIT_SHA_PATTERN)


class ReceiptAuthorityV1(StrictCanonicalModel):
    """Receipt rendering of the evaluator's ``Authorized<Copy>`` value."""

    result: Literal["AuthorizedCopyOnly"] = "AuthorizedCopyOnly"
    scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    authority_digest: str = Field(pattern=SHA256_PATTERN)
    allowed_effects: tuple[str, ...] = Field(min_length=1)
    evaluated_state_hash: str = Field(pattern=SHA256_PATTERN)
    refs: tuple[str, ...] = Field(min_length=1)

    @field_validator("allowed_effects", "refs", mode="before")
    @classmethod
    def exact_sets(cls, value: Sequence[str], info: Any) -> tuple[str, ...]:
        return _exact_strings(value, field=str(info.field_name))


class ReceiptDatabaseRefV1(StrictCanonicalModel):
    path_ref: str = Field(pattern=r"^private-local:sha256:[0-9a-f]{64}$")
    sha256: str = Field(pattern=SHA256_PATTERN)
    integrity: Literal["ok"] = "ok"
    lifecycle_fingerprint: str = Field(pattern=SHA256_PATTERN)


class ReceiptNamedArtifactV1(StrictCanonicalModel):
    id: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=SHA256_PATTERN)


class ReceiptArtifactsV1(StrictCanonicalModel):
    case: ReceiptNamedArtifactV1
    lease: ReceiptNamedArtifactV1
    verdict: ReceiptNamedArtifactV1
    countersign: ReceiptNamedArtifactV1
    disposition: ReceiptNamedArtifactV1
    lineage: ReceiptNamedArtifactV1


class InjectedFailureReceiptV1(StrictCanonicalModel):
    boundary: str = Field(min_length=1, max_length=160)
    injected: Literal[True] = True
    rolled_back: Literal[True] = True
    state_sha256: str = Field(pattern=SHA256_PATTERN)


class ReceiptTransactionV1(StrictCanonicalModel):
    idempotency_key: str = Field(min_length=1, max_length=240)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)
    boundaries: tuple[str, ...] = Field(min_length=1)
    injected_failure_matrix: tuple[InjectedFailureReceiptV1, ...] = Field(min_length=1)

    @field_validator("boundaries", mode="before")
    @classmethod
    def exact_boundaries(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="boundaries")

    @model_validator(mode="after")
    def failure_for_each_boundary(self) -> "ReceiptTransactionV1":
        failures = {item.boundary for item in self.injected_failure_matrix}
        if failures != set(self.boundaries):
            raise ValueError(
                "failure matrix must cover every mutation boundary exactly"
            )
        if len(failures) != len(self.injected_failure_matrix):
            raise ValueError("failure matrix contains duplicate boundaries")
        return self


class InvariantTableDigestV1(StrictCanonicalModel):
    table: str = Field(min_length=1, max_length=160)
    columns: tuple[str, ...] = Field(min_length=1)
    before_sha256: str = Field(pattern=SHA256_PATTERN)
    after_sha256: str = Field(pattern=SHA256_PATTERN)
    unchanged: Literal[True] = True

    @field_validator("columns", mode="before")
    @classmethod
    def exact_columns(cls, value: Sequence[str]) -> tuple[str, ...]:
        return _exact_strings(value, field="columns")

    @model_validator(mode="after")
    def digest_really_unchanged(self) -> "InvariantTableDigestV1":
        if self.before_sha256 != self.after_sha256:
            raise ValueError("unchanged table digest differs")
        return self


class SignedEventReplayV1(StrictCanonicalModel):
    event_id: str = Field(min_length=1, max_length=240)
    event_hash: str = Field(pattern=SHA256_PATTERN)
    public_key: str = Field(pattern=HEX_PUBLIC_KEY_PATTERN)
    signature_verified: Literal[True] = True
    replay_result: Literal["SignaturesVerified"] = "SignaturesVerified"


class ReceiptPreviewSummaryV1(StrictCanonicalModel):
    scanned: Literal[67] = 67
    eligible: Literal[61] = 61
    hermes: Literal[59] = 59
    dharma_cron: Literal[2] = 2
    membership_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_refs_sha256: str = Field(pattern=SHA256_PATTERN)
    no_write: Literal[True] = True


class ReceiptCheckpointChainV1(StrictCanonicalModel):
    head: str = Field(pattern=SHA256_PATTERN)
    count: int = Field(ge=1)
    valid: Literal[True] = True


class ReceiptMutationCountersV1(StrictCanonicalModel):
    live_db: Literal[0] = 0
    services: Literal[0] = 0
    providers: Literal[0] = 0
    external: Literal[0] = 0
    source_checkout: Literal[0] = 0
    fixture_or_copy_db: int = Field(ge=1)


class ReceiptTestResultV1(StrictCanonicalModel):
    command: str = Field(min_length=1, max_length=4000)
    exit_code: Literal[0] = 0
    stdout_sha256: str = Field(pattern=SHA256_PATTERN)
    proof_class: str | None = Field(default=None, min_length=1, max_length=160)


class ReceiptTerminalClaimV1(StrictCanonicalModel):
    engineering_status: Literal["proven_on_copy"] = "proven_on_copy"
    historic_live_win: Literal[False] = False
    live_mutations: Literal[0] = 0
    service_mutations: Literal[0] = 0
    provider_calls: Literal[0] = 0
    external_actions: Literal[0] = 0
    standing_effect: Literal["none"] = "none"
    master_vision_effect: Literal["none"] = "none"
    build_b: Literal["not_run_authority_unresolved"] = "not_run_authority_unresolved"


class FirstVerdictRunReceiptV1(StrictCanonicalModel):
    """Strict lifecycle receipt consumed and independently re-derived by C0."""

    schema_version: Literal["sab.first_verdict_run_receipt.v1"]
    run_id: str = Field(min_length=1, max_length=200)
    created_at: datetime
    proof_class: Literal[
        "copied_live_db_rehearsal", "fresh_context_same_operator_rederivation"
    ]
    accepted_base: ReceiptAcceptedBaseV1
    authority: ReceiptAuthorityV1
    source_db: ReceiptDatabaseRefV1
    copy_db: ReceiptDatabaseRefV1
    artifacts: ReceiptArtifactsV1
    transaction: ReceiptTransactionV1
    invariant_table_digests: tuple[InvariantTableDigestV1, ...] = Field(min_length=1)
    signed_events: tuple[SignedEventReplayV1, ...] = Field(min_length=1)
    preview: ReceiptPreviewSummaryV1
    checkpoint_chain: ReceiptCheckpointChainV1
    mutation_counters: ReceiptMutationCountersV1
    tests: tuple[ReceiptTestResultV1, ...] = Field(min_length=1)
    blockers: tuple[Any, ...] = Field(max_length=0)
    terminal_claim: ReceiptTerminalClaimV1

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def source_and_copy_are_distinct(self) -> "FirstVerdictRunReceiptV1":
        if self.source_db.path_ref == self.copy_db.path_ref:
            raise ValueError("source and copied database references must differ")
        return self


SCHEMA_EXPORTS: ClassVar[dict[str, Any]] = {
    "sab.disposition_authority.v1.schema.json": DISPOSITION_AUTHORITY_ADAPTER,
    "sab.session_write_lease.v1.schema.json": SessionWriteLeaseV1,
    "sab.artifact_case.v1.schema.json": ArtifactCaseV1,
    "sab.artifact_ballot.v1.schema.json": ArtifactBallotV1,
    "sab.council_verdict.v1.schema.json": CouncilVerdictV1,
    "sab.effective_verdict.v1.schema.json": EffectiveVerdictV1,
    "sab.operator_countersign.v1.schema.json": OperatorCountersignV1,
    "sab.rehearsal_disposition.v1.schema.json": RehearsalDispositionV1,
    "sab.seed_supersession.v1.schema.json": SeedSupersessionV1,
    "sab.compost_batch_preview.v1.schema.json": CompostBatchPreviewV1,
    "sab.first_verdict_run_receipt.v1.schema.json": FirstVerdictRunReceiptV1,
}


def exported_json_schemas() -> dict[str, dict[str, Any]]:
    """Return deterministic standalone Draft 2020-12 schemas."""

    result: dict[str, dict[str, Any]] = {}
    for filename, model_or_adapter in SCHEMA_EXPORTS.items():
        schema = (
            model_or_adapter.json_schema()
            if isinstance(model_or_adapter, TypeAdapter)
            else model_or_adapter.model_json_schema()
        )
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"https://sab.local/schemas/{filename}"
        result[filename] = schema
    return result


def write_exported_json_schemas(destination: str | Path) -> tuple[Path, ...]:
    """Mechanically write the checked-in schemas; no network or repository discovery."""

    root = Path(destination)
    written: list[Path] = []
    for filename, schema in exported_json_schemas().items():
        path = root / filename
        path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        written.append(path)
    return tuple(written)


# Compatibility aliases for integration code that uses the conceptual names.
DispositionAuthority = DispositionAuthorityV1
Authorized = AuthorizedDispositionAuthorityV1
AdvisoryOnly = AdvisoryOnlyDispositionAuthorityV1
NoJurisdiction = NoJurisdictionDispositionAuthorityV1
ArtifactCase = ArtifactCaseV1
ArtifactBallot = ArtifactBallotV1
CouncilVerdict = CouncilVerdictV1
OperatorCountersign = OperatorCountersignV1
RehearsalDisposition = RehearsalDispositionV1
EffectiveVerdict = EffectiveVerdictV1


__all__ = [
    "AdvisoryOnly",
    "AdvisoryOnlyDispositionAuthorityV1",
    "AllowedOperationV1",
    "ArtifactBallot",
    "ArtifactBallotV1",
    "ArtifactCase",
    "ArtifactCaseV1",
    "AuthorityDenied",
    "Authorized",
    "AuthorizedDispositionAuthorityV1",
    "BallotSource",
    "CompostBatchPreviewV1",
    "ContractSignatureV1",
    "CouncilVerdict",
    "CouncilVerdictV1",
    "DISPOSITION_AUTHORITY_ADAPTER",
    "DispositionAuthority",
    "DispositionAuthorityV1",
    "DispositionScope",
    "EffectiveVerdict",
    "EffectiveVerdictV1",
    "EvidenceProvenance",
    "EvidenceRefV1",
    "FROZEN_MAINTENANCE_OPERATIONS",
    "FirstVerdictRunReceiptV1",
    "MASTER_VISION_FORBIDDEN_EFFECTS",
    "MASTER_VISION_SEED_ID",
    "NoJurisdiction",
    "NoJurisdictionDispositionAuthorityV1",
    "OperatorCountersign",
    "OperatorCountersignV1",
    "RehearsalDisposition",
    "RehearsalDispositionV1",
    "SCHEMA_EXPORTS",
    "SeedSupersessionV1",
    "SessionWriteLeaseV1",
    "SignedDispositionPolicyV1",
    "allowed_operations_digest",
    "canonical_json",
    "canonical_json_bytes",
    "canonical_json_sha256",
    "canonical_sha256",
    "evaluate_disposition_authority",
    "exported_json_schemas",
    "require_authorized_effects",
    "require_live_authority",
    "require_rehearsal_authority",
    "validate_exact_allowed_operations",
    "verify_contract_signature",
    "write_exported_json_schemas",
]
