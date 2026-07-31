from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal, Optional

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .sab_attestations import ExternalAttestationV1, parse_datetime


AGENT_IDENTITY_SCHEMA = "sab.agent_identity.v1"
AUTHORITY_LEASE_SCHEMA = "sab.authority_lease.v1"
SIGNATURE_CANONICALIZATION = "json-sort-keys-compact-v1"
HIGH_IMPACT_LEVELS = {
    "high",
    "critical",
    "standing",
    "canon",
    "deployment",
    "payment",
    "authority",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def canonical_json_sha256(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def subject_id_from_public_key(public_key_hex: str) -> str:
    _validate_public_key_hex(public_key_hex)
    digest = hashlib.sha256(public_key_hex.encode()).hexdigest()
    return f"agent_ed25519_{digest[:32]}"


def _validate_public_key_hex(value: str) -> str:
    try:
        VerifyKey(value.encode(), encoder=HexEncoder)
    except Exception as exc:
        raise ValueError("invalid Ed25519 public key (hex)") from exc
    return value


def _non_empty_string(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} cannot be empty")
    return normalized


class SignatureEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alg: Literal["ed25519"] = "ed25519"
    signer: str = Field(..., min_length=8, max_length=160)
    signature: str = Field(..., min_length=128, max_length=128, pattern=r"^[0-9a-fA-F]{128}$")
    canonicalization: Literal["json-sort-keys-compact-v1"] = SIGNATURE_CANONICALIZATION

    @field_validator("signature")
    @classmethod
    def normalize_signature(cls, value: str) -> str:
        return value.lower()


class OperatorBacking(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator_id: str = Field("unknown", min_length=1, max_length=160)
    operator_kind: Literal["human", "organization", "agent", "unknown"] = "unknown"
    disclosure: str = Field("", max_length=1000)
    backing_count_attestation: Literal["unchecked", "self_attested", "verified"] = "unchecked"

    @field_validator("operator_id")
    @classmethod
    def normalize_operator_id(cls, value: str) -> str:
        normalized = value.strip()
        return normalized or "unknown"


class AgentIdentityV1(BaseModel):
    """Runtime model for `sab.agent_identity.v1`.

    This proves public-key control and operator disclosure. It does not prove
    truth, witness independence, permission, standing, or canon.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: Literal["sab.agent_identity.v1"] = Field(AGENT_IDENTITY_SCHEMA, alias="schema")
    subject_id: str = Field(..., min_length=8, max_length=160)
    display_name: str = Field(..., min_length=1, max_length=120)
    identity_rail: Literal["ed25519"] = "ed25519"
    public_key: str = Field(..., min_length=64, max_length=128)
    controller: Literal["self", "operator", "org", "unknown"] = "unknown"
    operator_backing: OperatorBacking = Field(default_factory=OperatorBacking)
    external_attestations: list[ExternalAttestationV1] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    revocation_status: Literal["active", "revoked", "superseded"] = "active"
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("public_key")
    @classmethod
    def valid_public_key(cls, value: str) -> str:
        return _validate_public_key_hex(value)

    @field_validator("display_name", "subject_id")
    @classmethod
    def required_text(cls, value: str, info: Any) -> str:
        return _non_empty_string(value, str(info.field_name))

    @field_validator("evidence_refs")
    @classmethod
    def evidence_refs_not_blank(cls, value: list[str]) -> list[str]:
        if any(not str(item).strip() for item in value):
            raise ValueError("evidence_refs cannot contain blank refs")
        return value

    @model_validator(mode="after")
    def subject_matches_key_when_canonical(self) -> "AgentIdentityV1":
        canonical = subject_id_from_public_key(self.public_key)
        if self.subject_id.startswith("agent_ed25519_") and self.subject_id != canonical:
            raise ValueError("subject_id does not match Ed25519 public key")
        return self

    @classmethod
    def from_public_key(
        cls,
        *,
        display_name: str,
        public_key: str,
        controller: Literal["self", "operator", "org", "unknown"] = "unknown",
        operator_backing: Optional[OperatorBacking] = None,
        created_at: Optional[datetime] = None,
        evidence_refs: Optional[list[str]] = None,
    ) -> "AgentIdentityV1":
        return cls(
            subject_id=subject_id_from_public_key(public_key),
            display_name=display_name,
            public_key=public_key,
            controller=controller,
            operator_backing=operator_backing or OperatorBacking(),
            created_at=created_at or utc_now(),
            evidence_refs=evidence_refs or [],
        )


def canonical_payload_for_signature(
    payload: Dict[str, Any],
    *,
    signature_field: str = "signature",
) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != signature_field}
    return canonical_json_bytes(unsigned)


def verify_ed25519_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        verify_key = VerifyKey(public_key_hex.encode(), encoder=HexEncoder)
        verify_key.verify(message, bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError):
        return False


def verify_signed_payload(
    payload: Dict[str, Any],
    *,
    public_key_hex: str,
    signature: Optional[SignatureEnvelope | Dict[str, Any] | str] = None,
    expected_signer: Optional[str] = None,
    signature_field: str = "signature",
) -> bool:
    if signature is None:
        raw_signature = payload.get(signature_field)
    else:
        raw_signature = signature

    if isinstance(raw_signature, str):
        if expected_signer is None:
            return False
        envelope = SignatureEnvelope(signer=expected_signer, signature=raw_signature)
    else:
        envelope = SignatureEnvelope.model_validate(raw_signature)

    if expected_signer is not None and envelope.signer != expected_signer:
        return False

    return verify_ed25519_signature(
        public_key_hex,
        canonical_payload_for_signature(payload, signature_field=signature_field),
        envelope.signature,
    )


def signing_payload_for(
    *,
    kind: str,
    payload: Dict[str, Any],
    actor_id: str,
    created_at: datetime | str,
    authority_lease_id: Optional[str] = None,
    witness_head: Optional[str] = None,
    extra_bindings: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    message: Dict[str, Any] = {
        "kind": kind,
        "payload_sha256": canonical_json_sha256(payload),
        "actor_id": actor_id,
        "created_at": parse_datetime(created_at).isoformat(),
    }
    if authority_lease_id:
        message["authority_lease_id"] = authority_lease_id
    if witness_head:
        message["witness_head"] = witness_head
    if extra_bindings:
        message.update(extra_bindings)
    return message


class AuthorityLeaseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: Literal["sab.authority_lease.v1"] = Field(AUTHORITY_LEASE_SCHEMA, alias="schema")
    lease_id: str = Field(..., min_length=8, max_length=160)
    subject_id: str = Field(..., min_length=8, max_length=160)
    purpose: Literal["submit_seed", "challenge", "witness", "request_standing"]
    scope: str = Field(..., min_length=1, max_length=1000)
    allowed_actions: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    allowed_reliance: list[str] = Field(default_factory=list)
    forbidden_reliance: list[str] = Field(default_factory=list)
    expires_at: datetime
    revoker: str = Field(..., min_length=1, max_length=200)
    challenge_path: str = Field(..., min_length=1, max_length=1000)
    issued_by: str = Field(..., min_length=1, max_length=160)
    issued_at: datetime = Field(default_factory=utc_now)
    policy_hash: str = Field(..., min_length=6, max_length=128)
    witness_event_id: str = Field(..., min_length=8, max_length=160)

    @field_validator("scope", "revoker", "challenge_path", "issued_by", "policy_hash", "witness_event_id")
    @classmethod
    def required_text(cls, value: str, info: Any) -> str:
        return _non_empty_string(value, str(info.field_name))

    @field_validator("allowed_actions", "forbidden_actions", "allowed_reliance", "forbidden_reliance")
    @classmethod
    def normalize_list(cls, value: list[str]) -> list[str]:
        normalized = []
        for item in value:
            text = str(item).strip()
            if not text:
                raise ValueError("authority lease lists cannot contain blank items")
            normalized.append(text)
        return normalized

    @model_validator(mode="after")
    def no_conflicting_action_or_reliance(self) -> "AuthorityLeaseV1":
        action_overlap = set(self.allowed_actions).intersection(self.forbidden_actions)
        if action_overlap:
            raise ValueError("actions cannot be both allowed and forbidden: " + ", ".join(sorted(action_overlap)))
        reliance_overlap = set(self.allowed_reliance).intersection(self.forbidden_reliance)
        if reliance_overlap:
            raise ValueError("reliance cannot be both allowed and forbidden: " + ", ".join(sorted(reliance_overlap)))
        return self


class LeaseValidationResult(BaseModel):
    ok: bool
    errors: list[str] = Field(default_factory=list)


def challenge_path_is_valid(challenge_path: str) -> bool:
    normalized = challenge_path.strip().lower()
    if normalized in {"", "none", "null", "n/a"}:
        return False
    return normalized.startswith(("/", "http://", "https://", "docs/"))


def scope_allows(lease_scope: str, requested_scope: str) -> bool:
    lease_scope = lease_scope.strip()
    requested_scope = requested_scope.strip()
    if lease_scope == "*":
        return True
    if requested_scope == lease_scope:
        return True
    return any(requested_scope.startswith(f"{lease_scope}{separator}") for separator in (":", "/", "."))


def validate_authority_lease(
    lease: AuthorityLeaseV1 | Dict[str, Any],
    *,
    action: str,
    requested_scope: str,
    now: Optional[datetime] = None,
    subject_id: Optional[str] = None,
) -> LeaseValidationResult:
    errors: list[str] = []
    try:
        parsed = lease if isinstance(lease, AuthorityLeaseV1) else AuthorityLeaseV1.model_validate(lease)
    except Exception as exc:
        return LeaseValidationResult(ok=False, errors=[f"invalid_authority_lease: {exc}"])

    checked_at = now or utc_now()
    if parsed.expires_at <= checked_at:
        errors.append("authority_lease_expired")
    if subject_id is not None and parsed.subject_id != subject_id:
        errors.append("authority_lease_subject_mismatch")
    if not parsed.scope.strip():
        errors.append("authority_lease_missing_scope")
    elif not scope_allows(parsed.scope, requested_scope):
        errors.append("authority_lease_scope_denied")
    if not parsed.revoker.strip():
        errors.append("authority_lease_missing_revoker")
    if not challenge_path_is_valid(parsed.challenge_path):
        errors.append("authority_lease_missing_challenge_path")
    if action in parsed.forbidden_actions:
        errors.append("authority_lease_action_forbidden")
    if action not in parsed.allowed_actions:
        errors.append("authority_lease_action_not_allowed")

    return LeaseValidationResult(ok=not errors, errors=errors)


class ReplayRecord(BaseModel):
    signature_digest: str
    payload_digest: str
    first_seen_at: datetime
    created_at: datetime
    witness_head: Optional[str] = None


class ReplayDecision(BaseModel):
    accepted: bool
    reason: str
    signature_digest: str
    payload_digest: str
    previous_payload_digest: Optional[str] = None


class InMemoryReplayStore:
    def __init__(self) -> None:
        self._records: Dict[str, ReplayRecord] = {}

    def get(self, signature_digest: str) -> Optional[ReplayRecord]:
        return self._records.get(signature_digest)

    def put(self, record: ReplayRecord) -> None:
        self._records[record.signature_digest] = record


class ReplayProtectionPolicy(BaseModel):
    max_age_seconds: int = 10 * 60
    max_future_skew_seconds: int = 60
    require_witness_head_match: bool = False


class ReplayProtector:
    def __init__(
        self,
        store: Optional[InMemoryReplayStore] = None,
        policy: Optional[ReplayProtectionPolicy] = None,
    ) -> None:
        self.store = store or InMemoryReplayStore()
        self.policy = policy or ReplayProtectionPolicy()

    def check_and_record(
        self,
        *,
        signature_hex: str,
        payload: Dict[str, Any],
        created_at: datetime | str,
        now: Optional[datetime] = None,
        witness_head: Optional[str] = None,
        expected_witness_head: Optional[str] = None,
    ) -> ReplayDecision:
        checked_at = now or utc_now()
        signed_at = parse_datetime(created_at)
        normalized_signature = signature_hex.strip().lower()
        signature_digest = hashlib.sha256(normalized_signature.encode()).hexdigest()
        payload_digest = canonical_json_sha256(payload)

        try:
            bytes.fromhex(normalized_signature)
        except ValueError:
            return ReplayDecision(
                accepted=False,
                reason="invalid_signature_hex",
                signature_digest=signature_digest,
                payload_digest=payload_digest,
            )

        age = (checked_at - signed_at).total_seconds()
        if age > self.policy.max_age_seconds:
            return ReplayDecision(
                accepted=False,
                reason="stale_signed_payload",
                signature_digest=signature_digest,
                payload_digest=payload_digest,
            )
        if age < -self.policy.max_future_skew_seconds:
            return ReplayDecision(
                accepted=False,
                reason="future_signed_payload",
                signature_digest=signature_digest,
                payload_digest=payload_digest,
            )
        if self.policy.require_witness_head_match and expected_witness_head != witness_head:
            return ReplayDecision(
                accepted=False,
                reason="witness_head_mismatch",
                signature_digest=signature_digest,
                payload_digest=payload_digest,
            )

        existing = self.store.get(signature_digest)
        if existing is not None:
            if existing.payload_digest != payload_digest:
                return ReplayDecision(
                    accepted=False,
                    reason="signature_reused_for_different_payload",
                    signature_digest=signature_digest,
                    payload_digest=payload_digest,
                    previous_payload_digest=existing.payload_digest,
                )
            return ReplayDecision(
                accepted=False,
                reason="duplicate_signature_replay",
                signature_digest=signature_digest,
                payload_digest=payload_digest,
                previous_payload_digest=existing.payload_digest,
            )

        self.store.put(
            ReplayRecord(
                signature_digest=signature_digest,
                payload_digest=payload_digest,
                first_seen_at=checked_at,
                created_at=signed_at,
                witness_head=witness_head,
            )
        )
        return ReplayDecision(
            accepted=True,
            reason="accepted",
            signature_digest=signature_digest,
            payload_digest=payload_digest,
        )


class OperatorConcentrationPolicy(BaseModel):
    forbid_self_witness_for_high_impact: bool = True
    forbid_same_operator_for_high_impact: bool = True
    max_high_impact_witnesses_per_operator: int = 1


class WitnessPolicyDecision(BaseModel):
    ok: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def identity_operator_id(identity: AgentIdentityV1) -> str:
    return identity.operator_backing.operator_id.strip() or "unknown"


def same_operator(first: AgentIdentityV1, second: AgentIdentityV1) -> bool:
    first_operator = identity_operator_id(first)
    second_operator = identity_operator_id(second)
    if "unknown" in {first_operator, second_operator}:
        # R2 conservative collapse (SAB_STANDING_SEMANTICS_V0 §1.3): undisclosed
        # operators are treated as same-operator; independence fails closed.
        return True
    return first_operator == second_operator


INDEPENDENCE_GRADE_TIERS = {
    "self": 0,
    "same_operator": 1,
    "undisclosed": 1,
    "same_operator_distinct_keys": 2,
    "cross_operator_unverified": 3,
    "cross_operator_attested": 4,
}

STANDING_TIER_REQUIREMENTS = {
    "provisional": {"min_witnesses": 1, "min_grade": "self", "min_distinct_operators": 1},
    "active": {"min_witnesses": 2, "min_grade": "cross_operator_unverified", "min_distinct_operators": 2},
    "canon": {"min_witnesses": 3, "min_grade": "cross_operator_attested", "min_distinct_operators": 3},
}

MIN_INDEPENDENT_OPERATORS_FOR_STANDING = 3


def independence_grade(witness: AgentIdentityV1, claimant: AgentIdentityV1) -> str:
    if witness.subject_id == claimant.subject_id or witness.public_key == claimant.public_key:
        return "self"
    witness_operator = identity_operator_id(witness)
    claimant_operator = identity_operator_id(claimant)
    if "unknown" in {witness_operator, claimant_operator}:
        return "undisclosed"
    if witness_operator == claimant_operator:
        return "same_operator_distinct_keys"
    # cross_operator_attested requires verified external anchors (backlog);
    # self-declared distinct operators cap at cross_operator_unverified.
    return "cross_operator_unverified"


def quorum_tier(
    *,
    witnesses: list[tuple[str, str]],
    system_operator_count: int,
) -> str:
    """Highest standing tier this witness set supports (grade, operator_id) pairs.

    Fails closed: ungradable input or too few disclosed operators collapses
    to `provisional` (the Independence Law cap, SAB_MASTER_VISION_V1 §6).
    """
    for tier in ("canon", "active"):
        if system_operator_count < MIN_INDEPENDENT_OPERATORS_FOR_STANDING:
            break
        requirement = STANDING_TIER_REQUIREMENTS[tier]
        min_tier = INDEPENDENCE_GRADE_TIERS[str(requirement["min_grade"])]
        counted = [
            (grade, operator_id)
            for grade, operator_id in witnesses
            if INDEPENDENCE_GRADE_TIERS.get(grade, INDEPENDENCE_GRADE_TIERS["undisclosed"]) >= min_tier
        ]
        distinct_operators = {
            operator_id
            for _, operator_id in counted
            if operator_id and operator_id.strip().lower() != "unknown"
        }
        if len(counted) >= int(requirement["min_witnesses"]) and len(distinct_operators) >= int(
            requirement["min_distinct_operators"]
        ):
            return tier
    return "provisional"


def validate_witness_independence(
    *,
    claimant_identity: AgentIdentityV1,
    witness_identity: AgentIdentityV1,
    impact: str = "low",
    existing_witness_identities: Optional[list[AgentIdentityV1]] = None,
    policy: Optional[OperatorConcentrationPolicy] = None,
) -> WitnessPolicyDecision:
    policy = policy or OperatorConcentrationPolicy()
    existing_witness_identities = existing_witness_identities or []
    errors: list[str] = []
    warnings: list[str] = []
    high_impact = impact.lower() in HIGH_IMPACT_LEVELS

    if not high_impact:
        if claimant_identity.subject_id == witness_identity.subject_id:
            warnings.append("self_witness_low_impact")
        if same_operator(claimant_identity, witness_identity):
            warnings.append("same_operator_low_impact")
        return WitnessPolicyDecision(ok=True, errors=errors, warnings=warnings)

    if policy.forbid_self_witness_for_high_impact and claimant_identity.subject_id == witness_identity.subject_id:
        errors.append("self_witness_forbidden_for_high_impact")
    if policy.forbid_same_operator_for_high_impact and same_operator(claimant_identity, witness_identity):
        errors.append("same_operator_witness_forbidden_for_high_impact")

    witness_operator = identity_operator_id(witness_identity)
    if witness_operator != "unknown":
        existing_same_operator = sum(
            1
            for existing in existing_witness_identities
            if identity_operator_id(existing) == witness_operator
        )
        if existing_same_operator >= policy.max_high_impact_witnesses_per_operator:
            errors.append("operator_witness_concentration_forbidden_for_high_impact")

    return WitnessPolicyDecision(ok=not errors, errors=errors, warnings=warnings)
