"""Unsigned operator approval packets for an attended SAB ceremony.

This module is deliberately non-authorizing.  It binds the evidence an
operator must inspect to one canonical digest, but it neither accepts a human
signature nor constructs an executable live capability.  The short checksum
is display assistance only and can never substitute for the full digest.

The module is pure: it performs no persistence, provider calls, network I/O,
key access, or service/database mutation.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .sab_artifact_verdict import canonical_json, canonical_json_sha256


SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_OBJECT_PATTERN = r"^[0-9a-f]{40}$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
USD_PATTERN = r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?$"
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
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


class CeremonyCodeBindingV1(_StrictModel):
    commit_sha: str = Field(pattern=GIT_OBJECT_PATTERN)
    tree_sha: str = Field(pattern=GIT_OBJECT_PATTERN)
    build_a_closeout_sha256: str = Field(pattern=SHA256_PATTERN)


class CeremonyAuthorityBindingV1(_StrictModel):
    case_id: str = Field(pattern=IDENTIFIER_PATTERN)
    case_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_evaluation_sha256: str = Field(pattern=SHA256_PATTERN)
    authority_result: Literal["Authorized<Live>"]


class CeremonyBenchBindingV1(_StrictModel):
    frozen_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    provider_probe_bundle_sha256: str = Field(pattern=SHA256_PATTERN)
    cost_envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    transcript_head_sha256: str = Field(pattern=SHA256_PATTERN)
    final_ballot_set_sha256: str = Field(pattern=SHA256_PATTERN)
    compiled_outcome_kind: Literal["verdict"]
    compiled_outcome_sha256: str = Field(pattern=SHA256_PATTERN)


class CeremonyMaintenanceBindingV1(_StrictModel):
    runtime_attestation_sha256: str = Field(pattern=SHA256_PATTERN)
    service_state_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    tick_exclusion_receipt_sha256: str = Field(pattern=SHA256_PATTERN)
    restoration_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    write_lease_sha256: str = Field(pattern=SHA256_PATTERN)


class CeremonyEffectBindingV1(_StrictModel):
    effect_type: str = Field(pattern=IDENTIFIER_PATTERN)
    effect_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=IDENTIFIER_PATTERN)


class CeremonyOperatorLimitsV1(_StrictModel):
    public_key_fingerprint: str = Field(pattern=SHA256_PATTERN)
    spend_cap_usd: str = Field(pattern=USD_PATTERN)
    automatic_top_up: Literal[False]


class CeremonyApprovalEnvelopeV1(_StrictModel):
    """Full evidence binding an operator would sign in an attended window."""

    schema_version: Literal["sab.ceremony_approval_envelope.v1"]
    ceremony_id: str = Field(pattern=IDENTIFIER_PATTERN)
    prepared_at: str
    requested_scope: Literal["Live"]
    code: CeremonyCodeBindingV1
    authority: CeremonyAuthorityBindingV1
    bench: CeremonyBenchBindingV1
    maintenance: CeremonyMaintenanceBindingV1
    proposed_effect: CeremonyEffectBindingV1
    operator_limits: CeremonyOperatorLimitsV1

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at_is_exact_utc(cls, value: str) -> str:
        if not UTC_PATTERN.fullmatch(value):
            raise ValueError("prepared_at must use exact second-resolution UTC Z form")
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.tzinfo is None or parsed.astimezone(timezone.utc) != parsed:
            raise ValueError("prepared_at must be UTC")
        return value


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


def short_display_checksum(full_sha256: str) -> str:
    """Return a human display aid; this value is explicitly non-authorizing."""

    if not re.fullmatch(SHA256_PATTERN, full_sha256):
        raise ApprovalPacketError(
            "digest_invalid", "full approval digest must be lowercase SHA-256"
        )
    return f"SAB-{full_sha256[:8].upper()}-{full_sha256[-8:].upper()}"


def build_operator_approval_packet(
    envelope: CeremonyApprovalEnvelopeV1 | Mapping[str, Any],
) -> dict[str, Any]:
    """Build a canonical, unsigned and non-executable approval packet."""

    raw: Any = (
        envelope.model_dump(mode="json")
        if isinstance(envelope, CeremonyApprovalEnvelopeV1)
        else envelope
    )
    _reject_secret_bearing_keys(raw)
    parsed = CeremonyApprovalEnvelopeV1.model_validate(raw)
    payload = parsed.model_dump(mode="json")
    digest = canonical_json_sha256(payload)
    return {
        "schema_version": "sab.operator_approval_packet.v1",
        "status": "awaiting_operator_countersign",
        "proof_class": "unsigned_operator_approval_packet",
        "canonicalization": "json-sort-keys-compact-v1",
        "approval_payload": payload,
        "approval_payload_sha256": digest,
        "short_display_checksum": short_display_checksum(digest),
        "operator_signature": None,
        "effect_executable": False,
        "signing_instruction": (
            "Inspect and sign the full approval_payload_sha256 during the attended "
            "window; the short display checksum is non-authorizing."
        ),
    }


def verify_operator_approval_packet(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Verify an unsigned packet and preserve its non-authorizing status."""

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
        "signing_instruction",
    }
    if set(packet) != required:
        raise ApprovalPacketError(
            "packet_shape_invalid", "approval packet has missing or unknown fields"
        )
    if (
        packet.get("schema_version") != "sab.operator_approval_packet.v1"
        or packet.get("status") != "awaiting_operator_countersign"
        or packet.get("proof_class") != "unsigned_operator_approval_packet"
        or packet.get("canonicalization") != "json-sort-keys-compact-v1"
        or packet.get("operator_signature") is not None
        or packet.get("effect_executable") is not False
    ):
        raise ApprovalPacketError(
            "packet_state_invalid",
            "unsigned approval packet state or proof class is invalid",
        )
    payload = CeremonyApprovalEnvelopeV1.model_validate(packet["approval_payload"])
    payload_dict = payload.model_dump(mode="json")
    digest = canonical_json_sha256(payload_dict)
    if packet.get("approval_payload_sha256") != digest:
        raise ApprovalPacketError(
            "packet_digest_mismatch", "approval payload digest does not verify"
        )
    if packet.get("short_display_checksum") != short_display_checksum(digest):
        raise ApprovalPacketError(
            "display_checksum_mismatch", "short display checksum does not verify"
        )
    return {
        "valid": True,
        "schema_version": "sab.operator_approval_packet_verification.v1",
        "status": "awaiting_operator_countersign",
        "proof_class": "unsigned_operator_approval_packet",
        "approval_payload_sha256": digest,
        "short_display_checksum": short_display_checksum(digest),
        "authority_result": payload.authority.authority_result,
        "effect_executable": False,
        "live_authority_created": False,
    }


def render_operator_approval_markdown(packet: Mapping[str, Any]) -> str:
    """Render the verified packet as a compact phone-readable approval view."""

    verified = verify_operator_approval_packet(packet)
    payload = CeremonyApprovalEnvelopeV1.model_validate(packet["approval_payload"])
    return "\n".join(
        [
            "# SAB attended ceremony approval — unsigned",
            "",
            "**Status:** `awaiting_operator_countersign`",
            "",
            "This packet is non-authorizing and cannot execute an effect. Review it "
            "during the attended maintenance window.",
            "",
            f"- Ceremony: `{payload.ceremony_id}`",
            f"- Code commit: `{payload.code.commit_sha}`",
            f"- Code tree: `{payload.code.tree_sha}`",
            f"- Case: `{payload.authority.case_id}`",
            f"- Authority: `{payload.authority.authority_result}`",
            f"- Compiled outcome: `{payload.bench.compiled_outcome_kind}`",
            f"- Proposed effect: `{payload.proposed_effect.effect_type}`",
            f"- Idempotency key: `{payload.proposed_effect.idempotency_key}`",
            f"- Maximum spend: `${payload.operator_limits.spend_cap_usd}`",
            "- Automatic top-up: `false`",
            "",
            "## Full canonical digest to sign",
            "",
            f"`{verified['approval_payload_sha256']}`",
            "",
            "## Display checksum (non-authorizing)",
            "",
            f"`{verified['short_display_checksum']}`",
            "",
            "Do not sign the short checksum. Inspect and sign the full 64-character "
            "digest only after the live state and maintenance gates are rechecked.",
            "",
        ]
    )


def canonical_packet_json(packet: Mapping[str, Any]) -> str:
    """Return the packet's stable JSON representation after verification."""

    verify_operator_approval_packet(packet)
    return canonical_json(dict(packet))
