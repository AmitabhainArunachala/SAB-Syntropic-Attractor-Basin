from __future__ import annotations

import copy
import base64
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from pydantic import ValidationError

from agora.sab_artifact_verdict import (
    AdvisoryOnlyDispositionAuthorityV1,
    AllowedOperationV1,
    AuthorityDenied,
    AuthorizedDispositionAuthorityV1,
    EffectiveVerdictV1,
    EvidenceProvenance,
    MASTER_VISION_SEED_ID,
    MasterVisionPolicyEvidenceV1,
    MasterVisionStateObservationV1,
    NoJurisdictionDispositionAuthorityV1,
    RehearsalDispositionV1,
    SignedDispositionPolicyV1,
    TrustedPolicyIssuerV1,
    canonical_json_bytes,
    canonical_sha256,
    evaluate_disposition_authority,
    require_authorized_effects,
    require_live_authority,
    require_rehearsal_authority,
    validate_exact_allowed_operations,
)


ROOT = Path(__file__).resolve().parents[1]
PACKETS = ROOT / "docs" / "lanes" / "sab-agent-seeding-v1" / "contributions" / "packets"
MASTER_SEED = PACKETS / "sab_seed_master_vision_v1_ebe422aab149.json"
MASTER_CHALLENGE = PACKETS / "sab_challenge_master_vision_v1_ebe422aab149.json"
MASTER_DOCUMENT = ROOT / "docs" / "SAB_MASTER_VISION_V1.md"
NOW = datetime(2026, 7, 27, 15, 0, tzinfo=timezone.utc)
ARTIFACT_ID = "sab_seed_fixture_first_verdict"
ARTIFACT_HASH = "a" * 64
STATE_HASH = "b" * 64
EFFECTS = ("challenge:resolve", "seed:supersede")


def signed_policy(
    *,
    mode: str = "authorized",
    scope: str = "Copy",
    permitted_effects: tuple[str, ...] = EFFECTS,
    forbidden_effects: tuple[str, ...] = (),
    state_hash: str = STATE_HASH,
    live_eligible: bool = False,
    test_issuer: bool = True,
    expires_at: datetime | None = None,
) -> SignedDispositionPolicyV1:
    key = SigningKey.generate()
    public_key = key.verify_key.encode(encoder=HexEncoder).decode("ascii")
    unsigned_body: dict[str, Any] = {
        "schema": "sab.signed_disposition_policy.v1",
        "policy_id": "sab_policy_fixture_first_verdict",
        "artifact_id": ARTIFACT_ID,
        "artifact_sha256": ARTIFACT_HASH,
        "disposition_mode": mode,
        "scope": scope,
        "permitted_effects": list(permitted_effects),
        "forbidden_effects": list(forbidden_effects),
        "preconditions": ["challenge_state=pending", "seed_state=challenged"],
        "evaluated_state_hash": state_hash,
        "source_fixture_id": "fixture:first-verdict" if test_issuer else None,
        "copied_database_id": "copy:fixture-db" if test_issuer else None,
        "test_issuer": test_issuer,
        "live_eligible": live_eligible,
        "standing_effect": "none",
        "authority_refs": ["fixture:signed-policy"],
        "issued_at": "2026-07-27T15:00:00Z",
        "expires_at": (expires_at or (NOW + timedelta(hours=1)))
        .isoformat()
        .replace("+00:00", "Z"),
        "issuer": "fixture:test-issuer",
    }
    policy_hash = canonical_sha256(unsigned_body)
    signed_payload = {**unsigned_body, "policy_sha256": policy_hash}
    message = canonical_json_bytes(signed_payload)
    signature = {
        "alg": "ed25519",
        "signer": "fixture:test-issuer",
        "public_key": public_key,
        "signature": key.sign(message).signature.hex(),
        "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return SignedDispositionPolicyV1.model_validate(
        {**signed_payload, "signature": signature}
    )


def evaluate(policy: SignedDispositionPolicyV1 | dict[str, Any] | None, **changes: Any):
    request = {
        "artifact_id": ARTIFACT_ID,
        "artifact_sha256": ARTIFACT_HASH,
        "requested_scope": "Copy",
        "requested_effects": EFFECTS,
        "evaluated_state_hash": STATE_HASH,
        "signed_policy": policy,
        "trusted_policy_issuer": (
            TrustedPolicyIssuerV1(
                issuer_identity=policy.issuer,
                issuer_public_key=policy.signature.public_key,
                source_fixture_id=str(policy.source_fixture_id),
                copied_database_id=str(policy.copied_database_id),
                authority_basis="founder_bootstrap_self_declared",
            )
            if isinstance(policy, SignedDispositionPolicyV1)
            and policy.source_fixture_id
            and policy.copied_database_id
            else None
        ),
        "now": NOW,
    }
    request.update(changes)
    return evaluate_disposition_authority(**request)


def test_authorized_copy_is_constructed_from_verified_exact_policy() -> None:
    result = evaluate(signed_policy())
    assert isinstance(result, AuthorizedDispositionAuthorityV1)
    assert result.result == "Authorized"
    assert result.scope == "Copy"
    assert result.allowed_effects == EFFECTS
    assert not result.live_eligible
    assert len(result.authority_digest) == 64
    assert require_rehearsal_authority(result, effects=EFFECTS) is result


def test_all_three_authority_variants_are_distinct_typed_results() -> None:
    authorized = evaluate(signed_policy())
    advisory = evaluate(
        signed_policy(
            mode="advisory_only",
            permitted_effects=(),
            forbidden_effects=("seed:supersede",),
        ),
        requested_effects=(),
    )
    refused = evaluate(
        signed_policy(mode="no_jurisdiction", permitted_effects=()),
        requested_effects=(),
    )
    assert isinstance(authorized, AuthorizedDispositionAuthorityV1)
    assert isinstance(advisory, AdvisoryOnlyDispositionAuthorityV1)
    assert isinstance(refused, NoJurisdictionDispositionAuthorityV1)
    assert advisory.allowed_effects == ()
    assert refused.allowed_effects == refused.forbidden_effects == ()


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"signed_policy": None}, "missing_signed_policy"),
        ({"evaluated_state_hash": "c" * 64}, "state_hash_mismatch"),
        ({"requested_scope": "Live"}, "live_authority_outside_build_a"),
        ({"requested_effects": ("canon",)}, "effect_not_authorized"),
    ],
)
def test_missing_or_scope_state_effect_mismatch_fails_closed(
    changes: dict[str, Any], reason: str
) -> None:
    policy = None if changes.get("signed_policy", object()) is None else signed_policy()
    result = evaluate(
        policy, **{k: v for k, v in changes.items() if k != "signed_policy"}
    )
    assert isinstance(result, NoJurisdictionDispositionAuthorityV1)
    assert reason in result.reason_codes


def test_expired_and_cryptographically_invalid_policy_fail_closed() -> None:
    expired = signed_policy(expires_at=NOW + timedelta(minutes=1))
    assert (
        "policy_expired"
        in evaluate(expired, now=NOW + timedelta(minutes=2)).reason_codes
    )

    tampered = signed_policy().canonical_payload()
    tampered["signature"]["signature"] = "0" * 128
    invalid_signature = SignedDispositionPolicyV1.model_validate(tampered)
    result = evaluate(invalid_signature)
    assert isinstance(result, NoJurisdictionDispositionAuthorityV1)
    assert "policy_signature_invalid" in result.reason_codes


def test_malformed_or_ambiguous_policy_never_raises_into_authority() -> None:
    result = evaluate(
        {"schema": "sab.signed_disposition_policy.v1", "live_eligible": True}
    )
    assert isinstance(result, NoJurisdictionDispositionAuthorityV1)
    assert result.reason_codes == ("invalid_policy_contract",)


def test_master_vision_exact_signed_inputs_need_database_capability() -> None:
    document_bytes = subprocess.run(
        ["git", "show", "bc9d2f6:docs/SAB_MASTER_VISION_V1.md"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    seed_packet = json.loads(MASTER_SEED.read_text())
    challenge_packet = json.loads(MASTER_CHALLENGE.read_text())
    claimed = seed_packet["evidence_bundle"][0]["digest"].removeprefix("sha256:")
    assert hashlib.sha256(document_bytes).hexdigest() == claimed
    assert seed_packet["seed_id"] == MASTER_VISION_SEED_ID
    assert challenge_packet["target_seed_id"] == MASTER_VISION_SEED_ID
    assert challenge_packet["blocking"] is True
    assert "independent operator" in challenge_packet["demanded_correction"]

    evidence = MasterVisionPolicyEvidenceV1(
        document_base64=base64.b64encode(document_bytes).decode("ascii"),
        seed_packet_base64=base64.b64encode(MASTER_SEED.read_bytes()).decode("ascii"),
        challenge_packet_base64=base64.b64encode(MASTER_CHALLENGE.read_bytes()).decode(
            "ascii"
        ),
    )
    observation_body = {
        "schema": "sab.master_vision_state_observation.v1",
        "proof_class": "attested_copied_database_observation",
        "database_lifecycle_fingerprint": "d" * 64,
        "seed_id": MASTER_VISION_SEED_ID,
        "seed_state": "challenged",
        "seed_packet_sha256": evidence.seed_packet_sha256,
        "seed_packet_json_sha256": canonical_sha256(seed_packet),
        "challenge_id": "sab_challenge_master_vision_v1_ebe422aab149",
        "challenge_state": "pending",
        "challenge_packet_sha256": evidence.challenge_packet_sha256,
        "challenge_packet_json_sha256": canonical_sha256(challenge_packet),
        "signer": evidence.signer,
        "signer_public_key": evidence.signer_public_key,
        "witness_event_count": 2,
        "witness_event_types": ["challenge", "submit"],
        "witness_event_chain_sha256": "e" * 64,
        "terminal_witness_count": 0,
        "supersession_edge_count": 0,
        "effective_disposition_count": 0,
    }
    observation = MasterVisionStateObservationV1.model_validate(
        {
            **observation_body,
            "observed_state_hash": canonical_sha256(observation_body),
        }
    )
    result = evaluate_disposition_authority(
        artifact_id=MASTER_VISION_SEED_ID,
        artifact_sha256=claimed,
        requested_scope="Live",
        requested_effects=("canon", "compost", "resolve_challenge", "supersede"),
        evaluated_state_hash=observation.observed_state_hash,
        signed_policy=evidence,
        master_vision_observation=observation,
        now=NOW,
    )
    assert isinstance(result, NoJurisdictionDispositionAuthorityV1)
    assert result.reason_codes == (
        "master_vision_state_observation_missing_or_invalid",
    )


def test_fixture_authority_cannot_promote_live() -> None:
    authority = evaluate(signed_policy())
    with pytest.raises(AuthorityDenied, match="scope"):
        require_authorized_effects(
            authority,
            scope="Live",
            effects=("seed:supersede",),
            evidence_provenance=EvidenceProvenance.REAL_EXTERNAL_MODELS,
        )
    with pytest.raises(ValidationError):
        EffectiveVerdictV1.model_validate(
            {
                "schema": "sab.effective_verdict.v1",
                "effective_verdict_id": "sab_effective_illegal_fixture",
                "verdict_id": "sab_verdict_fixture",
                "verdict_sha256": ARTIFACT_HASH,
                "authority": authority.canonical_payload(),
                "effects": ["seed:supersede"],
                "evidence_provenance": "real_external_models",
                "scope": "Live",
                "fixture_derived": False,
                "applied_at": NOW,
                "standing_effect": "none",
            }
        )


def test_self_signed_live_policy_cannot_manufacture_build_a_authority() -> None:
    self_signed = signed_policy(
        scope="Live",
        permitted_effects=("compost",),
        live_eligible=True,
        test_issuer=False,
    )
    result = evaluate(
        self_signed,
        requested_scope="Live",
        requested_effects=("compost",),
    )
    assert isinstance(result, NoJurisdictionDispositionAuthorityV1)
    assert result.reason_codes == ("live_authority_outside_build_a",)
    with pytest.raises(AuthorityDenied):
        require_live_authority(result, effects=("compost",))


def test_rehearsal_constructor_requires_authorized_copy_and_fixture_provenance() -> (
    None
):
    authority = evaluate(signed_policy())
    payload = {
        "schema": "sab.rehearsal_disposition.v1",
        "disposition_id": "sab_rehearsal_fixture",
        "verdict_id": "sab_verdict_fixture",
        "verdict_sha256": ARTIFACT_HASH,
        "case_id": "sab_case_fixture",
        "case_sha256": ARTIFACT_HASH,
        "authority": authority.canonical_payload(),
        "countersign_id": "sab_countersign_fixture",
        "countersign_sha256": ARTIFACT_HASH,
        "effects": ["seed:supersede"],
        "ballot_source": "fixture_model",
        "evidence_provenance": "fixture_models",
        "scope": "Copy",
        "proof_class": "copied_live_db_rehearsal",
        "source_fixture_id": "fixture:first-verdict",
        "copied_database_id": "copy:fixture-db",
        "before_state_hash": STATE_HASH,
        "after_state_hash": "c" * 64,
        "applied_at": NOW,
        "standing_effect": "none",
        "live_eligible": False,
    }
    disposition = RehearsalDispositionV1.model_validate(payload)
    assert disposition.scope == "Copy"
    forbidden = copy.deepcopy(payload)
    forbidden["effects"] = ["canon"]
    with pytest.raises(ValidationError, match="exact authority set"):
        RehearsalDispositionV1.model_validate(forbidden)


def test_serialized_or_model_copied_authority_is_not_an_effect_capability() -> None:
    evaluated = evaluate(signed_policy())
    serialized = AuthorizedDispositionAuthorityV1.model_validate(
        evaluated.canonical_payload()
    )
    with pytest.raises(AuthorityDenied, match="serialized authority receipt"):
        require_rehearsal_authority(serialized, effects=EFFECTS)

    # Pydantic model_copy intentionally does not revalidate updates.  The
    # evaluator seal binds the old digest, so the copied value still cannot be
    # used as an effect capability.
    promoted = evaluated.model_copy(
        update={
            "scope": "Live",
            "live_eligible": True,
            "allowed_effects": ("compost",),
        }
    )
    with pytest.raises(AuthorityDenied, match="serialized authority receipt"):
        require_authorized_effects(
            promoted,
            scope="Live",
            effects=("compost",),
            evidence_provenance="real_external_models",
        )
    with pytest.raises(ValidationError, match="outside Build A"):
        EffectiveVerdictV1.model_validate(
            {
                "schema": "sab.effective_verdict.v1",
                "effective_verdict_id": "forged-live",
                "verdict_id": "forged-verdict",
                "verdict_sha256": ARTIFACT_HASH,
                "authority": promoted,
                "effects": ["compost"],
                "evidence_provenance": "real_external_models",
                "scope": "Live",
                "fixture_derived": False,
                "applied_at": NOW,
                "standing_effect": "none",
            }
        )


def test_exact_method_path_allowlist_rejects_wildcards_and_unmounted_routes() -> None:
    parsed = validate_exact_allowed_operations(
        [
            {"method": "POST", "path": "/api/v1/artifact-cases"},
            {"method": "GET", "path": "/health"},
        ]
    )
    assert [(item.method, item.path) for item in parsed] == [
        ("GET", "/health"),
        ("POST", "/api/v1/artifact-cases"),
    ]
    with pytest.raises(ValidationError, match="wildcard"):
        AllowedOperationV1(method="POST", path="/api/v1/*")
    with pytest.raises(ValidationError, match="outside"):
        AllowedOperationV1(method="POST", path="/api/v1/compost-batches/apply")
    with pytest.raises(ValueError, match="unique"):
        validate_exact_allowed_operations(
            [
                {"method": "GET", "path": "/health"},
                {"method": "GET", "path": "/health"},
            ]
        )


def test_copy_authority_cannot_claim_standing_or_live_eligibility() -> None:
    payload = evaluate(signed_policy()).canonical_payload()
    payload["standing_effect"] = "rank_up"
    with pytest.raises(ValidationError):
        AuthorizedDispositionAuthorityV1.model_validate(payload)
    payload = evaluate(signed_policy()).canonical_payload()
    payload["live_eligible"] = True
    with pytest.raises(ValidationError, match="Input should be False"):
        AuthorizedDispositionAuthorityV1.model_validate(payload)


def test_policy_hash_and_exact_effect_sets_are_self_binding() -> None:
    policy = signed_policy()
    altered = policy.canonical_payload()
    altered["permitted_effects"].append("canon")
    with pytest.raises(ValidationError, match="policy_sha256"):
        SignedDispositionPolicyV1.model_validate(altered)
    duplicate = policy.canonical_payload()
    duplicate["permitted_effects"].append("seed:supersede")
    reparsed = SignedDispositionPolicyV1.model_validate(duplicate)
    assert reparsed.permitted_effects == EFFECTS
