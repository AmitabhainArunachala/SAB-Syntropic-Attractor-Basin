from __future__ import annotations

import base64
import importlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from pydantic import ValidationError


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agora.sab_attestations import (  # noqa: E402
    ExternalAttestationV1,
    MoltbookIdentityTokenVerifier,
    load_external_attestation,
    store_external_attestation,
)
from agora.sab_identity import (  # noqa: E402
    AgentIdentityV1,
    AuthorityLeaseV1,
    InMemoryReplayStore,
    OperatorBacking,
    OperatorConcentrationPolicy,
    ReplayProtectionPolicy,
    ReplayProtector,
    SignatureEnvelope,
    canonical_payload_for_signature,
    independence_grade,
    quorum_tier,
    same_operator,
    subject_id_from_public_key,
    validate_authority_lease,
    validate_witness_independence,
    verify_signed_payload,
)


def _reset_agora_modules() -> None:
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]


def _public_key(sk: SigningKey) -> str:
    return sk.verify_key.encode(encoder=HexEncoder).decode()


def _identity(name: str, operator_id: str = "operator-a") -> tuple[SigningKey, AgentIdentityV1]:
    sk = SigningKey.generate()
    identity = AgentIdentityV1.from_public_key(
        display_name=name,
        public_key=_public_key(sk),
        operator_backing=OperatorBacking(
            operator_id=operator_id,
            operator_kind="human",
            disclosure=f"{operator_id} backs {name}",
            backing_count_attestation="self_attested",
        ),
    )
    return sk, identity


def _valid_lease(identity: AgentIdentityV1, now: datetime) -> AuthorityLeaseV1:
    return AuthorityLeaseV1(
        lease_id="sab_lease_test_identity",
        subject_id=identity.subject_id,
        purpose="submit_seed",
        scope="seed:public",
        allowed_actions=["submit_seed"],
        forbidden_actions=["grant_standing", "canonize"],
        allowed_reliance=[],
        forbidden_reliance=["standing", "canon"],
        expires_at=now + timedelta(days=1),
        revoker="sab_policy",
        challenge_path="/api/v1/authority-leases/sab_lease_test_identity/challenge",
        issued_by="sab_policy",
        issued_at=now,
        policy_hash="sha256:test-policy",
        witness_event_id="sab_witness_test_identity",
    )


def _jwt_for_claims(claims: Dict[str, Any], header: Dict[str, Any] | None = None) -> str:
    header = header or {"alg": "none", "typ": "JWT", "kid": "dev-test-key"}

    def encode(obj: Dict[str, Any]) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{encode(header)}.{encode(claims)}.devsig"


def test_register_route_returns_canonical_agent_identity(tmp_path, monkeypatch) -> None:
    shared_db = tmp_path / "sab_authority.db"
    system_key = tmp_path / ".sab_system_ed25519.key"
    monkeypatch.setenv("SAB_AUTHORITY_DB_PATH", str(shared_db))
    monkeypatch.delenv("SAB_SPARK_DB_PATH", raising=False)
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(system_key))

    _reset_agora_modules()
    web_app = importlib.import_module("agora.app")
    client = TestClient(web_app.app)

    sk = SigningKey.generate()
    public_key = _public_key(sk)
    res = client.post("/api/agents/register", json={"name": "lane-four-agent", "public_key": public_key})

    assert res.status_code == 201, res.text
    body = res.json()
    assert body["id"]
    assert body["public_key"] == public_key
    assert body["identity"]["schema"] == "sab.agent_identity.v1"
    assert body["identity"]["subject_id"] == subject_id_from_public_key(public_key)
    assert body["identity"]["identity_rail"] == "ed25519"
    assert body["identity"]["external_attestations"] == []
    assert body["identity"]["evidence_refs"] == [f"web_agents:{body['id']}"]


def test_canonical_signed_payload_verifies_and_rejects_tampering() -> None:
    sk, identity = _identity("signer")
    payload = {
        "schema": "sab.seed_packet.v1",
        "seed_id": "sab_seed_test",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "claim": {"text": "Canonical signing must be stable.", "scope": "test"},
    }
    signature_hex = sk.sign(canonical_payload_for_signature(payload)).signature.hex()
    signed_payload = {
        **payload,
        "signature": SignatureEnvelope(
            signer=identity.subject_id,
            signature=signature_hex,
        ).model_dump(),
    }

    assert verify_signed_payload(
        dict(reversed(list(signed_payload.items()))),
        public_key_hex=identity.public_key,
        expected_signer=identity.subject_id,
    )

    tampered = dict(signed_payload)
    tampered["claim"] = {"text": "Tampered claim.", "scope": "test"}
    assert not verify_signed_payload(
        tampered,
        public_key_hex=identity.public_key,
        expected_signer=identity.subject_id,
    )


def test_authority_lease_validation_enforces_scope_expiry_revoker_actions_and_challenge_path() -> None:
    _, identity = _identity("lease-holder")
    now = datetime(2026, 7, 4, 12, tzinfo=timezone.utc)
    lease = _valid_lease(identity, now)

    result = validate_authority_lease(
        lease,
        action="submit_seed",
        requested_scope="seed:public:first",
        now=now,
        subject_id=identity.subject_id,
    )
    assert result.ok

    expired = lease.model_dump()
    expired["expires_at"] = (now - timedelta(seconds=1)).isoformat()
    assert validate_authority_lease(expired, action="submit_seed", requested_scope="seed:public", now=now).errors == [
        "authority_lease_expired"
    ]

    forbidden = lease.model_dump()
    forbidden["allowed_actions"] = ["submit_seed", "grant_standing"]
    with pytest.raises(ValidationError):
        AuthorityLeaseV1.model_validate(forbidden)

    action_denied = validate_authority_lease(
        lease,
        action="request_standing",
        requested_scope="seed:public",
        now=now,
    )
    assert "authority_lease_action_not_allowed" in action_denied.errors

    scope_denied = validate_authority_lease(
        lease,
        action="submit_seed",
        requested_scope="standing:public",
        now=now,
    )
    assert "authority_lease_scope_denied" in scope_denied.errors

    no_challenge_path = lease.model_dump()
    no_challenge_path["challenge_path"] = "none"
    assert "authority_lease_missing_challenge_path" in validate_authority_lease(
        no_challenge_path,
        action="submit_seed",
        requested_scope="seed:public",
        now=now,
    ).errors

    missing_scope = lease.model_dump()
    missing_scope.pop("scope")
    invalid = validate_authority_lease(
        missing_scope,
        action="submit_seed",
        requested_scope="seed:public",
        now=now,
    )
    assert not invalid.ok
    assert invalid.errors[0].startswith("invalid_authority_lease:")


def test_replay_protection_rejects_duplicates_reused_signatures_stale_payloads_and_head_mismatch() -> None:
    now = datetime(2026, 7, 4, 12, tzinfo=timezone.utc)
    payload = {"kind": "sab_seed_submit", "seed_id": "sab_seed_replay", "created_at": now.isoformat()}
    signature_hex = "ab" * 64
    protector = ReplayProtector(store=InMemoryReplayStore())

    accepted = protector.check_and_record(signature_hex=signature_hex, payload=payload, created_at=now, now=now)
    assert accepted.accepted

    duplicate = protector.check_and_record(signature_hex=signature_hex, payload=payload, created_at=now, now=now)
    assert not duplicate.accepted
    assert duplicate.reason == "duplicate_signature_replay"

    tampered = {**payload, "seed_id": "sab_seed_other"}
    reused = protector.check_and_record(signature_hex=signature_hex, payload=tampered, created_at=now, now=now)
    assert not reused.accepted
    assert reused.reason == "signature_reused_for_different_payload"
    assert reused.previous_payload_digest == accepted.payload_digest

    stale = ReplayProtector().check_and_record(
        signature_hex="cd" * 64,
        payload=payload,
        created_at=now - timedelta(minutes=11),
        now=now,
    )
    assert not stale.accepted
    assert stale.reason == "stale_signed_payload"

    head_bound = ReplayProtector(policy=ReplayProtectionPolicy(require_witness_head_match=True))
    mismatch = head_bound.check_and_record(
        signature_hex="ef" * 64,
        payload=payload,
        created_at=now,
        now=now,
        witness_head="head-old",
        expected_witness_head="head-new",
    )
    assert not mismatch.accepted
    assert mismatch.reason == "witness_head_mismatch"


def test_external_attestations_and_moltbook_stub_never_grant_standing() -> None:
    _, identity = _identity("attested")
    now = datetime(2026, 7, 4, 12, tzinfo=timezone.utc)

    disabled = MoltbookIdentityTokenVerifier()
    assert disabled.verify(subject_id=identity.subject_id, token="not-used", now=now).status == "disabled"

    enabled = MoltbookIdentityTokenVerifier(
        enabled=True,
        expected_issuer="https://moltbook.example",
        expected_audience="sab",
        accept_unsigned_dev_tokens=True,
    )
    token = _jwt_for_claims(
        {
            "iss": "https://moltbook.example",
            "aud": "sab",
            "sub": "moltbook-user-123",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "token_use": "identity",
        }
    )

    result = enabled.verify(subject_id=identity.subject_id, token=token, now=now)
    assert result.accepted
    assert result.standing_effect == "none"
    assert result.attestation is not None
    assert result.attestation.standing_effect == "none"
    assert result.attestation.provider == "moltbook"

    api_key_result = enabled.verify(subject_id=identity.subject_id, token="mb_live_secret_key", now=now)
    assert not api_key_result.accepted
    assert "API keys" in api_key_result.reason

    long_lived = _jwt_for_claims(
        {
            "iss": "https://moltbook.example",
            "aud": "sab",
            "sub": "moltbook-user-123",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=4)).timestamp()),
            "token_use": "identity",
        }
    )
    assert "not short-lived" in enabled.verify(subject_id=identity.subject_id, token=long_lived, now=now).reason

    with pytest.raises(ValidationError):
        ExternalAttestationV1(
            attestation_id="sab_att_bad_standing",
            subject_id=identity.subject_id,
            provider="moltbook",
            provider_subject="moltbook-user-123",
            verification_status="verified",
            public_claims={"standing_id": "sab_standing_forbidden"},
        )

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store_external_attestation(conn, result.attestation)
    loaded = load_external_attestation(conn, result.attestation.attestation_id)
    assert loaded == result.attestation
    stored_effect = conn.execute(
        "SELECT standing_effect FROM external_identity_attestations WHERE attestation_id = ?",
        (result.attestation.attestation_id,),
    ).fetchone()["standing_effect"]
    assert stored_effect == "none"


def test_high_impact_witness_policy_rejects_self_witness_same_operator_and_concentration() -> None:
    _, claimant = _identity("claimant", operator_id="operator-a")
    _, same_operator_witness = _identity("same-operator", operator_id="operator-a")
    _, independent_witness = _identity("independent", operator_id="operator-b")
    _, second_same_witness = _identity("second-same", operator_id="operator-b")

    self_decision = validate_witness_independence(
        claimant_identity=claimant,
        witness_identity=claimant,
        impact="high",
    )
    assert not self_decision.ok
    assert "self_witness_forbidden_for_high_impact" in self_decision.errors

    same_operator_decision = validate_witness_independence(
        claimant_identity=claimant,
        witness_identity=same_operator_witness,
        impact="high",
    )
    assert not same_operator_decision.ok
    assert "same_operator_witness_forbidden_for_high_impact" in same_operator_decision.errors

    independent_decision = validate_witness_independence(
        claimant_identity=claimant,
        witness_identity=independent_witness,
        impact="high",
    )
    assert independent_decision.ok

    concentration_decision = validate_witness_independence(
        claimant_identity=claimant,
        witness_identity=second_same_witness,
        existing_witness_identities=[independent_witness],
        impact="standing",
        policy=OperatorConcentrationPolicy(max_high_impact_witnesses_per_operator=1),
    )
    assert not concentration_decision.ok
    assert "operator_witness_concentration_forbidden_for_high_impact" in concentration_decision.errors

    low_impact = validate_witness_independence(
        claimant_identity=claimant,
        witness_identity=same_operator_witness,
        impact="low",
    )
    assert low_impact.ok
    assert "same_operator_low_impact" in low_impact.warnings


def test_unknown_operator_fails_closed_as_not_independent() -> None:
    _, claimant = _identity("fail-closed-claimant", operator_id="operator-a")
    _, undisclosed_witness = _identity("fail-closed-witness", operator_id="unknown")
    _, disclosed_witness = _identity("fail-closed-independent", operator_id="operator-b")

    assert same_operator(claimant, undisclosed_witness) is True
    assert same_operator(claimant, disclosed_witness) is False
    assert independence_grade(undisclosed_witness, claimant) == "undisclosed"
    assert independence_grade(disclosed_witness, claimant) == "cross_operator_unverified"

    decision = validate_witness_independence(
        claimant_identity=claimant,
        witness_identity=undisclosed_witness,
        impact="high",
    )
    assert not decision.ok
    assert "same_operator_witness_forbidden_for_high_impact" in decision.errors


def test_quorum_tier_caps_at_provisional_below_three_operators() -> None:
    cross = [("cross_operator_unverified", "operator-a"), ("cross_operator_unverified", "operator-b")]
    assert quorum_tier(witnesses=cross, system_operator_count=1) == "provisional"
    assert quorum_tier(witnesses=cross, system_operator_count=2) == "provisional"
    assert quorum_tier(witnesses=cross, system_operator_count=3) == "active"
    assert quorum_tier(witnesses=[("self", "operator-a")], system_operator_count=3) == "provisional"
    assert quorum_tier(witnesses=[("undisclosed", "unknown")] * 3, system_operator_count=3) == "provisional"
    attested = [
        ("cross_operator_attested", "operator-a"),
        ("cross_operator_attested", "operator-b"),
        ("cross_operator_attested", "operator-c"),
    ]
    assert quorum_tier(witnesses=attested, system_operator_count=3) == "canon"
