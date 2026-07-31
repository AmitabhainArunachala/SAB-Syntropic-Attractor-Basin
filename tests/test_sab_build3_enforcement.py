"""Build 3 enforcement tests (closes B2-B6 from the 2026-07-05 SAB review).

Covers, per docs/SAB_STANDING_SEMANTICS_V0.md §1.3-1.5 (graded independence)
and §2.3 (finality state machine):
- B2: witness_plan.forbidden_witnesses enforced; validate_witness_independence wired.
- B3: independence fails closed on unknown operators; register persists operator_backing.
- B4: compost is absorbing; parties cannot adjudicate their own challenge;
  canon unreachable from a single signature.
- B5: challenge window enforced as law; unresolved challenges resolve by deadline
  (pending -> sustained_by_default -> compost; responded -> lapsed).
- B6: standing issues as provisional unless the independence gate passes;
  with three disclosed operators the gate becomes mechanically passable.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pytest

nacl_signing = pytest.importorskip("nacl.signing")
from nacl.encoding import HexEncoder  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256_obj(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class _Agent:
    def __init__(self) -> None:
        self.key = nacl_signing.SigningKey.generate()
        self.public_key = self.key.verify_key.encode(encoder=HexEncoder).decode()
        self.subject_id = ""

    def sign(self, message: dict[str, Any]) -> str:
        return self.key.sign(_canonical_bytes(message)).signature.hex()


@pytest.fixture
def sab_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "build3_enforcement.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / ".build3_system_ed25519.key"))
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]
    return importlib.import_module("agora.app")


@pytest.fixture
def client(sab_app):
    with TestClient(sab_app.app) as test_client:
        yield test_client


def _register(client: TestClient, agent: _Agent, label: str, operator_id: str) -> dict[str, Any]:
    response = client.post(
        "/api/v1/agents/register",
        json={
            "schema": "sab.agent_identity.v1",
            "display_name": label,
            "identity_rail": "ed25519",
            "public_key": agent.public_key,
            "controller": "operator",
            "operator_backing": {
                "operator_id": operator_id,
                "operator_kind": "human",
                "disclosure": f"{operator_id} operates {label}",
                "backing_count_attestation": "self_attested",
            },
            "external_attestations": [],
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    agent.subject_id = body["subject_id"]
    return body


def _submit_seed(
    client: TestClient,
    claimant: _Agent,
    seed_id: str,
    *,
    challenge_window: str = "P7D",
    forbidden_witnesses: Optional[list[str]] = None,
) -> dict[str, Any]:
    created_at = _iso(_now())
    packet: dict[str, Any] = {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "seed_type": "claim",
        "title": f"Build 3 enforcement seed {seed_id}",
        "claim": {
            "claim_id": f"sab_claim_{seed_id}",
            "text": "Build 3 enforcement fixture claim.",
            "scope": "this repo, this venv, one machine",
        },
        "claimant_identity": {"subject_id": claimant.subject_id},
        "authority_lease": {
            "lease_ref": f"sab_lease_{seed_id}_submit",
            "subject_id": claimant.subject_id,
            "purpose": "submit_seed",
            "scope": "submit one enforcement-test seed",
            "expires_at": _iso(_now() + timedelta(days=14)),
            "revoker": "operator_build3",
            "challenge_path": f"/api/v1/seeds/{seed_id}/challenges",
        },
        "challenge_plan": {"required": True, "challenge_window": challenge_window},
        "witness_plan": {
            "required_roles": ["challenger", "witness"],
            "minimum_witnesses": 1,
            "forbidden_witnesses": forbidden_witnesses if forbidden_witnesses is not None else [claimant.subject_id],
        },
        "created_at": created_at,
    }
    message = {
        "kind": "sab_seed_submit",
        "seed_packet_sha256": _sha256_obj(packet),
        "claimant_identity": claimant.subject_id,
        "authority_lease_id": packet["authority_lease"]["lease_ref"],
        "created_at": created_at,
    }
    packet["signature"] = {
        "alg": "ed25519",
        "signer": claimant.subject_id,
        "signature": claimant.sign(message),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    response = client.post("/api/v1/seeds", json=packet)
    assert response.status_code == 201, response.text
    return response.json()


def _submit_challenge(
    client: TestClient,
    challenger: _Agent,
    seed_id: str,
    challenge_id: str,
    *,
    deadline: Optional[str] = None,
    prosecute_by: Optional[str] = None,
    expect_status: int = 201,
) -> dict[str, Any]:
    created_at = _iso(_now())
    claim_id = f"sab_claim_{seed_id}"
    packet: dict[str, Any] = {
        "schema": "sab.challenge_packet.v1",
        "challenge_id": challenge_id,
        "target_seed_id": seed_id,
        "target_claim_id": claim_id,
        "challenger_identity": challenger.subject_id,
        "challenge_type": "scope",
        "challenge_text": "Scope is broader than the receipts support.",
        "severity": "blocking",
        "created_at": created_at,
    }
    if deadline is not None:
        packet["deadline"] = deadline
    if prosecute_by is not None:
        packet["prosecute_by"] = prosecute_by
    message = {
        "kind": "sab_challenge_submit",
        "target_seed_id": seed_id,
        "target_claim_id": claim_id,
        "challenge_packet_sha256": _sha256_obj(packet),
        "challenger_identity": challenger.subject_id,
        "created_at": created_at,
    }
    packet["signature"] = {
        "alg": "ed25519",
        "signer": challenger.subject_id,
        "signature": challenger.sign(message),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    response = client.post(f"/api/v1/seeds/{seed_id}/challenges", json=packet)
    assert response.status_code == expect_status, response.text
    return response.json()


def _challenge_action(
    client: TestClient,
    actor: _Agent,
    challenge_id: str,
    action: str,
    payload_body: dict[str, Any],
) -> Any:
    created_at = _iso(_now())
    message = {
        "kind": f"sab_challenge_{action}",
        "challenge_id": challenge_id,
        "actor_identity": actor.subject_id,
        "payload_sha256": _sha256_obj(payload_body),
        "created_at": created_at,
    }
    body: dict[str, Any] = {
        "actor_identity": actor.subject_id,
        "created_at": created_at,
        "signature": actor.sign(message),
    }
    if action == "respond":
        body["response"] = payload_body
    else:
        body["reason"] = payload_body
    return client.post(f"/api/v1/challenges/{challenge_id}/{action}", json=body)


def _witness_event(
    client: TestClient,
    actor: _Agent,
    seed_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> Any:
    chain = client.get(f"/api/v1/seeds/{seed_id}/chain").json()
    prev_hash = chain["head"]
    created_at = _iso(_now())
    message = {
        "kind": "sab_witness_event",
        "event_type": event_type,
        "subject_type": "seed",
        "subject_id": seed_id,
        "payload_hash": _sha256_obj(payload),
        "prev_hash": prev_hash,
        "created_at": created_at,
    }
    return client.post(
        "/api/v1/witness-events",
        json={
            "event_type": event_type,
            "actor_identity": actor.subject_id,
            "subject_type": "seed",
            "subject_id": seed_id,
            "created_at": created_at,
            "payload": payload,
            "prev_hash": prev_hash,
            "signature": actor.sign(message),
        },
    )


def _withdraw_seed(client: TestClient, claimant: _Agent, seed_id: str) -> None:
    created_at = _iso(_now())
    reason = "withdrawing for finality test"
    message = {
        "kind": "sab_seed_withdraw",
        "target_seed_id": seed_id,
        "actor_identity": claimant.subject_id,
        "reason_sha256": hashlib.sha256(reason.encode()).hexdigest(),
        "created_at": created_at,
    }
    response = client.post(
        f"/api/v1/seeds/{seed_id}/withdraw",
        json={
            "actor_identity": claimant.subject_id,
            "created_at": created_at,
            "reason": reason,
            "signature": claimant.sign(message),
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "compost"


def _review_standing(
    client: TestClient,
    reviewer: _Agent,
    seed_id: str,
    standing_id: str,
) -> Any:
    issued_at = _iso(_now())
    lease: dict[str, Any] = {
        "standing_id": standing_id,
        "subject_seed_id": seed_id,
        "subject_claim_id": f"sab_claim_{seed_id}",
        "scope": "enforcement-test reliance only",
        "purpose": "build3_enforcement",
        "expiry": _iso(_now() + timedelta(days=30)),
        "revoker": "operator_build3",
        "challenge_path": f"/api/v1/standing/{standing_id}/challenge",
        "issued_by": reviewer.subject_id,
        "issued_at": issued_at,
    }
    message = {
        "kind": "sab_standing_review",
        "standing_lease_sha256": _sha256_obj(lease),
        "subject_seed_id": seed_id,
        "reviewer_identity": reviewer.subject_id,
        "created_at": issued_at,
    }
    lease["signature"] = {
        "alg": "ed25519",
        "signer": reviewer.subject_id,
        "signature": reviewer.sign(message),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return client.post(
        "/api/v1/standing/review",
        json={"standing_lease": lease, "reviewer_identity": reviewer.subject_id, "created_at": issued_at},
    )


def test_b2_forbidden_witness_other_than_claimant_is_rejected(client: TestClient) -> None:
    claimant, blocked = _Agent(), _Agent()
    _register(client, claimant, "b2-claimant", "operator_one")
    _register(client, blocked, "b2-blocked-witness", "operator_one")
    seed_id = "sab_seed_b2_forbidden"
    _submit_seed(client, claimant, seed_id, forbidden_witnesses=[blocked.subject_id])

    response = _witness_event(client, blocked, seed_id, "affirm", {"attestation": "should be blocked"})
    assert response.status_code == 403, response.text
    assert "forbidden" in response.text


def test_b3_register_persists_operator_backing_and_grades_witnesses(client: TestClient) -> None:
    claimant, witness = _Agent(), _Agent()
    _register(client, claimant, "b3-claimant", "operator_one")
    _register(client, witness, "b3-witness", "operator_two")
    seed_id = "sab_seed_b3_grades"
    _submit_seed(client, claimant, seed_id)

    response = _witness_event(client, witness, seed_id, "affirm", {"attestation": "cross-operator affirm"})
    assert response.status_code == 201, response.text

    chain = client.get(f"/api/v1/seeds/{seed_id}/chain").json()
    affirm_events = [
        json.loads(event["payload_json"])
        for event in chain["state_events"]
        if event["event_type"] == "affirm"
    ]
    assert affirm_events, chain["state_events"]
    independence = affirm_events[-1]["independence"]
    # Register persisted both operator disclosures, so the grade is evidence-backed.
    assert independence["grade"] == "cross_operator_unverified"


def test_b3_witness_without_disclosure_grades_undisclosed(client: TestClient) -> None:
    claimant, witness = _Agent(), _Agent()
    _register(client, claimant, "b3-claimant-u", "operator_one")
    _register(client, witness, "b3-witness-u", "unknown")
    seed_id = "sab_seed_b3_undisclosed"
    _submit_seed(client, claimant, seed_id)

    response = _witness_event(client, witness, seed_id, "affirm", {"attestation": "undisclosed affirm"})
    assert response.status_code == 201, response.text
    chain = client.get(f"/api/v1/seeds/{seed_id}/chain").json()
    affirm_events = [
        json.loads(event["payload_json"])
        for event in chain["state_events"]
        if event["event_type"] == "affirm"
    ]
    assert affirm_events[-1]["independence"]["grade"] == "undisclosed"


def test_b4_composted_seed_is_absorbing(client: TestClient) -> None:
    claimant, witness = _Agent(), _Agent()
    _register(client, claimant, "b4-claimant", "operator_one")
    _register(client, witness, "b4-witness", "operator_two")
    seed_id = "sab_seed_b4_compost"
    _submit_seed(client, claimant, seed_id)
    _withdraw_seed(client, claimant, seed_id)

    affirm = _witness_event(client, witness, seed_id, "affirm", {"attestation": "resurrection attempt"})
    assert affirm.status_code == 409, affirm.text
    assert "final" in affirm.text

    challenge = _submit_challenge(
        client,
        witness,
        seed_id,
        "sab_challenge_b4_compost",
        expect_status=409,
    )
    assert "final" in json.dumps(challenge)

    assert client.get(f"/api/v1/seeds/{seed_id}").json()["state"] == "compost"


def test_b4_parties_cannot_adjudicate_their_own_challenge(client: TestClient) -> None:
    claimant, challenger = _Agent(), _Agent()
    _register(client, claimant, "b4-role-claimant", "operator_one")
    _register(client, challenger, "b4-role-challenger", "operator_two")
    seed_id = "sab_seed_b4_roles"
    _submit_seed(client, claimant, seed_id)
    challenge_id = "sab_challenge_b4_roles"
    _submit_challenge(client, challenger, seed_id, challenge_id)

    rejected = _challenge_action(client, claimant, challenge_id, "reject", {"value": "self-serving reject"})
    assert rejected.status_code == 403, rejected.text

    sustained = _challenge_action(client, challenger, challenge_id, "sustain", {"value": "self-serving sustain"})
    assert sustained.status_code == 403, sustained.text

    responded_by_challenger = _challenge_action(client, challenger, challenge_id, "respond", {"value": "not yours"})
    assert responded_by_challenger.status_code == 403, responded_by_challenger.text

    responded = _challenge_action(client, claimant, challenge_id, "respond", {"value": "narrowed"})
    assert responded.status_code == 201, responded.text


def test_b4_reserved_event_types_rejected_on_witness_endpoint(client: TestClient) -> None:
    claimant = _Agent()
    _register(client, claimant, "b4-reserved", "operator_one")
    seed_id = "sab_seed_b4_reserved"
    _submit_seed(client, claimant, seed_id)
    for event_type in ("canon", "compost", "standing_issued", "revoked", "expired"):
        response = _witness_event(client, claimant, seed_id, event_type, {"attempt": event_type})
        assert response.status_code == 403, f"{event_type}: {response.text}"


def test_b5_challenge_window_closed_refuses_new_challenges(client: TestClient) -> None:
    claimant, challenger = _Agent(), _Agent()
    _register(client, claimant, "b5-claimant", "operator_one")
    _register(client, challenger, "b5-challenger", "operator_two")
    seed_id = "sab_seed_b5_window"
    seed = _submit_seed(client, claimant, seed_id, challenge_window="P0D")
    assert seed["challenge_window_closes_at"] is not None

    body = _submit_challenge(
        client,
        challenger,
        seed_id,
        "sab_challenge_b5_late",
        expect_status=409,
    )
    assert "window" in json.dumps(body)


def test_b5_pending_challenge_past_respond_by_sustains_by_default(client: TestClient) -> None:
    claimant, challenger = _Agent(), _Agent()
    _register(client, claimant, "b5-default-claimant", "operator_one")
    _register(client, challenger, "b5-default-challenger", "operator_two")
    seed_id = "sab_seed_b5_default"
    _submit_seed(client, claimant, seed_id)
    challenge_id = "sab_challenge_b5_default"
    _submit_challenge(
        client,
        challenger,
        seed_id,
        challenge_id,
        deadline=_iso(_now() - timedelta(hours=1)),
    )

    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    assert seed["state"] == "compost"
    challenge = client.get(f"/api/v1/challenges/{challenge_id}").json()
    assert challenge["status"] == "sustained_by_default"


def test_b5_responded_challenge_past_prosecute_by_lapses(client: TestClient) -> None:
    claimant, challenger = _Agent(), _Agent()
    _register(client, claimant, "b5-lapse-claimant", "operator_one")
    _register(client, challenger, "b5-lapse-challenger", "operator_two")
    seed_id = "sab_seed_b5_lapse"
    _submit_seed(client, claimant, seed_id)
    challenge_id = "sab_challenge_b5_lapse"
    _submit_challenge(
        client,
        challenger,
        seed_id,
        challenge_id,
        prosecute_by=_iso(_now() - timedelta(hours=1)),
    )
    responded = _challenge_action(client, claimant, challenge_id, "respond", {"value": "narrowed scope"})
    assert responded.status_code == 201, responded.text

    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    assert seed["state"] == "corrected"
    challenge = client.get(f"/api/v1/challenges/{challenge_id}").json()
    assert challenge["status"] == "lapsed"


def test_b6_single_operator_standing_capped_at_provisional(client: TestClient) -> None:
    claimant, challenger, witness = _Agent(), _Agent(), _Agent()
    for agent, label in ((claimant, "b6-claimant"), (challenger, "b6-challenger"), (witness, "b6-witness")):
        _register(client, agent, label, "operator_one")
    seed_id = "sab_seed_b6_single"
    _submit_seed(client, claimant, seed_id)
    challenge_id = "sab_challenge_b6_single"
    _submit_challenge(client, challenger, seed_id, challenge_id)
    responded = _challenge_action(client, claimant, challenge_id, "respond", {"value": "narrowed"})
    assert responded.status_code == 201, responded.text
    affirm = _witness_event(client, witness, seed_id, "affirm", {"attestation": "same-operator affirm"})
    assert affirm.status_code == 201, affirm.text

    review = _review_standing(client, witness, seed_id, "sab_standing_b6_single")
    assert review.status_code == 201, review.text
    body = review.json()
    assert body["status"] == "provisional"
    assert body["issued_under"]["tier"] == "provisional"
    assert body["issued_under"]["rehearsal_flag"] == "single_operator_rehearsal"


def test_b6_gate_passes_with_three_disclosed_operators(client: TestClient) -> None:
    claimant, challenger, witness_b, witness_c = _Agent(), _Agent(), _Agent(), _Agent()
    _register(client, claimant, "b6-multi-claimant", "operator_one")
    _register(client, challenger, "b6-multi-challenger", "operator_two")
    _register(client, witness_b, "b6-multi-witness-b", "operator_two")
    _register(client, witness_c, "b6-multi-witness-c", "operator_three")
    seed_id = "sab_seed_b6_multi"
    _submit_seed(client, claimant, seed_id)
    challenge_id = "sab_challenge_b6_multi"
    _submit_challenge(client, challenger, seed_id, challenge_id)
    responded = _challenge_action(client, claimant, challenge_id, "respond", {"value": "narrowed"})
    assert responded.status_code == 201, responded.text
    # witness_c is cross-operator vs both parties, so may adjudicate.
    rejected = _challenge_action(client, witness_c, challenge_id, "reject", {"value": "narrowing suffices"})
    assert rejected.status_code == 201, rejected.text

    for witness in (witness_b, witness_c):
        affirm = _witness_event(client, witness, seed_id, "affirm", {"attestation": "cross-operator affirm"})
        assert affirm.status_code == 201, affirm.text

    review = _review_standing(client, witness_c, seed_id, "sab_standing_b6_multi")
    assert review.status_code == 201, review.text
    body = review.json()
    assert body["status"] == "active"
    assert body["issued_under"]["tier"] == "active"
    assert body["issued_under"]["rehearsal_flag"] == "multi_operator"

    # Canon still requires cross_operator_attested evidence, which cannot be
    # self-declared, so single-signature canon remains unreachable.
    created_at = _iso(_now())
    action_payload = {"reason": "promote", "evidence": {}}
    message = {
        "kind": "sab_standing_revalidate",
        "standing_id": "sab_standing_b6_multi",
        "actor_identity": witness_c.subject_id,
        "payload_sha256": _sha256_obj(action_payload),
        "created_at": created_at,
    }
    canon_attempt = client.post(
        "/api/v1/standing/sab_standing_b6_multi/revalidate",
        json={
            "actor_identity": witness_c.subject_id,
            "created_at": created_at,
            "reason": "promote",
            "evidence": {},
            "promote_to_canon": True,
            "signature": witness_c.sign(message),
        },
    )
    assert canon_attempt.status_code == 409, canon_attempt.text
