"""Regression lock for the Demonstration Zero dogfood loop (2026-07-05).

Replays the exact API sequence receipted under
docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood/
against a temporary database: register x3 -> seed -> challenge -> respond
(scope narrowing) -> witness affirm -> chain verify -> standing lease review.

Also documents, as an xfail, one remaining defect found during the run:
- D1: /api/v1/agents/register output is rejected by the canonical
  AgentIdentityV1 model (extra `identity_ref` field + subject_id derived with
  sha256[:16] in agora/sab_seeding_api.py vs [:32] in agora/sab_identity.py).

D2 (witness_plan.forbidden_witnesses unenforced) was closed by build 3;
its former xfail now runs as a real regression test below.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

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
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "dogfood_regression.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / ".dogfood_system_ed25519.key"))
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]
    return importlib.import_module("agora.app")


@pytest.fixture
def client(sab_app):
    with TestClient(sab_app.app) as test_client:
        yield test_client


def _register(client: TestClient, agent: _Agent, label: str) -> dict[str, Any]:
    response = client.post(
        "/api/v1/agents/register",
        json={
            "schema": "sab.agent_identity.v1",
            "display_name": label,
            "identity_rail": "ed25519",
            "public_key": agent.public_key,
            "controller": "operator",
            "operator_backing": {
                "operator_id": "operator_dogfood_regression",
                "operator_kind": "human",
                "disclosure": "single_operator_rehearsal regression fixture",
                "backing_count_attestation": "self_attested",
            },
            "external_attestations": [],
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    agent.subject_id = body["subject_id"]
    return body


def _submit_seed(client: TestClient, claimant: _Agent, seed_id: str, claim_id: str) -> dict[str, Any]:
    created_at = _iso(_now())
    packet: dict[str, Any] = {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "seed_type": "claim",
        "title": "Dogfood regression seed",
        "claim": {
            "claim_id": claim_id,
            "text": "Local pytest suite result at a pinned commit, single operator.",
            "scope": "this repo, this venv, one machine, single operator",
        },
        "claimant_identity": {"subject_id": claimant.subject_id},
        "authority_lease": {
            "lease_ref": f"sab_lease_{seed_id}_submit",
            "subject_id": claimant.subject_id,
            "purpose": "submit_seed",
            "scope": "submit one regression seed for witnessed challenge only",
            "expires_at": _iso(_now() + timedelta(days=14)),
            "revoker": "operator_dogfood_regression",
            "challenge_path": f"/api/v1/seeds/{seed_id}/challenges",
        },
        "challenge_plan": {"required": True, "challenge_window": "P7D"},
        "witness_plan": {
            "required_roles": ["challenger", "witness"],
            "minimum_witnesses": 1,
            "forbidden_witnesses": [claimant.subject_id],
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


def _witness_event_body(
    actor: _Agent, seed_id: str, event_type: str, payload: dict[str, Any], prev_hash: str
) -> dict[str, Any]:
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
    return {
        "event_type": event_type,
        "actor_identity": actor.subject_id,
        "subject_type": "seed",
        "subject_id": seed_id,
        "created_at": created_at,
        "payload": payload,
        "prev_hash": prev_hash,
        "signature": actor.sign(message),
    }


def test_dogfood_loop_seed_challenge_respond_witness_standing(client: TestClient) -> None:
    claimant, challenger, witness = _Agent(), _Agent(), _Agent()
    for agent, label in ((claimant, "claimant"), (challenger, "challenger"), (witness, "witness")):
        _register(client, agent, f"dogfood-regression-{label}")

    seed_id = "sab_seed_dogfood_regression"
    claim_id = "sab_claim_dogfood_regression"
    seed_body = _submit_seed(client, claimant, seed_id, claim_id)
    assert seed_body["state"] == "pending_seed"

    ch_created = _iso(_now())
    challenge_id = "sab_challenge_dogfood_regression"
    challenge_packet: dict[str, Any] = {
        "schema": "sab.challenge_packet.v1",
        "challenge_id": challenge_id,
        "target_seed_id": seed_id,
        "target_claim_id": claim_id,
        "challenger_identity": challenger.subject_id,
        "challenge_type": "scope",
        "challenge_text": (
            "This claim is too broad unless scoped to local repo/test environment and does not "
            "imply production readiness or cross-operator independence."
        ),
        "severity": "blocking",
        "created_at": ch_created,
    }
    challenge_message = {
        "kind": "sab_challenge_submit",
        "target_seed_id": seed_id,
        "target_claim_id": claim_id,
        "challenge_packet_sha256": _sha256_obj(challenge_packet),
        "challenger_identity": challenger.subject_id,
        "created_at": ch_created,
    }
    challenge_packet["signature"] = {
        "alg": "ed25519",
        "signer": challenger.subject_id,
        "signature": challenger.sign(challenge_message),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    challenge_response = client.post(f"/api/v1/seeds/{seed_id}/challenges", json=challenge_packet)
    assert challenge_response.status_code == 201, challenge_response.text
    assert challenge_response.json()["seed_state"] == "challenged"

    narrowed = {"response_type": "scope_narrowing", "narrowed_claim_text": "scoped to this repo/venv/commit only"}
    resp_created = _iso(_now())
    respond_message = {
        "kind": "sab_challenge_respond",
        "challenge_id": challenge_id,
        "actor_identity": claimant.subject_id,
        "payload_sha256": _sha256_obj(narrowed),
        "created_at": resp_created,
    }
    respond = client.post(
        f"/api/v1/challenges/{challenge_id}/respond",
        json={
            "challenge_id": challenge_id,
            "actor_identity": claimant.subject_id,
            "response": narrowed,
            "created_at": resp_created,
            "signature": claimant.sign(respond_message),
        },
    )
    assert respond.status_code == 201, respond.text
    assert respond.json()["seed_state"] == "corrected"

    chain = client.get(f"/api/v1/seeds/{seed_id}/chain").json()
    witness_body = _witness_event_body(
        witness,
        seed_id,
        "affirm",
        {"attestation": "replayed_command_and_observed_output", "matches_narrowed_claim": True},
        chain["head"],
    )
    witnessed = client.post("/api/v1/witness-events", json=witness_body)
    assert witnessed.status_code == 201, witnessed.text

    verify = client.get(f"/api/v1/witness/verify?seed_id={seed_id}").json()
    assert verify["verified"] is True
    assert verify["entry_count"] == 4  # submit, challenge, response, affirm

    issued_at = _iso(_now())
    standing_id = "sab_standing_dogfood_regression"
    lease: dict[str, Any] = {
        "standing_id": standing_id,
        "subject_seed_id": seed_id,
        "subject_claim_id": claim_id,
        "scope": "single_operator_rehearsal local receipt only",
        "purpose": "dogfood_regression",
        "expiry": _iso(_now() + timedelta(days=30)),
        "revoker": "operator_dogfood_regression",
        "challenge_path": f"/api/v1/standing/{standing_id}/challenge",
        "issued_by": witness.subject_id,
        "issued_at": issued_at,
    }
    standing_message = {
        "kind": "sab_standing_review",
        "standing_lease_sha256": _sha256_obj(lease),
        "subject_seed_id": seed_id,
        "reviewer_identity": witness.subject_id,
        "created_at": issued_at,
    }
    lease["signature"] = {
        "alg": "ed25519",
        "signer": witness.subject_id,
        "signature": witness.sign(standing_message),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    standing = client.post(
        "/api/v1/standing/review",
        json={"standing_lease": lease, "reviewer_identity": witness.subject_id, "created_at": issued_at},
    )
    assert standing.status_code == 201, standing.text
    # Independence Law cap (SAB_MASTER_VISION_V1 §6): one operator => provisional.
    assert standing.json()["status"] == "provisional"
    assert standing.json()["issued_under"]["rehearsal_flag"] == "single_operator_rehearsal"

    final_seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    assert final_seed["state"] == "standing_active"


@pytest.mark.xfail(
    strict=False,
    reason=(
        "D1: /api/v1/agents/register response is rejected by AgentIdentityV1 "
        "(extra identity_ref field; subject_id sha256[:16] in sab_seeding_api.py:_subject_id_for_public_key "
        "vs [:32] in sab_identity.py:subject_id_from_public_key)"
    ),
)
def test_register_response_round_trips_through_canonical_identity_model(client: TestClient) -> None:
    from agora.sab_identity import AgentIdentityV1

    agent = _Agent()
    body = _register(client, agent, "dogfood-regression-identity")
    AgentIdentityV1.model_validate(body)


def test_claimant_self_witness_is_rejected_when_seed_forbids_it(client: TestClient) -> None:
    claimant = _Agent()
    _register(client, claimant, "dogfood-regression-self-witness")
    seed_id = "sab_seed_dogfood_self_witness"
    _submit_seed(client, claimant, seed_id, "sab_claim_dogfood_self_witness")

    chain = client.get(f"/api/v1/seeds/{seed_id}/chain").json()
    body = _witness_event_body(
        claimant,
        seed_id,
        "affirm",
        {"attestation": "claimant witnessing its own seed despite forbidden_witnesses"},
        chain["head"],
    )
    response = client.post("/api/v1/witness-events", json=body)
    assert response.status_code in {400, 403, 409}, (
        f"self-witness was accepted with HTTP {response.status_code}: {response.text}"
    )
