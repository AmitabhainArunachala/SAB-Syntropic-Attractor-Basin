"""Regression lock for the Demonstration Zero dogfood loop (2026-07-05).

Extends the historical API sequence receipted under
docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood/
against a temporary database: register x3 -> seed -> challenge -> respond
(scope narrowing) -> explicit adjudication -> witness affirm -> chain verify
-> standing lease review, now under authentic exact seed permissions and an
explicitly synthetic control review for adjudication. This runner owns every
fixture key; no actual cross-operator independence follows.

D1 (registration/canonical identity round trip) and D2
(witness_plan.forbidden_witnesses enforcement) are locked as real regression
tests below.
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
from operator_control_fixtures import adjudication_assessment

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
    from authority_fixtures import provision_authority_policy
    from operator_control_fixtures import provision_operator_policy
    authority = provision_authority_policy(tmp_path, monkeypatch)
    control = provision_operator_policy(tmp_path, monkeypatch)
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]
    module = importlib.import_module("agora.app")
    module.authority_test_fixture = authority
    module.operator_control_test_fixture = control
    return module


@pytest.fixture
def client(sab_app):
    with TestClient(sab_app.app) as test_client:
        sab_app.authority_test_fixture.enroll(test_client)
        sab_app.operator_control_test_fixture.enroll(test_client)
        yield test_client


def _register(client: TestClient, agent: _Agent, label: str) -> dict[str, Any]:
    from keycontrol_fixtures import enroll_identity

    body = enroll_identity(
        client,
        agent.key,
        {
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
        "authority_lease": client.authority.reference(claimant.subject_id, seed_id),
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
    client.authority.issue(client, claimant.subject_id, seed_id, ["submit_seed", "respond_challenge"])
    client.authority.issue(client, challenger.subject_id, seed_id, ["submit_challenge"])
    client.authority.issue(client, witness.subject_id, seed_id, ["adjudicate_challenge", "submit_witness_event", "request_standing_review"])
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
        "authority_lease": client.authority.reference(challenger.subject_id, seed_id),
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

    adjudication = {"value": "The scoped correction resolves the challenged breadth in this rehearsal",
                    "operator_control_assessment": adjudication_assessment(
                        client, seed_id, challenge_id, witness.subject_id)}
    reviewed_at = _iso(_now())
    adjudication_message = {"kind": "sab_challenge_reject", "challenge_id": challenge_id,
                           "actor_identity": witness.subject_id, "payload_sha256": _sha256_obj(adjudication),
                           "created_at": reviewed_at}
    resolved = client.post(f"/api/v1/challenges/{challenge_id}/reject", json={
        "actor_identity": witness.subject_id, "reason": adjudication, "created_at": reviewed_at,
        "signature": witness.sign(adjudication_message),
    })
    assert resolved.status_code == 201, resolved.text
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
    assert verify["entry_count"] == 5  # submit, challenge, response, adjudication, affirm

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
    # No complete signed standing basis: the adjudication review cannot promote it.
    assert standing.json()["status"] == "provisional"
    assert standing.json()["issued_under"]["rehearsal_flag"] == "unestablished_operator_control"

    final_seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    assert final_seed["state"] == "standing_active"


def test_register_response_round_trips_through_canonical_identity_model(client: TestClient) -> None:
    from agora.sab_identity import AgentIdentityV1, subject_id_from_public_key

    agent = _Agent()
    body = _register(client, agent, "dogfood-regression-identity")
    identity = AgentIdentityV1.model_validate(body)

    assert identity.subject_id == subject_id_from_public_key(agent.public_key)
    assert len(identity.subject_id.removeprefix("agent_ed25519_")) == 32
    assert identity.identity_ref == f"sab_identity_{identity.subject_id}"


def test_register_preserves_existing_named_legacy_subject(client: TestClient, sab_app) -> None:
    from agora.sab_identity import AgentIdentityV1
    from keycontrol_fixtures import enroll_identity, historical_identity

    agent = _Agent()
    legacy_subject = "agent_claude_fable_5"
    legacy_ref = f"sab_identity_{legacy_subject}"
    registration = {
        "subject_id": legacy_subject,
        "identity_ref": legacy_ref,
        "display_name": "Fable legacy identity",
        "identity_rail": "ed25519",
        "public_key": agent.public_key,
        "controller": "operator",
        "operator_backing": {
            "operator_id": "operator_dogfood_regression",
            "operator_kind": "human",
            "disclosure": "explicit legacy subject compatibility fixture",
            "backing_count_attestation": "self_attested",
        },
        "external_attestations": [],
    }
    before = historical_identity(sab_app, registration)
    proved = enroll_identity(client, agent.key, registration)
    assert proved == before
    identity = AgentIdentityV1.model_validate(proved)
    assert identity.subject_id == legacy_subject
    assert identity.identity_ref == legacy_ref


def test_register_rejects_noncanonical_ed25519_subject_alias(client: TestClient) -> None:
    agent = _Agent()
    obsolete_subject = f"agent_ed25519_{hashlib.sha256(agent.public_key.encode()).hexdigest()[:16]}"
    response = client.post(
        "/api/v1/agents/challenge",
        json={
            "action": "register",
            "registration": {
                "subject_id": obsolete_subject,
                "display_name": "obsolete sixteen character identity",
                "identity_rail": "ed25519",
                "public_key": agent.public_key,
                "controller": "operator",
                "operator_backing": {
                    "operator_id": "operator_dogfood_regression",
                    "operator_kind": "human",
                    "disclosure": "negative canonical namespace fixture",
                    "backing_count_attestation": "self_attested",
                },
                "external_attestations": [],
            },
        },
    )

    assert response.status_code in {400, 422}, response.text
    rejected_home = client.get(
        "/api/v1/agents/me/home",
        params={"subject_id": obsolete_subject},
    )
    assert rejected_home.status_code == 404


def test_claimant_self_witness_is_rejected_when_seed_forbids_it(client: TestClient) -> None:
    claimant = _Agent()
    _register(client, claimant, "dogfood-regression-self-witness")
    seed_id = "sab_seed_dogfood_self_witness"
    client.authority.issue(client, claimant.subject_id, seed_id, ["submit_seed", "submit_witness_event"])
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
