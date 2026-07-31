from __future__ import annotations

import copy
import hashlib
import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest
from fastapi.testclient import TestClient
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _hash_json(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _reset_agora_modules() -> None:
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]


@pytest.fixture
def web_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "sab_seeding_api.db"
    key_path = tmp_path / ".sab_seeding_system_ed25519.key"
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(key_path))
    _reset_agora_modules()
    return importlib.import_module("agora.app")


@pytest.fixture
def client(web_app):
    with TestClient(web_app.app) as test_client:
        yield test_client


def _register(client: TestClient, sk: SigningKey, name: str) -> str:
    public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
    res = client.post("/api/agents/register", json={"name": name, "public_key": public_key})
    assert res.status_code == 201, res.text
    return str(res.json()["id"])


def _seed_packet(agent_id: str, *, seed_id: str = "sab_seed_test_001", expires_at: str | None = None) -> Dict[str, Any]:
    return {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "seed_type": "project",
        "title": f"Seed Packet {seed_id}",
        "status": "draft",
        "loop_position": "spark",
        "north_star": "deepen_truth",
        "claim": {
            "claim_id": f"sab_claim_{seed_id}",
            "text": f"Claim for {seed_id} survives challenge only inside this test scope.",
            "claim_type": "semantic",
            "scope": "test scope",
            "decision_context": "API state machine verification",
            "success_conditions": ["hash chain verifies"],
            "failure_conditions": ["signature or lease validation fails"],
        },
        "claimant_identity": {"subject_id": agent_id, "identity_ref": f"sab_identity_{agent_id}"},
        "operator_backing": {
            "operator_ref": "test-operator",
            "disclosure": "unit test",
            "concentration_attestation": "self_attested",
        },
        "authority_lease": {
            "lease_ref": f"sab_lease_{seed_id}",
            "scope": "submit one public test seed",
            "expires_at": expires_at or _future(),
            "revoker": agent_id,
            "challenge_path": "/api/v1/seeds/{seed_id}/challenges",
        },
        "evidence_bundle": [{"ref": "test://evidence", "kind": "test", "digest": "", "notes": "local"}],
        "challenge_plan": {
            "required": True,
            "challenge_window": "P7D",
            "strongest_objections": ["test objection"],
            "challenge_refs": [],
            "falsification_routes": ["submit challenge"],
        },
        "witness_plan": {
            "required_roles": ["tester"],
            "minimum_witnesses": 1,
            "non_adjacent_required": True,
            "forbidden_witnesses": [],
        },
        "build_plan": {"artifact_refs": ["test://artifact"], "production_grade_definition": "test only"},
        "anti_capture_rules": ["no self-standing without challenge"],
        "commons_return": {"mode": "public_receipt", "minimum_return": "test receipt"},
        "canon_compost_policy": {
            "canon_conditions": ["standing revalidates"],
            "compost_conditions": ["sustained blocking challenge"],
            "revalidation_due": _future(60),
        },
        "privacy_class": "public",
        "created_at": _now(),
    }


def _sign_seed(sk: SigningKey, packet: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
    unsigned = copy.deepcopy(packet)
    unsigned.pop("signature", None)
    message = {
        "kind": "sab_seed_submit",
        "seed_packet_sha256": _hash_json(unsigned),
        "claimant_identity": agent_id,
        "authority_lease_id": unsigned["authority_lease"]["lease_ref"],
        "created_at": unsigned["created_at"],
    }
    signed = copy.deepcopy(unsigned)
    signed["signature"] = {
        "alg": "ed25519",
        "signer": agent_id,
        "signature": sk.sign(_canonical_bytes(message)).signature.hex(),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return signed


def _submit_seed(client: TestClient, sk: SigningKey, agent_id: str, seed_id: str) -> Dict[str, Any]:
    packet = _sign_seed(sk, _seed_packet(agent_id, seed_id=seed_id), agent_id)
    res = client.post("/api/v1/seeds", json=packet)
    assert res.status_code == 201, res.text
    return res.json()


def _challenge_packet(
    sk: SigningKey,
    *,
    challenger_id: str,
    seed_id: str,
    claim_id: str,
    challenge_id: str,
) -> Dict[str, Any]:
    packet = {
        "schema": "sab.challenge_packet.v1",
        "challenge_id": challenge_id,
        "target_seed_id": seed_id,
        "target_claim_id": claim_id,
        "challenger_identity": challenger_id,
        "quoted_claim_fragment": "survives challenge",
        "challenge_type": "scope",
        "evidence": [{"ref": "test://challenge", "kind": "counterexample"}],
        "proposed_falsification_or_narrowing": "narrow the test scope",
        "severity": "medium",
        "deadline": _future(3),
        "created_at": _now(),
    }
    message = {
        "kind": "sab_challenge_submit",
        "target_seed_id": seed_id,
        "target_claim_id": claim_id,
        "challenge_packet_sha256": _hash_json(packet),
        "challenger_identity": challenger_id,
        "created_at": packet["created_at"],
    }
    packet["signature"] = {
        "alg": "ed25519",
        "signer": challenger_id,
        "signature": sk.sign(_canonical_bytes(message)).signature.hex(),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return packet


def _sign_challenge_action(
    sk: SigningKey,
    *,
    action: str,
    challenge_id: str,
    actor_identity: str,
    payload: Dict[str, Any],
    created_at: str,
) -> str:
    message = {
        "kind": f"sab_challenge_{action}",
        "challenge_id": challenge_id,
        "actor_identity": actor_identity,
        "payload_sha256": _hash_json(payload),
        "created_at": created_at,
    }
    return sk.sign(_canonical_bytes(message)).signature.hex()


def _submit_challenge(
    client: TestClient,
    sk: SigningKey,
    *,
    challenger_id: str,
    seed_id: str,
    claim_id: str,
    challenge_id: str,
) -> Dict[str, Any]:
    packet = _challenge_packet(
        sk,
        challenger_id=challenger_id,
        seed_id=seed_id,
        claim_id=claim_id,
        challenge_id=challenge_id,
    )
    res = client.post(f"/api/v1/seeds/{seed_id}/challenges", json=packet)
    assert res.status_code == 201, res.text
    return res.json()


def _sign_witness(
    sk: SigningKey,
    *,
    event_type: str,
    subject_type: str,
    subject_id: str,
    payload: Dict[str, Any],
    prev_hash: str,
    created_at: str,
) -> str:
    message = {
        "kind": "sab_witness_event",
        "event_type": event_type,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "payload_hash": _hash_json(payload),
        "prev_hash": prev_hash,
        "created_at": created_at,
    }
    return sk.sign(_canonical_bytes(message)).signature.hex()


def _standing_lease(
    *,
    standing_id: str,
    seed_id: str,
    claim_id: str,
    reviewer_id: str,
) -> Dict[str, Any]:
    return {
        "schema": "sab.standing_lease.v1",
        "standing_id": standing_id,
        "subject_seed_id": seed_id,
        "subject_claim_id": claim_id,
        "scope": "test standing scope",
        "purpose": "test reliance only",
        "allowed_reliance": ["test assertions"],
        "forbidden_reliance": ["production deployment"],
        "expiry": _future(30),
        "revoker": reviewer_id,
        "challenge_path": f"/api/v1/standing/{standing_id}/challenge",
        "challenge_summary": [],
        "witness_quorum": {"minimum_witnesses": 1, "witnesses": [], "diversity_policy": "test"},
        "status": "provisional",
        "revalidation_policy": "manual test revalidation",
        "machine_readable_evidence_bundle": ["test://standing"],
        "issued_at": _now(),
        "issued_by": reviewer_id,
        "policy_hash": "sha256:test",
    }


def _sign_standing_review(sk: SigningKey, lease: Dict[str, Any], reviewer_id: str) -> Dict[str, Any]:
    unsigned = copy.deepcopy(lease)
    unsigned.pop("signature", None)
    message = {
        "kind": "sab_standing_review",
        "standing_lease_sha256": _hash_json(unsigned),
        "subject_seed_id": unsigned["subject_seed_id"],
        "reviewer_identity": reviewer_id,
        "created_at": unsigned["issued_at"],
    }
    signed = copy.deepcopy(unsigned)
    signed["signature"] = {
        "alg": "ed25519",
        "signer": reviewer_id,
        "signature": sk.sign(_canonical_bytes(message)).signature.hex(),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return signed


def _sign_standing_action(
    sk: SigningKey,
    *,
    action: str,
    standing_id: str,
    actor_identity: str,
    reason: str,
    evidence: Dict[str, Any],
    created_at: str,
) -> str:
    message = {
        "kind": f"sab_standing_{action}",
        "standing_id": standing_id,
        "actor_identity": actor_identity,
        "payload_sha256": _hash_json({"reason": reason, "evidence": evidence}),
        "created_at": created_at,
    }
    return sk.sign(_canonical_bytes(message)).signature.hex()


def test_seed_submit_fetch_list_chain_and_projection(client: TestClient) -> None:
    sk = SigningKey.generate()
    agent_id = _register(client, sk, "seed-author")
    packet = _sign_seed(sk, _seed_packet(agent_id), agent_id)

    submit = client.post("/api/v1/seeds", json=packet)

    assert submit.status_code == 201, submit.text
    body = submit.json()
    assert body["accepted"] is True
    assert body["seed_id"] == "sab_seed_test_001"
    assert body["state"] == "pending_seed"
    assert isinstance(body["spark_projection_id"], int)
    assert body["witness_head"] != "genesis"

    fetched = client.get("/api/v1/seeds/sab_seed_test_001")
    assert fetched.status_code == 200
    assert fetched.json()["state"] == "pending_seed"
    assert fetched.json()["seed_packet"]["claimant_identity"]["subject_id"] == agent_id

    listed = client.get(f"/api/v1/seeds?claimant={agent_id}")
    assert listed.status_code == 200
    assert [item["seed_id"] for item in listed.json()["items"]] == ["sab_seed_test_001"]

    chain = client.get("/api/v1/seeds/sab_seed_test_001/chain")
    assert chain.status_code == 200
    chain_body = chain.json()
    assert chain_body["verified"] is True
    assert chain_body["entries"][0]["event_type"] == "submit"


def test_seed_submit_rejects_invalid_signature_and_bad_leases(client: TestClient) -> None:
    sk = SigningKey.generate()
    agent_id = _register(client, sk, "seed-author-bad")

    bad_sig_packet = _sign_seed(sk, _seed_packet(agent_id, seed_id="sab_seed_bad_sig"), agent_id)
    bad_sig_packet["signature"]["signature"] = "00" * 64
    bad_sig = client.post("/api/v1/seeds", json=bad_sig_packet)
    assert bad_sig.status_code == 400
    assert "Invalid Ed25519 signature" in bad_sig.text

    missing_lease = _seed_packet(agent_id, seed_id="sab_seed_missing_lease")
    missing_lease.pop("authority_lease")
    missing_lease["signature"] = {
        "alg": "ed25519",
        "signer": agent_id,
        "signature": "00" * 64,
        "canonicalization": "json-sort-keys-compact-v1",
    }
    missing = client.post("/api/v1/seeds", json=missing_lease)
    assert missing.status_code == 400
    assert "authority_lease" in missing.text

    expired_packet = _sign_seed(
        sk,
        _seed_packet(agent_id, seed_id="sab_seed_expired", expires_at=_past()),
        agent_id,
    )
    expired = client.post("/api/v1/seeds", json=expired_packet)
    assert expired.status_code == 400
    assert "expired" in expired.text


def test_challenge_respond_sustain_reject_and_seed_correct(client: TestClient) -> None:
    author_sk = SigningKey.generate()
    challenger_sk = SigningKey.generate()
    reviewer_sk = SigningKey.generate()
    author = _register(client, author_sk, "challenge-author")
    challenger = _register(client, challenger_sk, "challenge-agent")
    reviewer = _register(client, reviewer_sk, "challenge-reviewer")

    _submit_seed(client, author_sk, author, "sab_seed_respond")
    seed = client.get("/api/v1/seeds/sab_seed_respond").json()
    challenge = _submit_challenge(
        client,
        challenger_sk,
        challenger_id=challenger,
        seed_id="sab_seed_respond",
        claim_id=seed["claim_id"],
        challenge_id="sab_challenge_respond",
    )
    assert challenge["status"] == "pending"
    assert challenge["seed_state"] == "challenged"

    response_payload = {"text": "Narrowed response with correction."}
    created_at = _now()
    response_sig = _sign_challenge_action(
        author_sk,
        action="respond",
        challenge_id="sab_challenge_respond",
        actor_identity=author,
        payload=response_payload,
        created_at=created_at,
    )
    response = client.post(
        "/api/v1/challenges/sab_challenge_respond/respond",
        json={
            "actor_identity": author,
            "created_at": created_at,
            "response": response_payload,
            "signature": response_sig,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["challenge"]["status"] == "responded"
    assert response.json()["seed_state"] == "corrected"

    correction = {"patch": "explicit correction artifact"}
    created_at = _now()
    correction_sig = reviewer_sk.sign(
        _canonical_bytes(
            {
                "kind": "sab_seed_correct",
                "target_seed_id": "sab_seed_respond",
                "actor_identity": reviewer,
                "correction_sha256": _hash_json(correction),
                "created_at": created_at,
            }
        )
    ).signature.hex()
    non_claimant_corrected = client.post(
        "/api/v1/seeds/sab_seed_respond/correct",
        json={
            "actor_identity": reviewer,
            "created_at": created_at,
            "correction": correction,
            "signature": correction_sig,
        },
    )
    assert non_claimant_corrected.status_code == 403, non_claimant_corrected.text

    created_at = _now()
    author_correction_sig = author_sk.sign(
        _canonical_bytes(
            {
                "kind": "sab_seed_correct",
                "target_seed_id": "sab_seed_respond",
                "actor_identity": author,
                "correction_sha256": _hash_json(correction),
                "created_at": created_at,
            }
        )
    ).signature.hex()
    corrected = client.post(
        "/api/v1/seeds/sab_seed_respond/correct",
        json={
            "actor_identity": author,
            "created_at": created_at,
            "correction": correction,
            "signature": author_correction_sig,
        },
    )
    assert corrected.status_code == 200, corrected.text
    assert corrected.json()["state"] == "corrected"

    _submit_seed(client, author_sk, author, "sab_seed_sustain")
    seed = client.get("/api/v1/seeds/sab_seed_sustain").json()
    _submit_challenge(
        client,
        challenger_sk,
        challenger_id=challenger,
        seed_id="sab_seed_sustain",
        claim_id=seed["claim_id"],
        challenge_id="sab_challenge_sustain",
    )
    reason_payload = {"value": "blocking challenge sustained"}
    created_at = _now()
    sustain_sig = _sign_challenge_action(
        reviewer_sk,
        action="sustain",
        challenge_id="sab_challenge_sustain",
        actor_identity=reviewer,
        payload=reason_payload,
        created_at=created_at,
    )
    sustained = client.post(
        "/api/v1/challenges/sab_challenge_sustain/sustain",
        json={
            "actor_identity": reviewer,
            "created_at": created_at,
            "reason": reason_payload["value"],
            "signature": sustain_sig,
        },
    )
    assert sustained.status_code == 201, sustained.text
    assert sustained.json()["challenge"]["status"] == "sustained"
    assert sustained.json()["seed_state"] == "compost"

    _submit_seed(client, author_sk, author, "sab_seed_reject")
    seed = client.get("/api/v1/seeds/sab_seed_reject").json()
    _submit_challenge(
        client,
        challenger_sk,
        challenger_id=challenger,
        seed_id="sab_seed_reject",
        claim_id=seed["claim_id"],
        challenge_id="sab_challenge_reject",
    )
    created_at = _now()
    reject_sig = _sign_challenge_action(
        reviewer_sk,
        action="reject",
        challenge_id="sab_challenge_reject",
        actor_identity=reviewer,
        payload={"value": "challenge does not falsify the scoped claim"},
        created_at=created_at,
    )
    rejected = client.post(
        "/api/v1/challenges/sab_challenge_reject/reject",
        json={
            "actor_identity": reviewer,
            "created_at": created_at,
            "reason": "challenge does not falsify the scoped claim",
            "signature": reject_sig,
        },
    )
    assert rejected.status_code == 201, rejected.text
    assert rejected.json()["challenge"]["status"] == "rejected"
    assert rejected.json()["seed_state"] == "challenge_window_open"


def test_witness_and_standing_surfaces_verify_chain(client: TestClient) -> None:
    author_sk = SigningKey.generate()
    challenger_sk = SigningKey.generate()
    reviewer_sk = SigningKey.generate()
    author = _register(client, author_sk, "standing-author")
    challenger = _register(client, challenger_sk, "standing-challenger")
    reviewer = _register(client, reviewer_sk, "standing-reviewer")

    _submit_seed(client, author_sk, author, "sab_seed_standing")
    seed = client.get("/api/v1/seeds/sab_seed_standing").json()
    _submit_challenge(
        client,
        challenger_sk,
        challenger_id=challenger,
        seed_id="sab_seed_standing",
        claim_id=seed["claim_id"],
        challenge_id="sab_challenge_standing",
    )
    created_at = _now()
    reject_sig = _sign_challenge_action(
        reviewer_sk,
        action="reject",
        challenge_id="sab_challenge_standing",
        actor_identity=reviewer,
        payload={"value": "resolved for standing review"},
        created_at=created_at,
    )
    reject = client.post(
        "/api/v1/challenges/sab_challenge_standing/reject",
        json={
            "actor_identity": reviewer,
            "created_at": created_at,
            "reason": "resolved for standing review",
            "signature": reject_sig,
        },
    )
    assert reject.status_code == 201, reject.text

    prev_hash = client.get("/api/v1/seeds/sab_seed_standing/chain").json()["head"]
    witness_payload = {"reason": "challenge path witnessed"}
    created_at = _now()
    witness_sig = _sign_witness(
        reviewer_sk,
        event_type="affirm",
        subject_type="seed",
        subject_id="sab_seed_standing",
        payload=witness_payload,
        prev_hash=prev_hash,
        created_at=created_at,
    )
    witness = client.post(
        "/api/v1/witness-events",
        json={
            "event_type": "affirm",
            "actor_identity": reviewer,
            "subject_type": "seed",
            "subject_id": "sab_seed_standing",
            "created_at": created_at,
            "prev_hash": prev_hash,
            "payload": witness_payload,
            "signature": witness_sig,
        },
    )
    assert witness.status_code == 201, witness.text
    witness_event_id = witness.json()["event_id"]
    assert client.get(f"/api/v1/witness-events/{witness_event_id}").status_code == 200
    assert client.get("/api/v1/witness/verify?seed_id=sab_seed_standing").json()["verified"] is True
    assert client.get("/api/v1/seeds/sab_seed_standing").json()["state"] == "witnessed"

    lease = _sign_standing_review(
        reviewer_sk,
        _standing_lease(
            standing_id="sab_standing_test",
            seed_id="sab_seed_standing",
            claim_id=seed["claim_id"],
            reviewer_id=reviewer,
        ),
        reviewer,
    )
    review = client.post("/api/v1/standing/review", json=lease)
    assert review.status_code == 201, review.text
    # Independence Law cap: no disclosed independent operators => provisional.
    assert review.json()["status"] == "provisional"
    assert client.get("/api/v1/seeds/sab_seed_standing").json()["state"] == "standing_active"

    standing = client.get("/api/v1/standing/sab_standing_test")
    assert standing.status_code == 200
    assert standing.json()["standing_id"] == "sab_standing_test"
    listed = client.get("/api/v1/standing?subject=sab_seed_standing")
    assert listed.status_code == 200
    assert listed.json()["items"][0]["standing_id"] == "sab_standing_test"

    created_at = _now()
    canon_sig = _sign_standing_action(
        reviewer_sk,
        action="revalidate",
        standing_id="sab_standing_test",
        actor_identity=reviewer,
        reason="canon-ready after witnessed challenge",
        evidence={"review": "ok"},
        created_at=created_at,
    )
    canon_attempt = client.post(
        "/api/v1/standing/sab_standing_test/revalidate",
        json={
            "actor_identity": reviewer,
            "created_at": created_at,
            "reason": "canon-ready after witnessed challenge",
            "evidence": {"review": "ok"},
            "promote_to_canon": True,
            "signature": canon_sig,
        },
    )
    # Canon is never reachable from a single signature: quorum gate required.
    assert canon_attempt.status_code == 409, canon_attempt.text

    created_at = _now()
    revalidate_sig = _sign_standing_action(
        reviewer_sk,
        action="revalidate",
        standing_id="sab_standing_test",
        actor_identity=reviewer,
        reason="revalidated within provisional cap",
        evidence={"review": "ok"},
        created_at=created_at,
    )
    revalidated = client.post(
        "/api/v1/standing/sab_standing_test/revalidate",
        json={
            "actor_identity": reviewer,
            "created_at": created_at,
            "reason": "revalidated within provisional cap",
            "evidence": {"review": "ok"},
            "signature": revalidate_sig,
        },
    )
    assert revalidated.status_code == 200, revalidated.text
    assert revalidated.json()["standing"]["status"] == "provisional"
    assert revalidated.json()["seed_state"] == "standing_active"

    created_at = _now()
    challenge_sig = _sign_standing_action(
        challenger_sk,
        action="challenge",
        standing_id="sab_standing_test",
        actor_identity=challenger,
        reason="standing should be checked again",
        evidence={},
        created_at=created_at,
    )
    standing_challenge = client.post(
        "/api/v1/standing/sab_standing_test/challenge",
        json={
            "actor_identity": challenger,
            "created_at": created_at,
            "reason": "standing should be checked again",
            "signature": challenge_sig,
        },
    )
    assert standing_challenge.status_code == 200, standing_challenge.text
    assert standing_challenge.json()["standing"]["status"] == "challenged"
    assert standing_challenge.json()["seed_state"] == "challenged"

    created_at = _now()
    revoke_sig = _sign_standing_action(
        reviewer_sk,
        action="revoke",
        standing_id="sab_standing_test",
        actor_identity=reviewer,
        reason="revocation path is explicit",
        evidence={},
        created_at=created_at,
    )
    revoked = client.post(
        "/api/v1/standing/sab_standing_test/revoke",
        json={
            "actor_identity": reviewer,
            "created_at": created_at,
            "reason": "revocation path is explicit",
            "signature": revoke_sig,
        },
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["standing"]["status"] == "revoked"
    assert revoked.json()["seed_state"] == "revoked"
