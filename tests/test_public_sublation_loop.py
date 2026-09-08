from __future__ import annotations

import hashlib
import importlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _canonical_bytes(payload: Dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sign_submit(sk: SigningKey, agent_id: str, content: str) -> str:
    content_sha = hashlib.sha256(content.encode()).hexdigest()
    payload = {
        "kind": "spark_submit",
        "author_id": agent_id,
        "content_sha256": content_sha,
    }
    return sk.sign(_canonical_bytes(payload)).signature.hex()


def _sign_challenge(sk: SigningKey, spark_id: int, challenger_id: str, content: str) -> str:
    content_sha = hashlib.sha256(content.encode()).hexdigest()
    payload = {
        "kind": "spark_challenge",
        "spark_id": spark_id,
        "challenger_id": challenger_id,
        "content_sha256": content_sha,
    }
    return sk.sign(_canonical_bytes(payload)).signature.hex()


def _sign_sublation(
    sk: SigningKey,
    *,
    challenge_id: int,
    predecessor_spark_id: int,
    corrector_id: str,
    corrected_content: str,
    artifact_ref: str = "",
    note: str = "",
) -> str:
    payload = {
        "kind": "spark_challenge_sublation",
        "challenge_id": challenge_id,
        "predecessor_spark_id": predecessor_spark_id,
        "corrector_id": corrector_id,
        "successor_content_sha256": hashlib.sha256(corrected_content.encode()).hexdigest(),
        "artifact_ref_sha256": hashlib.sha256(artifact_ref.encode()).hexdigest(),
        "note_sha256": hashlib.sha256(note.encode()).hexdigest(),
    }
    return sk.sign(_canonical_bytes(payload)).signature.hex()


def _sign_witness(sk: SigningKey, spark_id: int, witness_id: str, action: str, payload: Dict[str, object]) -> str:
    payload_sha = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    envelope = {
        "kind": "witness_attestation",
        "spark_id": spark_id,
        "witness_id": witness_id,
        "action": action,
        "payload_sha256": payload_sha,
    }
    return sk.sign(_canonical_bytes(envelope)).signature.hex()


def _register(client: TestClient, sk: SigningKey, name: str) -> str:
    public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
    res = client.post("/api/agents/register", json={"name": name, "public_key": public_key})
    assert res.status_code == 201, res.text
    return str(res.json()["id"])


def _submit_spark(client: TestClient, sk: SigningKey, author_id: str, content: str) -> int:
    res = client.post(
        "/api/spark/submit",
        json={
            "content": content,
            "content_type": "text",
            "author_id": author_id,
            "signature": _sign_submit(sk, author_id, content),
        },
    )
    assert res.status_code == 201, res.text
    return int(res.json()["id"])


def _challenge_spark(
    client: TestClient,
    sk: SigningKey,
    challenger_id: str,
    spark_id: int,
    content: str,
) -> Dict[str, Any]:
    res = client.post(
        f"/api/spark/{spark_id}/challenge",
        json={
            "challenger_id": challenger_id,
            "content": content,
            "signature": _sign_challenge(sk, spark_id, challenger_id, content),
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def _sublate_challenge(
    client: TestClient,
    sk: SigningKey,
    corrector_id: str,
    spark_id: int,
    challenge_id: int,
    corrected_content: str,
    artifact_ref: str,
    note: str,
) -> Dict[str, Any]:
    res = client.post(
        f"/api/spark/{spark_id}/challenge/{challenge_id}/sublate",
        json={
            "corrector_id": corrector_id,
            "corrected_content": corrected_content,
            "content_type": "text",
            "artifact_ref": artifact_ref,
            "note": note,
            "signature": _sign_sublation(
                sk,
                challenge_id=challenge_id,
                predecessor_spark_id=spark_id,
                corrector_id=corrector_id,
                corrected_content=corrected_content,
                artifact_ref=artifact_ref,
                note=note,
            ),
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def _affirm(client: TestClient, sk: SigningKey, witness_id: str, spark_id: int, reason: str) -> Dict[str, Any]:
    payload = {"reason": reason}
    res = client.post(
        "/api/witness/sign",
        json={
            "spark_id": spark_id,
            "witness_id": witness_id,
            "action": "affirm",
            "payload": payload,
            "signature": _sign_witness(sk, spark_id, witness_id, "affirm", payload),
        },
    )
    assert res.status_code == 200, res.text
    return res.json()


@pytest.fixture
def spark_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "public_sublation.db"
    key_path = tmp_path / ".public_sublation_system_ed25519.key"
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(key_path))

    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]

    return importlib.import_module("agora.app")


@pytest.fixture
def client(spark_app):
    with TestClient(spark_app.app) as test_client:
        yield test_client


def test_pending_challenge_blocks_canon_quorum(client: TestClient) -> None:
    sks = [SigningKey.generate() for _ in range(5)]
    agents = [_register(client, sk, f"block-{idx}") for idx, sk in enumerate(sks)]
    spark_id = _submit_spark(
        client,
        sks[0],
        agents[0],
        "Original public spark with enough structure for a witness quorum attempt.",
    )

    attack = "Attack: the spark overclaims invariance without naming the falsifier."
    challenge = _challenge_spark(client, sks[1], agents[1], spark_id, attack)
    assert challenge["resolution"] == "pending"

    for sk, agent_id in zip(sks[2:], agents[2:]):
        _affirm(client, sk, agent_id, spark_id, "quorum attempt while challenge is pending")

    spark = client.get(f"/api/spark/{spark_id}")
    assert spark.status_code == 200
    assert spark.json()["status"] == "spark"

    replay = client.get(f"/api/spark/{spark_id}/replay")
    assert replay.status_code == 200
    body = replay.json()
    assert body["verified"] is True
    assert body["replay"]["attacks"][0]["content"] == attack
    assert body["replay"]["attacks"][0]["resolution"] == "pending"
    assert body["replay"]["canon_events"] == []


def test_sublation_preserves_correction_without_quorum_granting_standing(
    client: TestClient,
    spark_app,
) -> None:
    sks = [SigningKey.generate() for _ in range(6)]
    agents = [_register(client, sk, f"loop-{idx}") for idx, sk in enumerate(sks)]
    spark_id = _submit_spark(
        client,
        sks[0],
        agents[0],
        "Original spark that needs a correction before it may enter canon.",
    )
    attack = "Attack: missing scope boundary and no predecessor-successor link."
    challenge = _challenge_spark(client, sks[1], agents[1], spark_id, attack)
    challenge_id = int(challenge["id"])

    corrected = "Corrected successor: the invariant claim is scoped and cites the preserved attack."
    artifact_ref = "artifact://public-sublation/scope-boundary-v1"
    sublation = _sublate_challenge(
        client,
        sks[2],
        agents[2],
        spark_id,
        challenge_id,
        corrected,
        artifact_ref,
        "Sublates the attack by narrowing the claim.",
    )
    successor_id = int(sublation["successor"]["id"])
    assert sublation["sublation_status"] == "sublated"
    assert sublation["challenge"]["resolution"] == "sustained"
    assert sublation["challenge"]["successor_spark_id"] == successor_id
    assert sublation["challenge"]["correction_artifact"] == artifact_ref
    assert sublation["successor"]["status"] == "spark"

    original_replay = client.get(f"/api/spark/{spark_id}/replay").json()
    assert original_replay["verified"] is True
    assert original_replay["replay"]["attacks"][0]["content"] == attack
    correction = next(
        event for event in original_replay["replay"]["corrections"] if event["action"] == "challenge_sublated"
    )
    assert correction["payload_obj"]["challenge_id"] == challenge_id
    assert correction["payload_obj"]["successor_spark_id"] == successor_id
    assert correction["hash"] == original_replay["replay"]["successor_links"][0]["sublation_witness_hash"]

    for sk, agent_id in zip(sks[3:5], agents[3:5]):
        _affirm(client, sk, agent_id, successor_id, "partial successor quorum")
    assert client.get(f"/api/spark/{successor_id}").json()["status"] == "spark"

    _affirm(client, sks[5], agents[5], successor_id, "final successor quorum")
    successor = client.get(f"/api/spark/{successor_id}").json()
    assert successor["status"] == "spark"
    assert successor["authority"]["standing_effect"] == "none"

    successor_replay = client.get(f"/api/spark/{successor_id}/replay").json()
    assert successor_replay["verified"] is True
    assert successor_replay["replay"]["attacks"][0]["content"] == attack
    assert successor_replay["replay"]["successor_links"][0]["successor_spark_id"] == successor_id
    successor_event = next(
        event for event in successor_replay["replay"]["corrections"] if event["action"] == "sublation_successor"
    )
    assert successor_event["payload_obj"]["predecessor_spark_id"] == spark_id
    assert successor_event["payload_obj"]["challenge_id"] == challenge_id
    assert successor_replay["replay"]["canon_events"] == []

    seed_claim = spark_app._founding_seed_claim()
    assert seed_claim is not None
    with sqlite3.connect(str(spark_app.SPARK_DB)) as conn:
        spark_app._bind_seed_claim_to_spark(
            conn,
            spark_id=successor_id,
            claim=seed_claim,
            sublation_status="sublated",
        )
        conn.commit()

    seed_page = client.get("/seed")
    assert seed_page.status_code == 200
    assert "Agentic Immune X-Ray" in seed_page.text
    assert "Node_04" in seed_page.text
    assert str(seed_claim["claim_id"]) in seed_page.text
    assert attack in seed_page.text
    assert artifact_ref in seed_page.text
    assert "replay verified" in seed_page.text
    assert f"spark #{successor_id}" in seed_page.text
    assert "Spark" in seed_page.text


def test_replay_verification_detects_tampered_sublation_event(
    client: TestClient,
    spark_app,
) -> None:
    sks = [SigningKey.generate() for _ in range(3)]
    agents = [_register(client, sk, f"tamper-{idx}") for idx, sk in enumerate(sks)]
    spark_id = _submit_spark(
        client,
        sks[0],
        agents[0],
        "Original spark for tamper detection after sublation.",
    )
    challenge = _challenge_spark(
        client,
        sks[1],
        agents[1],
        spark_id,
        "Attack: replay must preserve this challenge before correction.",
    )
    _sublate_challenge(
        client,
        sks[2],
        agents[2],
        spark_id,
        int(challenge["id"]),
        "Corrected successor for tamper verification.",
        "artifact://public-sublation/tamper-proof",
        "Close the loop before tampering.",
    )
    assert client.get(f"/api/spark/{spark_id}/replay").json()["verified"] is True

    with sqlite3.connect(str(spark_app.SPARK_DB)) as conn:
        conn.execute(
            "UPDATE spark_witness_chain SET payload = ? WHERE spark_id = ? AND action = ?",
            (json.dumps({"tampered": True}), spark_id, "challenge_sublated"),
        )

    tampered = client.get(f"/api/spark/{spark_id}/replay")
    assert tampered.status_code == 200
    assert tampered.json()["verified"] is False
