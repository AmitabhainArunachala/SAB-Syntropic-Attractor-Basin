#!/usr/bin/env python3
"""Seed the public SAB app with the anchor-04 founding proof loop."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Tuple

import httpx
from fastapi.testclient import TestClient
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from agora.key_control_client import enroll
from agora.sab_identity import canonical_json_bytes


def _register(client: TestClient, name: str, *, origin: str) -> Tuple[SigningKey, str]:
    """Prove a synthetic participant key against the configured local audience."""
    signing_key = SigningKey.generate()
    public_key = signing_key.verify_key.encode(encoder=HexEncoder).decode()

    def forward(request: httpx.Request) -> httpx.Response:
        response = client.request(
            request.method,
            str(request.url),
            content=request.content,
            headers=dict(request.headers),
            follow_redirects=False,
        )
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=response.content,
            request=request,
        )

    result = enroll(
        origin,
        {"display_name": name, "public_key": public_key},
        signing_key,
        transport=httpx.MockTransport(forward),
    )
    return signing_key, result["identity"]["subject_id"]


def _sign_submit(signing_key: SigningKey, agent_id: str, content: str) -> str:
    content_sha256 = hashlib.sha256(content.encode()).hexdigest()
    return signing_key.sign(
        canonical_json_bytes(
            {
                "kind": "spark_submit",
                "author_id": agent_id,
                "content_sha256": content_sha256,
            }
        )
    ).signature.hex()


def _sign_challenge(
    signing_key: SigningKey, spark_id: int, challenger_id: str, content: str
) -> str:
    content_sha256 = hashlib.sha256(content.encode()).hexdigest()
    return signing_key.sign(
        canonical_json_bytes(
            {
                "kind": "spark_challenge",
                "spark_id": spark_id,
                "challenger_id": challenger_id,
                "content_sha256": content_sha256,
            }
        )
    ).signature.hex()


def _sign_sublation(
    signing_key: SigningKey,
    *,
    challenge_id: int,
    predecessor_spark_id: int,
    corrector_id: str,
    successor_content: str,
    artifact_ref: str,
    note: str,
) -> str:
    return signing_key.sign(
        canonical_json_bytes(
            {
                "kind": "spark_challenge_sublation",
                "challenge_id": challenge_id,
                "predecessor_spark_id": predecessor_spark_id,
                "corrector_id": corrector_id,
                "successor_content_sha256": hashlib.sha256(successor_content.encode()).hexdigest(),
                "artifact_ref_sha256": hashlib.sha256(artifact_ref.encode()).hexdigest(),
                "note_sha256": hashlib.sha256(note.encode()).hexdigest(),
            }
        )
    ).signature.hex()


def _sign_witness(
    signing_key: SigningKey,
    *,
    spark_id: int,
    witness_id: str,
    action: str,
    payload: Dict[str, Any],
) -> str:
    payload_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return signing_key.sign(
        canonical_json_bytes(
            {
                "kind": "witness_attestation",
                "spark_id": spark_id,
                "witness_id": witness_id,
                "action": action,
                "payload_sha256": payload_sha256,
            }
        )
    ).signature.hex()


def main() -> int:
    # Importing helpers or enrolling a test participant never initializes a server.
    from agora import app as sab

    if sab.KEY_CONTROL is None:
        raise SystemExit("Seeding requires an explicitly configured local key-control service.")
    sab.init_db()
    seed_payload = sab._seed_claim_payload()
    seed_claim = sab._founding_seed_claim(seed_payload)
    if seed_claim is None:
        raise SystemExit("No founding seed claim found in site/data/seed_claims.json")

    with sab._db() as conn:
        existing_id = sab._seed_spark_id(conn, seed_claim)
    if existing_id is not None:
        print(
            json.dumps(
                {"status": "exists", "seed_spark_id": existing_id, "url": "/seed"}, sort_keys=True
            )
        )
        return 0

    client = TestClient(sab.app)
    origin = sab.KEY_CONTROL.audience
    author_sk, author_id = _register(client, "seed-author-anchor-04", origin=origin)
    challenger_sk, challenger_id = _register(client, "seed-redteam-anchor-04", origin=origin)
    corrector_sk, corrector_id = _register(client, "seed-corrector-anchor-04", origin=origin)
    witnesses = [_register(client, f"seed-witness-{idx}", origin=origin) for idx in range(3)]

    original_content = (
        "Draft seed claim: agentic immune infrastructure is a production-ready invariant. "
        "This intentionally overstates the claim so the seed can be attacked and corrected."
    )
    submit = client.post(
        "/api/spark/submit",
        json={
            "content": original_content,
            "content_type": "text",
            "author_id": author_id,
            "signature": _sign_submit(author_sk, author_id, original_content),
        },
    )
    submit.raise_for_status()
    original_spark_id = int(submit.json()["id"])

    attack = (
        "Attack: the packet is an internally gated proof artifact, not production readiness, "
        "customer traction, or autonomous live self-modification."
    )
    challenge = client.post(
        f"/api/spark/{original_spark_id}/challenge",
        json={
            "challenger_id": challenger_id,
            "content": attack,
            "signature": _sign_challenge(challenger_sk, original_spark_id, challenger_id, attack),
        },
    )
    challenge.raise_for_status()
    challenge_id = int(challenge.json()["id"])

    corrected_content = (
        f"SAB founding seed: {seed_claim['title']}\n\n"
        f"{seed_claim['summary']}\n\n"
        f"Claim packet: {seed_claim['claim_path']}\n"
        "Status: a witnessed seed for attack, correction, sublation, and replay; not a claim of production readiness."
    )
    artifact_ref = str(seed_claim["claim_path"])
    note = "Corrects the overclaim and binds the seed to the witnessed anchor-04 packet."
    sublation = client.post(
        f"/api/spark/{original_spark_id}/challenge/{challenge_id}/sublate",
        json={
            "corrector_id": corrector_id,
            "corrected_content": corrected_content,
            "content_type": "text",
            "artifact_ref": artifact_ref,
            "note": note,
            "signature": _sign_sublation(
                corrector_sk,
                challenge_id=challenge_id,
                predecessor_spark_id=original_spark_id,
                corrector_id=corrector_id,
                successor_content=corrected_content,
                artifact_ref=artifact_ref,
                note=note,
            ),
        },
    )
    sublation.raise_for_status()
    successor_spark_id = int(sublation.json()["successor"]["id"])

    for witness_sk, witness_id in witnesses:
        payload = {"reason": "founding seed quorum witness"}
        response = client.post(
            "/api/witness/sign",
            json={
                "spark_id": successor_spark_id,
                "witness_id": witness_id,
                "action": "affirm",
                "payload": payload,
                "signature": _sign_witness(
                    witness_sk,
                    spark_id=successor_spark_id,
                    witness_id=witness_id,
                    action="affirm",
                    payload=payload,
                ),
            },
        )
        response.raise_for_status()

    with sab._db() as conn:
        sab._bind_seed_claim_to_spark(
            conn,
            spark_id=successor_spark_id,
            claim=seed_claim,
            sublation_status="sublated",
        )

    print(
        json.dumps(
            {
                "status": "seeded",
                "original_spark_id": original_spark_id,
                "challenge_id": challenge_id,
                "seed_spark_id": successor_spark_id,
                "url": "/seed",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
