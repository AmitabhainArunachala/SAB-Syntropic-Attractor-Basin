"""An unsigned review cannot ask the system signer to decide standing."""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from keycontrol_fixtures import enroll_identity, signed_seed
from test_key_control_http import client, local_app  # noqa: F401


@pytest.mark.parametrize("request_fields", [{}, {"requested_state": "compost"}])
def test_unsigned_standing_review_preserves_resolved_seed_and_all_history(
    client, local_app, monkeypatch, request_fields
):
    from test_sab_seeding_api import _now, _sign_challenge_action, _submit_challenge

    author_key, challenger_key = SigningKey.generate(), SigningKey.generate()
    author = enroll_identity(client, author_key, display_name="review-author")["subject_id"]
    challenger = enroll_identity(client, challenger_key, display_name="review-challenger")[
        "subject_id"
    ]
    seed_id, challenge_id = "sab_seed_signed_review_only", "sab_challenge_signed_review_only"
    submitted = client.post("/api/v1/seeds", json=signed_seed(author_key, author, seed_id))
    assert submitted.status_code == 201
    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    _submit_challenge(
        client,
        challenger_key,
        challenger_id=challenger,
        seed_id=seed_id,
        claim_id=seed["claim_id"],
        challenge_id=challenge_id,
    )
    response_payload = {"text": "A scoped response, without a standing decision."}
    created_at = _now()
    signature = _sign_challenge_action(
        author_key,
        action="respond",
        challenge_id=challenge_id,
        actor_identity=author,
        payload=response_payload,
        created_at=created_at,
    )
    responded = client.post(
        f"/api/v1/challenges/{challenge_id}/respond",
        json={
            "actor_identity": author,
            "created_at": created_at,
            "response": response_payload,
            "signature": signature,
        },
    )
    assert responded.status_code == 201
    assert responded.json()["seed_state"] == "corrected"
    with local_app._db() as conn:
        before = tuple(conn.iterdump())

    def forbidden_database():
        raise AssertionError("Unsigned review reached database initialization or mutation")

    with monkeypatch.context() as patch:
        patch.setattr(local_app, "_db", forbidden_database)
        denied = client.post(
            "/api/v1/standing/review",
            json={
                "subject_seed_id": seed_id,
                "witness_refs": ["nonexistent-reference"],
                **request_fields,
            },
        )
    assert denied.status_code == 428
    assert denied.json()["code"] == "signed_standing_review_required"
    assert denied.json()["authority_effect"] == denied.json()["standing_effect"] == "none"
    assert denied.headers["cache-control"] == "no-store"
    with local_app._db() as conn:
        assert tuple(conn.iterdump()) == before
    assert client.get(f"/api/v1/seeds/{seed_id}").json()["state"] == "corrected"
    assert client.get(f"/api/v1/seeds/{seed_id}/chain").json()["verified"] is True
