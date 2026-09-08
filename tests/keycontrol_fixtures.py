"""Synthetic key-control fixtures that prove ownership through the HTTP boundary.

Imports stay inside helpers because integration fixtures reload the Agora package.
Historical identity setup inserts only old identity projections, never control
bindings or proofs; enrollment still requires a real locally signed challenge.
"""

from __future__ import annotations


def registration_for(key, display_name="key-control-test", **overrides):
    return {
        "display_name": display_name,
        "public_key": key.verify_key.encode().hex(),
        **overrides,
    }


def issue_control(client, payload):
    response = client.post("/api/v1/agents/challenge", json=payload)
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def proof_for(key, challenge, *, successor_key=None):
    from agora.sab_identity import canonical_json_bytes

    message = challenge["message"]
    encoded = canonical_json_bytes(message)
    proof = {
        "challenge_id": message["challenge_id"],
        "signature": key.sign(encoded).signature.hex(),
    }
    if successor_key is not None:
        proof["successor_signature"] = successor_key.sign(encoded).signature.hex()
    return proof


def prove_control(client, key, payload, *, successor_key=None):
    challenge = issue_control(client, payload)
    response = client.post(
        "/api/v1/agents/verify",
        json=proof_for(key, challenge, successor_key=successor_key),
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["authority_effect"] == body["standing_effect"] == "none"
    return body


def enroll_identity(client, key, registration=None, **overrides):
    request = registration if registration is not None else registration_for(key, **overrides)
    return prove_control(client, key, {"action": "register", "registration": request})["identity"]


def historical_identity(module, registration):
    """Seed a complete historical identity, explicitly without key-control proof."""
    from agora.key_control import prepare_identity
    from agora.sab_identity import canonical_json_bytes
    from agora.sab_seeding_api import _init_v1_tables

    identity = prepare_identity(registration, "2026-07-05T00:00:00+00:00")
    module.init_db()
    with module._db() as conn:
        _init_v1_tables(conn)
        conn.execute(
            "INSERT INTO web_agents "
            "(id, name, public_key, created_at, witness_count, witness_accuracy) "
            "VALUES (?, ?, ?, ?, 0, 0)",
            (
                identity["subject_id"],
                identity["display_name"],
                identity["public_key"],
                identity["created_at"],
            ),
        )
        conn.execute(
            "INSERT INTO sab_agent_identities_v1 "
            "(subject_id, display_name, public_key, controller, operator_id, operator_backing_json, "
            "identity_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                identity["subject_id"],
                identity["display_name"],
                identity["public_key"],
                identity["controller"],
                identity["operator_backing"]["operator_id"],
                canonical_json_bytes(identity["operator_backing"]).decode(),
                canonical_json_bytes(identity).decode(),
                identity["created_at"],
                identity["created_at"],
            ),
        )
    return identity


def historical_web_identity(module, public_key, display_name):
    """Represent an old web-only row without manufacturing enrollment proof."""
    import hashlib

    subject_id = hashlib.sha256(public_key.encode()).hexdigest()[:16]
    module.init_db()
    with module._db() as conn:
        conn.execute(
            "INSERT INTO web_agents "
            "(id, name, public_key, created_at, witness_count, witness_accuracy) "
            "VALUES (?, ?, ?, '2026-07-05T00:00:00+00:00', 0, 0)",
            (subject_id, display_name, public_key),
        )
        return dict(conn.execute("SELECT * FROM web_agents WHERE id=?", (subject_id,)).fetchone())


def signed_seed(key, subject_id, seed_id="sab_seed_key_control_http", *, authority_reference=None):
    # Reuse the existing complete seed contract; registration is independent.
    from test_sab_seeding_api import _seed_packet, _sign_seed

    return _sign_seed(key, _seed_packet(subject_id, seed_id=seed_id, authority_reference=authority_reference), subject_id)
