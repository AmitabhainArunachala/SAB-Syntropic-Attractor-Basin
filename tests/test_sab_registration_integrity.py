"""Registration cannot replace another key or bypass signed enrollment."""

from __future__ import annotations

import hashlib
import importlib
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from keycontrol_fixtures import (
    enroll_identity,
    historical_identity,
    historical_web_identity,
    issue_control,
    proof_for,
)


@pytest.fixture
def registration_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAB_PUBLIC_MODE", "local")
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "registration.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "system.key"))
    for name in list(sys.modules):
        if name == "agora" or name.startswith("agora."):
            del sys.modules[name]
    return importlib.import_module("agora.app")


@pytest.fixture
def client(registration_app):
    with TestClient(registration_app.app) as test_client:
        yield test_client


def _registration(key: SigningKey, **overrides) -> dict:
    return {
        "display_name": "registered-agent",
        "public_key": key.verify_key.encode().hex(),
        "controller": "operator",
        "operator_backing": {
            "operator_id": "operator-original",
            "operator_kind": "human",
            "backing_count_attestation": "self_attested",
        },
        **overrides,
    }


def _identity_rows(module):
    with module._db() as conn:
        return (
            [dict(row) for row in conn.execute("SELECT * FROM web_agents ORDER BY id")],
            [
                dict(row)
                for row in conn.execute("SELECT * FROM sab_agent_identities_v1 ORDER BY subject_id")
            ],
        )


def test_unsigned_named_identity_takeover_preserves_original_signer(client, registration_app):
    owner, attacker = SigningKey.generate(), SigningKey.generate()
    request = _registration(owner, subject_id="agent_existing_named_subject")
    historical = historical_identity(registration_app, request)
    registered = enroll_identity(client, owner, request)
    assert registered == historical
    before = _identity_rows(registration_app)

    attack = client.post(
        "/api/v1/agents/register",
        json={**request, "public_key": attacker.verify_key.encode().hex()},
    )
    assert attack.status_code == 428, attack.text
    assert _identity_rows(registration_app) == before
    subject_id = registered["subject_id"]
    message = b"original owner still controls this subject"
    with registration_app._db() as conn:
        registration_app._verify_sab_agent_signature(
            conn, subject_id, message, owner.sign(message).signature.hex()
        )
        with pytest.raises(HTTPException) as rejected:
            registration_app._verify_sab_agent_signature(
                conn, subject_id, message, attacker.sign(message).signature.hex()
            )
        assert rejected.value.status_code == 400


@pytest.mark.parametrize(
    "changed",
    [
        {"display_name": "impersonated-name"},
        {"controller": "self"},
        {"identity_ref": "sab_identity_agent_someone_else"},
        {
            "operator_backing": {
                "operator_id": "operator-forged",
                "backing_count_attestation": "verified",
            }
        },
    ],
)
def test_public_key_knowledge_cannot_rewrite_identity_metadata(client, registration_app, changed):
    key = SigningKey.generate()
    request = _registration(key)
    enroll_identity(client, key, request)
    before = _identity_rows(registration_app)
    attack = client.post("/api/v1/agents/register", json={**request, **changed})
    assert attack.status_code == 428, attack.text
    challenged = client.post(
        "/api/v1/agents/challenge",
        json={"action": "register", "registration": {**request, **changed}},
    )
    assert challenged.status_code == 409, challenged.text
    assert _identity_rows(registration_app) == before


def test_same_key_cannot_delete_original_subject_through_new_alias(client, registration_app):
    key = SigningKey.generate()
    request = _registration(key)
    registered = enroll_identity(client, key, request)
    before = _identity_rows(registration_app)
    duplicate = client.post(
        "/api/v1/agents/challenge",
        json={"action": "register", "registration": {**request, "subject_id": "agent_new_alias"}},
    )
    assert duplicate.status_code == 409, duplicate.text
    home = client.get("/api/v1/agents/me/home", params={"subject_id": registered["subject_id"]})
    assert home.status_code == 200, home.text
    assert home.json()["agent"]["public_key"] == request["public_key"]
    assert (
        client.get("/api/v1/agents/me/home", params={"subject_id": "agent_new_alias"}).status_code
        == 404
    )
    assert _identity_rows(registration_app) == before


def test_new_proof_for_identical_identity_preserves_document_and_witness_history(
    client, registration_app
):
    key = SigningKey.generate()
    request = _registration(key)
    registered = enroll_identity(client, key, request)
    with registration_app._db() as conn:
        conn.execute(
            "UPDATE web_agents SET witness_count = 7, witness_accuracy = 0.75 WHERE id = ?",
            (registered["subject_id"],),
        )
    before = _identity_rows(registration_app)
    retried = enroll_identity(client, key, request)
    assert retried == registered
    assert _identity_rows(registration_app) == before
    with registration_app._db() as conn:
        assert conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM sab_key_control_bindings_v1").fetchone()[0] == 1


def test_hex_case_cannot_create_second_identity_for_same_key(client):
    key = SigningKey.generate()
    request = _registration(key)
    registered = enroll_identity(client, key, request)
    retried = enroll_identity(client, key, {**request, "public_key": request["public_key"].upper()})
    assert retried == registered


@pytest.mark.parametrize("public_key", ["not-a-key", "00" * 31, "00" * 33])
@pytest.mark.parametrize("subject", [{}, {"subject_id": "agent_invalid_key"}])
def test_invalid_public_key_challenge_is_rejected_without_server_error(client, public_key, subject):
    response = client.post(
        "/api/v1/agents/challenge",
        json={
            "action": "register",
            "registration": {"display_name": "invalid-key", "public_key": public_key, **subject},
        },
    )
    assert response.status_code == 400, response.text


@pytest.mark.parametrize("legacy_uppercase", [False, True])
@pytest.mark.parametrize("v1_uppercase", [False, True])
def test_v1_registration_cannot_replace_legacy_web_identity(
    client, registration_app, legacy_uppercase, v1_uppercase
):
    request = _registration(SigningKey.generate())
    historical_web_identity(
        registration_app,
        request["public_key"].upper() if legacy_uppercase else request["public_key"],
        request["display_name"],
    )
    legacy = client.post(
        "/api/agents/register",
        json={
            "name": request["display_name"],
            "public_key": (
                request["public_key"].upper() if legacy_uppercase else request["public_key"]
            ),
        },
    )
    assert legacy.status_code == 201, legacy.text
    with registration_app._db() as conn:
        before = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
    attempted = client.post(
        "/api/v1/agents/register",
        json={
            **request,
            "public_key": request["public_key"].upper() if v1_uppercase else request["public_key"],
        },
    )
    assert attempted.status_code == 428, attempted.text
    challenged = client.post(
        "/api/v1/agents/challenge",
        json={
            "action": "register",
            "registration": {
                **request,
                "public_key": (
                    request["public_key"].upper() if v1_uppercase else request["public_key"]
                ),
            },
        },
    )
    assert challenged.status_code == 409, challenged.text
    with registration_app._db() as conn:
        assert [dict(row) for row in conn.execute("SELECT * FROM web_agents")] == before


@pytest.mark.parametrize("v1_uppercase", [False, True])
@pytest.mark.parametrize("legacy_uppercase", [False, True])
@pytest.mark.parametrize("subject", [{}, {"subject_id": "agent_existing_named_subject"}])
def test_legacy_registration_returns_existing_v1_subject_without_alias(
    client, registration_app, v1_uppercase, legacy_uppercase, subject
):
    key = SigningKey.generate()
    request = _registration(key, **subject)
    if subject:
        historical_identity(registration_app, request)
    registered = enroll_identity(
        client,
        key,
        {
            **request,
            "public_key": request["public_key"].upper() if v1_uppercase else request["public_key"],
        },
    )
    with registration_app._db() as conn:
        conn.execute(
            "UPDATE web_agents SET witness_count = 9, witness_accuracy = 0.875 WHERE id = ?",
            (registered["subject_id"],),
        )
    before = _identity_rows(registration_app)
    legacy = client.post(
        "/api/agents/register",
        json={
            "name": request["display_name"],
            "public_key": (
                request["public_key"].upper() if legacy_uppercase else request["public_key"]
            ),
        },
    )
    assert legacy.status_code == 201, legacy.text
    assert legacy.json()["id"] == registered["subject_id"]
    assert legacy.json()["identity"] == registered
    assert _identity_rows(registration_app) == before


@pytest.mark.parametrize("source", ["legacy", "v1"])
@pytest.mark.parametrize("uppercase", [False, True])
def test_legacy_registration_cannot_rewrite_existing_name(
    client, registration_app, source, uppercase
):
    key = SigningKey.generate()
    request = _registration(key)
    if source == "v1":
        enroll_identity(client, key, request)
    else:
        historical_web_identity(registration_app, request["public_key"], request["display_name"])
        registered = client.post(
            "/api/agents/register",
            json={"name": request["display_name"], "public_key": request["public_key"]},
        )
        assert registered.status_code == 201, registered.text
    with registration_app._db() as conn:
        before = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
    attack = client.post(
        "/api/agents/register",
        json={
            "name": "rewritten-name",
            "public_key": request["public_key"].upper() if uppercase else request["public_key"],
        },
    )
    assert attack.status_code == 409, attack.text
    with registration_app._db() as conn:
        assert [dict(row) for row in conn.execute("SELECT * FROM web_agents")] == before


@pytest.mark.parametrize("uppercase", [False, True])
def test_legacy_registration_preserves_historical_uppercase_key_and_subject(
    client, registration_app, uppercase
):
    public_key = SigningKey.generate().verify_key.encode().hex().upper()
    historical_id = hashlib.sha256(public_key.encode()).hexdigest()[:16]
    created_at = "2026-07-05T00:00:00+00:00"
    with registration_app._db() as conn:
        conn.execute(
            "INSERT INTO web_agents (id, name, public_key, created_at, witness_count, witness_accuracy) "
            "VALUES (?, 'historical-agent', ?, ?, 6, 0.625)",
            (historical_id, public_key, created_at),
        )
        before = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]

    retried = client.post(
        "/api/agents/register",
        json={
            "name": "historical-agent",
            "public_key": public_key if uppercase else public_key.lower(),
        },
    )
    assert retried.status_code == 201, retried.text
    assert retried.json()["id"] == historical_id
    assert retried.json()["public_key"] == public_key
    assert retried.json()["created_at"] == created_at
    with registration_app._db() as conn:
        after = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
    assert after == before


def test_fresh_unsigned_legacy_registration_rejects_both_key_encodings(client, registration_app):
    public_key = SigningKey.generate().verify_key.encode().hex()
    with registration_app._db() as conn:
        before = tuple(conn.iterdump())
    for encoded in (public_key.upper(), public_key):
        response = client.post(
            "/api/agents/register", json={"name": "legacy-agent", "public_key": encoded}
        )
        assert response.status_code == 428, response.text
        assert response.json()["code"] == "key_control_required"
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["authority_effect"] == response.json()["standing_effect"] == "none"
        with registration_app._db() as conn:
            assert tuple(conn.iterdump()) == before


def test_racing_proof_and_legacy_registration_leave_one_key_binding(registration_app):
    barrier = Barrier(2)
    key = SigningKey.generate()
    request = _registration(key)
    with TestClient(registration_app.app) as client:
        challenge = issue_control(client, {"action": "register", "registration": request})
    requests = [
        ("/api/v1/agents/verify", proof_for(key, challenge)),
        (
            "/api/agents/register",
            {"name": request["display_name"], "public_key": request["public_key"].upper()},
        ),
    ]

    def register(item):
        path, payload = item
        with TestClient(registration_app.app) as client:
            barrier.wait(timeout=10)
            return path, client.post(path, json=payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = dict(pool.map(register, requests))
    legacy = outcomes["/api/agents/register"]
    verified = outcomes["/api/v1/agents/verify"]
    assert verified.status_code == 200, verified.text
    assert legacy.status_code in {201, 428}, legacy.text
    if legacy.status_code == 201:
        assert legacy.json()["id"] == verified.json()["identity"]["subject_id"]
        assert legacy.json()["identity"] == verified.json()["identity"]
    else:
        assert legacy.json()["code"] == "key_control_required"
    with registration_app._db() as conn:
        rows = conn.execute("SELECT id, public_key FROM web_agents").fetchall()
        bindings = conn.execute("SELECT * FROM sab_key_control_bindings_v1").fetchall()
    assert len(rows) == 1
    assert rows[0]["id"] == verified.json()["identity"]["subject_id"]
    assert rows[0]["public_key"] == request["public_key"]
    assert len(bindings) == 1


def test_racing_new_named_registrations_cannot_squat_a_subject(registration_app):
    barrier = Barrier(2)
    requests = [
        _registration(SigningKey.generate(), subject_id="agent_contested_subject"),
        _registration(SigningKey.generate(), subject_id="agent_contested_subject"),
    ]
    registration_app.init_db()

    def register(request):
        with TestClient(registration_app.app) as client:
            barrier.wait(timeout=10)
            return client.post(
                "/api/v1/agents/challenge", json={"action": "register", "registration": request}
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, requests))
    assert [response.status_code for response in outcomes] == [400, 400]
    assert {response.json()["code"] for response in outcomes} == {"canonical_identity_required"}
    with registration_app._db() as conn:
        assert conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM sab_agent_identities_v1").fetchone()[0] == 0
