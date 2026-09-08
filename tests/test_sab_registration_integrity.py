"""Registration must never replace another agent's key or authority history."""
from __future__ import annotations

import importlib
import hashlib
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from nacl.signing import SigningKey


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


def test_unsigned_named_identity_takeover_preserves_original_signer(client, registration_app):
    owner, attacker = SigningKey.generate(), SigningKey.generate()
    request = _registration(owner, subject_id="agent_existing_named_subject")
    registered = client.post("/api/v1/agents/register", json=request)
    assert registered.status_code == 201, registered.text

    attack = client.post(
        "/api/v1/agents/register",
        json={**request, "public_key": attacker.verify_key.encode().hex()},
    )
    assert attack.status_code == 409, attack.text
    subject_id = registered.json()["subject_id"]
    message = b"original owner still controls this subject"
    with registration_app._db() as conn:
        registration_app._verify_agent_signature(conn, subject_id, message, owner.sign(message).signature.hex())
        with pytest.raises(HTTPException) as rejected:
            registration_app._verify_agent_signature(conn, subject_id, message, attacker.sign(message).signature.hex())
        assert rejected.value.status_code == 400
        identity = conn.execute(
            "SELECT public_key FROM sab_agent_identities_v1 WHERE subject_id = ?", (subject_id,)
        ).fetchone()
        assert identity["public_key"] == request["public_key"]


@pytest.mark.parametrize(
    "changed",
    [
        {"display_name": "impersonated-name"},
        {"controller": "self"},
        {"identity_ref": "sab_identity_agent_someone_else"},
        {"operator_backing": {"operator_id": "operator-forged", "backing_count_attestation": "verified"}},
    ],
)
def test_public_key_knowledge_cannot_rewrite_identity_metadata(client, registration_app, changed):
    request = _registration(SigningKey.generate())
    registered = client.post("/api/v1/agents/register", json=request)
    assert registered.status_code == 201, registered.text
    subject_id = registered.json()["subject_id"]
    with registration_app._db() as conn:
        before = dict(conn.execute(
            "SELECT * FROM sab_agent_identities_v1 WHERE subject_id = ?", (subject_id,)
        ).fetchone())

    attack = client.post("/api/v1/agents/register", json={**request, **changed})
    assert attack.status_code == 409, attack.text
    with registration_app._db() as conn:
        after = dict(conn.execute(
            "SELECT * FROM sab_agent_identities_v1 WHERE subject_id = ?", (subject_id,)
        ).fetchone())
    assert after == before


def test_same_key_cannot_delete_original_subject_through_new_alias(client):
    request = _registration(SigningKey.generate())
    registered = client.post("/api/v1/agents/register", json=request)
    assert registered.status_code == 201, registered.text
    subject_id = registered.json()["subject_id"]

    duplicate = client.post(
        "/api/v1/agents/register", json={**request, "subject_id": "agent_new_alias"}
    )
    assert duplicate.status_code == 409, duplicate.text
    home = client.get("/api/v1/agents/me/home", params={"subject_id": subject_id})
    assert home.status_code == 200, home.text
    assert home.json()["agent"]["public_key"] == request["public_key"]
    assert client.get("/api/v1/agents/me/home", params={"subject_id": "agent_new_alias"}).status_code == 404


def test_identical_retry_preserves_identity_document_and_witness_history(client, registration_app):
    request = _registration(SigningKey.generate())
    registered = client.post("/api/v1/agents/register", json=request)
    assert registered.status_code == 201, registered.text
    subject_id = registered.json()["subject_id"]
    with registration_app._db() as conn:
        conn.execute(
            "UPDATE web_agents SET witness_count = 7, witness_accuracy = 0.75 WHERE id = ?", (subject_id,)
        )
        before = dict(conn.execute("SELECT * FROM web_agents WHERE id = ?", (subject_id,)).fetchone())

    retried = client.post("/api/v1/agents/register", json=request)
    assert retried.status_code == 201, retried.text
    assert retried.json() == registered.json()
    with registration_app._db() as conn:
        after = dict(conn.execute("SELECT * FROM web_agents WHERE id = ?", (subject_id,)).fetchone())
    assert after == before


def test_hex_case_cannot_create_second_identity_for_same_key(client):
    request = _registration(SigningKey.generate())
    registered = client.post("/api/v1/agents/register", json=request)
    assert registered.status_code == 201, registered.text
    retried = client.post(
        "/api/v1/agents/register", json={**request, "public_key": request["public_key"].upper()}
    )
    assert retried.status_code == 201, retried.text
    assert retried.json() == registered.json()


@pytest.mark.parametrize("public_key", ["not-a-key", "00" * 31, "00" * 33])
@pytest.mark.parametrize("subject", [{}, {"subject_id": "agent_invalid_key"}])
def test_invalid_public_key_is_rejected_without_server_error(client, public_key, subject):
    response = client.post(
        "/api/v1/agents/register",
        json={"display_name": "invalid-key", "public_key": public_key, **subject},
    )
    assert response.status_code == 400, response.text


@pytest.mark.parametrize("legacy_uppercase", [False, True])
@pytest.mark.parametrize("v1_uppercase", [False, True])
def test_v1_registration_cannot_replace_legacy_web_identity(client, registration_app, legacy_uppercase, v1_uppercase):
    request = _registration(SigningKey.generate())
    legacy = client.post(
        "/api/agents/register",
        json={
            "name": request["display_name"],
            "public_key": request["public_key"].upper() if legacy_uppercase else request["public_key"],
        },
    )
    assert legacy.status_code == 201, legacy.text
    with registration_app._db() as conn:
        before = dict(conn.execute("SELECT * FROM web_agents WHERE id = ?", (legacy.json()["id"],)).fetchone())
    attempted_migration = client.post(
        "/api/v1/agents/register",
        json={**request, "public_key": request["public_key"].upper() if v1_uppercase else request["public_key"]},
    )
    assert attempted_migration.status_code == 409, attempted_migration.text
    with registration_app._db() as conn:
        after = dict(conn.execute("SELECT * FROM web_agents WHERE id = ?", (legacy.json()["id"],)).fetchone())
    assert after == before


@pytest.mark.parametrize("v1_uppercase", [False, True])
@pytest.mark.parametrize("legacy_uppercase", [False, True])
@pytest.mark.parametrize("subject", [{}, {"subject_id": "agent_existing_named_subject"}])
def test_legacy_registration_returns_existing_v1_subject_without_alias(
    client, registration_app, v1_uppercase, legacy_uppercase, subject
):
    request = _registration(SigningKey.generate(), **subject)
    registered = client.post(
        "/api/v1/agents/register",
        json={**request, "public_key": request["public_key"].upper() if v1_uppercase else request["public_key"]},
    )
    assert registered.status_code == 201, registered.text
    with registration_app._db() as conn:
        conn.execute(
            "UPDATE web_agents SET witness_count = 9, witness_accuracy = 0.875 WHERE id = ?",
            (registered.json()["subject_id"],),
        )
        before_web = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
        before_identities = [dict(row) for row in conn.execute("SELECT * FROM sab_agent_identities_v1")]

    legacy = client.post(
        "/api/agents/register",
        json={
            "name": request["display_name"],
            "public_key": request["public_key"].upper() if legacy_uppercase else request["public_key"],
        },
    )
    assert legacy.status_code == 201, legacy.text
    assert legacy.json()["id"] == registered.json()["subject_id"]
    assert legacy.json()["identity"] == registered.json()
    with registration_app._db() as conn:
        after_web = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
        after_identities = [dict(row) for row in conn.execute("SELECT * FROM sab_agent_identities_v1")]
    assert after_web == before_web
    assert after_identities == before_identities


@pytest.mark.parametrize("source", ["legacy", "v1"])
@pytest.mark.parametrize("uppercase", [False, True])
def test_legacy_registration_cannot_rewrite_existing_name(client, registration_app, source, uppercase):
    request = _registration(SigningKey.generate())
    registered = client.post(
        "/api/v1/agents/register" if source == "v1" else "/api/agents/register",
        json=request if source == "v1" else {"name": request["display_name"], "public_key": request["public_key"]},
    )
    assert registered.status_code == 201, registered.text
    with registration_app._db() as conn:
        before = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
    attack = client.post(
        "/api/agents/register",
        json={"name": "rewritten-name", "public_key": request["public_key"].upper() if uppercase else request["public_key"]},
    )
    assert attack.status_code == 409, attack.text
    with registration_app._db() as conn:
        after = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
    assert after == before


@pytest.mark.parametrize("uppercase", [False, True])
def test_legacy_registration_preserves_historical_uppercase_key_and_subject(client, registration_app, uppercase):
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
        json={"name": "historical-agent", "public_key": public_key if uppercase else public_key.lower()},
    )
    assert retried.status_code == 201, retried.text
    assert retried.json()["id"] == historical_id
    assert retried.json()["public_key"] == public_key
    assert retried.json()["created_at"] == created_at
    with registration_app._db() as conn:
        after = [dict(row) for row in conn.execute("SELECT * FROM web_agents")]
    assert after == before


def test_new_legacy_registration_normalizes_key_before_deriving_subject(client):
    public_key = SigningKey.generate().verify_key.encode().hex()
    upper = client.post("/api/agents/register", json={"name": "legacy-agent", "public_key": public_key.upper()})
    assert upper.status_code == 201, upper.text
    assert upper.json()["id"] == hashlib.sha256(public_key.encode()).hexdigest()[:16]
    assert upper.json()["public_key"] == public_key
    lower = client.post("/api/agents/register", json={"name": "legacy-agent", "public_key": public_key})
    assert lower.status_code == 201, lower.text
    assert lower.json() == upper.json()


def test_racing_v1_and_legacy_registrations_leave_one_key_binding(registration_app):
    barrier = Barrier(2)
    request = _registration(SigningKey.generate())
    registration_app.init_db()
    requests = [
        ("/api/v1/agents/register", request),
        ("/api/agents/register", {"name": request["display_name"], "public_key": request["public_key"].upper()}),
    ]

    def register(item):
        path, payload = item
        with TestClient(registration_app.app) as test_client:
            barrier.wait(timeout=10)
            return path, test_client.post(path, json=payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = dict(pool.map(register, requests))
    legacy = outcomes["/api/agents/register"]
    v1 = outcomes["/api/v1/agents/register"]
    assert legacy.status_code == 201, legacy.text
    assert v1.status_code in {201, 409}, v1.text
    if v1.status_code == 201:
        assert legacy.json()["id"] == v1.json()["subject_id"]
        assert legacy.json()["identity"] == v1.json()
    with registration_app._db() as conn:
        rows = conn.execute("SELECT id, public_key FROM web_agents").fetchall()
    assert len(rows) == 1
    assert rows[0]["id"] == legacy.json()["id"]
    assert rows[0]["public_key"] == request["public_key"]


def test_racing_named_registrations_have_one_immutable_winner(registration_app):
    barrier = Barrier(2)
    requests = [
        _registration(SigningKey.generate(), subject_id="agent_contested_subject"),
        _registration(SigningKey.generate(), subject_id="agent_contested_subject"),
    ]
    registration_app.init_db()

    def register(request):
        with TestClient(registration_app.app) as test_client:
            barrier.wait(timeout=10)
            return request, test_client.post("/api/v1/agents/register", json=request)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, requests))
    assert sorted(response.status_code for _, response in outcomes) == [201, 409]
    winner = next(request for request, response in outcomes if response.status_code == 201)
    with registration_app._db() as conn:
        web = conn.execute("SELECT public_key FROM web_agents WHERE id = 'agent_contested_subject'").fetchone()
        identity = conn.execute(
            "SELECT public_key FROM sab_agent_identities_v1 WHERE subject_id = 'agent_contested_subject'"
        ).fetchone()
    assert web["public_key"] == identity["public_key"] == winner["public_key"]
