"""Exercise private-key ownership and retirement through the real HTTP app."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from keycontrol_fixtures import (
    enroll_identity,
    historical_web_identity,
    issue_control,
    proof_for,
    prove_control,
    registration_for,
    signed_seed,
)


def _reload_app():
    for name in list(sys.modules):
        if name == "agora" or name.startswith("agora."):
            del sys.modules[name]
    return importlib.import_module("agora.app")


@pytest.fixture
def local_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SAB_PUBLIC_MODE", "local")
    monkeypatch.setenv("SAB_IDENTITY_ORIGIN", "http://127.0.0.1:8000")
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "http.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "system.key"))
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT", raising=False)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    return _reload_app()


@pytest.fixture
def client(local_app):
    with TestClient(local_app.app) as test_client:
        yield test_client


def _state(module):
    """Observe every stored row and schema; do not create a synthetic proof."""
    with module._db() as conn:
        return tuple(conn.iterdump())


def _row_count(module, table):
    with module._db() as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
            return 0
        return conn.execute('SELECT count(*) FROM "' + table + '"').fetchone()[0]


def _problem(response, status, code):
    assert response.status_code == status, response.text
    assert response.json()["code"] == code
    assert response.json()["authority_effect"] == response.json()["standing_effect"] == "none"
    assert response.headers["cache-control"] == "no-store"


def test_challenge_is_not_identity_and_only_verified_proof_enables_contribution(client, local_app):
    from agora.sab_identity import canonical_json_bytes, subject_id_from_public_key

    key = SigningKey.generate()
    registration = registration_for(key, "synthetic contributor")
    challenge = issue_control(client, {"action": "register", "registration": registration})
    message = challenge["message"]
    subject = subject_id_from_public_key(registration["public_key"])
    assert message["subject_id"] == subject
    assert message["audience"] == "http://127.0.0.1:8000"
    assert (message["method"], message["path"]) == ("POST", "/api/v1/agents/verify")
    assert (
        message["proposed_identity_sha256"]
        == hashlib.sha256(canonical_json_bytes(message["proposed_identity"])).hexdigest()
    )
    assert challenge["authority_effect"] == challenge["standing_effect"] == "none"
    assert _row_count(local_app, "sab_key_control_challenges_v1") == 1
    assert _row_count(local_app, "sab_key_control_proofs_v1") == 0
    assert _row_count(local_app, "sab_key_control_bindings_v1") == 0
    assert _row_count(local_app, "web_agents") == 0
    assert client.get("/api/v1/agents/me/home", params={"subject_id": subject}).status_code == 404
    packet = signed_seed(key, subject)
    before = _state(local_app)
    rejected = client.post("/api/v1/seeds", json=packet)
    assert rejected.status_code == 428, rejected.text
    assert rejected.json()["detail"]["code"] == "key_control_unproven"
    assert _state(local_app) == before

    proof = proof_for(key, challenge)
    verified = client.post("/api/v1/agents/verify", json=proof)
    assert verified.status_code == 200, verified.text
    result = verified.json()
    assert result["identity"] == message["proposed_identity"]
    assert result["binding"]["status"] == "active"
    assert result["binding"]["scope"] == "key_control_only"
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert _row_count(local_app, "sab_key_control_challenges_v1") == 0
    assert _row_count(local_app, "sab_key_control_proofs_v1") == 1
    submitted = client.post("/api/v1/seeds", json=packet)
    assert submitted.status_code == 201, submitted.text
    assert submitted.json()["state"] == "pending_seed"
    home = client.get("/api/v1/agents/me/home", params={"subject_id": subject}).json()
    assert home["identity_status"] == "active"
    assert home["recommended_next_action"] == "submit_seed_or_review_challenges"
    assert home["identity"] == result["identity"]
    assert home["key_control"] == result["binding"]
    assert home["active_authority_leases"] == []
    assert home["authority_effect"] == home["standing_effect"] == "none"


def test_unsigned_endpoint_cannot_enroll_or_update_metadata(client, local_app):
    before = _state(local_app)
    denied = client.post("/api/v1/agents/register", json=registration_for(SigningKey.generate()))
    _problem(denied, 428, "key_control_required")
    assert _state(local_app) == before
    denied = client.post("/api/v1/agents/register", content=b"{malformed")
    _problem(denied, 428, "key_control_required")
    assert _state(local_app) == before


@pytest.mark.parametrize("uppercase", [False, True])
def test_attacker_cannot_squat_a_fresh_key_through_legacy_registration(
    client, local_app, uppercase
):
    owner = SigningKey.generate()
    public_key = owner.verify_key.encode().hex()
    before = _state(local_app)
    attack = client.post(
        "/api/agents/register",
        json={
            "name": "attacker-chosen-name",
            "public_key": public_key.upper() if uppercase else public_key,
        },
    )
    _problem(attack, 428, "key_control_required")
    assert _state(local_app) == before
    assert _row_count(local_app, "web_agents") == 0

    # The key owner can still enroll the same key with its own signed metadata.
    identity = enroll_identity(client, owner, display_name="owner-chosen-name")
    assert identity["display_name"] == "owner-chosen-name"
    assert identity["public_key"] == public_key
    assert _row_count(local_app, "web_agents") == 1
    assert _row_count(local_app, "sab_key_control_bindings_v1") == 1
    response = client.post("/api/v1/seeds", json=signed_seed(owner, identity["subject_id"]))
    assert response.status_code == 201, response.text


def test_wrong_signature_does_not_consume_challenge_but_successful_proof_cannot_replay(
    client, local_app
):
    key = SigningKey.generate()
    challenge = issue_control(client, {"action": "register", "registration": registration_for(key)})
    before = _state(local_app)
    _problem(
        client.post("/api/v1/agents/verify", json=proof_for(SigningKey.generate(), challenge)),
        401,
        "invalid_signature",
    )
    assert _state(local_app) == before
    proof = proof_for(key, challenge)
    assert client.post("/api/v1/agents/verify", json=proof).status_code == 200
    consumed = _state(local_app)
    _problem(client.post("/api/v1/agents/verify", json=proof), 409, "challenge_unavailable")
    assert _state(local_app) == consumed


@pytest.mark.parametrize(
    "field,value",
    [
        ("audience", "https://attacker.invalid"),
        ("method", "DELETE"),
        ("path", "/api/v1/seeds"),
        ("action", "revoke"),
        ("nonce", "0" * 64),
        ("expires_at", "2999-01-01T00:00:00+00:00"),
        ("proposed_identity_sha256", "0" * 64),
    ],
)
def test_signature_binds_the_exact_server_message(client, local_app, field, value):
    key = SigningKey.generate()
    challenge = issue_control(client, {"action": "register", "registration": registration_for(key)})
    modified = copy.deepcopy(challenge)
    modified["message"][field] = value
    before = _state(local_app)
    _problem(
        client.post("/api/v1/agents/verify", json=proof_for(key, modified)),
        401,
        "invalid_signature",
    )
    assert _state(local_app) == before
    assert client.post("/api/v1/agents/verify", json=proof_for(key, challenge)).status_code == 200


@pytest.mark.parametrize(
    "extra", [{"identity": {}}, {"registration": {}}, {"authority_effect": "grant"}]
)
def test_verify_cannot_attach_unsigned_metadata(client, local_app, extra):
    key = SigningKey.generate()
    challenge = issue_control(client, {"action": "register", "registration": registration_for(key)})
    before = _state(local_app)
    _problem(
        client.post("/api/v1/agents/verify", json={**proof_for(key, challenge), **extra}),
        400,
        "invalid_proof",
    )
    assert _state(local_app) == before


@pytest.mark.parametrize("path", ["/api/v1/agents/challenge", "/api/v1/agents/verify"])
@pytest.mark.parametrize(
    "body",
    [
        b'{"action":"register","action":"revoke"}',
        b'{"registration":{"display_name":"a","display_name":"b"}}',
        b'{"signature":"first","signature":"second"}',
        b'{"registration":{"operator_backing":{"score":NaN}}}',
        b'{"registration":{"operator_backing":{"score":Infinity}}}',
        b'{"registration":{"operator_backing":{"score":-Infinity}}}',
        b'{"registration":{"operator_backing":{"score":1e999}}}',
        b'{"registration":{"operator_backing":{"score":-1e999}}}',
        b"[]",
        b"null",
        b'{"value":"\xff"}',
    ],
)
def test_non_json_and_duplicate_members_are_rejected_before_service(
    client, local_app, monkeypatch, path, body
):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid JSON reached the key-control service")

    monkeypatch.setattr(local_app.KEY_CONTROL, "issue", forbidden)
    monkeypatch.setattr(local_app.KEY_CONTROL, "verify", forbidden)
    before = _state(local_app)
    response = client.post(path, content=body, headers={"Content-Type": "application/json"})
    _problem(response, 400, "invalid_json")
    assert _state(local_app) == before


@pytest.mark.parametrize("path", ["/api/v1/agents/challenge", "/api/v1/agents/verify"])
def test_size_and_media_type_are_bounded_before_service(client, local_app, monkeypatch, path):
    def forbidden(*args, **kwargs):
        pytest.fail("Unbounded command reached the key-control service")

    monkeypatch.setattr(local_app.KEY_CONTROL, "issue", forbidden)
    monkeypatch.setattr(local_app.KEY_CONTROL, "verify", forbidden)
    before = _state(local_app)
    _problem(
        client.post(path, content=b"{}", headers={"Content-Type": "text/plain"}),
        415,
        "invalid_content_type",
    )
    _problem(
        client.post(path, content=b" " * 16385, headers={"Content-Type": "application/json"}),
        413,
        "identity_command_too_large",
    )
    assert _state(local_app) == before


@pytest.mark.parametrize(
    "extra",
    [
        {"authority_effect": "grant_standing"},
        {"private_key": "synthetic-secret-marker"},
        {"operator_backing": {"signing-key": "synthetic-secret-marker"}},
        {"external_attestations": [{"payload": {"api_key": "synthetic-secret-marker"}}]},
    ],
)
def test_registration_rejects_secret_or_undeclared_fields_without_echo(client, local_app, extra):
    before = _state(local_app)
    response = client.post(
        "/api/v1/agents/challenge",
        json={
            "action": "register",
            "registration": registration_for(SigningKey.generate(), **extra),
        },
    )
    _problem(response, 400, "invalid_registration")
    assert "synthetic-secret-marker" not in response.text
    # Initialization may add empty private tables; no rejected metadata persists.
    assert _row_count(local_app, "web_agents") == 0
    assert _row_count(local_app, "sab_key_control_bindings_v1") == 0
    assert _row_count(local_app, "sab_key_control_proofs_v1") == 0
    assert "synthetic-secret-marker" not in "\n".join(_state(local_app))
    assert all("INSERT INTO" not in line for line in _state(local_app) if line not in before)


def _legacy_signed_contribution(client, key, subject):
    from agora.sab_identity import canonical_json_bytes

    content = "A synthetic legacy contribution after a key transition."
    message = {
        "kind": "spark_submit",
        "author_id": subject,
        "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
    }
    return client.post(
        "/api/spark/submit",
        json={
            "content": content,
            "content_type": "text",
            "author_id": subject,
            "signature": key.sign(canonical_json_bytes(message)).signature.hex(),
        },
    )


def test_revocation_rejects_new_writes_and_reenrollment_preserving_signed_history(
    client, local_app
):
    key = SigningKey.generate()
    registration = registration_for(key)
    identity = enroll_identity(client, key, registration)
    subject = identity["subject_id"]
    packet = signed_seed(key, subject, "sab_seed_before_revocation")
    assert client.post("/api/v1/seeds", json=packet).status_code == 201
    history = client.get("/api/v1/seeds/sab_seed_before_revocation").json()
    pending = issue_control(client, {"action": "register", "registration": registration})
    retired = prove_control(client, key, {"action": "revoke", "subject_id": subject})
    assert retired["binding"]["status"] == retired["identity"]["revocation_status"] == "revoked"
    assert retired["binding"]["scope"] == "key_control_only"
    before = _state(local_app)
    denied = client.post(
        "/api/v1/seeds", json=signed_seed(key, subject, "sab_seed_after_revocation")
    )
    assert denied.status_code == 403, denied.text
    assert denied.json()["detail"]["code"] == "key_control_inactive"
    assert _legacy_signed_contribution(client, key, subject).status_code == 403
    _problem(
        client.post("/api/v1/agents/verify", json=proof_for(key, pending)),
        409,
        "challenge_unavailable",
    )
    _problem(
        client.post(
            "/api/v1/agents/challenge", json={"action": "register", "registration": registration}
        ),
        403,
        "key_control_inactive",
    )
    _problem(client.post("/api/v1/agents/register", json=registration), 428, "key_control_required")
    assert _state(local_app) == before
    legacy_retry = client.post(
        "/api/agents/register",
        json={"name": registration["display_name"], "public_key": registration["public_key"]},
    )
    assert legacy_retry.status_code == 201, legacy_retry.text
    assert legacy_retry.json()["key_control"]["status"] == "revoked"
    assert _state(local_app) == before
    assert client.get("/api/v1/seeds/sab_seed_before_revocation").json() == history
    assert client.get("/api/v1/seeds/sab_seed_before_revocation/chain").json()["verified"] is True
    home = client.get("/api/v1/agents/me/home", params={"subject_id": subject}).json()
    assert home["identity_status"] == "revoked"
    assert home["recommended_next_action"] == "resolve_key_control"
    assert home["key_control"]["status"] == "revoked"


def test_rotation_requires_both_keys_and_leaves_original_authorship_with_retired_key(
    client, local_app
):
    old_key, new_key = SigningKey.generate(), SigningKey.generate()
    old_identity = enroll_identity(client, old_key)
    old_subject = old_identity["subject_id"]
    packet = signed_seed(old_key, old_subject, "sab_seed_before_rotation")
    assert client.post("/api/v1/seeds", json=packet).status_code == 201
    history = client.get("/api/v1/seeds/sab_seed_before_rotation").json()
    challenge = issue_control(
        client,
        {
            "action": "rotate",
            "subject_id": old_subject,
            "registration": registration_for(new_key, "successor"),
        },
    )
    before = _state(local_app)
    _problem(
        client.post("/api/v1/agents/verify", json=proof_for(old_key, challenge)),
        401,
        "invalid_signature",
    )
    _problem(
        client.post(
            "/api/v1/agents/verify",
            json=proof_for(old_key, challenge, successor_key=SigningKey.generate()),
        ),
        401,
        "invalid_signature",
    )
    assert _state(local_app) == before
    response = client.post(
        "/api/v1/agents/verify", json=proof_for(old_key, challenge, successor_key=new_key)
    )
    assert response.status_code == 200, response.text
    result = response.json()
    new_subject = result["identity"]["subject_id"]
    assert new_subject != old_subject
    assert result["binding"]["status"] == "active"
    assert result["previous_binding"]["status"] == "superseded"
    assert result["previous_binding"]["successor_subject_id"] == new_subject
    assert result["authority_effect"] == result["standing_effect"] == "none"
    transitioned = _state(local_app)
    assert (
        client.post(
            "/api/v1/seeds", json=signed_seed(old_key, old_subject, "sab_seed_retired_rotation")
        ).status_code
        == 403
    )
    assert _legacy_signed_contribution(client, old_key, old_subject).status_code == 403
    assert _state(local_app) == transitioned
    assert (
        client.post(
            "/api/v1/seeds", json=signed_seed(new_key, new_subject, "sab_seed_successor_rotation")
        ).status_code
        == 201
    )
    assert client.get("/api/v1/seeds/sab_seed_before_rotation").json() == history
    assert history["seed_packet"]["signature"]["signer"] == old_subject
    old_home = client.get("/api/v1/agents/me/home", params={"subject_id": old_subject}).json()
    new_home = client.get("/api/v1/agents/me/home", params={"subject_id": new_subject}).json()
    assert old_home["identity"]["revocation_status"] == "superseded"
    assert new_home["key_control"]["status"] == "active"
    assert [seed["seed_id"] for seed in old_home["pending_seeds"]] == ["sab_seed_before_rotation"]
    assert [seed["seed_id"] for seed in new_home["pending_seeds"]] == [
        "sab_seed_successor_rotation"
    ]


@pytest.mark.parametrize("source", ["legacy_api", "browser_custody"])
def test_rehearsal_keys_cannot_bypass_v1_key_control(client, local_app, source):
    if source == "legacy_api":
        key = SigningKey.generate()
        historical_web_identity(local_app, key.verify_key.encode().hex(), "legacy-unproven")
        response = client.post(
            "/api/agents/register",
            json={"name": "legacy-unproven", "public_key": key.verify_key.encode().hex()},
        )
        assert response.status_code == 201, response.text
        subject = response.json()["id"]
        assert response.json()["key_control"]["status"] == "unproven"
    else:
        response = client.post(
            "/register", data={"display_name": "browser-custody-unproven"}, follow_redirects=False
        )
        assert response.status_code == 303, response.text
        session = next(iter(local_app._WEB_SESSIONS.values()))
        subject = session["agent_id"]
        key = local_app._signing_key_from_session(session)
    # Historical browser/discourse use is still exercised, but cannot promote a
    # locally generated or merely disclosed key into a v1 enrollment proof.
    assert _legacy_signed_contribution(client, key, subject).status_code == 201
    before = _state(local_app)
    response = client.post("/api/v1/seeds", json=signed_seed(key, subject))
    assert response.status_code == 428, response.text
    assert response.json()["detail"]["code"] == "key_control_unproven"
    assert _state(local_app) == before
    home = client.get("/api/v1/agents/me/home", params={"subject_id": subject}).json()
    assert home["identity_status"] == "unproven"
    assert home["recommended_next_action"] == "prove_key_control"
    assert home["identity"] is None
    assert home["key_control"]["scope"] == "key_control_only"


def test_host_and_proxy_headers_do_not_choose_the_challenge_audience(client):
    response = client.post(
        "/api/v1/agents/challenge",
        json={"action": "register", "registration": registration_for(SigningKey.generate())},
        headers={
            "Host": "attacker.invalid",
            "Forwarded": "host=attacker.invalid;proto=https",
            "X-Forwarded-Host": "attacker.invalid",
            "X-Forwarded-Proto": "https",
            "X-Original-URL": "https://attacker.invalid/api/v1/agents/verify",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["message"]["audience"] == "http://127.0.0.1:8000"


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "http://example.org",
        "https://example.org/path",
        "https://user:password@example.org",
        "https://example.org?audience=elsewhere",
    ],
)
def test_invalid_configured_origin_fails_before_private_paths(tmp_path, monkeypatch, origin):
    monkeypatch.setenv("SAB_PUBLIC_MODE", "local")
    monkeypatch.setenv("SAB_IDENTITY_ORIGIN", origin)
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "private" / "authority.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "private" / "system.key"))
    with pytest.raises(ValueError, match="Identity audience"):
        _reload_app()
    assert not (tmp_path / "private").exists()


@pytest.mark.parametrize(
    "path", ["/api/v1/agents/register", "/api/v1/agents/challenge", "/api/v1/agents/verify"]
)
def test_public_key_commands_are_denied_before_body_or_private_services(
    tmp_path, monkeypatch, path
):
    from publication_fixtures import database_observation

    monkeypatch.setenv("SAB_PUBLIC_MODE", "public_readonly")
    monkeypatch.setenv("SAB_IDENTITY_ORIGIN", "invalid-but-unused-public-config")
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT", raising=False)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "private" / "authority.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "private" / "system.key"))
    module = _reload_app()
    assert module.KEY_CONTROL is None
    before = database_observation(module)

    async def run():
        messages = []

        async def forbidden():
            pytest.fail("Public identity command consumed a request body")

        async def send(message):
            messages.append(message)

        await module.app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "path": path,
                "raw_path": path.encode(),
                "root_path": "",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
                "scheme": "http",
                "server": ("127.0.0.1", 8000),
                "client": ("127.0.0.1", 10000),
            },
            forbidden,
            send,
        )
        assert messages[0]["status"] == 403
        assert json.loads(messages[1]["body"])["code"] == "public_readonly"

    asyncio.run(run())
    assert database_observation(module) == before
    with module._db() as conn:
        assert (
            conn.execute(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'sab_key_control_%'"
            ).fetchone()[0]
            == 0
        )
    assert not (tmp_path / "private").exists()


def test_concurrent_verification_consumes_one_challenge_once(client, local_app):
    key = SigningKey.generate()
    challenge = issue_control(client, {"action": "register", "registration": registration_for(key)})
    proof = proof_for(key, challenge)
    barrier = Barrier(2)

    def verify():
        with TestClient(local_app.app) as concurrent_client:
            barrier.wait(timeout=10)
            return concurrent_client.post("/api/v1/agents/verify", json=proof)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(verify) for _ in range(2)]
        outcomes = [future.result(timeout=20) for future in futures]
    assert sorted(response.status_code for response in outcomes) == [200, 409]
    assert _row_count(local_app, "sab_key_control_proofs_v1") == 1
    assert _row_count(local_app, "sab_key_control_bindings_v1") == 1
    assert _row_count(local_app, "sab_key_control_challenges_v1") == 0


def test_contribution_commits_before_concurrent_retirement_and_future_writes_fail(
    client, local_app, monkeypatch
):
    from contextlib import contextmanager

    from agora import key_control

    key = SigningKey.generate()
    identity = enroll_identity(client, key)
    subject = identity["subject_id"]
    revoke = issue_control(client, {"action": "revoke", "subject_id": subject})
    packet = signed_seed(key, subject, "sab_seed_linearized_before_revoke")
    writer_checked, retirement_entered, release_writer = Event(), Event(), Event()
    original_check = local_app.KEY_CONTROL.require_active_binding
    original_transaction = key_control._transaction

    def hold_writer_after_key_check(conn, subject_id):
        result = original_check(conn, subject_id)
        if not writer_checked.is_set():
            assert conn.in_transaction
            writer_checked.set()
            assert release_writer.wait(timeout=10), "Contribution transaction was not released"
        return result

    @contextmanager
    def observe_retirement_transaction(conn):
        retirement_entered.set()
        with original_transaction(conn):
            yield

    monkeypatch.setattr(
        local_app.KEY_CONTROL, "require_active_binding", hold_writer_after_key_check
    )
    monkeypatch.setattr(key_control, "_transaction", observe_retirement_transaction)

    def post(path, payload):
        with TestClient(local_app.app) as concurrent_client:
            return concurrent_client.post(path, json=payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(post, "/api/v1/seeds", packet)
        try:
            assert writer_checked.wait(timeout=10), "Contribution did not check the active binding"
            retirement = pool.submit(post, "/api/v1/agents/verify", proof_for(key, revoke))
            assert retirement_entered.wait(timeout=10), "Retirement did not reach its transaction"
            assert not retirement.done(), "Retirement passed the uncommitted contribution"
        finally:
            release_writer.set()
        written = writer.result(timeout=20)
        retired = retirement.result(timeout=20)
    assert written.status_code == 201, written.text
    assert retired.status_code == 200, retired.text
    assert retired.json()["binding"]["status"] == "revoked"
    history = client.get("/api/v1/seeds/sab_seed_linearized_before_revoke").json()
    assert history["seed_packet"] == packet
    before = _state(local_app)
    rejected = client.post(
        "/api/v1/seeds", json=signed_seed(key, subject, "sab_seed_linearized_after_revoke")
    )
    assert rejected.status_code == 403, rejected.text
    assert _state(local_app) == before


def test_expired_challenge_does_not_enroll_a_key_over_http(client, local_app, monkeypatch):
    key = SigningKey.generate()
    challenge = issue_control(client, {"action": "register", "registration": registration_for(key)})
    service = local_app.KEY_CONTROL
    wall, monotonic = service._utc_now, service._monotonic
    monkeypatch.setattr(service, "_utc_now", lambda: wall() + timedelta(seconds=121))
    monkeypatch.setattr(service, "_monotonic", lambda: monotonic() + 121)
    before = _state(local_app)
    _problem(
        client.post("/api/v1/agents/verify", json=proof_for(key, challenge)),
        410,
        "challenge_expired",
    )
    assert _state(local_app) == before


def test_clock_uncertainty_stops_http_proofs_and_remains_latched(client, local_app, monkeypatch):
    key = SigningKey.generate()
    challenge = issue_control(client, {"action": "register", "registration": registration_for(key)})
    service = local_app.KEY_CONTROL
    wall = service._utc_now
    monkeypatch.setattr(service, "_utc_now", lambda: wall() - timedelta(seconds=6))
    before = _state(local_app)
    _problem(
        client.post("/api/v1/agents/verify", json=proof_for(key, challenge)), 503, "clock_uncertain"
    )
    monkeypatch.setattr(service, "_utc_now", wall)
    _problem(
        client.post("/api/v1/agents/verify", json=proof_for(key, challenge)), 503, "clock_uncertain"
    )
    _problem(
        client.post(
            "/api/v1/agents/challenge",
            json={"action": "register", "registration": registration_for(SigningKey.generate())},
        ),
        503,
        "clock_uncertain",
    )
    assert _state(local_app) == before


def test_process_restart_preserves_active_proof_but_invalidates_pending_challenges(
    client, local_app
):
    active_key = SigningKey.generate()
    identity = enroll_identity(client, active_key)
    pending_key = SigningKey.generate()
    pending = issue_control(
        client, {"action": "register", "registration": registration_for(pending_key)}
    )
    reloaded = _reload_app()
    with TestClient(reloaded.app) as restarted_client:
        before = _state(reloaded)
        _problem(
            restarted_client.post("/api/v1/agents/verify", json=proof_for(pending_key, pending)),
            409,
            "challenge_unavailable",
        )
        assert _state(reloaded) == before
        response = restarted_client.post(
            "/api/v1/seeds", json=signed_seed(active_key, identity["subject_id"])
        )
        assert response.status_code == 201, response.text
        home = restarted_client.get(
            "/api/v1/agents/me/home", params={"subject_id": identity["subject_id"]}
        ).json()
        assert home["identity_status"] == "active"
        assert home["identity"] == identity
