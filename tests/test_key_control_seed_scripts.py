"""Synthetic seed-script compatibility without user identities or live services."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
from nacl.signing import SigningKey
import pytest

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:8000"


def load_script(name):
    spec = importlib.util.spec_from_file_location(
        "synthetic_" + name, ROOT / "scripts" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def codex():
    return load_script("register_codex_seed_agent")


@pytest.fixture
def demo():
    return load_script("seed_anchor04_demo")


@pytest.fixture
def local(tmp_path):
    from agora.key_control import KeyControlService
    from agora.sab_seeding_api import SabSeedingDeps, _init_v1_tables, create_sab_seeding_router

    database = tmp_path / "synthetic.sqlite"

    @contextmanager
    def db():
        conn = sqlite3.connect(database)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize():
        with db() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS web_agents (
                id TEXT PRIMARY KEY,name TEXT,public_key TEXT UNIQUE,created_at TEXT,
                witness_count INTEGER,witness_accuracy REAL)""")
            _init_v1_tables(conn)

    initialize()
    service = KeyControlService(ORIGIN)

    def unused(*args, **kwargs):
        raise AssertionError("unrelated lifecycle dependency was called")

    app = FastAPI()
    app.include_router(
        create_sab_seeding_router(
            SabSeedingDeps(
                init_db=initialize,
                db=db,
                verify_agent_signature=unused,
                system_sign=unused,
                utc_now=lambda: datetime.now(timezone.utc).isoformat(),
                invalidate_web_cache=lambda: None,
                key_control=service,
            )
        )
    )
    requests = []
    with TestClient(app, base_url=ORIGIN) as client:

        def forward(request):
            requests.append(
                (
                    request.method,
                    request.url.path,
                    json.loads(request.content) if request.content else None,
                )
            )
            assert request.url.path != "/api/agents/register"
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

        yield SimpleNamespace(
            client=client,
            db=db,
            service=service,
            requests=requests,
            transport=httpx.MockTransport(forward),
        )


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_identity(key, *, subject=None):
    from agora.sab_identity import subject_id_from_public_key

    public = key.verify_key.encode().hex()
    return {
        "agent_id": subject or subject_id_from_public_key(public),
        "display_name": "Codex-Seed-01",
        "private_key_hex": key.encode().hex(),
        "public_key_hex": public,
        "custom_history": "retain",
    }


def insert_historical(local, identity):
    with local.db() as conn:
        conn.execute(
            "INSERT INTO web_agents VALUES (?,?,?,?,7,0.8)",
            (
                identity["agent_id"],
                identity["display_name"],
                identity["public_key_hex"],
                "2026-07-01T00:00:00Z",
            ),
        )


def state(local):
    with local.db() as conn:
        return tuple(conn.iterdump())


@pytest.mark.parametrize("script", ["register_codex_seed_agent", "seed_anchor04_demo"])
def test_importing_helpers_has_no_server_or_identity_side_effect(script, tmp_path):
    sentinel = tmp_path / "must-not-exist"
    program = """
import importlib.util, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('synthetic_seed_script', sys.argv[2])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert 'agora.app' not in sys.modules
assert not Path(sys.argv[3]).exists()
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            program,
            str(ROOT),
            str(ROOT / "scripts" / (script + ".py")),
            str(sentinel),
        ],
        cwd=tmp_path,
        env={
            "PATH": os.defpath,
            "SAB_PUBLIC_MODE": "local",
            "SAB_SPARK_DB_PATH": str(sentinel / "server.sqlite"),
            "SAB_SYSTEM_WITNESS_KEY": str(sentinel / "system.key"),
        },
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert not sentinel.exists()


def test_new_codex_identity_has_canonical_subject_and_original_private_format(codex, tmp_path):
    from agora.sab_identity import subject_id_from_public_key

    path = tmp_path / "new.identity.json"
    identity, created = codex._load_or_create_identity(path)
    assert created
    assert identity["agent_id"] == subject_id_from_public_key(identity["public_key_hex"])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "private_key_hex" in identity and "public_key_hex" in identity
    before = file_digest(path), path.stat().st_mtime_ns
    loaded, created = codex._load_or_create_identity(path)
    assert not created
    assert loaded["agent_id"] == identity["agent_id"]
    assert (file_digest(path), path.stat().st_mtime_ns) == before


def test_new_codex_registration_uses_only_challenge_and_verify(codex, local, tmp_path):
    identity, _ = codex._load_or_create_identity(tmp_path / "new.identity.json")
    result = codex._register_agent(ORIGIN, identity, transport=local.transport)
    assert result["id"] == identity["agent_id"]
    assert result["key_control"]["status"] == "active"
    assert result["registration_basis"] == "signed_key_control"
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert [(method, path) for method, path, _ in local.requests] == [
        ("POST", "/api/v1/agents/challenge"),
        ("POST", "/api/v1/agents/verify"),
    ]
    assert all(identity["private_key_hex"] not in json.dumps(body) for _, _, body in local.requests)
    with local.db() as conn:
        assert (
            local.service.require_active_binding(conn, identity["agent_id"])
            == identity["public_key_hex"]
        )


def test_new_identity_intent_is_checked_before_signature(codex, local, tmp_path):
    from agora.key_control_client import KeyControlClientError

    identity, _ = codex._load_or_create_identity(tmp_path / "new.identity.json")
    seen = []

    def altered(request):
        seen.append(request.url.path)
        response = local.transport.handle_request(request)
        response.read()
        body = response.json()
        body["message"]["audience"] = "https://wrong.example"
        return httpx.Response(response.status_code, json=body, request=request)

    with pytest.raises(KeyControlClientError):
        codex._register_agent(ORIGIN, identity, transport=httpx.MockTransport(altered))
    assert seen == ["/api/v1/agents/challenge"]
    with local.db() as conn:
        assert conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 0


def test_historical_short_identity_is_only_read_and_private_file_untouched(codex, local, tmp_path):
    key = SigningKey.generate()
    old_subject = hashlib.sha256(key.verify_key.encode().hex().encode()).hexdigest()[:16]
    identity = private_identity(key, subject=old_subject)
    path = tmp_path / "historical.identity.json"
    path.write_text(json.dumps(identity, indent=3) + "\n")
    path.chmod(0o400)
    before_file = file_digest(path), path.stat().st_mtime_ns, path.stat().st_mode
    insert_historical(local, identity)
    before_db = state(local)
    loaded, created = codex._load_or_create_identity(path)
    result = codex._register_agent(ORIGIN, loaded, transport=local.transport)
    assert not created
    assert result["id"] == old_subject
    assert result["registration_basis"] == "existing_historical_row"
    assert result["key_control"]["status"] == "unproven"
    assert [(method, route) for method, route, _ in local.requests] == [
        ("GET", "/api/v1/agents/me/home")
    ]
    assert state(local) == before_db
    assert (file_digest(path), path.stat().st_mtime_ns, path.stat().st_mode) == before_file


def test_missing_historical_identity_never_falls_back_to_new_enrollment(codex, local):
    identity = private_identity(SigningKey.generate(), subject="0123456789abcdef")
    before = state(local)
    with pytest.raises(RuntimeError, match="seed_request_failed_http_404"):
        codex._register_agent(ORIGIN, identity, transport=local.transport)
    assert state(local) == before
    assert [(method, route) for method, route, _ in local.requests] == [
        ("GET", "/api/v1/agents/me/home")
    ]


@pytest.mark.parametrize("field", ["name", "public_key", "id", "inactive"])
def test_conflicting_historical_read_cannot_be_used_for_registration(codex, field):
    identity = private_identity(SigningKey.generate(), subject="0123456789abcdef")
    agent = {
        "id": identity["agent_id"],
        "name": identity["display_name"],
        "public_key": identity["public_key_hex"],
    }
    if field != "inactive":
        agent[field] = "conflict"
    home = {
        "agent": agent,
        "identity": None,
        "key_control": {"status": "revoked" if field == "inactive" else "unproven"},
    }
    seen = []

    def read_only(request):
        seen.append(request.method)
        return httpx.Response(200, json=home, request=request)

    with pytest.raises(RuntimeError, match="historical_identity_binding_mismatch_or_inactive"):
        codex._register_agent(ORIGIN, identity, transport=httpx.MockTransport(read_only))
    assert seen == ["GET"]


def test_existing_canonical_partial_binding_is_not_silently_migrated(codex, local):
    from agora.key_control_client import KeyControlClientError

    identity = private_identity(SigningKey.generate())
    insert_historical(local, identity)
    before = state(local)
    with pytest.raises(KeyControlClientError) as error:
        codex._register_agent(ORIGIN, identity, transport=local.transport)
    assert error.value.status_code == 409
    assert state(local) == before
    assert [(method, route) for method, route, _ in local.requests] == [
        ("POST", "/api/v1/agents/challenge")
    ]


def test_participant_key_mismatch_fails_before_network(codex):
    identity = private_identity(SigningKey.generate())
    identity["public_key_hex"] = SigningKey.generate().verify_key.encode().hex()

    def forbidden(request):
        raise AssertionError("mismatched private/public key reached the network")

    with pytest.raises(RuntimeError, match="participant_identity_key_mismatch"):
        codex._register_agent(ORIGIN, identity, transport=httpx.MockTransport(forbidden))


def test_codex_spark_signature_uses_existing_wire_without_server_import(codex):
    from agora.sab_identity import canonical_json_bytes

    key = SigningKey.generate()
    identity = private_identity(key)

    def verify(request):
        assert request.url.path == "/api/spark/submit"
        payload = json.loads(request.content)
        message = canonical_json_bytes(
            {
                "kind": "spark_submit",
                "author_id": identity["agent_id"],
                "content_sha256": hashlib.sha256(payload["content"].encode()).hexdigest(),
            }
        )
        key.verify_key.verify(message, bytes.fromhex(payload["signature"]))
        assert identity["private_key_hex"] not in request.content.decode()
        return httpx.Response(200, json={"id": 17, "status": "spark"}, request=request)

    assert (
        codex._submit_first_spark(ORIGIN, identity, transport=httpx.MockTransport(verify))["id"]
        == 17
    )


def test_demo_register_uses_real_signed_enrollment(demo, local):
    requests = []

    class RecordedClient:
        def request(self, method, url, **kwargs):
            requests.append((method, httpx.URL(url).path))
            return local.client.request(method, url, **kwargs)

    key, subject = demo._register(RecordedClient(), "synthetic demo", origin=ORIGIN)
    assert requests == [("POST", "/api/v1/agents/challenge"), ("POST", "/api/v1/agents/verify")]
    with local.db() as conn:
        assert local.service.require_active_binding(conn, subject) == key.verify_key.encode().hex()


def test_demo_checks_challenge_intent_before_signing(demo, local):
    from agora.key_control_client import KeyControlClientError

    requests = []

    class AlteredClient:
        def request(self, method, url, **kwargs):
            requests.append(httpx.URL(url).path)
            response = local.client.request(method, url, **kwargs)
            payload = response.json()
            payload["message"]["path"] = "/api/spark/submit"
            return httpx.Response(response.status_code, json=payload)

    with pytest.raises(KeyControlClientError):
        demo._register(AlteredClient(), "synthetic demo", origin=ORIGIN)
    assert requests == ["/api/v1/agents/challenge"]


def test_demo_signing_helpers_preserve_all_existing_purposes(demo):
    from agora.sab_identity import canonical_json_bytes

    key = SigningKey.generate()
    digest = hashlib.sha256(b"content").hexdigest()
    cases = [
        (
            demo._sign_submit(key, "agent_demo", "content"),
            {"kind": "spark_submit", "author_id": "agent_demo", "content_sha256": digest},
        ),
        (
            demo._sign_challenge(key, 1, "agent_demo", "content"),
            {
                "kind": "spark_challenge",
                "spark_id": 1,
                "challenger_id": "agent_demo",
                "content_sha256": digest,
            },
        ),
        (
            demo._sign_sublation(
                key,
                challenge_id=2,
                predecessor_spark_id=1,
                corrector_id="agent_demo",
                successor_content="content",
                artifact_ref="content",
                note="content",
            ),
            {
                "kind": "spark_challenge_sublation",
                "challenge_id": 2,
                "predecessor_spark_id": 1,
                "corrector_id": "agent_demo",
                "successor_content_sha256": digest,
                "artifact_ref_sha256": digest,
                "note_sha256": digest,
            },
        ),
        (
            demo._sign_witness(
                key, spark_id=1, witness_id="agent_demo", action="affirm", payload={"test": True}
            ),
            {
                "kind": "witness_attestation",
                "spark_id": 1,
                "witness_id": "agent_demo",
                "action": "affirm",
                "payload_sha256": hashlib.sha256(canonical_json_bytes({"test": True})).hexdigest(),
            },
        ),
    ]
    for signature, message in cases:
        key.verify_key.verify(canonical_json_bytes(message), bytes.fromhex(signature))
