from __future__ import annotations

import asyncio
import importlib
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agora.public_runtime import (
    PublicMode,
    PublicReadonlyMiddleware,
    public_read_request,
    read_public_mode,
)


WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "PROPFIND", "COPY")
BROWSER_SESSION_PATHS = (
    "/api/v1/browser/session", "/api/v1/browser/session/challenge",
    "/api/v1/browser/session/verify", "/api/v1/browser/session/logout",
)


def _load_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str | None = None):
    if mode is None:
        monkeypatch.delenv("SAB_PUBLIC_MODE", raising=False)
    else:
        monkeypatch.setenv("SAB_PUBLIC_MODE", mode)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT", raising=False)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    for name in ("SAB_SPARK_DB_PATH", "SAB_AUTHORITY_DB_PATH", "SAB_DB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / "readonly.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "system.key"))
    monkeypatch.setenv("SAB_SEED_CLAIMS_PATH", str(tmp_path / "no_seed_claims.json"))
    monkeypatch.delitem(sys.modules, "agora.app", raising=False)
    module = importlib.import_module("agora.app")
    monkeypatch.setattr(module, "FRONTIER_PACKET_DIR", tmp_path / "no_packets")
    monkeypatch.setattr(module, "FRONTIER_RECEIPT_DIR", tmp_path / "no_receipts")
    return module


@pytest.fixture
def public_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    return _load_app(tmp_path, monkeypatch)


def _database_snapshot(module) -> tuple[str, ...]:
    from publication_fixtures import database_observation

    return database_observation(module)


def _assert_readonly(response) -> None:
    assert response.status_code == 403, response.text
    assert response.json() == {
        "code": "public_readonly",
        "mode": "public_readonly",
        "detail": "This SAB instance is read-only. Write operations are disabled.",
    }
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers


def test_default_and_explicit_startup_modes() -> None:
    assert read_public_mode({}) == PublicMode.PUBLIC_READONLY
    assert read_public_mode({"SAB_PUBLIC_MODE": "public_readonly"}) == PublicMode.PUBLIC_READONLY
    assert read_public_mode({"SAB_PUBLIC_MODE": "local"}) == PublicMode.LOCAL


@pytest.mark.parametrize("value", ["", "LOCAL", "local ", " public_readonly", "false", "invite_beta"])
def test_invalid_mode_fails_before_database_or_key_creation(tmp_path, monkeypatch, value):
    with pytest.raises(ValueError, match="SAB_PUBLIC_MODE"):
        _load_app(tmp_path, monkeypatch, value)
    assert not (tmp_path / "readonly.db").exists()
    assert not (tmp_path / "system.key").exists()


@pytest.mark.parametrize("method", [*WRITE_METHODS, "PURGE", "UNKNOWN", "post", "get", "GET ", "", None])
def test_write_boundary_never_reads_body_or_calls_downstream(method):
    async def run():
        messages = []

        async def forbidden(*args):
            pytest.fail("read-only rejection called downstream code or read the request body")

        async def send(message):
            messages.append(message)

        scope = {"type": "http", "path": "/api/v1/seeds"}
        if method is not None:
            scope["method"] = method
        await PublicReadonlyMiddleware(forbidden)(scope, forbidden, send)
        assert messages[0]["status"] == 403
        assert json.loads(messages[1]["body"])["code"] == "public_readonly"

    asyncio.run(run())


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_read_methods_reach_downstream(method):
    async def run():
        scopes = []

        async def downstream(scope, receive, send):
            assert public_read_request() is True
            scopes.append(scope)

        scope = {"type": "http", "method": method}
        await PublicReadonlyMiddleware(downstream)(scope, None, None)
        assert scopes == [scope]
        assert public_read_request() is False

    asyncio.run(run())


@pytest.mark.parametrize("error", [RuntimeError, asyncio.CancelledError])
def test_public_read_context_resets_when_downstream_fails(error):
    async def run():
        async def downstream(scope, receive, send):
            assert public_read_request() is True
            raise error("request interrupted")

        with pytest.raises(error):
            await PublicReadonlyMiddleware(downstream)(
                {"type": "http", "method": "GET"}, None, None
            )
        assert public_read_request() is False

    asyncio.run(run())


def test_public_read_context_isolated_from_startup_and_concurrent_local_requests():
    async def run():
        public_entered = asyncio.Event()
        local_finished = asyncio.Event()

        async def public_downstream(scope, receive, send):
            assert public_read_request() is True
            public_entered.set()
            await local_finished.wait()
            assert public_read_request() is True

        async def local_downstream(scope, receive, send):
            await public_entered.wait()
            assert public_read_request() is False
            local_finished.set()

        await asyncio.gather(
            PublicReadonlyMiddleware(public_downstream)(
                {"type": "http", "method": "GET"}, None, None
            ),
            PublicReadonlyMiddleware(local_downstream, PublicMode.LOCAL)(
                {"type": "http", "method": "POST"}, None, None
            ),
        )

        async def lifespan(scope, receive, send):
            assert public_read_request() is False

        await PublicReadonlyMiddleware(lifespan)({"type": "lifespan"}, None, None)
        assert public_read_request() is False

    asyncio.run(run())


def test_public_websockets_are_rejected_before_handshake():
    async def run():
        messages = []

        async def forbidden(*args):
            pytest.fail("public WebSocket reached downstream or read a client message")

        async def send(message):
            messages.append(message)

        await PublicReadonlyMiddleware(forbidden)({"type": "websocket"}, forbidden, send)
        assert messages == [{"type": "websocket.close", "code": 1008, "reason": "public_readonly"}]

    asyncio.run(run())


def _registered_paths(routes, prefix="") -> set[str]:
    paths = set()
    for route in routes:
        path = getattr(route, "path", "")
        if path:
            paths.add(prefix + re.sub(r"\{[^}]+\}", "1", path))
        children = getattr(route, "routes", ())
        if not children:
            original = getattr(route, "original_router", None)
            children = getattr(original, "routes", ())
        paths.update(_registered_paths(children, prefix + path))
    return paths


def test_all_registered_paths_mounts_and_unknown_paths_reject_writes(public_app):
    child = FastAPI()
    reached = []

    @child.post("/write")
    async def child_write():
        reached.append(True)
        return {"written": True}

    public_app.app.mount("/_boundary_child", child)
    with TestClient(public_app.app) as client:
        paths = _registered_paths(public_app.app.routes)
        assert {"/api/v1/agents/register", "/api/agents/register", "/register", "/submit"} <= paths
        paths.update({"/never-registered", "/api/v1/never-registered", "/static/missing.css"})
        paths.update(BROWSER_SESSION_PATHS)
        before = _database_snapshot(public_app)
        assert public_app.BROWSER_SESSIONS is None
        assert not public_app.SYSTEM_KEY_PATH.exists()
        for path in sorted(paths):
            for method in WRITE_METHODS:
                # Invalid JSON and a spoofed method must not reach parsing or dependencies.
                response = client.request(
                    method,
                    path,
                    content=b"{malformed",
                    headers={"Content-Type": "application/json", "X-HTTP-Method-Override": "GET"},
                    follow_redirects=False,
                )
                _assert_readonly(response)
        assert not reached
        assert _database_snapshot(public_app) == before
        assert public_app.BROWSER_SESSIONS is None
        assert not public_app.SYSTEM_KEY_PATH.exists()
        assert not public_app.SPARK_DB.exists()
        assert not client.cookies


@pytest.mark.parametrize("old_cookie", ["old-local", "expired-local", "A" * 43])
def test_public_get_pages_do_not_create_or_mutate_browser_sessions(public_app, old_cookie):
    with TestClient(public_app.app) as client:
        # A cookie from a private deployment must not initialize a private
        # service, renew a cookie, or expose a session in the public process.
        client.cookies.set(public_app.WEB_SESSION_COOKIE, old_cookie)
        assert public_app.BROWSER_SESSIONS is None
        before = _database_snapshot(public_app)
        for path in ("/", "/frontier", "/submit", "/about", "/register", "/claims"):
            response = client.get(path)
            assert response.status_code == 200, f"{path}: {response.text}"
            assert "set-cookie" not in response.headers
        for path in BROWSER_SESSION_PATHS:
            response = client.get(path)
            assert response.status_code == 404
            assert "set-cookie" not in response.headers
        assert client.cookies.get(public_app.WEB_SESSION_COOKIE) == old_cookie
        assert public_app.BROWSER_SESSIONS is None
        assert _database_snapshot(public_app) == before
        with public_app._db() as conn:
            assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
        assert not public_app.SPARK_DB.exists()


def test_public_empty_process_never_initializes_authority_tables(public_app):
    with TestClient(public_app.app) as client:
        before = _database_snapshot(public_app)
        for path in ("/", "/api/frontier", "/api/v1/claims", "/api/v1/seeds", "/api/v1/standing", "/health", "/readyz"):
            response = client.get(path)
            assert response.status_code == 200, response.text
            assert response.headers["cache-control"] == "no-store"
        public_app.init_db()
        assert _database_snapshot(public_app) == before
        with public_app._db() as conn:
            assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
        assert not public_app.SPARK_DB.exists()
        assert not public_app.SYSTEM_KEY_PATH.exists()
        assert client.get("/publication").json()["status"] == "not_configured"
        assert client.get("/publication/manifest").status_code == 404
        assert client.get("/api/v1/witness/verify").status_code == 503
        with pytest.raises(RuntimeError, match="no signing key"):
            public_app._system_sign({"kind": "unauthorized startup work"})


@pytest.mark.parametrize("sync_handler", [False, True], ids=["async", "threadpool"])
@pytest.mark.parametrize("disable_query_only", [False, True], ids=["guarded", "pragma_override"])
def test_future_get_handler_cannot_insert_into_public_database(
    public_app, sync_handler, disable_query_only
):
    attempts = []

    def try_insert():
        attempts.append(True)
        with public_app._db() as conn:
            if disable_query_only:
                # A future helper cannot clear the frozen reader's guard.
                conn.execute("PRAGMA query_only = OFF")
            conn.execute("CREATE TABLE unauthorized_get_write (id INTEGER)")
        return {"written": True}

    if sync_handler:
        public_app.app.add_api_route("/_read_boundary_probe", try_insert, methods=["GET"])
    else:
        async def async_insert():
            return try_insert()

        public_app.app.add_api_route("/_read_boundary_probe", async_insert, methods=["GET"])

    with TestClient(public_app.app) as client:
        before = _database_snapshot(public_app)
        assert client.get("/_read_boundary_probe").status_code == 404
        assert attempts == []  # An unlisted path never reaches its handler.
        assert _database_snapshot(public_app) == before
        # Direct helpers and startup work have the same frozen source boundary.
        with pytest.raises(sqlite3.DatabaseError, match="authorized|readonly|read-only"):
            try_insert()
        assert _database_snapshot(public_app) == before


def _seed_expiring_records(conn) -> None:
    """Stored history that used to cause writes merely by being read."""
    timestamp = "2000-01-01T00:00:00+00:00"
    conn.execute(
        """INSERT INTO sab_seed_packets_v1
           (seed_id, seed_type, title, claim_id, claimant_identity,
            authority_lease_id, state, packet_json, packet_hash, created_at, updated_at)
           VALUES (?, 'claim', 'Read-only expiry fixture', 'claim_readonly', 'agent_readonly',
                   'lease_readonly', 'challenged', '{}', 'fixture_hash', ?, ?)""",
        ("seed_readonly", timestamp, timestamp),
    )
    conn.execute(
        """INSERT INTO sab_challenge_packets_v1
           (challenge_id, target_seed_id, target_claim_id, challenger_identity, status,
            packet_json, packet_hash, respond_by, created_at, updated_at)
           VALUES ('challenge_readonly', 'seed_readonly', 'claim_readonly', 'agent_challenger',
                   'pending', '{}', 'fixture_hash', ?, ?, ?)""",
        (timestamp, timestamp, timestamp),
    )
    for standing_id, stored_status, expiry in (
        ("standing_expired", "active", timestamp),
        ("standing_future", "active", "2999-01-01T00:00:00Z"),
        ("standing_canon_expired", "canon", timestamp),
        ("standing_invalid", "active", "not-a-date"),
        ("standing_empty", "active", ""),
    ):
        conn.execute(
            """INSERT INTO sab_standing_leases_v1
               (standing_id, subject_seed_id, subject_claim_id, scope, purpose, status,
                lease_json, lease_hash, expiry, revoker, challenge_path, issued_by,
                issued_at, updated_at)
               VALUES (?, 'seed_readonly', 'claim_readonly', 'fixture', 'expiry observation',
                       ?, '{}', 'fixture_hash', ?, 'agent_revoker', '/challenge',
                       'agent_issuer', ?, ?)""",
            (standing_id, stored_status, expiry, timestamp, timestamp),
        )


def test_v1_reads_observe_expiry_without_changing_stored_history(tmp_path, monkeypatch):
    from publication_fixtures import source_database, configure_publication, import_public_app
    from agora.public_freshness import FreshnessPolicy, PublicationFreshnessObserver

    with source_database() as source:
        _seed_expiring_records(source)
        bundle = configure_publication(source, tmp_path / "bundle", monkeypatch)
    public_app = import_public_app(tmp_path, monkeypatch)
    observed_at = datetime.fromisoformat(public_app.PUBLIC_SNAPSHOT.status["observed_at"])
    monkeypatch.setattr(public_app, "PUBLIC_FRESHNESS", PublicationFreshnessObserver(
        public_app.PUBLIC_SNAPSHOT.status, FreshnessPolicy(),
        utc_now=lambda: observed_at, monotonic=lambda: 0.0,
    ))
    bundle_before = {p.name: p.read_bytes() for p in bundle.iterdir()}
    with TestClient(public_app.app) as client:
        before = _database_snapshot(public_app)
        paths = (
            "/api/v1/seeds/seed_readonly",
            "/api/v1/seeds/seed_readonly/chain",
            "/api/v1/seeds",
            "/api/v1/challenges/challenge_readonly",
            "/api/v1/witness/chain?seed_id=seed_readonly",
            "/api/v1/witness/verify?seed_id=seed_readonly",
            "/api/v1/standing",
        )
        for path in paths:
            response = client.get(path)
            assert response.status_code == 200, f"{path}: {response.text}"
        expired = client.get("/api/v1/standing/standing_expired")
        assert expired.status_code == 200, expired.text
        assert expired.json()["status"] == "expired"
        assert expired.json()["stored_status"] == "active"
        assert expired.json()["status_basis"] == "local_expiry_observation"
        canon = client.get("/api/v1/standing/standing_canon_expired").json()
        assert canon["status"] == "expired"
        assert canon["stored_status"] == "canon"
        for standing_id in ("standing_invalid", "standing_empty"):
            invalid = client.get(f"/api/v1/standing/{standing_id}")
            assert invalid.status_code == 200, invalid.text
            assert invalid.json()["status"] == "unknown"
            assert invalid.json()["status_basis"] == "invalid_expiry"
        active = client.get("/api/v1/standing?status=active").json()["items"]
        assert active == []
        future = client.get("/api/v1/standing/standing_future").json()
        assert future["status"] == "unknown"
        assert future["stored_status"] == "active"
        assert future["status_basis"] == "currentness_unestablished"
        expired_items = client.get("/api/v1/standing?status=expired&limit=1").json()["items"]
        assert [item["standing_id"] for item in expired_items] == ["standing_canon_expired"]
        unknown = client.get("/api/v1/standing?status=unknown").json()["items"]
        assert {item["standing_id"] for item in unknown} == {"standing_invalid", "standing_empty", "standing_future"}
        assert client.get("/api/v1/seeds/seed_readonly").json()["state"] == "challenged"
        assert client.get("/api/v1/challenges/challenge_readonly").json()["status"] == "pending"
        assert _database_snapshot(public_app) == before
        assert public_app.BROWSER_SESSIONS is None
        assert not client.cookies
        assert {p.name: p.read_bytes() for p in bundle.iterdir()} == bundle_before


@pytest.mark.parametrize(
    ("stored", "expiry", "expected", "basis"),
    [
        ("active", "2026-01-01T00:00:00Z", "expired", "expiry_observation"),
        ("canon", "2026-01-01T09:00:00+09:00", "expired", "expiry_observation"),
        ("active", "2026-01-01T00:00:00.000001Z", "unknown", "operator_control_unestablished"),
        ("canon", "2999-01-01T00:00:00Z", "unknown", "operator_control_unestablished"),
        ("active", "garbled", "unknown", "invalid_expiry"),
        ("active", None, "unknown", "invalid_expiry"),
        ("canon", "", "unknown", "invalid_expiry"),
        ("revoked", None, "revoked", "stored"),
        ("superseded", "2000-01-01T00:00:00Z", "superseded", "stored"),
    ],
)
def test_standing_observation_handles_terminal_history_and_expiry(stored, expiry, expected, basis):
    from agora.sab_seeding_api import observe_standing_status

    observed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observation = observe_standing_status(stored, expiry, observed_at=observed_at)
    assert observation == {
        "status": expected,
        "stored_status": stored,
        "status_basis": basis,
        "observed_at": observed_at.isoformat(),
    }


def test_explicit_local_mode_requires_caller_signature_for_historical_discussion(tmp_path, monkeypatch):
    from historical_web_fixtures import database_state, historical_spark

    module = _load_app(tmp_path, monkeypatch, "local")
    with TestClient(module.app) as client:
        before = database_state(module)
        response = client.post(
            "/submit",
            data={"display_name": "Local test author", "content": "A concrete local observation."},
            follow_redirects=False,
        )
        assert response.status_code == 428, response.text
        assert response.json()["error"] == "browser_key_required"
        assert "set-cookie" not in response.headers
        assert not client.cookies
        assert database_state(module) == before
        location = historical_spark(client, "A concrete client-signed historical observation.")
        assert client.get(location).status_code == 200
        assert not client.cookies
        with module._db() as conn:
            assert conn.execute("SELECT COUNT(*) FROM web_agents").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM sparks").fetchone()[0] == 1


def test_mode_cannot_be_changed_by_environment_after_startup(public_app, monkeypatch):
    with TestClient(public_app.app) as client:
        monkeypatch.setenv("SAB_PUBLIC_MODE", "local")
        _assert_readonly(client.post("/register", data={"display_name": "override attempt"}))
        assert public_app.app.state.public_mode == "public_readonly"


def test_public_import_ignores_private_paths_and_does_not_generate_keys(tmp_path, monkeypatch):
    from nacl.signing import SigningKey

    private = tmp_path / "readonly.db"
    private.write_bytes(b"PRIVATE AUTHORITY DATA: deliberately not SQLite")
    key = tmp_path / "system.key"
    key.write_bytes(b"PRIVATE CUSTODY: deliberately not an Ed25519 key")
    files_before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    original_connect = sqlite3.connect

    def memory_only(database, *args, **kwargs):
        assert database == ":memory:", "public process opened a file database"
        return original_connect(database, *args, **kwargs)

    def forbidden_key(*args, **kwargs):
        pytest.fail("public import or startup generated a signing key")

    monkeypatch.setattr(sqlite3, "connect", memory_only)
    monkeypatch.setattr(SigningKey, "generate", forbidden_key)
    module = _load_app(tmp_path, monkeypatch)
    assert module.SYSTEM_SIGNING_KEY is None
    assert module.SYSTEM_VERIFY_KEY_HEX is None
    with TestClient(module.app) as client:
        for path in ("/", "/claims", "/api/frontier", "/api/node/status", "/health", "/readyz"):
            response = client.get(path)
            assert response.status_code == 200, response.text
            assert "PRIVATE" not in response.text
            assert str(tmp_path) not in response.text
    assert {p: p.read_bytes() for p in tmp_path.iterdir()} == files_before


def test_public_frontier_never_scans_private_repository_artifacts(public_app, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("public read consulted private repository artifacts")

    monkeypatch.setattr(public_app, "_frontier_receipts_by_seed", forbidden)
    monkeypatch.setattr(public_app, "_read_json_object", forbidden)
    assert public_app._seed_claim_payload() == {"claims": [], "stats": {"availability": "not_published"}}
    with TestClient(public_app.app) as client:
        assert client.get("/api/frontier").json()["packets"] == []
        assert client.get("/frontier").status_code == 200
        for path in ("/seed", "/feed", "/canon", "/compost", "/spark/1", "/agent/1",
                     "/api/feed", "/api/cache/stats", "/api/v1/agents/me/home", "/static/private.json"):
            response = client.get(path)
            assert response.status_code == 404, path
            assert response.json()["code"] == "not_published"


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_unapproved_snapshot_configuration_fails_without_private_fallback(tmp_path, monkeypatch, pin):
    from agora.public_snapshot import PublicSnapshotError
    from publication_fixtures import import_public_app

    monkeypatch.setenv("SAB_PUBLIC_SNAPSHOT", str(tmp_path / "unapproved"))
    if pin is None:
        monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    else:
        monkeypatch.setenv("SAB_PUBLIC_SNAPSHOT_SHA256", pin)
    with pytest.raises(PublicSnapshotError):
        import_public_app(tmp_path, monkeypatch)
    assert not (tmp_path / "private").exists()


def test_served_publication_is_frozen_after_external_bundle_changes(tmp_path, monkeypatch):
    from publication_fixtures import source_database, configure_publication, import_public_app
    from test_claim_dossier_web import seed

    with source_database() as source:
        seed(source)
        bundle = configure_publication(source, tmp_path / "bundle", monkeypatch)
    module = import_public_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        before = client.get("/api/v1/claims").json()
        manifest = client.get("/publication/manifest").json()
        frontier = client.get("/api/frontier").json()
        assert frontier["stats"]["store"]["available"] is True
        assert frontier["stats"]["store"]["seeds"] == 1
        assert client.get("/api/v1/witness/verify").json()["verified"] is None
        assert client.get("/api/v1/witness/chain").json()["verified"] is None
        with sqlite3.connect(bundle / "snapshot.sqlite3") as conn:
            conn.execute("UPDATE sab_seed_packets_v1 SET title = 'Unapproved replacement'")
        (bundle / "manifest.json").write_text('{"unapproved":"replacement"}')
        assert client.get("/api/v1/claims").json()["items"] == before["items"]
        assert client.get("/publication/manifest").json() == manifest
        assert "Unapproved replacement" not in client.get("/").text
        assert not module.SPARK_DB.exists()
