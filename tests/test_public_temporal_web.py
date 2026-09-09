"""Public pages and headers share one observation without promoting stored history."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from publication_fixtures import configure_publication, import_public_app, source_database
from test_claim_dossier import SEED, _seed, _standing

NOW = datetime(2026, 9, 9, tzinfo=timezone.utc)


class Clock:
    def __init__(self, wall=NOW):
        self.wall, self.elapsed, self.reads = wall, 0.0, 0

    def utc_now(self):
        self.reads += 1
        return self.wall

    def monotonic(self):
        return self.elapsed

    def advance(self, seconds):
        self.wall += timedelta(seconds=seconds)
        self.elapsed += seconds


@pytest.fixture
def site(tmp_path, monkeypatch):
    with source_database() as source:
        _seed(source)
        _standing(source, status="active", expiry="2040-01-01T00:00:00Z")
        bundle = configure_publication(source, tmp_path / "bundle", monkeypatch)
    module = import_public_app(tmp_path, monkeypatch)
    from agora.public_freshness import FreshnessPolicy, PublicationFreshnessObserver

    clock = Clock()
    monkeypatch.setattr(
        module,
        "PUBLIC_FRESHNESS",
        PublicationFreshnessObserver(
            module.PUBLIC_SNAPSHOT.status,
            FreshnessPolicy(maximum_age_seconds=60),
            utc_now=clock.utc_now,
            monotonic=clock.monotonic,
        ),
    )
    with TestClient(module.app) as client:
        yield module, client, clock, bundle
    assert not (tmp_path / "private").exists()


@pytest.mark.parametrize(
    "scenario,age,message",
    [
        ("recent", "within_limit", "Historical inspection"),
        ("stale", "stale", "This publication is out of date"),
        ("future", "future_observation", "Publication time needs review"),
        ("uncertain", "clock_uncertain", "Time checks are uncertain"),
    ],
)
def test_rendered_notice_status_schema_and_headers_agree(site, monkeypatch, scenario, age, message):
    from agora.public_freshness import FreshnessPolicy, PublicationFreshnessObserver

    module, client, clock, bundle = site
    if scenario == "stale":
        clock.advance(60)
    elif scenario == "future":
        clock.wall -= timedelta(seconds=10)
        monkeypatch.setattr(
            module,
            "PUBLIC_FRESHNESS",
            PublicationFreshnessObserver(
                module.PUBLIC_SNAPSHOT.status,
                FreshnessPolicy(maximum_age_seconds=60),
                utc_now=clock.utc_now,
                monotonic=clock.monotonic,
            ),
        )
    elif scenario == "uncertain":
        clock.wall -= timedelta(seconds=30)
        clock.elapsed += 1
    schema_response = client.get("/schemas/sab.public_read_observation.v1.schema.json")
    validator = Draft202012Validator(schema_response.json(), format_checker=FormatChecker())
    for path in ("/", "/status", "/claims", f"/claims/{SEED}", "/frontier"):
        reads = clock.reads
        response = client.get(path)
        assert response.status_code == 200, response.text
        assert clock.reads == reads + 1
        assert response.headers["sab-publication-age-status"] == age
        assert response.headers["sab-currentness"] == "unestablished"
        assert response.headers["cache-control"] == "no-store"
        assert message in response.text
        assert f'data-publication-age="{age}"' in response.text
    publication = client.get("/publication").json()
    observation = publication["publication_observation"]
    validator.validate(observation)
    assert observation["local_age_policy"]["status"] == age
    assert observation["currentness"]["status"] == "unestablished"
    assert client.get("/publication/manifest").content == (bundle / "manifest.json").read_bytes()
    assert "A stable clock can still be wrong" in client.get("/status").text


def test_frontier_and_health_cannot_turn_recorded_history_into_current_permission(site):
    _, client, clock, _ = site
    response = client.get("/api/frontier")
    assert response.status_code == 200
    frontier = response.json()
    assert frontier["generated_at"] == frontier["publication_observation"]["observed_at"]
    assert frontier["board"]["ready_to_build"] == []
    assert frontier["board"]["readiness_basis"] == "currentness_unestablished"
    assert frontier["stats"]["standing_grant_count"] is None
    assert frontier["stats"]["store"]["active_standing"] is None
    card = next(card for card in frontier["packets"] if card["seed_id"] == SEED)
    assert card["standing_effect"] == "none"
    assert card["status_basis"] == "stored"
    assert card["standing_observation"]["stored_status"] == "active"
    assert card["standing_observation"]["status"] == "unknown"
    assert "Recorded Candidates" in client.get("/frontier").text
    for path in ("/readyz", "/health", "/healthz", "/api/node/status"):
        reads = clock.reads
        response = client.get(path)
        assert clock.reads == reads + 1
        body = response.json()
        assert body["timestamp"] == body["publication"]["publication_observation"]["observed_at"]
        assert body["publication"]["readiness_scope"] == "historical_inspection"
        if path == "/readyz":
            assert body["current_use_eligible"] is False


def test_request_inputs_cannot_select_clock_or_publication_policy(site):
    _, client, clock, _ = site
    clock.advance(60)
    response = client.get(
        "/publication?observed_at=2026-09-09T00:00:00Z&maximum_age_seconds=999999999",
        headers={
            "Date": "Wed, 09 Sep 2026 00:00:00 GMT",
            "X-Forwarded-Date": "2000-01-01",
            "SAB-Publication-Age-Status": "within_limit",
            "SAB-Currentness": "verified",
        },
    )
    observation = response.json()["publication_observation"]
    assert observation["local_age_policy"]["status"] == "stale"
    assert observation["policy"]["maximum_age_seconds"] == 60
    assert response.headers["sab-currentness"] == "unestablished"


def test_transport_context_is_fixed_and_resets_after_failure():
    from agora.public_freshness import (
        FreshnessPolicy,
        PublicationFreshnessObserver,
        current_publication_observation,
    )
    from agora.public_runtime import PublicReadonlyMiddleware, public_read_request

    clock = Clock()
    observer = PublicationFreshnessObserver(
        {"configured": True, "observed_at": NOW.isoformat(), "manifest_sha256": "a" * 64},
        FreshnessPolicy(maximum_age_seconds=60),
        utc_now=clock.utc_now,
        monotonic=clock.monotonic,
    )
    clock.advance(59)
    seen = []

    async def downstream(scope, receive, send):
        observation = current_publication_observation()
        assert public_read_request()
        assert observation.local_age_status == "within_limit"
        clock.advance(2)
        assert current_publication_observation() is observation
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"SAB-Currentness", b"verified"),
                    (b"sab-clock-state", b"spoofed"),
                    (b"sab-publication-age-status", b"spoofed"),
                    (b"cache-control", b"public"),
                ],
            }
        )
        raise RuntimeError("handler failure")

    async def send(message):
        seen.append(message)

    async def exercise():
        with pytest.raises(RuntimeError, match="handler failure"):
            await PublicReadonlyMiddleware(downstream, observation_provider=observer.observe)(
                {"type": "http", "method": "GET", "path": "/"}, None, send
            )
        assert current_publication_observation() is None
        assert public_read_request() is False

    asyncio.run(exercise())
    headers = dict(seen[0]["headers"])
    assert headers[b"sab-publication-age-status"] == b"within_limit"
    assert headers[b"sab-currentness"] == b"unestablished"
    assert headers[b"sab-clock-state"] == b"stable"
    assert headers[b"cache-control"] == b"no-store"
    assert b"SAB-Currentness" not in headers
    assert observer.observe().local_age_status == "stale"


@pytest.mark.parametrize(
    "mode,method,path",
    [
        ("public_readonly", "POST", "/"),
        ("public_readonly", "GET", "/private"),
        ("local", "GET", "/"),
    ],
)
def test_denied_and_local_requests_do_not_invoke_public_clock(mode, method, path):
    from agora.public_freshness import current_publication_observation
    from agora.public_runtime import PublicReadonlyMiddleware

    def forbidden():
        pytest.fail("this request must not invoke the public clock")

    async def downstream(scope, receive, send):
        assert mode == "local"
        assert current_publication_observation() is None

    async def send(message):
        pass

    asyncio.run(
        PublicReadonlyMiddleware(
            downstream,
            mode,
            public_read_paths=[r"/"],
            observation_provider=forbidden,
        )({"type": "http", "method": method, "path": path}, None, send)
    )


def test_invalid_policy_rejects_startup_before_loading_publication(tmp_path, monkeypatch):
    from agora import public_snapshot

    def forbidden(*args, **kwargs):
        pytest.fail("invalid policy reached publication loader")

    monkeypatch.setattr(public_snapshot, "load_public_snapshot", forbidden)
    monkeypatch.setenv("SAB_PUBLIC_MAX_SNAPSHOT_AGE_SECONDS", "86401")
    with pytest.raises(ValueError, match="86400"):
        import_public_app(tmp_path, monkeypatch)
    assert not (tmp_path / "private").exists()


def test_unconfigured_reader_does_not_assert_a_current_standing_count(tmp_path, monkeypatch):
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT", raising=False)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    module = import_public_app(tmp_path, monkeypatch)
    with TestClient(module.app) as client:
        response = client.get("/api/frontier")
        assert response.status_code == 200
        store = response.json()["stats"]["store"]
        assert store["available"] is False
        assert store["active_standing"] is None
        assert store["active_standing_basis"] == "currentness_unestablished"
        page = client.get("/status")
        assert page.status_code == 200
        assert "No publication configured" in page.text
        assert page.headers["sab-publication-age-status"] == "not_configured"
    assert not (tmp_path / "private").exists()
