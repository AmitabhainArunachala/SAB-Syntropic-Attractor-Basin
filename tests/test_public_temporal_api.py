"""Public time projections preserve approved bytes and never infer current standing."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


NOW = datetime(2026, 9, 9, tzinfo=timezone.utc)
LEASES = (
    ("future_active", "active", "2040-01-01T00:00:00Z"),
    ("future_canon", "canon", "2040-01-01T00:00:00Z"),
    ("elapsed", "active", "2000-01-01T00:00:00Z"),
    ("offset_elapsed", "active", "2026-09-09T09:00:00+09:00"),
    ("naive", "active", "2000-01-01T00:00:00"),
    ("invalid", "active", "garbled"),
    ("revoked", "revoked", "2040-01-01T00:00:00Z"),
    ("expired_stored", "expired", "2040-01-01T00:00:00Z"),
    ("superseded", "superseded", "2040-01-01T00:00:00Z"),
    ("compost", "compost", "2040-01-01T00:00:00Z"),
    ("unrecognized", "future_custom_status", "2040-01-01T00:00:00Z"),
)


class Clock:
    def __init__(self, wall=NOW):
        self.wall, self.monotonic_value, self.reads = wall, 0.0, 0

    def utc_now(self):
        self.reads += 1
        return self.wall

    def monotonic(self):
        return self.monotonic_value

    def advance(self, seconds):
        self.wall += timedelta(seconds=seconds)
        self.monotonic_value += seconds


def _forbidden(*args, **kwargs):
    pytest.fail("public read invoked initialization, signing, mutation time, or a cache write")


def _rows(snapshot):
    from agora.public_snapshot import PUBLIC_TABLES

    with snapshot.connection() as conn:
        return tuple(
            (name, tuple(tuple(row) for row in conn.execute(f"SELECT * FROM {name} ORDER BY id")))
            if name != "sab_agent_identities_v1"
            else (
                name,
                tuple(
                    tuple(row) for row in conn.execute(f"SELECT * FROM {name} ORDER BY subject_id")
                ),
            )
            for name in PUBLIC_TABLES
        )


@pytest.fixture
def publication(tmp_path, monkeypatch):
    from publication_fixtures import configure_publication, source_database
    from test_claim_dossier import SEED, _challenge, _event, _packet, _seed, _standing
    from agora.public_snapshot import load_public_snapshot
    from agora.sab_seeding_api import _hash_json, _without_signature

    with source_database() as source:
        packet = _packet(text="SYNTHETIC temporal API fixture; no real-world reliance.")
        _seed(source, packet=packet)
        challenge = _challenge(source, response={"response": "Synthetic response remains pending."})
        source.execute(
            "UPDATE sab_seed_packets_v1 SET challenge_window_closes_at = ?",
            ("2000-01-01T00:00:00",),
        )
        source.execute(
            "UPDATE sab_challenge_packets_v1 SET respond_by = ?, prosecute_by = ?",
            ("2000-01-01T00:00:00", "2000-01-01T09:00:00+09:00"),
        )
        witness = _event(
            source, payload={"seed_packet_hash": _hash_json(_without_signature(packet))}
        )
        leases = {
            identifier: _standing(source, standing_id=identifier, status=status, expiry=expiry)
            for identifier, status, expiry in LEASES
        }
        bundle = configure_publication(source, tmp_path / "bundle", monkeypatch)
        original_json = source.execute("SELECT packet_json FROM sab_seed_packets_v1").fetchone()[0]
        source_before = tuple(source.iterdump())
        bundle_before = {path.name: path.read_bytes() for path in bundle.iterdir()}
        snapshot = load_public_snapshot(
            bundle, hashlib.sha256(bundle_before["manifest.json"]).hexdigest()
        )
        frozen_before = _rows(snapshot)
        yield SimpleNamespace(
            snapshot=snapshot,
            seed_id=SEED,
            packet=packet,
            packet_json=original_json,
            challenge=challenge,
            witness=witness,
            leases=leases,
        )
        assert tuple(source.iterdump()) == source_before
        assert _rows(snapshot) == frozen_before
        assert {path.name: path.read_bytes() for path in bundle.iterdir()} == bundle_before


def _observer(publication, scenario="recent"):
    from agora.public_freshness import FreshnessPolicy, PublicationFreshnessObserver

    wall = NOW - timedelta(seconds=10) if scenario == "future" else NOW
    clock = Clock(wall)
    observer = PublicationFreshnessObserver(
        publication.snapshot.status,
        FreshnessPolicy(maximum_age_seconds=60),
        utc_now=clock.utc_now,
        monotonic=clock.monotonic,
    )
    if scenario == "stale":
        clock.advance(61)
    elif scenario == "uncertain":
        clock.wall -= timedelta(seconds=30)
        clock.monotonic_value += 1
    return observer, clock


def _app(publication, callback, *, read_only=True, publication_configured=True):
    from agora.sab_seeding_api import SabSeedingDeps, create_sab_seeding_router

    app = FastAPI()
    app.include_router(
        create_sab_seeding_router(
            SabSeedingDeps(
                init_db=_forbidden,
                db=publication.snapshot.connection,
                verify_agent_signature=_forbidden,
                system_sign=_forbidden,
                utc_now=_forbidden,
                invalidate_web_cache=_forbidden,
                read_only=read_only,
                read_observation=callback,
                publication_configured=publication_configured,
            )
        )
    )
    return app


@pytest.mark.parametrize(
    "scenario,age,basis",
    [
        ("recent", "within_limit", "currentness_unestablished"),
        ("stale", "stale", "publication_stale"),
        ("future", "future_observation", "publication_future_observation"),
        ("uncertain", "clock_uncertain", "clock_uncertain"),
    ],
)
def test_public_status_detail_filter_and_dossier_share_one_observation(
    publication, scenario, age, basis
):
    observer, clock = _observer(publication, scenario)
    with TestClient(_app(publication, observer.observe)) as client:
        reads = clock.reads
        listing = client.get("/api/v1/standing").json()
        assert clock.reads == reads + 1
        metadata = listing["publication_observation"]
        assert metadata["local_age_policy"]["status"] == age
        assert metadata["currentness"]["status"] == "unestablished"
        assert metadata["clock"]["externally_verified"] is False
        assert {row["observed_at"] for row in listing["items"]} == {metadata["observed_at"]}
        items = {row["standing_id"]: row for row in listing["items"]}
        for identifier, stored_status, _ in LEASES:
            detail = client.get(f"/api/v1/standing/{identifier}").json()
            assert detail["publication_observation"] == metadata
            assert detail["status"] == items[identifier]["status"]
            assert detail["status_basis"] == items[identifier]["status_basis"]
            assert detail["stored_status"] == stored_status
            assert detail["standing_lease"] == publication.leases[identifier]
        for identifier in ("future_active", "future_canon"):
            assert items[identifier]["status"] == "unknown"
            assert items[identifier]["status_basis"] == basis
        for identifier in ("revoked", "expired_stored", "superseded", "compost"):
            assert items[identifier]["status"] == items[identifier]["stored_status"]
            assert items[identifier]["status_basis"] == "stored"
        assert items["unrecognized"]["status_basis"] == "invalid_stored_status"
        if scenario == "recent":
            for identifier in ("elapsed", "offset_elapsed"):
                assert items[identifier]["status"] == "expired"
                assert items[identifier]["status_basis"] == "local_expiry_observation"
            for identifier in ("naive", "invalid"):
                assert items[identifier]["status"] == "unknown"
                assert items[identifier]["status_basis"] == "invalid_expiry"
        for wanted in ("unknown", "expired", "revoked", "active", "canon"):
            expected = [
                item["standing_id"] for item in listing["items"] if item["status"] == wanted
            ][:1]
            filtered = client.get(f"/api/v1/standing?status={wanted}&limit=1").json()
            assert [item["standing_id"] for item in filtered["items"]] == expected
            assert filtered["publication_observation"] == metadata
        dossier = client.get(f"/api/v1/seeds/{publication.seed_id}/dossier").json()
        assert dossier["publication_observation"] == metadata
        assert dossier["observed_at"] == metadata["observed_at"]
        assert dossier["original_packet_json"] == publication.packet_json
        assert dossier["original_packet"] == publication.packet
        assert dossier["seed"]["state_basis"] == "stored"
        assert dossier["challenges"]["unresolved_count"] == 1
        assert dossier["challenges"]["items"][0]["status"] == "pending"
        assert dossier["challenges"]["items"][0]["status_basis"] == "stored"
        assert {item["standing_id"]: item["status"] for item in dossier["standing"]["items"]} == {
            key: value["status"] for key, value in items.items()
        }
        deadlines = [
            dossier["finality"]["challenge_window"],
            dossier["challenges"]["items"][0]["respond_deadline"],
            dossier["challenges"]["items"][0]["prosecute_deadline"],
        ]
        assert {deadline["observed_at"] for deadline in deadlines} == {metadata["observed_at"]}
        if scenario == "uncertain":
            assert all(
                deadline["state"] == "unknown" and deadline["elapsed"] is None
                for deadline in deadlines
            )
        else:
            assert all(
                deadline["state"] == "unknown" and deadline["reason"] == "invalid_expiry"
                for deadline in deadlines[:2]
            )
            assert deadlines[2]["state"] == "elapsed"


def test_every_raw_and_fallback_envelope_retains_provenance_without_editing_originals(publication):
    observer, _ = _observer(publication)
    observation = observer.observe().to_dict()
    with TestClient(_app(publication, observer.observe)) as client:
        for path in (
            "/api/v1/seeds",
            f"/api/v1/seeds/{publication.seed_id}",
            f"/api/v1/seeds/{publication.seed_id}/chain",
            "/api/v1/claims",
            f"/api/v1/challenges/{publication.challenge['challenge_id']}",
            f"/api/v1/witness-events/{publication.witness['event_id']}",
            "/api/v1/witness/chain",
            "/api/v1/witness/verify",
            "/api/v1/standing",
        ):
            response = client.get(path)
            assert response.status_code == 200, response.text
            assert response.json()["publication_observation"] == observation
        seed = client.get(f"/api/v1/seeds/{publication.seed_id}").json()
        assert seed["seed_packet"] == publication.packet and seed["state_basis"] == "stored"
        challenge = client.get(f"/api/v1/challenges/{publication.challenge['challenge_id']}").json()
        assert (
            challenge["challenge_packet"] == publication.challenge
            and challenge["status_basis"] == "stored"
        )
        for kind, identifier in (
            ("seed", publication.seed_id),
            ("chain", publication.seed_id),
            ("dossier", publication.seed_id),
            ("standing", "future_active"),
            ("challenge", publication.challenge["challenge_id"]),
            ("witness_event", publication.witness["event_id"]),
        ):
            response = client.get(
                "/api/v1/claims/record",
                params={"kind": kind, "identifier": identifier, "download": "true"},
            )
            assert response.status_code == 200, response.text
            assert response.json()["publication_observation"] == observation
            assert "attachment" in response.headers["content-disposition"]
            if kind == "seed":
                assert response.json()["seed_packet"] == publication.packet
            if kind == "standing":
                assert response.json()["standing_lease"] == publication.leases[identifier]
                assert response.json()["status"] == "unknown"
        download = client.get(f"/api/v1/seeds/{publication.seed_id}/dossier?download=true")
        assert download.json()["publication_observation"] == observation
        assert download.json()["original_packet_json"] == publication.packet_json


def test_explicit_and_context_observations_override_legacy_time_without_resampling(publication):
    from agora.claim_dossier import list_claims, load_claim_dossier, load_claim_record
    from agora.public_freshness import publication_context
    from agora.sab_seeding_api import observe_standing_status

    observer, clock = _observer(publication, "uncertain")
    observation = observer.observe()
    reads = clock.reads
    with publication.snapshot.connection() as conn:
        explicit = load_claim_dossier(
            conn,
            publication.seed_id,
            observed_at=NOW + timedelta(days=1000),
            publication_observation=observation,
        )
        assert explicit["observed_at"] == observation.observed_at.isoformat()
        with publication_context(observation):
            assert load_claim_dossier(conn, publication.seed_id) == explicit
            assert list_claims(conn)["publication_observation"] == observation.to_dict()
            assert load_claim_record(conn, "standing", "elapsed")["status"] == "unknown"
            status = observe_standing_status("active", "2000-01-01T00:00:00Z")
            assert status["status_basis"] == "clock_uncertain"
    assert clock.reads == reads


def test_readonly_requires_callback_and_missing_observation_fails_before_database_read(publication):
    forbidden_database = SimpleNamespace(snapshot=SimpleNamespace(connection=_forbidden))
    with pytest.raises(ValueError, match="read_observation"):
        _app(forbidden_database, None)
    with TestClient(_app(forbidden_database, lambda: None)) as client:
        for path in ("/api/v1/standing", "/api/v1/claims", "/api/v1/seeds"):
            response = client.get(path)
            assert response.status_code == 503
            assert "observation is unavailable" in response.json()["detail"]


def test_request_context_is_used_instead_of_a_second_observation_callback(publication):
    from agora.public_freshness import publication_context

    observer, clock = _observer(publication)
    observation = observer.observe()
    app = _app(publication, _forbidden)

    async def in_context(scope, receive, send):
        with publication_context(observation):
            await app(scope, receive, send)

    reads = clock.reads
    with TestClient(in_context) as client:
        result = client.get("/api/v1/standing?status=unknown&limit=1")
        assert result.status_code == 200, result.text
        assert result.json()["publication_observation"] == observation.to_dict()
    assert clock.reads == reads


def test_unconfigured_public_lists_still_disclose_temporal_limits():
    from agora.public_freshness import FreshnessPolicy, PublicationFreshnessObserver
    from agora.public_snapshot import load_public_snapshot

    publication = SimpleNamespace(snapshot=load_public_snapshot(None, None))
    observer = PublicationFreshnessObserver(
        publication.snapshot.status, FreshnessPolicy(), utc_now=lambda: NOW, monotonic=lambda: 0.0
    )
    with TestClient(_app(publication, observer.observe, publication_configured=False)) as client:
        for path in ("/api/v1/seeds", "/api/v1/standing", "/api/v1/claims"):
            response = client.get(path)
            assert response.status_code == 200, response.text
            data = response.json()
            assert data["items"] == []
            assert data["publication_observation"]["local_age_policy"]["status"] == "not_configured"
            assert data["publication_observation"]["currentness"]["status"] == "unestablished"
