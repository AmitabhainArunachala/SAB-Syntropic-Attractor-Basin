from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from historical_web_fixtures import historical_actor, historical_spark


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@pytest.fixture
def web_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "web_surface.db"
    key_path = tmp_path / ".web_surface_system_ed25519.key"
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(key_path))

    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]

    mod = importlib.import_module("agora.app")
    packet_dir = tmp_path / "frontier_packets"
    packet_dir.mkdir()
    monkeypatch.setattr(mod, "FRONTIER_PACKET_DIR", packet_dir)
    return mod


@pytest.fixture
def client(web_app):
    with TestClient(web_app.app) as test_client:
        yield test_client


def test_web_pages_render(client: TestClient):
    for path in ("/", "/frontier", "/seed", "/submit", "/canon", "/compost", "/about", "/register"):
        res = client.get(path)
        assert res.status_code == 200, f"{path}: {res.text}"


def test_frontier_api_shape(client: TestClient):
    res = client.get("/api/frontier")
    assert res.status_code == 200
    payload = res.json()
    assert payload["schema"] == "sab.frontier_snapshot.v1"
    assert payload["frontier"]["id"] == "language_womb.epistemic_authority.v1"
    assert "needs_challenge" in payload["board"]
    assert payload["stats"]["standing_surface_count"] == 0
    assert any("standing" in boundary.lower() for boundary in payload["security_boundaries"])


def test_frontier_reads_live_store_rows(client: TestClient, web_app):
    packet = {
        "schema": "sab.seed_packet.v1",
        "seed_id": "sab_seed_frontier_store_test",
        "seed_type": "claim",
        "title": "Frontier Store Test",
        "status": "pending_seed",
        "loop_position": "spark",
        "claim": {
            "claim_id": "sab_claim_frontier_store_test",
            "text": "Attested claims need an explicit promotion route before they become proven claims.",
            "claim_type": "semantic",
            "scope": "language_womb.epistemic_authority.v1",
        },
        "claimant_identity": {"subject_id": "agent_frontier_test"},
        "authority_lease": {"scope": "Submit one test seed.", "expires_at": "2026-08-01T00:00:00Z"},
        "challenge_plan": {"required": True, "challenge_window": "P7D"},
        "witness_plan": {"minimum_witnesses": 1, "required_roles": ["language_reviewer"]},
        "evidence_bundle": [{"ref": "tests:test-frontier", "kind": "test"}],
        "anti_capture_rules": ["No standing by packet alone."],
        "created_at": "2026-07-06T00:00:00Z",
        "signature": {"signer": "agent_frontier_test"},
    }
    web_app._frontier_store_stats()
    with web_app._db() as conn:
        conn.execute(
            """
            INSERT INTO sab_seed_packets_v1
                (
                    seed_id, seed_type, title, claim_id, claimant_identity,
                    authority_lease_id, state, packet_json, packet_hash,
                    spark_projection_id, challenge_window_closes_at,
                    created_at, updated_at
                )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "sab_seed_frontier_store_test",
                "claim",
                "Frontier Store Test",
                "sab_claim_frontier_store_test",
                "agent_frontier_test",
                "sab_lease_frontier_store_test",
                "pending_seed",
                web_app.json.dumps(packet),
                "sha256:test",
                None,
                "2026-07-13T00:00:00Z",
                "2026-07-06T00:00:00Z",
                "2026-07-06T00:00:00Z",
            ),
        )

    res = client.get("/api/frontier")
    assert res.status_code == 200
    rows = res.json()["packets"]
    row = next(item for item in rows if item["seed_id"] == "sab_seed_frontier_store_test")
    assert row["source"] == "store"
    assert row["claimant"] == "agent_frontier_test"
    assert row["standing_effect"] == "none"


def test_frontier_artifact_paths_are_sanitized(
    client: TestClient,
    web_app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    packet_dir = tmp_path / "packets"
    receipt_dir = tmp_path / "receipts"
    packet_dir.mkdir()
    receipt_dir.mkdir()
    packet = {
        "schema": "sab.seed_packet.v1",
        "seed_id": "sab_seed_frontier_artifact_test",
        "seed_type": "claim",
        "title": "Frontier Artifact Test",
        "status": "pending_seed",
        "loop_position": "spark",
        "claim": {
            "claim_id": "sab_claim_frontier_artifact_test",
            "text": "Local source refs should be sanitized before reaching the public frontier API.",
            "claim_type": "semantic",
            "scope": "language_womb.epistemic_authority.v1",
        },
        "claimant_identity": {"subject_id": "agent_artifact_test"},
        "authority_lease": {"scope": "Submit one artifact test seed.", "expires_at": "2026-08-01T00:00:00Z"},
        "challenge_plan": {"required": True, "falsification_routes": ["Inspect sanitized refs."]},
        "witness_plan": {"minimum_witnesses": 1},
        "evidence_bundle": [
            {
                "ref": "/Users/dhyana/private/prior_art.md sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "kind": "source",
            }
        ],
        "created_at": "2026-07-06T00:00:00Z",
        "signature": {"signer": "agent_artifact_test"},
    }
    receipt = {
        "schema": "sab.language_womb_contribution_receipt.v1",
        "seed_id": "sab_seed_frontier_artifact_test",
        "claim_id": "sab_claim_frontier_artifact_test",
        "standing_effect": "none",
        "external_actions": [],
    }
    (packet_dir / "artifact.json").write_text(web_app.json.dumps(packet), encoding="utf-8")
    (receipt_dir / "artifact.receipt.json").write_text(web_app.json.dumps(receipt), encoding="utf-8")
    monkeypatch.setattr(web_app, "FRONTIER_PACKET_DIR", packet_dir)
    monkeypatch.setattr(web_app, "FRONTIER_RECEIPT_DIR", receipt_dir)

    res = client.get("/api/frontier")
    assert res.status_code == 200
    body = res.json()
    serialized = web_app.json.dumps(body)
    assert "/Users/dhyana/private" not in serialized
    row = next(item for item in body["packets"] if item["seed_id"] == "sab_seed_frontier_artifact_test")
    assert row["source"] == "artifact"
    assert row["evidence_refs"] == ["local:prior_art.md sha256:aaaaaaaaaaaa"]


def test_historical_discussion_renders_dimension_profile(client: TestClient):
    location = historical_spark(client, "Historical web surface smoke test content.")
    spark_page = client.get(location)
    assert spark_page.status_code == 200
    assert "17 Gate Dimensions" in spark_page.text
    assert "R_V" in spark_page.text
    assert "EXPERIMENTAL" in spark_page.text


def test_signed_historical_challenge_visible_on_spark_page(client: TestClient):
    location = historical_spark(client, "Spark to challenge.")
    spark_id = int(location.split("/")[2].split("?")[0])
    historical_actor(client).challenge(spark_id, "Signed historical challenge argument.")

    spark_page = client.get(f"/spark/{spark_id}")
    assert spark_page.status_code == 200
    assert "Signed historical challenge argument." in spark_page.text


def test_compost_feed_shows_why_card(client: TestClient):
    historical_spark(client, "This content says kill yourself and should fail Ahimsa.")

    compost_page = client.get("/compost")
    assert compost_page.status_code == 200
    assert "WHY this is compost" in compost_page.text
    assert "Failed Ahimsa safety gate." in compost_page.text
