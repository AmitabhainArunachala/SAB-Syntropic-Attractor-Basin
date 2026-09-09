"""
Historical discussion rendering and participant boundary integration tests.

Covers these compatibility invariants using explicit caller-signed fixtures:
  a. Feed pages render with expected status codes
  b. Signed historical discussion remains readable at its detail page
  c. Spark page shows 17 dimensions + R_V experimental label
  d. Signed legacy challenges remain visible in their historical thread
  e. Signed legacy witness observations remain visible in the timeline
  f. Compost page shows WHY card reason
  g. Agent profile reliability metrics render without division errors
  h. Cache invalidation reflects latest state after writes
  i. Invalid signature API paths remain rejected
  j. Unsigned browser forms reject requests without creating identities or writes
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from historical_web_fixtures import (
    HistoricalWebActor,
    database_state,
    historical_actor,
    historical_spark,
)


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def web_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolated web app with fresh DB and system key per test."""
    db_path = tmp_path / "vm_test.db"
    key_path = tmp_path / ".vm_system_ed25519.key"
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(key_path))

    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]

    return importlib.import_module("agora.app")


@pytest.fixture
def client(web_app):
    with TestClient(web_app.app) as tc:
        yield tc


def _submit_spark(client: TestClient, content: str) -> str:
    """Create caller-signed historical discussion, then return its read URL."""
    return historical_spark(client, content)


def _get_spark_id(location: str) -> int:
    """Extract spark_id from /spark/123?submitted=1 style URLs."""
    return int(location.split("/")[2].split("?")[0])


# ---------------------------------------------------------------------------
# (a) Feed pages render with expected status codes
# ---------------------------------------------------------------------------

class TestFeedPagesRender:
    def test_home_page_200(self, client: TestClient):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")

    def test_canon_page_200(self, client: TestClient):
        resp = client.get("/canon")
        assert resp.status_code == 200

    def test_compost_page_200(self, client: TestClient):
        resp = client.get("/compost")
        assert resp.status_code == 200

    def test_about_page_200(self, client: TestClient):
        resp = client.get("/about")
        assert resp.status_code == 200

    def test_submit_page_200(self, client: TestClient):
        resp = client.get("/submit")
        assert resp.status_code == 200

    def test_register_page_200(self, client: TestClient):
        resp = client.get("/register")
        assert resp.status_code == 200

    def test_home_query_modes(self, client: TestClient):
        """All query modes on / should return 200."""
        for mode in ("newest", "most-challenged", "canon", "compost"):
            resp = client.get(f"/?mode={mode}")
            assert resp.status_code == 200, f"mode={mode} failed"


# ---------------------------------------------------------------------------
# (b) Signed historical discussion creates a readable detail page
# ---------------------------------------------------------------------------

class TestSubmitFlow:
    def test_signed_discussion_has_spark_detail(self, client: TestClient):
        location = _submit_spark(client, "Submit flow verification test content.")
        assert "/spark/" in location

    def test_spark_detail_page_renders_after_submit(self, client: TestClient):
        location = _submit_spark(client, "Spark detail render verification.")
        detail = client.get(location)
        assert detail.status_code == 200
        assert "text/html" in detail.headers.get("content-type", "")

    def test_unsigned_empty_submission_is_rejected_without_effects(self, client: TestClient, web_app):
        before = database_state(web_app)
        resp = client.post(
            "/submit",
            data={"display_name": "vm-empty", "content": "", "content_type": "text"},
            follow_redirects=False,
        )
        assert resp.status_code == 428
        assert resp.json()["error"] == "browser_key_required"
        assert "set-cookie" not in resp.headers
        assert database_state(web_app) == before


# ---------------------------------------------------------------------------
# (c) Spark page shows 17 dimensions + R_V experimental label
# ---------------------------------------------------------------------------

class TestDimensionProfile:
    def test_17_dimensions_displayed(self, client: TestClient):
        location = _submit_spark(client, "Dimension profile check.")
        page = client.get(location)
        assert page.status_code == 200
        assert "17 Gate Dimensions" in page.text

    def test_rv_experimental_label(self, client: TestClient):
        location = _submit_spark(client, "R_V label verification.")
        page = client.get(location)
        assert page.status_code == 200
        assert "R_V" in page.text
        assert "EXPERIMENTAL" in page.text

    def test_dimension_labels_present(self, client: TestClient):
        """All canonical dimension labels should appear on the page."""
        location = _submit_spark(client, "All dimension labels verification.")
        page = client.get(location)
        assert page.status_code == 200
        expected_labels = [
            "Satya", "Ahimsa", "Asteya", "Brahmacharya", "Aparigraha",
            "Shaucha", "Santosha", "Tapas", "Svadhyaya", "Ishvara",
            "Witness", "Consent", "Nonviolence", "Transparency",
            "Reciprocity", "Humility", "Integrity",
        ]
        for label in expected_labels:
            assert label in page.text, f"Missing dimension label: {label}"


# ---------------------------------------------------------------------------
# (d) Historical challenge signatures and thread rendering
# ---------------------------------------------------------------------------

class TestChallengeFlow:
    def test_signed_challenge_records_author(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for challenge.")
        spark_id = _get_spark_id(location)
        actor = historical_actor(client)
        record = actor.challenge(spark_id, "Challenge signed by the historical author.")
        assert record["challenger_id"] == actor.subject_id
        assert record["resolution"] == "pending"

    def test_challenge_visible_on_spark_page(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for challenge visibility.")
        spark_id = _get_spark_id(location)
        historical_actor(client).challenge(spark_id, "Visible challenge argument.")
        page = client.get(f"/spark/{spark_id}")
        assert page.status_code == 200
        assert "Visible challenge argument." in page.text

    def test_multiple_challenges_all_visible(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for multi challenge.")
        spark_id = _get_spark_id(location)
        for i in range(3):
            historical_actor(client).challenge(spark_id, f"Challenge number {i}")
        page = client.get(f"/spark/{spark_id}")
        assert page.status_code == 200
        for i in range(3):
            assert f"Challenge number {i}" in page.text

    def test_unsigned_empty_challenge_is_rejected_without_effects(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for empty challenge test.")
        spark_id = _get_spark_id(location)
        before = database_state(web_app)
        resp = client.post(
            f"/spark/{spark_id}/challenge",
            data={"content": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 428
        assert resp.json()["error"] == "browser_key_required"
        assert "set-cookie" not in resp.headers
        assert database_state(web_app) == before


# ---------------------------------------------------------------------------
# (e) Signed historical witness observations update the discussion timeline
# ---------------------------------------------------------------------------

class TestWitnessWebAction:
    def test_signed_witness_affirm_is_recorded(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for witness action.")
        spark_id = _get_spark_id(location)
        record = historical_actor(client).witness(spark_id, "affirm", "Good spark.")
        assert record["entry"]["action"] == "affirm"
        assert record["authority"]["standing_effect"] == "none"

    def test_witness_action_appears_in_timeline(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for witness timeline check.")
        spark_id = _get_spark_id(location)
        historical_actor(client).witness(spark_id, "affirm", "Timeline entry.")
        page = client.get(f"/spark/{spark_id}")
        assert page.status_code == 200
        # The timeline section should include the witness action
        assert "affirm" in page.text.lower()

    def test_witness_api_records_attestation(self, client: TestClient, web_app):
        """API endpoint /api/witness/{agent_id} should reflect witness activity."""
        location = _submit_spark(client, "Spark for API witness check.")
        spark_id = _get_spark_id(location)
        actor = historical_actor(client)
        record = actor.witness(spark_id, "affirm", "API check.")
        response = client.get(f"/api/witness/{actor.subject_id}")
        assert response.status_code == 200
        assert any(entry["hash"] == record["entry"]["hash"] for entry in response.json()["entries"])

    def test_compost_witness_action(self, client: TestClient, web_app):
        """A signed historical compost observation remains inspectable."""
        location = _submit_spark(client, "Spark for compost witness.")
        spark_id = _get_spark_id(location)
        record = historical_actor(client).witness(spark_id, "compost", "Low quality.")
        assert record["legacy_status"] == "compost"
        assert client.get(f"/api/spark/{spark_id}").json()["legacy_status"] == "compost"


# ---------------------------------------------------------------------------
# (f) Compost page shows WHY card reason
# ---------------------------------------------------------------------------

class TestCompostWhyCard:
    def test_ahimsa_failure_shows_why_card(self, client: TestClient):
        _submit_spark(client, "This content says kill yourself and should fail Ahimsa.")
        page = client.get("/compost")
        assert page.status_code == 200
        assert "WHY this is compost" in page.text
        assert "Failed Ahimsa safety gate." in page.text

    def test_compost_spark_detail_shows_why(self, client: TestClient):
        """The detail page of a composted spark should also show why."""
        location = _submit_spark(client, "This content says kill yourself and should fail Ahimsa.")
        page = client.get(location)
        assert page.status_code == 200
        assert "compost" in page.text.lower()


# ---------------------------------------------------------------------------
# (g) Agent profile reliability metrics render without division errors
# ---------------------------------------------------------------------------

class TestAgentProfileReliability:
    def test_new_agent_profile_no_division_error(self, client: TestClient):
        """New agent with zero submissions should not produce ZeroDivisionError."""
        actor = HistoricalWebActor(client, display_name="zero-division-test")
        profile = client.get(f"/agent/{actor.subject_id}")
        assert profile.status_code == 200
        assert "text/html" in profile.headers.get("content-type", "")
        assert "zero-division-test" in profile.text
        assert "<dt>Contributions</dt><dd>0</dd>" in profile.text

    def test_agent_with_submissions_renders_metrics(self, client: TestClient):
        """Agent who submitted sparks should have renderable reliability metrics."""
        _submit_spark(client, "Agent metrics test submission.")
        profile = client.get(f"/agent/{historical_actor(client).subject_id}")
        assert profile.status_code == 200
        assert "<dt>Contributions</dt><dd>1</dd>" in profile.text

    def test_agent_with_witness_activity_renders(self, client: TestClient):
        """Agent who witnessed sparks should have renderable profile."""
        location = _submit_spark(client, "Spark for profile witness check.")
        spark_id = _get_spark_id(location)
        actor = HistoricalWebActor(client, display_name="profile-witness")
        actor.witness(spark_id, "affirm", "Profile test.")
        profile = client.get(f"/agent/{actor.subject_id}")
        assert profile.status_code == 200
        assert "profile-witness" in profile.text
        assert "<dt>Endorsements given</dt><dd>1</dd>" in profile.text

    def test_nonexistent_agent_returns_404(self, client: TestClient):
        resp = client.get("/agent/nonexistent999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# (h) Cache invalidation reflects latest state after writes
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    def test_feed_reflects_new_spark_immediately(self, client: TestClient):
        """After submitting a spark, the discussion feed should include it."""
        content = "Cache invalidation test spark content."
        _submit_spark(client, content)
        page = client.get("/feed")
        assert page.status_code == 200
        assert "Cache invalidation test spark" in page.text

    def test_compost_feed_reflects_new_compost_immediately(self, client: TestClient):
        """After an ahimsa-failing spark, the compost feed updates immediately."""
        _submit_spark(client, "This content says kill yourself and should fail Ahimsa now.")
        page = client.get("/compost")
        assert page.status_code == 200
        assert "WHY this is compost" in page.text

    def test_second_spark_visible_after_first(self, client: TestClient, web_app):
        """Two sequential submissions should both appear."""
        _submit_spark(client, "First spark for cache test AAA.")
        _submit_spark(client, "Second spark for cache test BBB.")
        page = client.get("/feed")
        assert page.status_code == 200
        assert "First spark for cache test AAA" in page.text
        assert "Second spark for cache test BBB" in page.text

    def test_challenge_count_updates_in_feed(self, client: TestClient, web_app):
        """After a challenge, the feed should reflect the updated challenge count."""
        location = _submit_spark(client, "Spark for challenge count cache test.")
        spark_id = _get_spark_id(location)
        # Populate the cache before the command; the command must invalidate it.
        assert client.get("/feed").status_code == 200
        assert client.get(f"/api/spark/{spark_id}").json()["challenge_count"] == 0
        historical_actor(client).challenge(spark_id, "Challenge for cache count.")
        detail = client.get(f"/spark/{spark_id}")
        assert detail.status_code == 200
        assert "Challenge for cache count." in detail.text
        assert client.get(f"/api/spark/{spark_id}").json()["challenge_count"] == 1


# ---------------------------------------------------------------------------
# (i) Invalid signature API paths remain rejected
# ---------------------------------------------------------------------------

class TestInvalidSignatureRejection:
    def test_submit_with_bad_signature_rejected(self, client: TestClient, web_app):
        """API submit with forged signature must be rejected."""
        from nacl.signing import SigningKey
        from keycontrol_fixtures import enroll_identity

        sk = SigningKey.generate()

        agent_id = enroll_identity(client, sk, display_name="bad-sig-agent")["subject_id"]

        bad_sig = "00" * 64
        resp = client.post(
            "/api/spark/submit",
            json={
                "content": "Test with bad signature.",
                "content_type": "text",
                "author_id": agent_id,
                "signature": bad_sig,
            },
        )
        assert resp.status_code == 400
        assert "Invalid Ed25519 signature" in resp.text

    def test_witness_with_bad_signature_rejected(self, client: TestClient, web_app):
        """API witness/sign with forged signature must be rejected."""
        import hashlib
        from nacl.signing import SigningKey
        from keycontrol_fixtures import enroll_identity

        sk = SigningKey.generate()

        agent_id = enroll_identity(client, sk, display_name="witness-bad-sig")["subject_id"]

        # Submit a valid spark first
        content = "Valid spark for signature rejection test."
        content_sha = hashlib.sha256(content.encode()).hexdigest()
        payload = {
            "kind": "spark_submit",
            "author_id": agent_id,
            "content_sha256": content_sha,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        sig = sk.sign(canonical).signature.hex()
        submit = client.post(
            "/api/spark/submit",
            json={
                "content": content,
                "content_type": "text",
                "author_id": agent_id,
                "signature": sig,
            },
        )
        assert submit.status_code == 201
        spark_id = int(submit.json()["id"])

        # Now try witness with bad signature
        bad_sig = "ff" * 64
        resp = client.post(
            "/api/witness/sign",
            json={
                "spark_id": spark_id,
                "witness_id": agent_id,
                "action": "affirm",
                "payload": {"reason": "test"},
                "signature": bad_sig,
            },
        )
        assert resp.status_code == 400

    def test_challenge_with_bad_signature_rejected(self, client: TestClient, web_app):
        """API challenge with forged signature must be rejected."""
        import hashlib
        from nacl.signing import SigningKey
        from keycontrol_fixtures import enroll_identity

        sk = SigningKey.generate()

        agent_id = enroll_identity(client, sk, display_name="challenge-bad-sig")["subject_id"]

        # Submit a valid spark
        content = "Valid spark for challenge rejection test."
        content_sha = hashlib.sha256(content.encode()).hexdigest()
        payload = {
            "kind": "spark_submit",
            "author_id": agent_id,
            "content_sha256": content_sha,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        sig = sk.sign(canonical).signature.hex()
        submit = client.post(
            "/api/spark/submit",
            json={
                "content": content,
                "content_type": "text",
                "author_id": agent_id,
                "signature": sig,
            },
        )
        assert submit.status_code == 201
        spark_id = int(submit.json()["id"])

        bad_sig = "ab" * 64
        resp = client.post(
            f"/api/spark/{spark_id}/challenge",
            json={
                "challenger_id": agent_id,
                "content": "Forged challenge.",
                "signature": bad_sig,
            },
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# API feed endpoints
# ---------------------------------------------------------------------------

class TestApiFeedEndpoints:
    def test_api_feed_returns_json(self, client: TestClient):
        resp = client.get("/api/feed")
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_api_feed_canon_returns_json(self, client: TestClient):
        resp = client.get("/api/feed/canon")
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_api_feed_compost_returns_json(self, client: TestClient):
        resp = client.get("/api/feed/compost")
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_api_node_status(self, client: TestClient):
        resp = client.get("/api/node/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"

    def test_spark_404_for_missing_id(self, client: TestClient):
        resp = client.get("/api/spark/999999")
        assert resp.status_code == 404

    def test_web_spark_404_for_missing_id(self, client: TestClient):
        resp = client.get("/spark/999999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Browser registration requires a client-held key and independent session proof
# ---------------------------------------------------------------------------

class TestWebRegistration:
    def test_client_registration_and_session_proof_allow_profile_read(self, client: TestClient, web_app):
        actor = HistoricalWebActor(client, display_name="reg-test-agent")
        assert not client.cookies
        observation = actor.open_session(web_app.KEY_CONTROL.audience)
        assert observation["display_name"] == "reg-test-agent"
        session = client.get("/api/v1/browser/session").json()["session"]
        assert session == observation
        assert client.get(f"/agent/{actor.subject_id}").status_code == 200
        assert client.get("/register").status_code == 200
        assert web_app.WEB_SESSION_COOKIE in client.cookies

    @pytest.mark.parametrize("name", ["reg-test-agent", "  "])
    def test_unsigned_registration_creates_no_identity_or_session(self, client: TestClient, web_app, name):
        before = database_state(web_app)
        resp = client.post(
            "/register",
            data={"display_name": name},
            follow_redirects=False,
        )
        assert resp.status_code == 428
        assert resp.json()["error"] == "browser_key_required"
        assert "set-cookie" not in resp.headers
        assert not client.cookies
        assert database_state(web_app) == before


# ---------------------------------------------------------------------------
# Historical scoring preserves its structure and records changed context
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_repeat_content_retains_dimensions_and_records_originality_warning(self, client: TestClient, web_app):
        """A repeat keeps the profile structure while changing the originality observation."""
        content = "Determinism check with stable content for gate scoring."
        loc1 = _submit_spark(client, content)
        loc2 = _submit_spark(client, content)
        page1 = client.get(loc1)
        page2 = client.get(loc2)
        assert page1.status_code == 200
        assert page2.status_code == 200
        # Both should show same dimension structure
        assert "17 Gate Dimensions" in page1.text
        assert "17 Gate Dimensions" in page2.text
        first = client.get(f"/api/spark/{_get_spark_id(loc1)}").json()
        second = client.get(f"/api/spark/{_get_spark_id(loc2)}").json()
        first_dimensions = first["gate_scores"]["dimensions"]
        second_dimensions = second["gate_scores"]["dimensions"]
        assert first_dimensions.keys() == second_dimensions.keys()
        assert first_dimensions["ahimsa"] == second_dimensions["ahimsa"]
        assert first_dimensions["originality"]["result"] == "passed"
        assert second_dimensions["originality"]["result"] == "warning"
        assert second_dimensions["originality"]["reason"] == "Duplicate of recent content"

    def test_api_chain_verification_on_fresh_spark(self, client: TestClient, web_app):
        """Chain verification should pass on a freshly submitted spark."""
        from nacl.signing import SigningKey
        from keycontrol_fixtures import enroll_identity

        sk = SigningKey.generate()

        agent_id = enroll_identity(client, sk, display_name="chain-verify")["subject_id"]

        content = "Chain verification check."
        content_sha = __import__("hashlib").sha256(content.encode()).hexdigest()
        payload = {
            "kind": "spark_submit",
            "author_id": agent_id,
            "content_sha256": content_sha,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        sig = sk.sign(canonical).signature.hex()
        submit = client.post(
            "/api/spark/submit",
            json={
                "content": content,
                "content_type": "text",
                "author_id": agent_id,
                "signature": sig,
            },
        )
        assert submit.status_code == 201
        spark_id = int(submit.json()["id"])

        chain = client.get(f"/api/spark/{spark_id}/chain")
        assert chain.status_code == 200
        assert chain.json()["verified"] is True
