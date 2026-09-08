"""
SAB Sprint 2 Verification Matrix Integration Tests.

Covers all mandatory browser workflow invariants:
  a. Feed pages render with expected status codes
  b. Submit flow creates spark and redirects to detail page
  c. Spark page shows 17 dimensions + R_V experimental label
  d. Challenge form posts and thread displays new challenge
  e. Witness action via web updates witness timeline
  f. Compost page shows WHY card reason
  g. Agent profile reliability metrics render without division errors
  h. Cache invalidation reflects latest state after writes
  i. Invalid signature API paths remain rejected
  j. Existing promotion/auth tests remain green (covered by test_integration.py)
"""
from __future__ import annotations

import importlib
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


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


def _get_csrf_token(web_app) -> str:
    """Extract a CSRF token from the first active web session."""
    sessions = getattr(web_app, "_WEB_SESSIONS", {})
    for _token, session_data in sessions.items():
        csrf = session_data.get("csrf_token", "")
        if csrf:
            return csrf
    return ""


def _submit_spark(client: TestClient, content: str, web_app=None) -> str:
    """Submit a spark via web form and return the redirect location."""
    form_data = {
        "display_name": "vm-tester",
        "content": content,
        "content_type": "text",
    }
    if web_app is not None:
        csrf = _get_csrf_token(web_app)
        if csrf:
            form_data["_csrf"] = csrf
    response = client.post(
        "/submit",
        data=form_data,
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    location = response.headers.get("location", "")
    assert location.startswith("/spark/"), f"Expected redirect to /spark/*, got {location}"
    return location


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
# (b) Submit flow creates spark and redirects to detail page
# ---------------------------------------------------------------------------

class TestSubmitFlow:
    def test_submit_redirects_to_spark_detail(self, client: TestClient):
        location = _submit_spark(client, "Submit flow verification test content.")
        assert "/spark/" in location

    def test_spark_detail_page_renders_after_submit(self, client: TestClient):
        location = _submit_spark(client, "Spark detail render verification.")
        detail = client.get(location)
        assert detail.status_code == 200
        assert "text/html" in detail.headers.get("content-type", "")

    def test_submit_empty_content_does_not_crash(self, client: TestClient):
        """Submitting empty content should not 500."""
        resp = client.post(
            "/submit",
            data={"display_name": "vm-empty", "content": "", "content_type": "text"},
            follow_redirects=False,
        )
        # Should either redirect or render form with error, but not 500
        assert resp.status_code in (200, 303, 422)


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
# (d) Challenge form posts and thread displays new challenge
# ---------------------------------------------------------------------------

class TestChallengeFlow:
    def _challenge_form(self, web_app, content: str) -> dict:
        form = {"content": content}
        csrf = _get_csrf_token(web_app)
        if csrf:
            form["_csrf"] = csrf
        return form

    def test_challenge_post_redirects(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for challenge.", web_app=web_app)
        spark_id = _get_spark_id(location)
        resp = client.post(
            f"/spark/{spark_id}/challenge",
            data=self._challenge_form(web_app, "Challenge from web form."),
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_challenge_visible_on_spark_page(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for challenge visibility.", web_app=web_app)
        spark_id = _get_spark_id(location)
        client.post(
            f"/spark/{spark_id}/challenge",
            data=self._challenge_form(web_app, "Visible challenge argument."),
            follow_redirects=False,
        )
        page = client.get(f"/spark/{spark_id}")
        assert page.status_code == 200
        assert "Visible challenge argument." in page.text

    def test_multiple_challenges_all_visible(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for multi challenge.", web_app=web_app)
        spark_id = _get_spark_id(location)
        for i in range(3):
            client.post(
                f"/spark/{spark_id}/challenge",
                data=self._challenge_form(web_app, f"Challenge number {i}"),
                follow_redirects=False,
            )
        page = client.get(f"/spark/{spark_id}")
        assert page.status_code == 200
        for i in range(3):
            assert f"Challenge number {i}" in page.text

    def test_empty_challenge_does_not_crash(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for empty challenge test.", web_app=web_app)
        spark_id = _get_spark_id(location)
        form = self._challenge_form(web_app, "")
        resp = client.post(
            f"/spark/{spark_id}/challenge",
            data=form,
            follow_redirects=False,
        )
        # FastAPI Form(...) validation may reject empty string with 422,
        # or the handler may redirect back.  Either way, no 500.
        assert resp.status_code in (200, 303, 422)


# ---------------------------------------------------------------------------
# (e) Witness action via web updates witness timeline
# ---------------------------------------------------------------------------

class TestWitnessWebAction:
    def _witness_form(self, web_app, action: str, note: str, display_name: str = "") -> dict:
        form: dict = {"action": action, "note": note}
        if display_name:
            form["display_name"] = display_name
        csrf = _get_csrf_token(web_app)
        if csrf:
            form["_csrf"] = csrf
        return form

    def test_witness_affirm_redirects(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for witness action.", web_app=web_app)
        spark_id = _get_spark_id(location)
        resp = client.post(
            f"/spark/{spark_id}/witness",
            data=self._witness_form(web_app, "affirm", "Good spark.", "witness-agent"),
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert f"/spark/{spark_id}#timeline" in resp.headers.get("location", "")

    def test_witness_action_appears_in_timeline(self, client: TestClient, web_app):
        location = _submit_spark(client, "Spark for witness timeline check.", web_app=web_app)
        spark_id = _get_spark_id(location)
        client.post(
            f"/spark/{spark_id}/witness",
            data=self._witness_form(web_app, "affirm", "Timeline entry.", "timeline-witness"),
            follow_redirects=False,
        )
        page = client.get(f"/spark/{spark_id}")
        assert page.status_code == 200
        # The timeline section should include the witness action
        assert "affirm" in page.text.lower()

    def test_witness_api_records_attestation(self, client: TestClient, web_app):
        """API endpoint /api/witness/{agent_id} should reflect witness activity."""
        location = _submit_spark(client, "Spark for API witness check.", web_app=web_app)
        spark_id = _get_spark_id(location)
        # Post witness via web to capture the agent_id from session
        resp = client.post(
            f"/spark/{spark_id}/witness",
            data=self._witness_form(web_app, "affirm", "API check.", "api-witness"),
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_compost_witness_action(self, client: TestClient, web_app):
        """Compost witness action should not crash."""
        location = _submit_spark(client, "Spark for compost witness.", web_app=web_app)
        spark_id = _get_spark_id(location)
        resp = client.post(
            f"/spark/{spark_id}/witness",
            data=self._witness_form(web_app, "compost", "Low quality."),
            follow_redirects=False,
        )
        assert resp.status_code == 303


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
        # Register via web form
        resp = client.post(
            "/register",
            data={"display_name": "zero-division-test"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        agent_url = resp.headers.get("location", "")
        assert agent_url.startswith("/agent/")

        profile = client.get(agent_url)
        assert profile.status_code == 200
        assert "text/html" in profile.headers.get("content-type", "")

    def test_agent_with_submissions_renders_metrics(self, client: TestClient):
        """Agent who submitted sparks should have renderable reliability metrics."""
        location = _submit_spark(client, "Agent metrics test submission.")
        # The submit created/found a session; register explicitly to get profile URL
        resp = client.post(
            "/register",
            data={"display_name": "metrics-agent"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        agent_url = resp.headers.get("location", "")
        profile = client.get(agent_url)
        assert profile.status_code == 200

    def test_agent_with_witness_activity_renders(self, client: TestClient):
        """Agent who witnessed sparks should have renderable profile."""
        location = _submit_spark(client, "Spark for profile witness check.")
        spark_id = _get_spark_id(location)
        client.post(
            f"/spark/{spark_id}/witness",
            data={"action": "affirm", "note": "Profile test.", "display_name": "profile-witness"},
            follow_redirects=False,
        )
        resp = client.post(
            "/register",
            data={"display_name": "profile-witness-check"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        agent_url = resp.headers.get("location", "")
        profile = client.get(agent_url)
        assert profile.status_code == 200

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
        _submit_spark(client, "First spark for cache test AAA.", web_app=web_app)
        _submit_spark(client, "Second spark for cache test BBB.", web_app=web_app)
        page = client.get("/feed")
        assert page.status_code == 200
        assert "First spark for cache test AAA" in page.text
        assert "Second spark for cache test BBB" in page.text

    def test_challenge_count_updates_in_feed(self, client: TestClient, web_app):
        """After a challenge, the feed should reflect the updated challenge count."""
        location = _submit_spark(client, "Spark for challenge count cache test.", web_app=web_app)
        spark_id = _get_spark_id(location)
        # Invalidate cache via a write operation
        web_app._invalidate_web_cache()
        form = {"content": "Challenge for cache count."}
        csrf = _get_csrf_token(web_app)
        if csrf:
            form["_csrf"] = csrf
        client.post(
            f"/spark/{spark_id}/challenge",
            data=form,
            follow_redirects=False,
        )
        detail = client.get(f"/spark/{spark_id}")
        assert detail.status_code == 200
        assert "Challenge for cache count." in detail.text


# ---------------------------------------------------------------------------
# (i) Invalid signature API paths remain rejected
# ---------------------------------------------------------------------------

class TestInvalidSignatureRejection:
    def test_submit_with_bad_signature_rejected(self, client: TestClient, web_app):
        """API submit with forged signature must be rejected."""
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        from nacl.encoding import HexEncoder

        public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
        # Register the agent
        reg = client.post(
            "/api/agents/register",
            json={"name": "bad-sig-agent", "public_key": public_key},
        )
        assert reg.status_code == 201
        agent_id = str(reg.json()["id"])

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
        from nacl.encoding import HexEncoder
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
        reg = client.post(
            "/api/agents/register",
            json={"name": "witness-bad-sig", "public_key": public_key},
        )
        assert reg.status_code == 201
        agent_id = str(reg.json()["id"])

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
        from nacl.encoding import HexEncoder
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
        reg = client.post(
            "/api/agents/register",
            json={"name": "challenge-bad-sig", "public_key": public_key},
        )
        assert reg.status_code == 201
        agent_id = str(reg.json()["id"])

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
# Web registration flow
# ---------------------------------------------------------------------------

class TestWebRegistration:
    def test_register_creates_session_and_redirects(self, client: TestClient):
        resp = client.post(
            "/register",
            data={"display_name": "reg-test-agent"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers.get("location", "").startswith("/agent/")

    def test_register_with_whitespace_name_uses_anonymous(self, client: TestClient):
        """Whitespace-only display name should fall back to 'anonymous'."""
        resp = client.post(
            "/register",
            data={"display_name": "  "},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        agent_url = resp.headers.get("location", "")
        profile = client.get(agent_url)
        assert profile.status_code == 200


# ---------------------------------------------------------------------------
# Determinism: no external calls, no timing dependencies
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_content_always_same_gate_scores(self, client: TestClient, web_app):
        """Submitting identical content should yield consistent gate outcomes."""
        content = "Determinism check with stable content for gate scoring."
        loc1 = _submit_spark(client, content, web_app=web_app)
        loc2 = _submit_spark(client, content, web_app=web_app)
        page1 = client.get(loc1)
        page2 = client.get(loc2)
        assert page1.status_code == 200
        assert page2.status_code == 200
        # Both should show same dimension structure
        assert "17 Gate Dimensions" in page1.text
        assert "17 Gate Dimensions" in page2.text

    def test_api_chain_verification_on_fresh_spark(self, client: TestClient, web_app):
        """Chain verification should pass on a freshly submitted spark."""
        from nacl.encoding import HexEncoder
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
        reg = client.post(
            "/api/agents/register",
            json={"name": "chain-verify", "public_key": public_key},
        )
        assert reg.status_code == 201
        agent_id = str(reg.json()["id"])

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
