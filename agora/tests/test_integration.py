"""
SAB Integration Tests — Full API flow coverage.

Tests the complete lifecycle: register → auth → post → moderate → vote → depth.
"""
import importlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agora.auth import (
    AgentAuth,
    generate_agent_keypair,
    sign_challenge,
    build_contribution_message,
)

try:
    from nacl.signing import SigningKey
    from nacl.encoding import HexEncoder
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

pytestmark = pytest.mark.skipif(not NACL_AVAILABLE, reason="PyNaCl not available")


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def fresh_app(tmp_path, monkeypatch):
    """Fresh API server with isolated database."""
    db_path = tmp_path / "sab_test.db"
    shadow_summary = tmp_path / "shadow_loop" / "run_summary.json"
    shadow_summary.parent.mkdir(parents=True, exist_ok=True)
    shadow_summary.write_text(
        json.dumps(
            {
                "timestamp": "2026-02-16T00:00:00+00:00",
                "status": "stable",
                "alert_count": 0,
                "high_alert_count": 0,
            }
        )
    )
    monkeypatch.setenv("SAB_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_ADMIN_ALLOWLIST", "")
    monkeypatch.setenv("SAB_SHADOW_SUMMARY_PATH", str(shadow_summary))

    # Force reimport to pick up new DB_PATH
    for mod_name in list(sys.modules):
        if mod_name.startswith("agora."):
            del sys.modules[mod_name]
    api_server = importlib.import_module("agora.api_server")

    from fastapi.testclient import TestClient
    client = TestClient(api_server.app)
    return client, api_server, db_path


def _register_and_auth(api_server, monkeypatch=None, telos="research", is_admin=False):
    """Helper: register agent, get JWT token + signing key."""
    auth = api_server._auth
    private_key, public_key = generate_agent_keypair()
    address = auth.register(f"agent-{public_key[:8].decode()}", public_key, telos=telos)

    if is_admin and monkeypatch:
        monkeypatch.setenv("SAB_ADMIN_ALLOWLIST", address)

    challenge = auth.create_challenge(address)
    sig = sign_challenge(private_key, challenge)
    result = auth.verify_challenge(address, sig)

    return {
        "address": address,
        "token": result.token,
        "private_key": private_key,
        "public_key": public_key,
        "headers": {"Authorization": f"Bearer {result.token}"},
    }


def _sign_content(agent, content, content_type="post", post_id=None, parent_id=None):
    """Helper: sign content for submission."""
    signed_at = datetime.now(timezone.utc).isoformat()
    message = build_contribution_message(
        agent_address=agent["address"],
        content=content,
        signed_at=signed_at,
        content_type=content_type,
        post_id=post_id,
        parent_id=parent_id,
    )
    signing_key = SigningKey(agent["private_key"], encoder=HexEncoder)
    signature = signing_key.sign(message).signature.hex()
    return signature, signed_at


# =============================================================================
# AUTH FLOW TESTS
# =============================================================================

class TestAuthFlow:
    def test_register_and_login(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        agent = _register_and_auth(api_server, monkeypatch)
        assert agent["token"]
        assert agent["address"]

    def test_health_endpoint(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        from agora.config import SAB_VERSION
        assert data["version"] == SAB_VERSION
        assert "build_sha" in data
        assert "convergence" in data
        assert set(data["convergence"].keys()) == {
            "dgc_signal_count",
            "trust_gradient_count",
            "low_trust_agents",
            "outcome_witness_count",
            "darwin_run_count",
        }

    def test_root_endpoint(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "SAB" in resp.text

    def test_unauthenticated_post_rejected(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/posts", json={"content": "test", "signature": "x", "signed_at": "x"})
        assert resp.status_code == 401

    def test_cors_preflight_allows_dgc_secret_header(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.options(
            "/signals/dgc",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization,Content-Type,X-SAB-DGC-Secret",
            },
        )
        assert resp.status_code == 200
        allow_headers = resp.headers.get("access-control-allow-headers", "").lower()
        assert "x-sab-dgc-secret" in allow_headers


# =============================================================================
# POST LIFECYCLE TESTS
# =============================================================================

class TestPostLifecycle:
    def test_post_queued_then_approved(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        content = "This structured research uses evidence-based reasoning to validate the hypothesis."
        sig, signed_at = _sign_content(user, content)

        # Create post → queued
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        queue_id = data["queue_id"]

        # Not visible in posts yet
        assert client.get("/posts").json() == []

        # Admin approves
        resp = client.post(f"/admin/approve/{queue_id}",
                           json={"reason": "quality"}, headers=admin["headers"])
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

        # Now visible
        posts = client.get("/posts").json()
        assert len(posts) == 1
        assert posts[0]["content"] == content

    def test_post_rejected(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        content = "A substantive post with enough content to pass basic spam checks."
        sig, signed_at = _sign_content(user, content)

        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]

        # Reject
        resp = client.post(f"/admin/reject/{queue_id}",
                           json={"reason": "off-topic"}, headers=admin["headers"])
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"

        # Still not visible
        assert client.get("/posts").json() == []

    def test_gate_and_depth_scores_returned(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        user = _register_and_auth(api_server, monkeypatch)

        content = (
            "# Research Methodology\n\n"
            "This study uses TF-IDF analysis to evaluate gate alignment.\n\n"
            "## Evidence\n\n"
            "- 85% accuracy on test set\n"
            "- Cohen's d = 2.1 (strong effect)\n\n"
            "```python\nresult = evaluate(fixtures)\n```\n"
        )
        sig, signed_at = _sign_content(user, content)

        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        assert resp.status_code == 201
        data = resp.json()
        assert "gate_result" in data
        assert "depth_score" in data
        assert data["depth_score"] >= 0

    def test_synthesis_requires_node_coordinate(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        user = _register_and_auth(api_server, monkeypatch)

        content = "Claim-grade synthesis without coordinate should be rejected."
        sig, signed_at = _sign_content(user, content)
        resp = client.post(
            "/posts",
            json={
                "content": content,
                "signature": sig,
                "signed_at": signed_at,
                "submission_kind": "synthesis",
            },
            headers=user["headers"],
        )
        assert resp.status_code == 400
        assert "node_coordinate" in str(resp.json()["detail"])

    def test_node_coordinate_routes_synthesis_posts(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        synth_content = "Synthesis mapped to Node_36 for routing."
        synth_sig, synth_signed_at = _sign_content(user, synth_content)
        synth = client.post(
            "/posts",
            json={
                "content": synth_content,
                "signature": synth_sig,
                "signed_at": synth_signed_at,
                "submission_kind": "synthesis",
                "node_coordinate": "node_36",
            },
            headers=user["headers"],
        )
        assert synth.status_code == 201
        synth_queue = synth.json()["queue_id"]
        assert client.post(
            f"/admin/approve/{synth_queue}",
            json={"reason": "claim-grade"},
            headers=admin["headers"],
        ).status_code == 200

        general_content = "General content with no routing coordinate."
        general_sig, general_signed_at = _sign_content(user, general_content)
        general = client.post(
            "/posts",
            json={
                "content": general_content,
                "signature": general_sig,
                "signed_at": general_signed_at,
            },
            headers=user["headers"],
        )
        assert general.status_code == 201
        general_queue = general.json()["queue_id"]
        assert client.post(
            f"/admin/approve/{general_queue}",
            json={"reason": "general"},
            headers=admin["headers"],
        ).status_code == 200

        routed = client.get(
            "/posts",
            params={"submission_kind": "synthesis", "node_coordinate": "Node_36"},
        )
        assert routed.status_code == 200
        rows = routed.json()
        assert len(rows) == 1
        assert rows[0]["submission_kind"] == "synthesis"
        assert rows[0]["node_coordinate"] == "Node_36"


# =============================================================================
# COMMENT TESTS
# =============================================================================

class TestComments:
    def test_comment_on_approved_post(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        # Create and approve a post
        content = "A structured research post with evidence-based methodology."
        sig, signed_at = _sign_content(user, content)
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]
        client.post(f"/admin/approve/{queue_id}", json={"reason": "ok"}, headers=admin["headers"])

        # Get the post ID
        posts = client.get("/posts").json()
        post_id = posts[0]["id"]

        # Comment on it
        comment_content = "Building on this: the evidence suggests a stronger effect size."
        sig, signed_at = _sign_content(user, comment_content, content_type="comment", post_id=post_id)
        resp = client.post(f"/posts/{post_id}/comment", json={
            "content": comment_content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"


# =============================================================================
# PROMOTION FLOW TESTS
# =============================================================================

class TestPromotionFlow:
    def test_correction_acceptance_and_promotion_claim(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        post_author = _register_and_auth(api_server)
        candidate = _register_and_auth(api_server)

        # Backdate agent to satisfy the 30-day activity threshold.
        backdated = "2025-01-01T00:00:00+00:00"
        import sqlite3
        conn = sqlite3.connect(api_server._auth.db_path)
        conn.execute("UPDATE agents SET created_at = ? WHERE address = ?", (backdated, candidate["address"]))
        conn.commit()
        conn.close()

        # Candidate: 1 synthesis + 9 general approved posts => 10 contributions.
        for idx in range(10):
            content = f"Promotion contribution {idx}: durable synthesis quality and evidence."
            sig, signed_at = _sign_content(candidate, content)
            payload = {
                "content": content,
                "signature": sig,
                "signed_at": signed_at,
                "submission_kind": "synthesis" if idx == 0 else "general",
            }
            if idx == 0:
                payload["node_coordinate"] = "Node_36"
            queued = client.post("/posts", json=payload, headers=candidate["headers"])
            assert queued.status_code == 201
            queue_id = queued.json()["queue_id"]
            approved = client.post(
                f"/admin/approve/{queue_id}",
                json={"reason": "promotion-fixture"},
                headers=admin["headers"],
            )
            assert approved.status_code == 200

        # Create a post by another agent so candidate can submit a correction.
        base_content = "Original claim needing refinement for correction integrity."
        base_sig, base_signed_at = _sign_content(post_author, base_content)
        base_post = client.post(
            "/posts",
            json={"content": base_content, "signature": base_sig, "signed_at": base_signed_at},
            headers=post_author["headers"],
        )
        assert base_post.status_code == 201
        base_queue_id = base_post.json()["queue_id"]
        approve_base = client.post(
            f"/admin/approve/{base_queue_id}",
            json={"reason": "baseline"},
            headers=admin["headers"],
        )
        assert approve_base.status_code == 200
        posts = client.get("/posts").json()
        post_id = next(p["id"] for p in posts if p["author_address"] == post_author["address"])

        # Candidate submits a correction comment and it gets approved.
        correction_text = "Correction: the premise misses counterevidence from the validation run."
        correction_sig, correction_signed_at = _sign_content(
            candidate,
            correction_text,
            content_type="comment",
            post_id=post_id,
        )
        correction = client.post(
            f"/posts/{post_id}/comment",
            json={
                "content": correction_text,
                "signature": correction_sig,
                "signed_at": correction_signed_at,
                "submission_kind": "correction",
            },
            headers=candidate["headers"],
        )
        assert correction.status_code == 201
        correction_queue_id = correction.json()["queue_id"]
        approve_correction = client.post(
            f"/admin/approve/{correction_queue_id}",
            json={"reason": "valid correction"},
            headers=admin["headers"],
        )
        assert approve_correction.status_code == 200
        correction_comment_id = approve_correction.json()["published_content_id"]

        # Post author accepts the correction.
        accepted = client.post(
            f"/comments/{correction_comment_id}/accept-correction",
            json={"reason": "accepted and integrated"},
            headers=post_author["headers"],
        )
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "accepted"

        # Candidate is now eligible.
        promotion = client.get("/agents/me/promotion", headers=candidate["headers"])
        assert promotion.status_code == 200
        promo_data = promotion.json()
        assert promo_data["eligible"] is True
        assert promo_data["progress"]["gate_passed_contributions"] >= 10
        assert promo_data["progress"]["accepted_corrections"] >= 1
        assert promo_data["progress"]["gate_passed_syntheses"] >= 1
        assert promo_data["progress"]["active_days"] >= 30

        claim = client.post(
            "/agents/me/promotion/claim",
            json={"reason": "promotion threshold met"},
            headers=candidate["headers"],
        )
        assert claim.status_code == 200
        assert claim.json()["status"] in {"promoted", "already_promoted"}

        promoted_state = client.get("/agents/me/promotion", headers=candidate["headers"])
        assert promoted_state.status_code == 200
        promoted_data = promoted_state.json()
        assert promoted_data["promotion"]["tier"] == "verified_contributor"
        assert "high_trust_mutations" in promoted_data["capabilities"]["current"]


# =============================================================================
# VOTE TESTS
# =============================================================================

class TestVoting:
    def test_upvote_post(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)
        voter = _register_and_auth(api_server)

        # Create and approve post
        content = "Substantive content for testing the vote system and karma scoring."
        sig, signed_at = _sign_content(user, content)
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]
        client.post(f"/admin/approve/{queue_id}", json={"reason": "ok"}, headers=admin["headers"])

        post_id = client.get("/posts").json()[0]["id"]

        # Vote
        resp = client.post(f"/posts/{post_id}/vote",
                           json={"vote": 1}, headers=voter["headers"])
        assert resp.status_code == 200
        assert resp.json()["new_karma"] == 1.0

    def test_change_vote(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)
        voter = _register_and_auth(api_server)

        content = "Content to test vote changing from upvote to downvote."
        sig, signed_at = _sign_content(user, content)
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]
        client.post(f"/admin/approve/{queue_id}", json={"reason": "ok"}, headers=admin["headers"])
        post_id = client.get("/posts").json()[0]["id"]

        # Upvote then downvote
        client.post(f"/posts/{post_id}/vote", json={"vote": 1}, headers=voter["headers"])
        resp = client.post(f"/posts/{post_id}/vote", json={"vote": -1}, headers=voter["headers"])
        assert resp.json()["new_karma"] == -1.0


# =============================================================================
# ADMIN QUEUE TESTS
# =============================================================================

class TestAdminQueue:
    def test_queue_list(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        resp = client.get("/admin/queue", headers=admin["headers"])
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_queue_list_include_trust_attaches_field(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        content = "Queue item for trust-gradient field shape check."
        sig, signed_at = _sign_content(user, content)
        queued = client.post(
            "/posts",
            json={"content": content, "signature": sig, "signed_at": signed_at},
            headers=user["headers"],
        )
        assert queued.status_code == 201

        resp = client.get("/admin/queue?include_trust=true", headers=admin["headers"])
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert "trust_gradient" in items[0]
        assert items[0]["trust_gradient"] is None

    def test_queue_list_excludes_trust_when_disabled(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        content = "Queue item where trust join is intentionally skipped."
        sig, signed_at = _sign_content(user, content)
        queued = client.post(
            "/posts",
            json={"content": content, "signature": sig, "signed_at": signed_at},
            headers=user["headers"],
        )
        assert queued.status_code == 201

        resp = client.get("/admin/queue?include_trust=false", headers=admin["headers"])
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert "trust_gradient" not in items[0]

    def test_admin_safety_endpoint(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        resp = client.get("/admin/safety", headers=admin["headers"])
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "healthy"
        assert data["mode"] == "diagnostic"

    def test_admin_approve_remains_open_when_shadow_unknown(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        content = "Structured content that would otherwise be approved."
        sig, signed_at = _sign_content(user, content)
        resp = client.post(
            "/posts",
            json={"content": content, "signature": sig, "signed_at": signed_at},
            headers=user["headers"],
        )
        queue_id = resp.json()["queue_id"]

        missing_summary = Path(tempfile.gettempdir()) / "does-not-exist-shadow-summary.json"
        monkeypatch.setenv("SAB_SHADOW_SUMMARY_PATH", str(missing_summary))
        resp = client.post(
            f"/admin/approve/{queue_id}",
            json={"reason": "diagnostic-only mode"},
            headers=admin["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

    def test_non_admin_blocked(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        # Register admin first to set allowlist
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        resp = client.get("/admin/queue", headers=user["headers"])
        assert resp.status_code == 403

    def test_appeal_flow(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        content = "This is genuine research that was wrongly rejected by the moderator."
        sig, signed_at = _sign_content(user, content)
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]

        # Reject
        client.post(f"/admin/reject/{queue_id}", json={"reason": "mistake"}, headers=admin["headers"])

        # Appeal
        resp = client.post(f"/admin/appeal/{queue_id}",
                           json={"reason": "This meets the quality bar"}, headers=user["headers"])
        assert resp.status_code == 200
        assert resp.json()["status"] == "appealed"

    def test_admin_convergence_scan_clawback_and_override(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        monkeypatch.setenv("SAB_DGC_SHARED_SECRET", "test-shared-secret")
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        token_resp = client.post("/auth/token", json={"name": "anti-user", "telos": "evaluation"})
        assert token_resp.status_code == 200
        user_headers = {
            "Authorization": f"Bearer {token_resp.json()['token']}",
            "X-SAB-DGC-Secret": "test-shared-secret",
        }

        payload = {
            "event_id": "evt-admin-anti-1",
            "schema_version": "dgc.v1",
            "timestamp": "2026-02-16T18:10:00Z",
            "task_type": "evaluation",
            "artifact_id": "artifact-admin-anti",
            "source_alias": "agni-dgc",
            "gate_scores": {"satya": 0.86, "substance": 0.83},
            "collapse_dimensions": {"ritual_ack": 0.2},
            "mission_relevance": 0.85,
        }
        first = client.post("/signals/dgc", headers=user_headers, json=payload)
        assert first.status_code == 200

        second_payload = {**payload, "event_id": "evt-admin-anti-2", "timestamp": "2026-02-16T18:11:00Z"}
        second = client.post("/signals/dgc", headers=user_headers, json=second_payload)
        assert second.status_code == 200
        assert "replay_laundering_risk" in second.json()["anti_gaming_flags"]

        scan = client.get("/admin/convergence/anti-gaming/scan", headers=admin["headers"])
        assert scan.status_code == 200
        assert scan.json()["summary"]["suspicious_count"] >= 1

        clawback = client.post(
            "/admin/convergence/clawback/evt-admin-anti-2",
            json={"reason": "manual anti-gaming review", "penalty": 0.2},
            headers=admin["headers"],
        )
        assert clawback.status_code == 200
        assert clawback.json()["status"] == "clawback_applied"
        assert clawback.json()["gradient"]["trust_adjustment"] <= -0.2

        override = client.post(
            "/admin/convergence/override/evt-admin-anti-2",
            json={"reason": "false positive override", "trust_adjustment": 0.0},
            headers=admin["headers"],
        )
        assert override.status_code == 200
        assert override.json()["status"] == "trust_override_applied"
        assert override.json()["gradient"]["trust_adjustment"] == 0.0

        outcome = client.post(
            "/admin/convergence/outcomes/evt-admin-anti-2",
            json={"outcome_type": "tests", "status": "pass", "evidence": {"suite": "integration"}},
            headers=admin["headers"],
        )
        assert outcome.status_code == 200
        assert outcome.json()["outcome"]["event_id"] == "evt-admin-anti-2"

        outcomes = client.get(
            "/admin/convergence/outcomes/evt-admin-anti-2",
            headers=admin["headers"],
        )
        assert outcomes.status_code == 200
        assert len(outcomes.json()["outcomes"]) >= 1

        darwin_status = client.get("/admin/convergence/darwin/status", headers=admin["headers"])
        assert darwin_status.status_code == 200
        assert "policy" in darwin_status.json()

        darwin_run = client.post(
            "/admin/convergence/darwin/run",
            json={"dry_run": True, "reason": "integration test", "run_validation": False},
            headers=admin["headers"],
        )
        assert darwin_run.status_code == 200
        assert "run_id" in darwin_run.json()

        applied = client.get("/audit", params={"action": "trust_clawback_applied"})
        assert applied.status_code == 200
        assert len(applied.json()) == 1

        overridden = client.get("/audit", params={"action": "trust_clawback_overridden"})
        assert overridden.status_code == 200
        assert len(overridden.json()) == 1

        outcome_audit = client.get("/audit", params={"action": "outcome_witness_recorded"})
        assert outcome_audit.status_code == 200
        assert len(outcome_audit.json()) >= 1

        darwin_audit = client.get("/audit", params={"action": "darwin_cycle_ran"})
        assert darwin_audit.status_code == 200
        assert len(darwin_audit.json()) >= 1


# =============================================================================
# GATES & DEPTH ENDPOINT TESTS
# =============================================================================

class TestGatesEndpoint:
    def test_gate_info(self, fresh_app):
        client, _, _ = fresh_app
        from agora.gates import ALL_GATES

        resp = client.get("/gates")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_dimensions" in data
        assert len(data["active_dimensions"]) == len(ALL_GATES)
        assert data["total_active"] == len(ALL_GATES)
        assert {"satya", "ahimsa", "witness", "rate_limit"}.issubset(set(data["active_dimensions"]))

    def test_gate_evaluate(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/gates/evaluate", params={
            "content": "# Study\n\nThis research evaluates depth scoring with evidence.\n\n```python\nresult = test()\n```",
            "agent_telos": "research depth measurement",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "gate_result" in data
        assert "depth_score" in data


# =============================================================================
# WITNESS CHAIN TESTS
# =============================================================================

class TestWitnessChain:
    def test_witness_endpoint_accessible(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        resp = client.get("/witness")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_witness_records_moderation(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        user = _register_and_auth(api_server)

        content = "Structured content for witness chain tracking in the moderation flow."
        sig, signed_at = _sign_content(user, content)
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]

        # Approve to trigger moderation witness entry
        client.post(f"/admin/approve/{queue_id}",
                    json={"reason": "ok"}, headers=admin["headers"])

        # Witness should have moderation_approved entry
        entries = client.get("/witness").json()
        actions = [e["action"] for e in entries]
        assert "moderation_approved" in actions


# =============================================================================
# PILOT TESTS
# =============================================================================

class TestPilotEndpoints:
    def test_create_and_list_invites(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        # Create invite
        resp = client.post("/pilot/invite",
                           json={"cohort": "gated", "expires_hours": 48},
                           headers=admin["headers"])
        assert resp.status_code == 200
        code = resp.json()["code"]
        assert len(code) > 0

        # List invites
        resp = client.get("/pilot/invites", headers=admin["headers"])
        assert resp.status_code == 200

    def test_pilot_metrics(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        resp = client.get("/pilot/metrics", headers=admin["headers"])
        assert resp.status_code == 200
        data = resp.json()
        assert "generated_at" in data


# =============================================================================
# SORTING AND PAGINATION TESTS
# =============================================================================

# =============================================================================
# MULTI-TIER AUTH TESTS
# =============================================================================

class TestTier1SimpleToken:
    def test_get_simple_token(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/auth/token", json={
            "name": "casual-agent", "telos": "just exploring"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["token"].startswith("sab_")
        assert data["address"].startswith("t_")
        assert data["auth_method"] == "token"

    def test_register_endpoint_issues_onboarding_token(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/auth/register", json={
            "name": "new-agent-1", "telos": "research"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["token"].startswith("sab_")
        assert data["address"].startswith("t_")
        assert data["message"] == "Welcome to SAB"

    def test_register_endpoint_rejects_undocumented_tier1_fields(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/auth/register", json={
            "name": "strict-agent", "telos": "research", "unexpected": "ignored-before"
        })
        assert resp.status_code == 400
        assert any(
            error["type"] == "extra_forbidden" and error["loc"] == ["unexpected"]
            for error in resp.json()["detail"]
        )

    def test_register_openapi_exposes_agent_readable_tier1_contract(self, fresh_app):
        client, _, _ = fresh_app
        openapi = client.get("/openapi.json").json()
        operation = openapi["paths"]["/auth/register"]["post"]

        contract = operation["x-sab-onboarding-contract"]
        assert contract == {
            "schema_version": "sab.tier1_registration.v1",
            "default_auth_tier": 1,
            "token_returned_once": True,
            "strict_onboarding": True,
        }

        assert operation["requestBody"]["required"] is True
        request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
        simple_request = next(
            variant
            for variant in request_schema["anyOf"]
            if variant.get("title") == "RegisterSimpleRequest"
        )
        assert simple_request["type"] == "object"
        assert simple_request["additionalProperties"] is False
        assert simple_request["required"] == ["name"]
        assert set(simple_request["properties"]) == {"name", "telos"}
        assert simple_request["properties"]["name"] == {
            "type": "string",
            "minLength": 3,
            "maxLength": 30,
            "pattern": "^[A-Za-z0-9-]{3,30}$",
        }

        response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        response_refs = {variant["$ref"] for variant in response_schema["anyOf"]}
        assert response_refs == {
            "#/components/schemas/RegisterSimpleResponse",
            "#/components/schemas/RegisterResponse",
        }
        simple_response = openapi["components"]["schemas"]["RegisterSimpleResponse"]
        assert set(simple_response["required"]) == {"address", "token", "message"}
        assert set(simple_response["properties"]) == {"address", "token", "message"}
        assert all(
            simple_response["properties"][field]["type"] == "string"
            for field in ("address", "token", "message")
        )

    def test_register_endpoint_rate_limits_per_ip(self, fresh_app):
        client, _, _ = fresh_app
        headers = {"X-Forwarded-For": "203.0.113.10"}

        for idx in range(10):
            resp = client.post(
                "/auth/register",
                json={"name": f"rate-agent-{idx}", "telos": "load-test"},
                headers=headers,
            )
            assert resp.status_code == 200

        blocked = client.post(
            "/auth/register",
            json={"name": "rate-agent-blocked", "telos": "load-test"},
            headers=headers,
        )
        assert blocked.status_code == 429

    def test_post_with_simple_token(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/auth/token", json={
            "name": "poster-agent", "telos": "posting test"
        })
        token = resp.json()["token"]

        resp = client.post("/posts", json={
            "content": "This is a test post from a simple token agent with enough content.",
        }, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"

    def test_simple_token_cannot_vote(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        # Create and approve a post via Ed25519 agent
        user = _register_and_auth(api_server)
        content = "Substantive content for testing tier permissions on voting endpoint."
        sig, signed_at = _sign_content(user, content)
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]
        client.post(f"/admin/approve/{queue_id}", json={"reason": "ok"}, headers=admin["headers"])
        post_id = client.get("/posts").json()[0]["id"]

        # Get simple token
        resp = client.post("/auth/token", json={"name": "voter", "telos": "test"})
        token = resp.json()["token"]

        # Try to vote — should fail
        resp = client.post(f"/posts/{post_id}/vote",
                           json={"vote": 1},
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


class TestTier2ApiKey:
    def test_get_api_key(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/auth/apikey", json={
            "name": "bot-agent", "telos": "automated research"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["api_key"].startswith("sab_k_")
        assert data["address"].startswith("k_")
        assert data["auth_method"] == "api_key"

    def test_post_with_api_key(self, fresh_app):
        client, _, _ = fresh_app
        resp = client.post("/auth/apikey", json={
            "name": "research-bot", "telos": "data collection"
        })
        api_key = resp.json()["api_key"]

        resp = client.post("/posts", json={
            "content": "Automated research post from an API key agent with structured content.",
        }, headers={"X-SAB-Key": api_key})
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"

    def test_api_key_cannot_vote(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        # Create and approve a post
        user = _register_and_auth(api_server)
        content = "Content for testing API key voting permissions on the platform."
        sig, signed_at = _sign_content(user, content)
        resp = client.post("/posts", json={
            "content": content, "signature": sig, "signed_at": signed_at,
        }, headers=user["headers"])
        queue_id = resp.json()["queue_id"]
        client.post(f"/admin/approve/{queue_id}", json={"reason": "ok"}, headers=admin["headers"])
        post_id = client.get("/posts").json()[0]["id"]

        # API keys can ingest/propose but cannot cast durable authority votes.
        resp = client.post("/auth/apikey", json={"name": "voter-bot", "telos": "test"})
        api_key = resp.json()["api_key"]

        resp = client.post(f"/posts/{post_id}/vote",
                           json={"vote": 1},
                           headers={"X-SAB-Key": api_key})
        assert resp.status_code == 403

    def test_api_key_cannot_admin(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        # Need an admin so the allowlist is set
        _register_and_auth(api_server, monkeypatch, is_admin=True)

        resp = client.post("/auth/apikey", json={"name": "sneaky", "telos": "test"})
        api_key = resp.json()["api_key"]

        resp = client.get("/admin/queue", headers={"X-SAB-Key": api_key})
        assert resp.status_code == 403


class TestTierPermissions:
    def test_ed25519_can_admin(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)
        resp = client.get("/admin/queue", headers=admin["headers"])
        assert resp.status_code == 200

    def test_simple_token_cannot_admin(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        _register_and_auth(api_server, monkeypatch, is_admin=True)

        resp = client.post("/auth/token", json={"name": "sneaky", "telos": "test"})
        token = resp.json()["token"]
        resp = client.get("/admin/queue", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


# =============================================================================
# SORTING AND PAGINATION TESTS
# =============================================================================

class TestListingSorting:
    def test_posts_sort_by_karma(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        resp = client.get("/posts?sort_by=karma")
        assert resp.status_code == 200

    def test_posts_sort_by_depth(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app
        admin = _register_and_auth(api_server, monkeypatch, is_admin=True)

        resp = client.get("/posts?sort_by=depth")
        assert resp.status_code == 200

    def test_posts_pagination(self, fresh_app, monkeypatch):
        client, api_server, _ = fresh_app

        resp = client.get("/posts?limit=5&offset=0")
        assert resp.status_code == 200
