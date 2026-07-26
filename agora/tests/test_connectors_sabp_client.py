from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import asyncio
import httpx
import pytest

from connectors.sabp_client import SabpAsyncClient, SabpClient


@pytest.fixture
def fresh_api(tmp_path: Path, monkeypatch):
    """Import a fresh api_server with an isolated DB."""
    db_path = tmp_path / "sab_connectors.db"
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
    monkeypatch.setenv("SAB_DGC_SHARED_SECRET", "test-shared-secret")

    for mod_name in list(sys.modules):
        if mod_name.startswith("agora.") and mod_name != "agora.auth":
            del sys.modules[mod_name]

    return importlib.import_module("agora.api_server")


def test_sabp_client_registration_and_queue_only(fresh_api):
    async def run():
        transport = httpx.ASGITransport(app=fresh_api.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c = SabpAsyncClient("http://test", client=client)
            registration = await c.register("t1-agent", telos="testing")
            assert registration["message"] == "Welcome to SAB"
            assert registration["address"].startswith("t_")
            assert c.auth.bearer_token == registration["token"]

            out = await c.submit_post("hello from a connector")
            assert out["status"] == "pending"
            assert isinstance(out["queue_id"], int)

            # Queue-first invariant: nothing is visible until approved.
            posts = await c.list_posts()
            assert posts == []

    asyncio.run(run())


def test_sync_client_register_uses_canonical_onboarding_route() -> None:
    observed: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["method"] = request.method
        observed["path"] = request.url.path
        observed["payload"] = json.loads(request.content)
        return httpx.Response(
            status_code=200,
            json={
                "address": "t_agent_1",
                "token": "sab_t_once_only",
                "message": "Welcome to SAB",
            },
            request=request,
        )

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, base_url="http://test") as raw:
        client = SabpClient("http://test", client=raw)
        registration = client.register("external-agent", telos="correct cited claims")

    assert observed == {
        "method": "POST",
        "path": "/auth/register",
        "payload": {"name": "external-agent", "telos": "correct cited claims"},
    }
    assert registration["address"] == "t_agent_1"
    assert client.auth.bearer_token == "sab_t_once_only"


@pytest.mark.parametrize(
    "response_payload",
    [
        [],
        {"address": "t_agent_1"},
        {"token": "sab_t_once_only"},
        {"address": "", "token": "sab_t_once_only"},
        {"address": "t_agent_1", "token": ""},
    ],
)
def test_sync_client_register_rejects_malformed_success_payload(response_payload) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, json=response_payload, request=request)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, base_url="http://test") as raw:
        client = SabpClient("http://test", client=raw)
        with pytest.raises(RuntimeError, match="POST /auth/register returned an invalid"):
            client.register("external-agent", telos="correct cited claims")
        assert client.auth.bearer_token is None


def test_sabp_client_convergence_flow(fresh_api):
    async def run():
        transport = httpx.ASGITransport(app=fresh_api.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c = SabpAsyncClient("http://test", client=client)
            token_data = await c.issue_token("diag-agent", telos="evaluation")
            address = token_data["address"]

            identity = await c.register_identity(
                {
                    "base_model": "claude-opus-4-6",
                    "alias": "AGNI",
                    "timestamp": "2026-02-16T14:30:00Z",
                    "perceived_role": "evaluator",
                    "self_grade": 0.7,
                    "context_hash": "ctx_convergence_001",
                    "task_affinity": ["evaluation", "research"],
                }
            )
            assert identity["status"] == "registered"

            signal = await c.ingest_dgc_signal(
                {
                    "event_id": "evt-client-1",
                    "timestamp": "2026-02-16T14:31:00Z",
                    "task_id": "task-1",
                    "task_type": "evaluation",
                    "artifact_id": "artifact-1",
                    "gate_scores": {"satya": 0.9, "substance": 0.85},
                    "collapse_dimensions": {"ritual_ack": 0.2},
                    "mission_relevance": 0.88,
                },
                dgc_shared_secret="test-shared-secret",
            )
            assert signal["event_id"] == "evt-client-1"
            assert signal["schema_version"] == "dgc.v1"

            trust = await c.trust_history(address)
            assert trust["latest"]["signal_event_id"] == "evt-client-1"

            landscape = await c.convergence_landscape()
            assert any(n["agent_address"] == address for n in landscape["nodes"])

    asyncio.run(run())


def test_sync_client_surfaces_http_detail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/signals/dgc":
            return httpx.Response(
                status_code=403,
                json={"detail": "Invalid DGC shared secret"},
                request=request,
            )
        return httpx.Response(status_code=404, json={"detail": "not found"}, request=request)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, base_url="http://test") as raw:
        client = SabpClient("http://test", client=raw)
        with pytest.raises(RuntimeError) as exc:
            client.ingest_dgc_signal(
                {
                    "event_id": "evt-client-error",
                    "timestamp": "2026-02-16T14:40:00Z",
                    "gate_scores": {"satya": 0.8},
                    "collapse_dimensions": {"ritual_ack": 0.2},
                },
                dgc_shared_secret="wrong-secret",
            )
        message = str(exc.value)
        assert "POST /signals/dgc -> 403" in message
        assert "Invalid DGC shared secret" in message


def test_async_client_surfaces_text_error_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=500, text="upstream meltdown", request=request)

    async def run() -> None:
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as raw:
            client = SabpAsyncClient("http://test", client=raw)
            with pytest.raises(RuntimeError) as exc:
                await client.health_check()
            assert "GET /health -> 500: upstream meltdown" in str(exc.value)

    asyncio.run(run())


def test_sync_client_admin_convergence_methods() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/admin/convergence/anti-gaming/scan":
            return httpx.Response(status_code=200, json={"summary": {"suspicious_count": 1}}, request=request)
        if request.url.path.endswith("/clawback/evt-1"):
            return httpx.Response(status_code=200, json={"status": "clawback_applied"}, request=request)
        if request.url.path.endswith("/override/evt-1"):
            return httpx.Response(status_code=200, json={"status": "trust_override_applied"}, request=request)
        if request.url.path.endswith("/outcomes/evt-1") and request.method == "POST":
            return httpx.Response(status_code=200, json={"outcome": {"event_id": "evt-1"}}, request=request)
        if request.url.path.endswith("/outcomes/evt-1") and request.method == "GET":
            return httpx.Response(status_code=200, json={"event_id": "evt-1", "outcomes": []}, request=request)
        if request.url.path == "/admin/convergence/darwin/status":
            return httpx.Response(status_code=200, json={"policy": {"version": 2}}, request=request)
        if request.url.path == "/admin/convergence/darwin/run":
            return httpx.Response(status_code=200, json={"run_id": "run-1"}, request=request)
        return httpx.Response(status_code=404, json={"detail": "not found"}, request=request)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, base_url="http://test") as raw:
        c = SabpClient("http://test", client=raw)
        scan = c.admin_anti_gaming_scan(limit=100)
        assert scan["summary"]["suspicious_count"] == 1
        claw = c.admin_convergence_clawback("evt-1", reason="manual", penalty=0.2)
        assert claw["status"] == "clawback_applied"
        override = c.admin_convergence_override("evt-1", reason="override", trust_adjustment=0.0)
        assert override["status"] == "trust_override_applied"
        outcome = c.admin_record_outcome("evt-1", outcome_type="tests", status="pass", evidence={"suite": "core"})
        assert outcome["outcome"]["event_id"] == "evt-1"
        outcomes = c.admin_list_outcomes("evt-1")
        assert outcomes["event_id"] == "evt-1"
        status = c.admin_darwin_status()
        assert status["policy"]["version"] == 2
        run = c.admin_darwin_run(dry_run=True, reason="cycle", run_validation=False)
        assert run["run_id"] == "run-1"

    assert ("GET", "/admin/convergence/anti-gaming/scan") in calls
    assert ("POST", "/admin/convergence/clawback/evt-1") in calls
    assert ("POST", "/admin/convergence/override/evt-1") in calls
    assert ("POST", "/admin/convergence/outcomes/evt-1") in calls
    assert ("GET", "/admin/convergence/outcomes/evt-1") in calls
    assert ("GET", "/admin/convergence/darwin/status") in calls
    assert ("POST", "/admin/convergence/darwin/run") in calls
