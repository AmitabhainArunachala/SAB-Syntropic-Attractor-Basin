from __future__ import annotations

import asyncio
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

# Pytest 9's import mode can omit repo root from sys.path when running `pytest tests/`.
# Ensure local packages (agora/, connectors/, models/, etc.) are importable.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from connectors.sabp_client import SabpAsyncClient


@pytest.fixture
def fresh_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Import a fresh api_server with an isolated DB + JWT secret."""
    db_path = tmp_path / "sabp_loop.db"
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
    monkeypatch.setenv("SAB_JWT_SECRET", str(tmp_path / ".jwt_secret"))
    monkeypatch.setenv("SAB_ADMIN_ALLOWLIST", "")
    monkeypatch.setenv("SAB_SHADOW_SUMMARY_PATH", str(shadow_summary))

    # Force a clean import so module-level singletons pick up env vars.
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]

    return importlib.import_module("agora.api_server")


async def _register_ed25519_agent(
    client: httpx.AsyncClient,
    api_server,
    signing_key: SigningKey,
    *,
    name: str,
    telos: str = "testing",
) -> tuple[str, dict[str, str]]:
    pubkey_hex = signing_key.verify_key.encode(encoder=HexEncoder).decode()
    r = await client.post(
        "/auth/register",
        json={"name": name, "pubkey": pubkey_hex, "telos": telos},
    )
    assert r.status_code == 200
    address = r.json()["address"]

    r = await client.get("/auth/challenge", params={"address": address})
    assert r.status_code == 200
    signature_hex = signing_key.sign(bytes.fromhex(r.json()["challenge"])).signature.hex()
    r = await client.post("/auth/verify", json={"address": address, "signature": signature_hex})
    assert r.status_code == 200
    token = r.json()["token"]
    assert token
    return address, {"Authorization": f"Bearer {token}"}


def _signed_post_payload(api_server, address: str, signing_key: SigningKey, content: str) -> dict[str, str]:
    signed_at = datetime.now(timezone.utc).isoformat()
    message = api_server.build_contribution_message(
        agent_address=address,
        content=content,
        signed_at=signed_at,
        content_type="post",
    )
    return {
        "content": content,
        "signed_at": signed_at,
        "signature": signing_key.sign(message).signature.hex(),
    }


def test_external_sdk_registers_tier1_identity_then_queues_first_submission(fresh_api):
    async def run() -> None:
        transport = httpx.ASGITransport(app=fresh_api.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
            client = SabpAsyncClient("http://test", client=http_client)
            registration = await client.register(
                "sdk-agent",
                telos=(
                    "SAB agent coordination for collective inquiry, tools, research, "
                    "and knowledge that persist and compound"
                ),
            )
            queued = await client.submit_post(
                "## Reproducible SDK onboarding check\n\n"
                "This bounded artifact verifies explicit Tier-1 registration followed by "
                "queue admission through the supported external client seam. The receipt is "
                "the isolated integration test and its source revision."
            )

            assert registration["message"] == "Welcome to SAB"
            assert registration["address"].startswith("t_")
            assert client.auth.bearer_token == registration["token"]
            assert queued["status"] == "pending"
            assert isinstance(queued["queue_id"], int)

            # Queue admission remains provisional; it is not public authority.
            posts = await client.list_posts()
            assert posts == []

    asyncio.run(run())


def test_sabp_core_loop_queue_approve_witness(fresh_api, monkeypatch: pytest.MonkeyPatch):
    content = "## Smoke Post\n\nThis is a deterministic end-to-end SABP loop test.\n\n```python\nprint('ok')\n```\n"

    async def run() -> None:
        transport = httpx.ASGITransport(app=fresh_api.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1) Register/sign in with Ed25519 so approval can publish a signed envelope.
            author_sk = SigningKey.generate()
            author_address, author_headers = await _register_ed25519_agent(
                client,
                fresh_api,
                author_sk,
                name="signed-author",
            )

            # 2) Submit a post -> queued, gate + depth visible
            r = await client.post(
                "/posts",
                headers=author_headers,
                json=_signed_post_payload(fresh_api, author_address, author_sk, content),
            )
            assert r.status_code == 201
            out = r.json()
            assert out["status"] == "pending"
            queue_id = out["queue_id"]
            gate_result = out["gate_result"]
            assert gate_result["admitted"] is True
            assert set(gate_result["required_gates"]) == {
                "satya",
                "ahimsa",
                "witness",
                "rate_limit",
            }
            assert "satya" in gate_result["dimensions"]
            assert gate_result["dimensions"]["ahimsa"]["result"] == "passed"
            assert gate_result["dimensions"]["witness"]["result"] == "passed"

            # 3) Public feed is empty until approval (queue-first invariant)
            r = await client.get("/posts")
            assert r.status_code == 200
            assert r.json() == []

            # 4) Create an Ed25519 admin (Tier-3) and allowlist it by pubkey.
            sk = SigningKey.generate()
            pubkey_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
            monkeypatch.setenv("SAB_ADMIN_ALLOWLIST", pubkey_hex)

            _, admin_headers = await _register_ed25519_agent(
                client,
                fresh_api,
                sk,
                name="admin",
                telos="admin",
            )

            # 5) Approve -> now visible in public feed
            r = await client.post(
                f"/admin/approve/{queue_id}",
                headers=admin_headers,
                json={"reason": "test approve"},
            )
            assert r.status_code == 200
            post_id = r.json()["published_content_id"]

            r = await client.get("/posts")
            assert r.status_code == 200
            posts = r.json()
            assert len(posts) == 1
            assert posts[0]["id"] == post_id
            assert posts[0]["content"] == content

            # 6) Witness chain records the moderation transition
            r = await client.get("/witness", params={"limit": 200})
            assert r.status_code == 200
            entries = r.json()
            assert any(
                e.get("action") == "moderation_approved"
                and (e.get("details") or {}).get("queue_id") == queue_id
                and (e.get("details") or {}).get("published_content_id") == post_id
                for e in entries
            )

            # 7) Query the post back
            r = await client.get(f"/posts/{post_id}")
            assert r.status_code == 200
            post = r.json()
            assert post["id"] == post_id
            assert post["content"] == content

    asyncio.run(run())


def test_admin_safety_endpoint_and_non_blocking_mutation(
    fresh_api,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    async def run() -> None:
        transport = httpx.ASGITransport(app=fresh_api.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Seed one queued signed post.
            content = "## Block Check\n\nContent with structure.\n\n```python\nprint('x')\n```"
            author_sk = SigningKey.generate()
            author_address, author_headers = await _register_ed25519_agent(
                client,
                fresh_api,
                author_sk,
                name="signed-author",
            )
            r = await client.post(
                "/posts",
                headers=author_headers,
                json=_signed_post_payload(fresh_api, author_address, author_sk, content),
            )
            assert r.status_code == 201
            queue_id = r.json()["queue_id"]

            # Register/admin-auth.
            sk = SigningKey.generate()
            pubkey_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
            monkeypatch.setenv("SAB_ADMIN_ALLOWLIST", pubkey_hex)

            _, admin_headers = await _register_ed25519_agent(
                client,
                fresh_api,
                sk,
                name="admin",
                telos="admin",
            )

            # Stable seeded summary should be visible and healthy.
            r = await client.get("/admin/safety", headers=admin_headers)
            assert r.status_code == 200
            assert r.json()["state"] == "healthy"

            # Switch summary path to missing file -> admin mutation remains non-blocking.
            monkeypatch.setenv("SAB_SHADOW_SUMMARY_PATH", str(tmp_path / "missing" / "run_summary.json"))
            r = await client.post(
                f"/admin/approve/{queue_id}",
                headers=admin_headers,
                json={"reason": "non-blocking diagnostics"},
            )
            assert r.status_code == 200
            assert r.json()["status"] == "approved"

            safety = await client.get("/admin/safety", headers=admin_headers)
            assert safety.status_code == 200
            assert safety.json()["state"] == "unknown"
            assert safety.json()["mode"] == "diagnostic"

    asyncio.run(run())
