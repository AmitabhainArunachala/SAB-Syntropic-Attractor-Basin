from __future__ import annotations

import importlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from historical_web_fixtures import HistoricalWebActor


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agora.auth import build_contribution_message, generate_agent_keypair, sign_challenge


def _reset_agora_modules() -> None:
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]


def _prepare_shared_env(tmp_path, monkeypatch) -> Path:
    shared_db = tmp_path / "sab_authority.db"
    shadow_summary = tmp_path / "shadow_loop" / "run_summary.json"
    system_key = tmp_path / ".sab_system_ed25519.key"
    shadow_summary.parent.mkdir(parents=True, exist_ok=True)
    shadow_summary.write_text(
        json.dumps(
            {
                "timestamp": "2026-04-16T00:00:00+00:00",
                "status": "stable",
                "alert_count": 0,
                "high_alert_count": 0,
            }
        )
    )

    monkeypatch.setenv("SAB_AUTHORITY_DB_PATH", str(shared_db))
    monkeypatch.delenv("SAB_DB_PATH", raising=False)
    monkeypatch.delenv("SAB_SPARK_DB_PATH", raising=False)
    monkeypatch.setenv("SAB_SHADOW_SUMMARY_PATH", str(shadow_summary))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(system_key))
    return shared_db


def test_shared_db_boot_allows_protocol_and_public_round_trips(tmp_path, monkeypatch):
    shared_db = _prepare_shared_env(tmp_path, monkeypatch)

    _reset_agora_modules()
    api_server = importlib.import_module("agora.api_server")
    web_app = importlib.import_module("agora.app")
    web_app.init_db()

    assert Path(api_server.AGORA_DB) == shared_db
    assert web_app.SPARK_DB == shared_db

    api_client = TestClient(api_server.app)
    web_client = TestClient(web_app.app)

    token_resp = api_client.post(
        "/auth/token",
        json={"name": "shared-api-agent", "telos": "shared-db-validation"},
    )
    assert token_resp.status_code == 200
    token = token_resp.json()["token"]

    queued = api_client.post(
        "/posts",
        json={"content": "Shared DB protocol submission for boot verification."},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert queued.status_code == 201

    feed = web_client.get("/")
    assert feed.status_code == 200
    actor = HistoricalWebActor(web_client, display_name="shared-web-agent")
    submission = actor.submit(
        "Shared DB signed historical discussion for boot verification."
    )
    spark_id = int(submission["id"])
    assert web_client.get(f"/spark/{spark_id}").status_code == 200
    assert not web_client.cookies

    chain = web_client.get(f"/api/spark/{spark_id}/chain")
    assert chain.status_code == 200
    entries = chain.json()["entries"]
    assert entries
    first_entry = entries[0]
    assert first_entry["witness_domain"] == "publication"
    assert first_entry["witness_link_id"]
    payload = json.loads(first_entry["payload"])
    assert payload["witness_meta"]["link_id"] == first_entry["witness_link_id"]
    assert payload["witness_meta"]["domain"] == "publication"

    with sqlite3.connect(shared_db) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "agents",
            "web_agents",
            "simple_tokens",
            "posts",
            "moderation_queue",
            "sparks",
            "spark_challenges",
            "witness_chain",
            "spark_witness_chain",
        }.issubset(tables)
        assert conn.execute("SELECT COUNT(*) FROM simple_tokens").fetchone()[0] >= 1
        assert conn.execute("SELECT COUNT(*) FROM web_agents").fetchone()[0] >= 1
        assert conn.execute("SELECT COUNT(*) FROM moderation_queue").fetchone()[0] >= 1
        assert conn.execute("SELECT COUNT(*) FROM sparks").fetchone()[0] >= 1


def test_shared_db_moderation_actions_cross_link_publication_and_governance_witness(tmp_path, monkeypatch):
    shared_db = _prepare_shared_env(tmp_path, monkeypatch)

    _reset_agora_modules()
    api_server = importlib.import_module("agora.api_server")
    importlib.import_module("agora.app").init_db()

    admin_private_key, admin_public_key = generate_agent_keypair()
    admin_address = api_server._auth.register("shared-admin", admin_public_key, telos="admin")
    monkeypatch.setenv("SAB_ADMIN_ALLOWLIST", admin_address)
    admin_challenge = api_server._auth.create_challenge(admin_address)
    admin_result = api_server._auth.verify_challenge(
        admin_address,
        sign_challenge(admin_private_key, admin_challenge),
    )
    assert admin_result.token is not None

    client = TestClient(api_server.app)
    user_private_key, user_public_key = generate_agent_keypair()
    user_address = api_server._auth.register("shared-protocol-user", user_public_key, telos="triad-check")
    user_challenge = api_server._auth.create_challenge(user_address)
    user_result = api_server._auth.verify_challenge(
        user_address,
        sign_challenge(user_private_key, user_challenge),
    )
    assert user_result.token is not None
    content = "Shared DB moderation triad validation content."
    signed_at = datetime.now(timezone.utc).isoformat()
    message = build_contribution_message(
        agent_address=user_address,
        content=content,
        signed_at=signed_at,
        content_type="post",
    )
    signature = SigningKey(user_private_key, encoder=HexEncoder).sign(message).signature.hex()

    queued = client.post(
        "/posts",
        json={"content": content, "signature": signature, "signed_at": signed_at},
        headers={"Authorization": f"Bearer {user_result.token}"},
    )
    assert queued.status_code == 201
    queue_id = int(queued.json()["queue_id"])

    approved = client.post(
        f"/admin/approve/{queue_id}",
        json={"reason": "triad test approve"},
        headers={"Authorization": f"Bearer {admin_result.token}"},
    )
    assert approved.status_code == 200
    witness_link_id = approved.json()["witness_link_id"]
    assert witness_link_id

    triad = client.get(f"/witness/triad/{witness_link_id}")
    assert triad.status_code == 200
    triad_payload = triad.json()
    assert triad_payload["witness_link_id"] == witness_link_id
    assert len(triad_payload["publication"]["protocol"]) == 1
    assert len(triad_payload["governance"]) == 1
    protocol_entry = triad_payload["publication"]["protocol"][0]
    governance_entry = triad_payload["governance"][0]
    assert protocol_entry["action"] == "moderation_approved"
    assert governance_entry["action"] == "moderation_approved"
    assert protocol_entry["witness_link_id"] == witness_link_id
    assert governance_entry["witness_link_id"] == witness_link_id
    assert protocol_entry["domain"] == "publication"
    assert governance_entry["domain"] == "governance"

    with sqlite3.connect(shared_db) as conn:
        witness_count = conn.execute(
            "SELECT COUNT(*) FROM witness_chain WHERE witness_link_id = ?",
            (witness_link_id,),
        ).fetchone()[0]
        audit_count = conn.execute(
            "SELECT COUNT(*) FROM audit_trail WHERE witness_link_id = ?",
            (witness_link_id,),
        ).fetchone()[0]
    assert witness_count == 1
    assert audit_count == 1
