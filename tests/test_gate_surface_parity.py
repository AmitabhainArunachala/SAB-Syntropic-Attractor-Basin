from __future__ import annotations

import hashlib
import importlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Dict, Tuple

from fastapi.testclient import TestClient
from nacl.signing import SigningKey


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _canonical_bytes(payload: Dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sign_submit(sk: SigningKey, agent_id: str, content: str) -> str:
    content_sha = hashlib.sha256(content.encode()).hexdigest()
    payload = {
        "kind": "spark_submit",
        "author_id": agent_id,
        "content_sha256": content_sha,
    }
    return sk.sign(_canonical_bytes(payload)).signature.hex()


def _reset_agora_modules() -> None:
    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]


def _prepare_shared_env(tmp_path, monkeypatch) -> Path:
    shared_db = tmp_path / "sab_authority.db"
    system_key = tmp_path / ".sab_system_ed25519.key"
    shadow_summary = tmp_path / "shadow_loop" / "run_summary.json"
    shadow_summary.parent.mkdir(parents=True, exist_ok=True)
    shadow_summary.write_text(
        json.dumps(
            {
                "timestamp": "2026-07-02T00:00:00+00:00",
                "status": "stable",
                "alert_count": 0,
                "high_alert_count": 0,
            }
        )
    )

    monkeypatch.setenv("SAB_AUTHORITY_DB_PATH", str(shared_db))
    monkeypatch.delenv("SAB_DB_PATH", raising=False)
    monkeypatch.delenv("SAB_SPARK_DB_PATH", raising=False)
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(system_key))
    monkeypatch.setenv("SAB_SHADOW_SUMMARY_PATH", str(shadow_summary))
    return shared_db


def _boot_clients(tmp_path, monkeypatch) -> Tuple[Path, TestClient, TestClient]:
    shared_db = _prepare_shared_env(tmp_path, monkeypatch)
    _reset_agora_modules()

    api_server = importlib.import_module("agora.api_server")
    web_app = importlib.import_module("agora.app")
    web_app.init_db()

    return shared_db, TestClient(api_server.app), TestClient(web_app.app)


def _register_web_agent(web_client: TestClient, name: str) -> Tuple[str, SigningKey]:
    from keycontrol_fixtures import enroll_identity

    signing_key = SigningKey.generate()
    identity = enroll_identity(web_client, signing_key, display_name=name)
    return identity["subject_id"], signing_key


def _api_token(api_client: TestClient, name: str) -> str:
    res = api_client.post("/auth/token", json={"name": name, "telos": ""})
    assert res.status_code == 200, res.text
    return str(res.json()["token"])


def _submit_public(web_client: TestClient, content: str, name: str = "public-agent") -> Dict[str, object]:
    author_id, signing_key = _register_web_agent(web_client, name)
    signature = _sign_submit(signing_key, author_id, content)
    res = web_client.post(
        "/api/spark/submit",
        json={
            "content": content,
            "content_type": "text",
            "author_id": author_id,
            "signature": signature,
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def _submit_protocol(api_client: TestClient, content: str, name: str = "protocol-agent") -> Dict[str, object]:
    token = _api_token(api_client, name)
    res = api_client.post(
        "/posts",
        json={"content": content},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 201, res.text
    return res.json()


def _core_gate_projection(gate_result: Dict[str, object]) -> Dict[str, object]:
    return {
        "required_passed": gate_result["required_passed"],
        "ahimsa_passed": gate_result["ahimsa_passed"],
        "composite": gate_result["composite"],
        "dimensions": gate_result["dimensions"],
        "evaluation_metadata": gate_result["evaluation_metadata"],
    }


def test_required_gate_failure_composts_public_but_queues_protocol(tmp_path, monkeypatch):
    shared_db, api_client, web_client = _boot_clients(tmp_path, monkeypatch)
    content = "ok"

    public = _submit_public(web_client, content, "short-public")
    protocol = _submit_protocol(api_client, content, "short-protocol")

    public_gate = public["gate_scores"]
    protocol_gate = protocol["gate_result"]
    assert _core_gate_projection(public_gate) == _core_gate_projection(protocol_gate)
    assert public_gate["required_passed"] is False
    assert public_gate["ahimsa_passed"] is True

    assert public["status"] == "compost"
    assert protocol["status"] == "pending"

    with sqlite3.connect(shared_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0] == 0


def test_required_pass_content_sparks_public_but_queues_protocol(tmp_path, monkeypatch):
    _, api_client, web_client = _boot_clients(tmp_path, monkeypatch)
    content = "SAB spark with enough structure to pass dharmic gates and share useful evidence."

    public = _submit_public(web_client, content, "valid-public")
    protocol = _submit_protocol(api_client, content, "valid-protocol")

    public_gate = public["gate_scores"]
    protocol_gate = protocol["gate_result"]
    assert _core_gate_projection(public_gate) == _core_gate_projection(protocol_gate)
    assert public_gate["required_passed"] is True

    assert public["status"] == "spark"
    assert protocol["status"] == "pending"
