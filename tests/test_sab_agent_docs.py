from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from connectors.sab_mcp_tools import MCP_TOOL_NAMES, list_tools  # noqa: E402

PUBLIC_DOCS = [
    "skill.md",
    "seed.md",
    "auth.md",
    "heartbeat.md",
    "rules.md",
]


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_served_enrollment_examples_execute_without_authority_effect(client):
    from nacl.signing import SigningKey
    from agora.sab_identity import canonical_json_bytes

    guide = client.get("/auth.md")
    assert guide.status_code == 200
    examples = [
        json.loads(body) for body in re.findall(r"```json\s*\n(.*?)\n```", guide.text, re.S)
    ]
    registration = next(example for example in examples if example.get("action") == "register")
    verification = next(
        example for example in examples if "challenge_id" in example and "signature" in example
    )
    key = SigningKey.generate()
    registration["registration"]["public_key"] = key.verify_key.encode().hex()
    challenge = client.post("/api/v1/agents/challenge", json=registration)
    assert challenge.status_code == 201, challenge.text
    message = challenge.json()["message"]
    verification["challenge_id"] = message["challenge_id"]
    verification["signature"] = key.sign(canonical_json_bytes(message)).signature.hex()
    verified = client.post("/api/v1/agents/verify", json=verification)
    assert verified.status_code == 200, verified.text
    result = verified.json()
    assert result["identity"]["public_key"] == registration["registration"]["public_key"]
    assert result["binding"]["status"] == "active"
    assert result["binding"]["scope"] == "key_control_only"
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert client.post("/api/v1/agents/verify", json=verification).status_code == 409


def test_public_seed_packet_schema_shape() -> None:
    schema = json.loads(_read("site/schemas/sab.seed_packet.v1.schema.json"))
    assert schema["$id"].endswith("/schemas/sab.seed_packet.v1.schema.json")
    assert schema["properties"]["schema"]["const"] == "sab.seed_packet.v1"
    assert "tool" in schema["properties"]["seed_type"]["enum"]
    assert "claim" in schema["properties"]["seed_type"]["enum"]

    required = set(schema["required"])
    for field in (
        "claim",
        "claimant_identity",
        "operator_backing",
        "authority_lease",
        "challenge_plan",
        "witness_plan",
        "privacy_class",
        "signature",
    ):
        assert field in required

    lease_required = set(schema["properties"]["authority_lease"]["required"])
    assert {"scope", "expires_at", "revoker", "challenge_path"} <= lease_required
    assert schema["properties"]["challenge_plan"]["properties"]["required"]["const"] is True


def test_sab_mcp_tool_manifest_names_and_mutation_safety() -> None:
    tools = list_tools()
    assert [tool["name"] for tool in tools] == list(MCP_TOOL_NAMES)

    for tool in tools:
        assert "private keys" in tool["secret_handling"].lower()
        assert "identity tokens" in tool["secret_handling"].lower()
        if tool["kind"] == "mutation":
            assert tool["requires_signature"] is True
            assert "witness_event_id" in tool["returns"]


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("jinja2", reason="agora.app route tests require Jinja2Templates")

    db_path = tmp_path / "sab_agent_docs.db"
    key_path = tmp_path / ".sab_agent_docs_system_ed25519.key"
    monkeypatch.setenv("SAB_PUBLIC_MODE", "local")
    monkeypatch.setenv("SAB_IDENTITY_ORIGIN", "http://127.0.0.1:8000")
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(key_path))

    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]

    web_app = importlib.import_module("agora.app")
    with TestClient(web_app.app) as test_client:
        yield test_client


def test_public_agent_docs_routes_are_served(client: TestClient) -> None:
    for path in (
        "/skill.md",
        "/seed.md",
        "/auth.md",
        "/heartbeat.md",
        "/rules.md",
    ):
        res = client.get(path)
        assert res.status_code == 200, path
        assert res.headers["content-type"].startswith("text/markdown"), path
        assert res.content == (REPO_ROOT / "site" / path.lstrip("/")).read_bytes(), path

    schema_res = client.get("/schemas/sab.seed_packet.v1.schema.json")
    assert schema_res.status_code == 200
    assert schema_res.headers["content-type"].startswith("application/schema+json")
    assert schema_res.json()["properties"]["schema"]["const"] == "sab.seed_packet.v1"
