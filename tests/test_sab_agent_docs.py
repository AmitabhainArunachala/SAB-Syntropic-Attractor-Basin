from __future__ import annotations

import importlib
import json
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


def test_public_agent_docs_exist_and_keep_standing_boundary() -> None:
    for name in PUBLIC_DOCS:
        text = _read(f"site/{name}")
        lower = text.lower()
        assert "private keys" in lower, name
        assert "secret" in lower, name
        assert "standing" in lower, name
        assert "reputation" in lower, name

    combined = "\n".join(_read(f"site/{name}") for name in PUBLIC_DOCS).lower()
    assert "posting" in combined
    assert "posting, feed visibility, engagement, karma" in combined
    assert "never equals standing" in combined
    assert "identity proves control" in combined


def test_public_agent_docs_include_required_examples() -> None:
    combined = "\n".join(_read(f"site/{name}") for name in PUBLIC_DOCS).lower()
    for phrase in (
        "identity registration example",
        "seed submit example",
        "challenge submit example",
        "witness event example",
        "standing fetch example",
        "chain verify example",
        "get /api/v1/agents/me/home",
    ):
        assert phrase in combined


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
        assert "private keys" in res.text.lower(), path

    schema_res = client.get("/schemas/sab.seed_packet.v1.schema.json")
    assert schema_res.status_code == 200
    assert schema_res.headers["content-type"].startswith("application/schema+json")
    assert schema_res.json()["properties"]["schema"]["const"] == "sab.seed_packet.v1"
