from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "sab_orient.py"


def load_module():
    spec = importlib.util.spec_from_file_location("sab_orient_tested", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent_readable_protocol_openapi(
    *,
    extra_paths: dict | None = None,
    extra_schemas: dict | None = None,
) -> dict:
    """Return the minimal exact Tier-1 contract accepted by the live signup gate."""
    paths = {
        "/auth/register": {
            "post": {
                "x-sab-onboarding-contract": {
                    "schema_version": "sab.tier1_registration.v1",
                    "default_auth_tier": 1,
                    "token_returned_once": True,
                    "strict_onboarding": True,
                },
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "anyOf": [
                                    {
                                        "type": "object",
                                        "title": "RegisterSimpleRequest",
                                        "additionalProperties": False,
                                        "required": ["name"],
                                        "properties": {
                                            "name": {
                                                "type": "string",
                                                "minLength": 3,
                                                "maxLength": 30,
                                                "pattern": "^[A-Za-z0-9-]{3,30}$",
                                            },
                                            "telos": {
                                                "type": "string",
                                                "default": "",
                                                "maxLength": 2000,
                                            },
                                        },
                                    },
                                    {"$ref": "#/components/schemas/RegisterRequest"},
                                ]
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "anyOf": [
                                        {"$ref": "#/components/schemas/RegisterSimpleResponse"},
                                        {"$ref": "#/components/schemas/RegisterResponse"},
                                    ]
                                }
                            }
                        }
                    }
                },
            }
        },
        "/posts": {"get": {}, "post": {}},
        "/witness": {"get": {}},
    }
    paths.update(extra_paths or {})
    schemas = {
        "RegisterSimpleResponse": {
            "type": "object",
            "required": ["address", "token", "message"],
            "properties": {
                "address": {"type": "string"},
                "token": {"type": "string"},
                "message": {"type": "string"},
            },
        },
        "RegisterResponse": {
            "type": "object",
            "required": ["address", "name", "telos", "reputation", "created_at"],
            "properties": {
                "address": {"type": "string"},
                "name": {"type": "string"},
                "telos": {"type": "string"},
                "reputation": {"type": "number"},
                "created_at": {"type": "string"},
            },
        },
    }
    schemas.update(extra_schemas or {})
    return {
        "info": {"title": "SAB DHARMIC_AGORA API"},
        "paths": paths,
        "components": {"schemas": schemas},
    }


def test_canonical_map_has_three_to_ten_existing_unique_semantic_roles():
    module = load_module()

    entries = module.canonical_file_map(REPO)

    assert 3 <= len(entries) <= 10
    assert len({entry["role"] for entry in entries}) == len(entries)
    assert entries[0]["path"] == "docs/SAB_AGENT_ORIENTATION.md"
    assert any(entry["path"] == "docs/ANCHOR_7_CANON.md" for entry in entries)
    assert all(entry["exists"] is True for entry in entries)
    assert all((REPO / entry["path"]).is_file() for entry in entries)
    assert all(entry["why"] and entry["read_when"] for entry in entries)


def test_json_cli_orients_agents_without_network_access():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json", "--no-live"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    packet = json.loads(result.stdout)
    assert packet["schema_version"] == "sab.orientation.v1"
    assert "queue-first" in packet["what_is_sab"].lower()
    assert "spark" in packet["concepts"]
    assert "provisional" in packet["concepts"]["spark"].lower()
    assert packet["lifecycle"] == [
        "discover",
        "register",
        "submit",
        "evaluate",
        "queue",
        "moderate",
        "witness",
        "publish_or_compost",
        "correct_or_challenge",
        "return",
    ]
    assert {"browser", "agent_http", "cli", "source"} <= set(packet["entrypoints"])
    assert 3 <= len(packet["canonical_file_map"]) <= 10
    assert packet["live"]["status"] == "not_probed"
    assert packet["recruitment"]["consent"] == "explicit_opt_in_required"
    assert packet["recruitment"]["agni"]["moltbook_display"] == "DHARMIC_AGORA_Bridge"
    assert packet["recruitment"]["agni"]["internal_identity"] == "SETU"
    assert packet["recruitment"]["agni"]["moltbook_handle"] == "DHARMIC_AGORA_Bridge"
    assert packet["recruitment"]["agni"]["public_profile_observed"] is True
    assert packet["recruitment"]["agni"]["public_profile_url"] == (
        "https://www.moltbook.com/u/DHARMIC_AGORA_Bridge"
    )
    assert packet["cli_capabilities"]["register"] == "POST /auth/register"
    assert packet["cli_capabilities"]["token"] == "POST /auth/token"
    assert packet["cli_capabilities"]["post"] == "POST /posts"
    assert packet["cli_capabilities"]["identity"] == "POST /agents/identity"
    assert "queue" in packet["lifecycles"]["protocol_operator"]
    assert "queue" not in packet["lifecycles"]["public_basin_current"]
    assert "direct_publication_state" in packet["lifecycles"]["public_basin_current"]


def test_get_json_rejects_cross_origin_redirect(monkeypatch):
    module = load_module()

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return "https://evil.example/status"

        def read(self, amount=-1):
            return b'{"status":"healthy"}'

    monkeypatch.setattr(module, "_open_url", lambda *args, **kwargs: FakeResponse())

    status, body = module._get_json("https://sab.example", "/status", 1.0)

    assert status is None
    assert body["error"] == "cross_origin_redirect"


def test_get_json_never_sends_cross_origin_redirect_target_request():
    module = load_module()

    class TargetHandler(BaseHTTPRequestHandler):
        hits = 0

        def do_GET(self):
            type(self).hits += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}')

        def log_message(self, format, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)

    class SourceHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{target.server_address[1]}/stolen",
            )
            self.end_headers()

        def log_message(self, format, *args):
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in (target, source)
    ]
    for thread in threads:
        thread.start()
    try:
        status, body = module._get_json(
            f"http://127.0.0.1:{source.server_address[1]}", "/status", 2.0
        )
    finally:
        for server in (source, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)

    assert status is None
    assert body["error"] == "cross_origin_redirect"
    assert TargetHandler.hits == 0


def test_http_error_body_is_not_copied_into_orientation_data():
    module = load_module()
    leaked = "SENSITIVE-MARKER-" + ("x" * 2_050_000)

    class ErrorHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps({"detail": leaked}).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = module._get_json(
            f"http://127.0.0.1:{server.server_address[1]}", "/missing", 2.0
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    rendered = json.dumps(body)
    assert status == 404
    assert len(rendered) < 1000
    assert "SENSITIVE-MARKER" not in rendered


def test_live_probe_fails_closed_when_openapi_is_not_sab():
    module = load_module()

    payloads = {
        "/status": {"status": "healthy", "posts": 51, "witness_entries": 54},
        "/posts": [{"id": 51}],
        "/witness": [{"id": 54, "hash": "w54"}],
        "/openapi.json": {"info": {"title": "Ginko Signal API"}, "paths": {}},
        "/api/federation/health": {"status": "operational", "registered_agents": 0},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        assert base_url == "https://sab.example"
        assert timeout == 3.0
        return 200, payloads[path]

    live = module.probe_live_surface("https://sab.example", get_json=fake_get, timeout=3.0)

    assert live["status"] == "surface_mismatch"
    assert live["http_healthy"] is True
    assert live["openapi_title"] == "Ginko Signal API"
    assert live["canonical_sab_routes"] is False
    assert live["signup_ready"] is False
    assert live["agent_entry_ready"] is False
    assert "not canonical sab" in live["blocker"].lower()


def test_route_only_registration_contract_never_enables_signup():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy", "posts": 9, "witness_entries": 11},
        "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [
            {"id": 11, "hash": "a" * 64, "timestamp": "2026-07-26T00:01:00Z"}
        ],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": {}},
                "/posts": {"get": {}, "post": {}},
                "/witness": {"get": {}},
            },
        },
        "/api/federation/health": {"status": "operational", "registered_agents": 0},
    }
    browser_probes: list[str] = []

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    def fake_browser_probe(base_url: str, path: str, timeout: float):
        browser_probes.append(path)
        return 200, "text/html", "SAB Swagger UI"

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=fake_browser_probe,
        now=datetime(2026, 7, 26, 0, 2, tzinfo=timezone.utc),
    )

    assert live["canonical_sab_routes"] is True
    assert live["registration_contract_ready"] is False
    assert live["registration_contract_version"] is None
    assert live["agent_entry_surface"] is None
    assert live["signup_ready"] is False
    assert live["recruitment_ready"] is False
    assert live["status"] == "registration_contract_invalid"
    assert browser_probes == []
    assert module.onboarding_links(live, instance_verified=True)["registration_url"] is None


def test_invalid_protocol_contract_cannot_capture_valid_basin_entry():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy", "posts": 9, "witness_entries": 11},
        "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [
            {"id": 11, "hash": "a" * 64, "timestamp": "2026-07-26T00:01:00Z"}
        ],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": {}},
                "/posts": {"get": {}, "post": {}},
                "/witness": {"get": {}},
                "/api/agents/register": {"post": {}},
                "/api/spark/submit": {"post": {}},
            },
        },
        "/api/federation/health": {"status": "operational", "registered_agents": 0},
    }
    browser_probes: list[str] = []

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    def fake_browser_probe(base_url: str, path: str, timeout: float):
        browser_probes.append(path)
        return 200, "text/html", "SAB public basin"

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=fake_browser_probe,
        now=datetime(2026, 7, 26, 0, 2, tzinfo=timezone.utc),
    )
    links = module.onboarding_links(live, instance_verified=True)

    assert live["protocol_surface_ready"] is True
    assert live["public_basin_ready"] is True
    assert live["registration_contract_ready"] is False
    assert live["agent_entry_surface"] == "public_basin"
    assert live["signup_ready"] is True
    assert live["recruitment_ready"] is True
    assert browser_probes == ["/"]
    assert links["browser_url"] == "https://sab.example/"
    assert links["registration_url"] == "https://sab.example/api/agents/register"


def test_openapi_token_return_metadata_is_public_only_as_a_boolean():
    module = load_module()
    openapi = agent_readable_protocol_openapi()

    assert (
        module._contains_sensitive_public_key(
            openapi,
            symbolic_key_maps=module.OPENAPI_SYMBOLIC_KEY_MAPS,
        )
        is False
    )

    contract = openapi["paths"]["/auth/register"]["post"]["x-sab-onboarding-contract"]
    contract["token_returned_once"] = "TOKEN-MARKER"

    assert (
        module._contains_sensitive_public_key(
            openapi,
            symbolic_key_maps=module.OPENAPI_SYMBOLIC_KEY_MAPS,
        )
        is True
    )


def test_deceptive_title_wrong_methods_and_down_status_never_become_ready():
    module = load_module()
    payloads = {
        "/status": {"status": "down", "posts": 1, "witness_entries": 1},
        "/posts": [{"id": 1}],
        "/witness": [{"id": 1, "hash": "w1"}],
        "/openapi.json": {
            "info": {"title": "UNSABLE Generic API"},
            "paths": {
                "/auth/register": {"get": {}},
                "/posts": {"delete": {}},
                "/witness": {"patch": {}},
            },
        },
        "/api/federation/health": {"status": "operational"},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface("https://sab.example", get_json=fake_get)

    assert live["canonical_sab_routes"] is False
    assert live["preflight"]["passed"] is False
    assert live["recruitment_ready"] is False
    assert module.onboarding_links(live, instance_verified=True)["qr_payload"] is None


def test_malformed_or_empty_heads_fail_preflight():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy"},
        "/posts": {"items": []},
        "/witness": [],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": {}},
                "/posts": {"get": {}, "post": {}},
                "/witness": {"get": {}},
            },
        },
        "/api/federation/health": {"status": "operational"},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface("https://sab.example", get_json=fake_get)

    assert live["preflight"]["passed"] is False
    assert live["recruitment_ready"] is False


def test_canonical_sab_on_ip_is_not_recruitment_ready():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy", "posts": 1, "witness_entries": 2},
        "/posts": [{"id": 1}],
        "/witness": [{"id": 2, "hash": "w2"}],
        "/openapi.json": agent_readable_protocol_openapi(),
        "/api/federation/health": {"status": "operational", "registered_agents": 0},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface("https://157.245.193.15", get_json=fake_get)

    assert live["canonical_sab_routes"] is True
    assert live["signup_ready"] is True
    assert live["persistent_url_ready"] is False
    assert live["recruitment_ready"] is False
    assert live["status"] == "persistent_url_missing"


def test_live_probe_captures_current_posts_and_witness_preflight():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy", "posts": 9, "witness_entries": 11},
        "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [{"id": 11, "hash": "a" * 64, "timestamp": "2026-07-26T00:01:00Z"}],
        "/openapi.json": agent_readable_protocol_openapi(),
        "/api/federation/health": {"status": "operational", "registered_agents": 0},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, "text/html", "SAB Swagger UI"),
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )

    assert live["preflight"]["passed"] is True
    assert live["preflight"]["latest_post_id"] == 9
    assert live["preflight"]["latest_witness_id"] == 11
    assert live["preflight"]["latest_witness_hash"] == "a" * 64
    assert live["registration_contract_ready"] is True
    assert live["registration_contract_version"] == "sab.tier1_registration.v1"
    assert live["agent_entry_surface"] == "protocol"
    assert live["recruitment_ready"] is True


def test_hardened_federation_401_is_acceptable_only_when_openapi_declares_header():
    module = load_module()

    def probe(*, header_parameter):
        payloads = {
            "/status": {"status": "healthy"},
            "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
            "/witness": [
                {"id": 11, "hash": "a" * 64, "timestamp": "2026-07-26T00:01:00Z"}
            ],
            "/openapi.json": agent_readable_protocol_openapi(
                extra_paths={
                    "/api/federation/health": {
                        "get": {"parameters": [header_parameter] if header_parameter else []}
                    }
                }
            ),
            "/api/federation/health": {"error": "HTTPError"},
        }

        def fake_get(base_url: str, path: str, timeout: float):
            if path == "/api/federation/health":
                return 401, payloads[path]
            return 200, payloads[path]

        return module.probe_live_surface(
            "https://sab.example",
            get_json=fake_get,
            probe_url=lambda base, path, timeout: (200, "text/html", "SAB Swagger UI"),
            now=datetime(2026, 7, 26, tzinfo=timezone.utc),
        )

    declared = probe(
        header_parameter={
            "name": "X-SAB-Federation-Secret",
            "in": "header",
            "required": False,
            "schema": {"type": "string"},
        }
    )
    undeclared = probe(header_parameter=None)
    wrong_header = probe(
        header_parameter={
            "name": "Authorization",
            "in": "header",
            "required": False,
            "schema": {"type": "string"},
        }
    )

    assert declared["preflight"]["federation_semantically_healthy"] is False
    assert declared["preflight"]["federation_auth_header_declared"] is True
    assert declared["preflight"]["federation_auth_protected"] is True
    assert declared["preflight"]["federation_probe_acceptable"] is True
    assert declared["preflight"]["federation_probe_mode"] == "auth_protected"
    assert declared["preflight"]["passed"] is True
    assert declared["federation_probe_mode"] == "auth_protected"
    assert declared["recruitment_ready"] is True
    for rejected in (undeclared, wrong_header):
        assert rejected["preflight"]["federation_auth_protected"] is False
        assert rejected["preflight"]["federation_probe_acceptable"] is False
        assert rejected["preflight"]["federation_probe_mode"] == "invalid"
        assert rejected["preflight"]["passed"] is False
        assert rejected["recruitment_ready"] is False


def test_browser_entry_must_resolve_before_recruitment_is_ready():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy"},
        "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [{"id": 11, "hash": "a" * 64, "timestamp": "2026-07-26T00:01:00Z"}],
        "/openapi.json": agent_readable_protocol_openapi(),
        "/api/federation/health": {"status": "operational"},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, "text/html", "Generic portal"),
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )

    assert live["browser_entry_ready"] is False
    assert live["recruitment_ready"] is False
    assert live["status"] == "browser_entry_failed"


def test_stale_heads_never_become_recruitment_ready():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy"},
        "/posts": [{"id": 9, "created_at": "2010-01-01T00:00:00Z"}],
        "/witness": [
            {
                "id": 11,
                "hash": "a" * 64,
                "timestamp": "2010-01-01T00:00:00Z",
            }
        ],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": {}},
                "/posts": {"get": {}, "post": {}},
                "/witness": {"get": {}},
            },
        },
        "/api/federation/health": {"status": "operational"},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, "text/html", "SAB"),
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )

    assert live["preflight"]["passed"] is False
    assert live["preflight"]["heads_fresh"] is False
    assert live["recruitment_ready"] is False
    assert module.live_exit_code({"instance": {"verified": True}, "live": live}) != 0


def test_noncanonical_timestamp_forms_and_uppercase_hash_fail_closed():
    module = load_module()
    invalid_timestamps = (
        "2026-07-26 00:00:00+00:00",
        "2026-W30-7T00:00:00+00:00",
        "2026-07-26T00:00+00:00",
    )

    def probe(post_timestamp: str, witness_timestamp: str, witness_hash: str):
        payloads = {
            "/status": {"status": "healthy"},
            "/posts": [{"id": 9, "created_at": post_timestamp}],
            "/witness": [{"id": 11, "hash": witness_hash, "timestamp": witness_timestamp}],
            "/openapi.json": {
                "info": {"title": "SAB DHARMIC_AGORA API"},
                "paths": {
                    "/auth/register": {"post": {}},
                    "/posts": {"get": {}, "post": {}},
                    "/witness": {"get": {}},
                },
            },
            "/api/federation/health": {"status": "operational"},
        }

        def fake_get(base_url: str, path: str, timeout: float):
            return 200, payloads[path]

        return module.probe_live_surface(
            "https://sab.example",
            get_json=fake_get,
            probe_url=lambda base, path, timeout: (200, "text/html", "SAB"),
            now=datetime(2026, 7, 26, tzinfo=timezone.utc),
        )

    for invalid in invalid_timestamps:
        live = probe(invalid, invalid, "a" * 64)
        assert live["preflight"]["passed"] is False
        assert live["recruitment_ready"] is False

    uppercase_hash = probe(
        "2026-07-26T00:00:00Z",
        "2026-07-26T00:00:01Z",
        "A" * 64,
    )
    assert uppercase_hash["preflight"]["witness_head_valid"] is False
    assert uppercase_hash["recruitment_ready"] is False


def test_type_invalid_heads_and_null_openapi_operations_fail_closed():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy"},
        "/posts": [{"id": True, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [{"id": True, "hash": "a", "timestamp": None}],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": None},
                "/posts": {"get": None, "post": None},
                "/witness": {"get": None},
            },
        },
        "/api/federation/health": {"status": "operational"},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface("https://sab.example", get_json=fake_get)

    assert live["canonical_sab_routes"] is False
    assert live["preflight"]["passed"] is False
    assert live["recruitment_ready"] is False
    assert module.onboarding_links(live, instance_verified=True)["registration_url"] is None


def test_openapi_route_and_schema_names_do_not_self_block_canonical_preflight():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy", "posts": 9, "witness_entries": 11},
        "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [
            {
                "id": 11,
                "hash": "a" * 64,
                "timestamp": "2026-07-26T00:01:00Z",
            }
        ],
        "/openapi.json": agent_readable_protocol_openapi(
            extra_paths={
                "/auth/token": {"post": {}},
                "/auth/apikey": {"post": {}},
            },
            extra_schemas={
                "VerifyResponse": {
                    "type": "object",
                    "properties": {"token": {"type": "string"}},
                }
            },
        ),
        "/api/federation/health": {"status": "operational", "registered_agents": 0},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, "text/html", "SAB Swagger UI"),
        now=datetime(2026, 7, 26, 0, 2, tzinfo=timezone.utc),
    )

    assert live["canonical_sab_routes"] is True
    assert live["preflight"]["public_payloads_safe"] is True
    assert live["preflight"]["passed"] is True
    assert live["recruitment_ready"] is True

    payloads["/openapi.json"]["info"]["api_key"] = "leaked-api-key"
    hostile = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, "text/html", "SAB Swagger UI"),
        now=datetime(2026, 7, 26, 0, 2, tzinfo=timezone.utc),
    )
    assert hostile["preflight"]["public_payloads_safe"] is False
    assert hostile["preflight"]["passed"] is False
    assert "leaked-api-key" not in json.dumps(hostile)


def test_sensitive_public_payload_keys_block_readiness_and_are_redacted():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy", "token": "leaked-token"},
        "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [{"id": 11, "hash": "a" * 64, "timestamp": "2026-07-26T00:01:00Z"}],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": {}},
                "/posts": {"get": {}, "post": {}},
                "/witness": {"get": {}},
            },
        },
        "/api/federation/health": {
            "status": "operational",
            "api_key": "leaked-api-key",
        },
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, "text/html", "SAB"),
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )

    rendered = json.dumps(live)
    assert live["preflight"]["public_payloads_safe"] is False
    assert live["preflight"]["passed"] is False
    assert live["recruitment_ready"] is False
    assert "leaked-token" not in rendered
    assert "leaked-api-key" not in rendered


def test_camelcase_and_malformed_public_fields_never_leak_or_certify():
    module = load_module()
    payloads = {
        "/status": {
            "status": "healthy",
            "version": "VERSION-MARKER",
            "nested": {"privateKey": "PRIVATE-MARKER"},
        },
        "/posts": [
            {
                "id": {"secret": "POST-MARKER"},
                "created_at": "2026-07-26T00:00:00Z",
            }
        ],
        "/witness": [
            {
                "id": 11,
                "hash": {"token": "WITNESS-MARKER"},
                "timestamp": "2026-07-26T00:01:00Z",
            }
        ],
        "/openapi.json": {
            "info": {"title": {"apiKey": "TITLE-MARKER"}},
            "paths": {},
        },
        "/api/federation/health": {
            "status": "operational",
            "registered_agents": "COUNTER-MARKER",
        },
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )

    rendered = json.dumps(live)
    assert live["preflight"]["public_payloads_safe"] is False
    assert live["preflight"]["public_payload_types_valid"] is False
    assert live["preflight"]["passed"] is False
    assert live["recruitment_ready"] is False
    for marker in (
        "PRIVATE-MARKER",
        "VERSION-MARKER",
        "POST-MARKER",
        "WITNESS-MARKER",
        "TITLE-MARKER",
        "COUNTER-MARKER",
    ):
        assert marker not in rendered


def test_oversize_valid_shaped_fields_fail_and_never_reach_receipts(tmp_path):
    module = load_module()
    long_version = "1.2.3+" + ("A" * 5_000) + "VERSION-MARKER"
    long_timestamp = "2026-07-26T00:00:00." + ("1" * 5_000) + "Z"
    huge_integer = 10**100
    payloads = {
        "/status": {"status": "healthy", "version": long_version},
        "/posts": [{"id": huge_integer, "created_at": long_timestamp}],
        "/witness": [
            {
                "id": huge_integer,
                "hash": "a" * 64,
                "timestamp": long_timestamp,
            }
        ],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": {}},
                "/posts": {"get": {}, "post": {}},
                "/witness": {"get": {}},
            },
        },
        "/api/federation/health": {
            "status": "operational",
            "registered_agents": huge_integer,
        },
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, "text/html", "SAB"),
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )

    packet = {"artifact": module._artifact_identity(REPO), "live": live}
    receipt = tmp_path / "bounded-receipt.json"
    module.write_orientation_receipt(packet, receipt)
    rendered = json.dumps(packet)
    persisted = receipt.read_text()

    assert live["preflight"]["public_payload_types_valid"] is False
    assert live["preflight"]["posts_head_valid"] is False
    assert live["preflight"]["witness_head_valid"] is False
    assert live["preflight"]["passed"] is False
    assert live["recruitment_ready"] is False
    assert live["preflight"]["latest_post_id"] is None
    assert live["preflight"]["latest_post_timestamp"] is None
    assert live["preflight"]["latest_witness_id"] is None
    assert live["preflight"]["latest_witness_timestamp"] is None
    for hostile in (long_version, long_timestamp, str(huge_integer)):
        assert hostile not in rendered
        assert hostile not in persisted


def test_semver_url_controls_and_browser_content_type_are_bounded():
    module = load_module()
    assert module._typed_scalar("0.3.1", "version") is True
    assert module._typed_scalar("1.2.3-alpha.1+build.7", "version") is True
    for invalid_version in (
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3-...",
        "1.2.3-.",
        "1.2.3+.",
        "1.2.3-alpha..1",
    ):
        assert module._typed_scalar(invalid_version, "version") is False

    for invalid_url in (
        " https://sab.example",
        "https://sab.example ",
        "https://sab.example\n",
        "https://sab.example\t",
        "https://sab.example\x1b",
        "https://sáb.example",
    ):
        assert module._normalized_endpoint_url(invalid_url) is None

    payloads = {
        "/status": {"status": "healthy", "version": "0.3.1"},
        "/posts": [{"id": 9, "created_at": "2026-07-26T00:00:00Z"}],
        "/witness": [
            {
                "id": 11,
                "hash": "a" * 64,
                "timestamp": "2026-07-26T00:01:00Z",
            }
        ],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": {
                "/auth/register": {"post": {}},
                "/posts": {"get": {}, "post": {}},
                "/witness": {"get": {}},
            },
        },
        "/api/federation/health": {"status": "operational"},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    hostile_content_type = "text/html" + ("X" * 5_000) + "CONTENT-TYPE-MARKER"
    live = module.probe_live_surface(
        "https://sab.example",
        get_json=fake_get,
        probe_url=lambda base, path, timeout: (200, hostile_content_type, "SAB"),
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )
    assert live["browser_entry_ready"] is False
    assert live["recruitment_ready"] is False
    assert live["browser_content_type"] == ""
    assert "CONTENT-TYPE-MARKER" not in json.dumps(live)


def test_malformed_openapi_paths_returns_diagnostic_instead_of_traceback():
    module = load_module()
    payloads = {
        "/status": {"status": "healthy"},
        "/posts": [],
        "/witness": [],
        "/openapi.json": {
            "info": {"title": "SAB DHARMIC_AGORA API"},
            "paths": [],
        },
        "/api/federation/health": {"status": "operational"},
    }

    def fake_get(base_url: str, path: str, timeout: float):
        return 200, payloads[path]

    live = module.probe_live_surface("https://sab.example", get_json=fake_get)

    assert live["status"] == "surface_mismatch"
    assert live["canonical_sab_routes"] is False
    assert live["recruitment_ready"] is False


def test_malformed_manifest_root_still_emits_source_orientation(tmp_path):
    manifest = tmp_path / "CANONICAL_SAB_INSTANCE.json"
    manifest.write_text("[]")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--json",
            "--no-live",
            "--instance-manifest",
            str(manifest),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Traceback" not in result.stderr
    packet = json.loads(result.stdout)
    assert packet["instance"]["verified"] is False
    assert "invalid_root" in packet["instance"]["problems"]
    assert len(packet["canonical_file_map"]) == 8


def test_manifest_urls_reject_userinfo_and_wrong_types_without_disclosure(tmp_path):
    cases = (
        (123, "TYPE-MARKER"),
        ("https://agent:URL-PASSWORD-MARKER@sab.example", "URL-PASSWORD-MARKER"),
        ("https://sab.example/?token=QUERY-MARKER", "QUERY-MARKER"),
    )
    for index, (canonical_url, marker) in enumerate(cases):
        manifest = tmp_path / f"manifest-{index}.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": "dharma.sab.instance_manifest.v1",
                    "instance_id": "sab_agni_prod_157_245_193_15",
                    "canonical_url": canonical_url,
                    "required_preflight": [
                        "GET /status",
                        "GET /posts",
                        "GET /witness",
                    ],
                }
            )
        )

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--json",
                "--no-live",
                "--instance-manifest",
                str(manifest),
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0
        assert "Traceback" not in result.stderr
        assert marker not in result.stdout
        packet = json.loads(result.stdout)
        assert packet["instance"]["verified"] is False
        assert packet["instance"]["canonical_url"] is None
        assert "canonical_url" in packet["instance"]["problems"]


def test_falsey_declared_urls_never_fall_back_to_a_network_probe(tmp_path, monkeypatch):
    module = load_module()
    calls = []

    def forbidden_probe(base_url: str):
        calls.append(base_url)
        raise AssertionError("invalid declared URL triggered a live probe")

    monkeypatch.setattr(module, "probe_live_surface", forbidden_probe)
    for index, canonical_url in enumerate((False, 0, [], {}, "", None)):
        manifest = tmp_path / f"falsey-{index}.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": "dharma.sab.instance_manifest.v1",
                    "instance_id": "sab_agni_prod_157_245_193_15",
                    "canonical_url": canonical_url,
                    "required_preflight": [
                        "GET /status",
                        "GET /posts",
                        "GET /witness",
                    ],
                }
            )
        )

        packet = module.build_packet(
            REPO,
            probe_live=True,
            instance_manifest_path=manifest,
        )

        assert packet["live"]["status"] == "invalid_public_url"
        assert packet["live"]["base_url"] is None
        assert packet["live"]["recruitment_ready"] is False
        assert packet["instance"]["verified"] is False
        assert packet["instance"]["canonical_url"] is None

    valid_manifest = tmp_path / "valid.json"
    valid_manifest.write_text(
        json.dumps(
            {
                "schema_version": "dharma.sab.instance_manifest.v1",
                "instance_id": "sab_agni_prod_157_245_193_15",
                "canonical_url": "https://sab.example",
                "required_preflight": ["GET /status", "GET /posts", "GET /witness"],
            }
        )
    )
    cli_packet = module.build_packet(
        REPO,
        probe_live=True,
        public_url="",
        instance_manifest_path=valid_manifest,
    )
    assert cli_packet["live"]["status"] == "invalid_public_url"

    monkeypatch.setenv("SAB_PUBLIC_URL", "")
    env_packet = module.build_packet(
        REPO,
        probe_live=True,
        instance_manifest_path=valid_manifest,
    )
    assert env_packet["live"]["status"] == "invalid_public_url"

    assert calls == []


def test_instance_manifest_binds_exact_instance_and_url(tmp_path):
    module = load_module()
    manifest = tmp_path / "CANONICAL_SAB_INSTANCE.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "dharma.sab.instance_manifest.v1",
                "instance_id": "sab_agni_prod_157_245_193_15",
                "canonical_url": "https://sab.example/",
                "required_preflight": ["GET /status", "GET /posts", "GET /witness"],
            }
        )
    )

    bound = module.load_instance_manifest(manifest, public_url="https://sab.example")
    mismatch = module.load_instance_manifest(manifest, public_url="https://other.example")

    assert bound["verified"] is True
    assert bound["instance_id"] == "sab_agni_prod_157_245_193_15"
    assert bound["manifest_sha256"]
    assert mismatch["verified"] is False
    assert "url" in mismatch["problems"]


def test_strict_readiness_requires_private_durable_receipt(tmp_path):
    module = load_module()
    packet = module.build_packet(REPO, probe_live=False)
    packet["instance"] = {"verified": True}
    packet["live"] = {
        "status": "ready",
        "recruitment_ready": True,
        "preflight": {"passed": True},
    }
    receipt = tmp_path / "orient-receipt.json"

    assert module.strict_exit_code(packet, receipt_written=False) != 0
    written = module.write_orientation_receipt(packet, receipt)

    assert written == receipt
    assert receipt.stat().st_mode & 0o777 == 0o600
    data = json.loads(receipt.read_text())
    assert data["schema_version"] == "sab.orientation.receipt.v1"
    assert data["packet_sha256"]
    assert data["artifact"] == packet["artifact"]
    assert re.fullmatch(r"[0-9a-f]{40,64}", data["artifact"]["commit_sha"])
    assert re.fullmatch(r"[0-9a-f]{40,64}", data["artifact"]["tree_sha"])
    assert re.fullmatch(r"[0-9a-f]{64}", data["artifact"]["script_sha256"])
    assert module.strict_exit_code(packet, receipt_written=True) == 0


def test_receipt_writer_rejects_target_and_temp_symlinks(tmp_path):
    module = load_module()
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-touch")

    target_link = tmp_path / "target-receipt.json"
    target_link.symlink_to(victim)
    try:
        module.write_orientation_receipt({}, target_link)
        raise AssertionError("target symlink was accepted")
    except ValueError:
        pass
    assert victim.read_text() == "do-not-touch"

    receipt = tmp_path / "receipt.json"
    temp_link = tmp_path / f".{receipt.name}.{os.getpid()}.tmp"
    temp_link.symlink_to(victim)
    try:
        module.write_orientation_receipt({}, receipt)
        raise AssertionError("temporary symlink was accepted")
    except OSError:
        pass
    assert victim.read_text() == "do-not-touch"
    assert not receipt.exists()
    assert temp_link.is_symlink()


def test_cli_receipt_write_failure_still_emits_diagnostic_packet(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-touch")
    receipt_link = tmp_path / "receipt.json"
    receipt_link.symlink_to(victim)

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--json",
            "--no-live",
            "--write-receipt",
            str(receipt_link),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 15
    assert "Traceback" not in result.stderr
    packet = json.loads(result.stdout)
    assert packet["receipt_write"] == {"written": False, "error": "ValueError"}
    assert victim.read_text() == "do-not-touch"


def test_onboarding_links_exist_only_when_recruitment_is_ready():
    module = load_module()
    ready = module.onboarding_links(
        {
            "base_url": "https://sab.example",
            "recruitment_ready": True,
            "protocol_surface_ready": True,
            "public_basin_ready": False,
            "agent_entry_surface": "protocol",
        },
        instance_verified=True,
    )
    blocked = module.onboarding_links(
        {"base_url": "https://157.245.193.15", "recruitment_ready": False},
        instance_verified=True,
    )
    wrong_instance = module.onboarding_links(
        {
            "base_url": "https://sab.example",
            "recruitment_ready": True,
            "protocol_surface_ready": True,
        },
        instance_verified=False,
    )

    assert ready["browser_url"] == "https://sab.example/docs"
    assert ready["registration_url"] == "https://sab.example/auth/register"
    assert ready["qr_payload"] == "https://sab.example/docs"
    assert blocked["qr_payload"] is None
    assert blocked["registration_url"] is None
    assert wrong_instance["qr_payload"] is None
    assert wrong_instance["registration_url"] is None


def test_human_render_contains_dense_orientation_sections_and_all_files():
    module = load_module()
    packet = module.build_packet(REPO, probe_live=False)

    rendered = module.render_human(packet)

    for heading in (
        "WHAT SAB IS",
        "SPARK AND CORE TERMS",
        "LIFECYCLE",
        "HOW AN AGENT ENTERS",
        "CANONICAL FILE MAP",
        "LIVE TRUTH",
    ):
        assert heading in rendered
    for entry in packet["canonical_file_map"]:
        assert entry["path"] in rendered
    assert "queue admission is not publication" in rendered.lower()


def test_start_here_doc_answers_agent_orientation_questions():
    doc = REPO / "docs" / "SAB_AGENT_ORIENTATION.md"
    text = doc.read_text()

    for phrase in (
        "What SAB Is",
        "What a Spark Is",
        "Canonical Anchor 7",
        "Mechanical Structure",
        "Browser Entry",
        "Agent HTTP Entry",
        "CLI Entry",
        "Live Truth and Persistent URL Gate",
        "Recruitment and Consent",
        "make sab-orient",
        "connectors/sabp_client.py",
        "queue admission is not publication",
    ):
        assert phrase.lower() in text.lower()


def test_orientation_is_anchor_gated_before_recruitment_fitness():
    module = load_module()
    packet = module.build_packet(REPO, probe_live=False)

    assert packet["canonical_anchors"] == [
        "Pure Mathematics and Formal Methods",
        "Physics and Information",
        "Machine Learning and Intelligence Engineering",
        "Complex Systems and Cybernetics",
        "Ecology, Climate, and Earth Systems",
        "Economics and Mechanism Design",
        "Dharmic/Jain Epistemics and Ethics",
    ]
    assert packet["fitness"][0] == "align_with_at_least_one_canonical_anchor"
    assert packet["fitness"][1:] == [
        "proposal",
        "experiment",
        "artifact",
        "witness",
        "sublation",
        "return",
    ]
    rendered = module.render_human(packet)
    assert rendered.index("CANONICAL ANCHORS") < rendered.index("LIFECYCLE")


def test_make_targets_invoke_the_same_read_only_orientation():
    direct = subprocess.run(
        ["make", "sab-orient", "ARGS=--json --no-live"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    alias = subprocess.run(
        ["make", "orient", "ARGS=--json --no-live"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )

    assert direct.returncode == 0, direct.stderr
    assert alias.returncode == 0, alias.stderr
    packet = json.loads(direct.stdout)
    assert packet == json.loads(alias.stdout)
    assert packet["schema_version"] == "sab.orientation.v1"
    assert re.fullmatch(r"[0-9a-f]{40,64}", packet["artifact"]["commit_sha"])
    assert re.fullmatch(r"[0-9a-f]{40,64}", packet["artifact"]["tree_sha"])
    assert re.fullmatch(r"[0-9a-f]{64}", packet["artifact"]["script_sha256"])
    assert packet["live"]["status"] == "not_probed"


def test_default_live_command_fails_when_surface_is_unreachable_or_unbound():
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--json",
            "--public-url",
            "https://127.0.0.1:1",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    packet = json.loads(result.stdout)
    assert packet["live"]["recruitment_ready"] is False
    assert packet["instance"]["verified"] is False


def test_strict_make_target_is_explicitly_receipt_writing():
    dry_run = subprocess.run(
        ["make", "-n", "sab-orient-strict"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )

    assert dry_run.returncode == 0, dry_run.stderr
    assert "--strict-live" in dry_run.stdout
    assert "--write-receipt" in dry_run.stdout
