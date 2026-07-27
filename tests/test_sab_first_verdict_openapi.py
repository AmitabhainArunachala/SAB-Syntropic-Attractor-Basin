from __future__ import annotations

from fastapi.testclient import TestClient

import agora.sab_first_verdict_api as api_module
from agora.sab_artifact_verdict import FROZEN_MAINTENANCE_OPERATIONS


def _schema_operations(schema: dict[str, object]) -> set[tuple[str, str]]:
    paths = schema["paths"]
    assert isinstance(paths, dict)
    return {
        (method.upper(), path)
        for path, path_item in paths.items()
        if isinstance(path_item, dict)
        for method in path_item
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }


def test_dedicated_openapi_is_callable_but_not_served(
    monkeypatch,
) -> None:
    monkeypatch.setattr(api_module, "_validate_runtime_binding", lambda *_: None)
    monkeypatch.setattr(api_module, "_bind_copy_file_identity", lambda *_: (0, 0))
    app = api_module.create_sab_first_verdict_app(object(), object())  # type: ignore[arg-type]
    schema = app.openapi()
    assert _schema_operations(schema) == set(FROZEN_MAINTENANCE_OPERATIONS)
    assert len(schema["paths"]) == 14

    client = TestClient(app)
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_openapi_excludes_every_legacy_or_effect_activation_surface(
    monkeypatch,
) -> None:
    monkeypatch.setattr(api_module, "_validate_runtime_binding", lambda *_: None)
    monkeypatch.setattr(api_module, "_bind_copy_file_identity", lambda *_: (0, 0))
    schema = api_module.create_sab_first_verdict_app(object(), object()).openapi()  # type: ignore[arg-type]
    paths = set(schema["paths"])
    forbidden = {
        "/api/witness/sign",
        "/api/v1/seeds",
        "/api/v1/sparks",
        "/api/v1/artifact-verdicts/{verdict_id}/activate",
        "/api/v1/artifact-verdicts/{verdict_id}/apply",
        "/api/v1/effective-verdicts/{effective_verdict_id}",
        "/api/v1/compost-batches/apply",
        "/api/v1/compost-batches/activate",
        "/api/v1/seeds/{seed_id}/sublate",
        "/api/v1/lineage/activate",
    }
    assert paths.isdisjoint(forbidden)
    assert all("private_key" not in str(item) for item in schema["components"].values())
    request_bodies = [
        operation.get("requestBody", {})
        for path_item in schema["paths"].values()
        for operation in path_item.values()
        if isinstance(operation, dict)
    ]
    assert "FixtureExecutionContext" not in str(request_bodies)
    assert '"fixture_context"' not in str(request_bodies)


def test_openapi_responses_are_closed_and_methods_do_not_redirect(
    monkeypatch,
) -> None:
    monkeypatch.setattr(api_module, "_validate_runtime_binding", lambda *_: None)
    monkeypatch.setattr(api_module, "_bind_copy_file_identity", lambda *_: (0, 0))
    app = api_module.create_sab_first_verdict_app(object(), object())  # type: ignore[arg-type]
    schema = app.openapi()
    component_schemas = schema["components"]["schemas"]

    for name, model_schema in component_schemas.items():
        if name.endswith("ResponseV1") or name == "ErrorEnvelopeV1":
            assert model_schema.get("additionalProperties") is False, name
    for path_item in schema["paths"].values():
        for method, operation in path_item.items():
            if method not in {"get", "post"}:
                continue
            success = next(
                response
                for code, response in operation["responses"].items()
                if code.startswith("2")
            )
            success_schema = success["content"]["application/json"]["schema"]
            assert "$ref" in success_schema
            assert success_schema["$ref"].startswith("#/components/schemas/")
            for code in ("403", "404", "409", "422"):
                error_schema = operation["responses"][code]["content"][
                    "application/json"
                ]["schema"]
                assert error_schema == {"$ref": "#/components/schemas/ErrorEnvelopeV1"}

    client = TestClient(app, follow_redirects=False)
    assert client.get("/health/").status_code == 404
    assert client.post("/api/v1/artifact-cases/").status_code == 404
    for method in ("head", "options", "put", "patch", "delete"):
        assert client.request(method, "/health").status_code == 405


def test_all_six_lease_guarded_writes_require_the_header_in_openapi(
    monkeypatch,
) -> None:
    monkeypatch.setattr(api_module, "_validate_runtime_binding", lambda *_: None)
    monkeypatch.setattr(api_module, "_bind_copy_file_identity", lambda *_: (0, 0))
    schema = api_module.create_sab_first_verdict_app(object(), object()).openapi()  # type: ignore[arg-type]
    guarded = {
        "/api/v1/session-write-leases/{lease_id}/release",
        "/api/v1/artifact-cases",
        "/api/v1/artifact-cases/{case_id}/ballots",
        "/api/v1/artifact-cases/{case_id}/authority-evaluations",
        "/api/v1/artifact-cases/{case_id}/verdicts",
        "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
    }

    observed = set()
    for path, path_item in schema["paths"].items():
        operation = path_item.get("post", {})
        header_parameters = [
            parameter
            for parameter in operation.get("parameters", [])
            if parameter.get("in") == "header"
            and parameter.get("name") == api_module.WRITE_LEASE_HEADER
        ]
        if path in guarded:
            assert header_parameters == [
                {
                    "name": api_module.WRITE_LEASE_HEADER,
                    "in": "header",
                    "required": True,
                    "schema": {"type": "string", "title": "X-Sab-Write-Lease"},
                }
            ]
            observed.add(path)
        else:
            assert header_parameters == []
    assert observed == guarded


def test_authority_policy_wire_union_is_schema_discriminated_and_closed(
    monkeypatch,
) -> None:
    monkeypatch.setattr(api_module, "_validate_runtime_binding", lambda *_: None)
    monkeypatch.setattr(api_module, "_bind_copy_file_identity", lambda *_: (0, 0))
    schema = api_module.create_sab_first_verdict_app(object(), object()).openapi()  # type: ignore[arg-type]
    components = schema["components"]["schemas"]
    for name in (
        "SignedDispositionPolicyWireV1",
        "MasterVisionPolicyEvidenceWireV1",
    ):
        assert components[name]["additionalProperties"] is False

    authority_request = components["AuthorityEvaluationRequestV1"]
    signed_policy = authority_request["properties"]["signed_policy"]
    discriminated = next(item for item in signed_policy["anyOf"] if "oneOf" in item)
    assert discriminated["discriminator"] == {
        "propertyName": "schema",
        "mapping": {
            "sab.master_vision_policy_evidence.v1": (
                "#/components/schemas/MasterVisionPolicyEvidenceWireV1"
            ),
            "sab.signed_disposition_policy.v1": (
                "#/components/schemas/SignedDispositionPolicyWireV1"
            ),
        },
    }
