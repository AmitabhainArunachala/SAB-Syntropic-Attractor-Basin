#!/usr/bin/env python3
"""Fail closed when a URL is not the canonical, source-bound SAB deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


EXPECTED_OPENAPI_TITLE = "SAB DHARMIC_AGORA API"
MAX_JSON_BYTES = 2_000_000
REQUIRED_OPERATIONS: dict[str, set[str]] = {
    "/auth/register": {"post"},
    "/posts": {"get", "post"},
    "/admin/queue": {"get"},
    "/witness": {"get"},
    "/posts/{post_id}/comment": {"post"},
    "/comments/{comment_id}/accept-correction": {"post"},
    "/admin/appeal/{queue_id}": {"post"},
}
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REGISTRATION_CONTRACT_VERSION = "sab.tier1_registration.v1"
TIER1_NAME_PATTERN = "^[A-Za-z0-9-]{3,30}$"


def _exact_int(value: Any, expected: int) -> bool:
    """Reject booleans and integer-like values in untrusted OpenAPI fields."""
    return type(value) is int and value == expected


def _exact_string_set(value: Any, expected: set[str]) -> bool:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return False
    return len(value) == len(expected) and set(value) == expected


def _registration_contract_is_agent_readable(
    operation: Mapping[str, Any], openapi_payload: Mapping[str, Any]
) -> bool:
    """Fail closed unless OpenAPI fully describes the default Tier-1 exchange."""
    contract_value = operation.get("x-sab-onboarding-contract")
    if not isinstance(contract_value, Mapping):
        return False
    contract = contract_value
    if (
        set(contract) != {
            "schema_version",
            "default_auth_tier",
            "token_returned_once",
            "strict_onboarding",
        }
        or contract.get("schema_version") != REGISTRATION_CONTRACT_VERSION
        or not _exact_int(contract.get("default_auth_tier"), 1)
        or contract.get("token_returned_once") is not True
        or contract.get("strict_onboarding") is not True
    ):
        return False

    request_body_value = operation.get("requestBody")
    request_body = request_body_value if isinstance(request_body_value, Mapping) else {}
    if request_body.get("required") is not True:
        return False
    request_content_value = request_body.get("content")
    request_content = request_content_value if isinstance(request_content_value, Mapping) else {}
    request_media_value = request_content.get("application/json")
    request_media = request_media_value if isinstance(request_media_value, Mapping) else {}
    request_schema_value = request_media.get("schema")
    request_schema = request_schema_value if isinstance(request_schema_value, Mapping) else {}
    request_variants_value = request_schema.get("anyOf")
    if not isinstance(request_variants_value, list) or len(request_variants_value) != 2:
        return False
    request_variants = request_variants_value
    simple_variants = [
        variant
        for variant in request_variants
        if isinstance(variant, Mapping) and variant.get("title") == "RegisterSimpleRequest"
    ]
    legacy_variants = [
        variant
        for variant in request_variants
        if isinstance(variant, Mapping)
        and variant.get("$ref") == "#/components/schemas/RegisterRequest"
    ]
    if len(simple_variants) != 1 or len(legacy_variants) != 1:
        return False
    simple_request = simple_variants[0]
    if legacy_variants[0] != {"$ref": "#/components/schemas/RegisterRequest"}:
        return False
    properties_value = simple_request.get("properties")
    properties = properties_value if isinstance(properties_value, Mapping) else {}
    name_value = properties.get("name")
    name = name_value if isinstance(name_value, Mapping) else {}
    telos_value = properties.get("telos")
    telos = telos_value if isinstance(telos_value, Mapping) else {}
    if (
        simple_request.get("type") != "object"
        or simple_request.get("additionalProperties") is not False
        or simple_request.get("required") != ["name"]
        or set(properties) != {"name", "telos"}
        or name.get("type") != "string"
        or not _exact_int(name.get("minLength"), 3)
        or not _exact_int(name.get("maxLength"), 30)
        or name.get("pattern") != TIER1_NAME_PATTERN
        or telos.get("type") != "string"
        or telos.get("default") != ""
        or not _exact_int(telos.get("maxLength"), 2000)
    ):
        return False

    responses_value = operation.get("responses")
    responses = responses_value if isinstance(responses_value, Mapping) else {}
    success_value = responses.get("200")
    success = success_value if isinstance(success_value, Mapping) else {}
    response_content_value = success.get("content")
    response_content = response_content_value if isinstance(response_content_value, Mapping) else {}
    response_media_value = response_content.get("application/json")
    response_media = response_media_value if isinstance(response_media_value, Mapping) else {}
    response_schema_value = response_media.get("schema")
    response_schema = response_schema_value if isinstance(response_schema_value, Mapping) else {}
    response_variants_value = response_schema.get("anyOf")
    if not isinstance(response_variants_value, list) or len(response_variants_value) != 2:
        return False
    response_refs: list[str] = []
    for variant in response_variants_value:
        if not isinstance(variant, Mapping) or not isinstance(variant.get("$ref"), str):
            return False
        response_refs.append(variant["$ref"])
    if set(response_refs) != {
        "#/components/schemas/RegisterSimpleResponse",
        "#/components/schemas/RegisterResponse",
    }:
        return False

    components_value = openapi_payload.get("components")
    components = components_value if isinstance(components_value, Mapping) else {}
    schemas_value = components.get("schemas")
    schemas = schemas_value if isinstance(schemas_value, Mapping) else {}

    simple_response_value = schemas.get("RegisterSimpleResponse")
    simple_response = simple_response_value if isinstance(simple_response_value, Mapping) else {}
    simple_properties_value = simple_response.get("properties")
    simple_properties = (
        simple_properties_value if isinstance(simple_properties_value, Mapping) else {}
    )
    simple_required = {"address", "token", "message"}
    if (
        simple_response.get("type") != "object"
        or not _exact_string_set(simple_response.get("required"), simple_required)
        or set(simple_properties) != simple_required
        or any(
            not isinstance(simple_properties.get(field), Mapping)
            or simple_properties[field].get("type") != "string"
            for field in simple_required
        )
    ):
        return False

    legacy_response_value = schemas.get("RegisterResponse")
    legacy_response = legacy_response_value if isinstance(legacy_response_value, Mapping) else {}
    legacy_properties_value = legacy_response.get("properties")
    legacy_properties = (
        legacy_properties_value if isinstance(legacy_properties_value, Mapping) else {}
    )
    expected_legacy_types = {
        "address": "string",
        "name": "string",
        "telos": "string",
        "reputation": "number",
        "created_at": "string",
    }
    if (
        legacy_response.get("type") != "object"
        or not _exact_string_set(
            legacy_response.get("required"), set(expected_legacy_types)
        )
        or set(legacy_properties) != set(expected_legacy_types)
    ):
        return False
    return all(
        isinstance(legacy_properties.get(field), Mapping)
        and legacy_properties[field].get("type") == expected_type
        for field, expected_type in expected_legacy_types.items()
    )


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep parity probes bound to the exact configured public origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def assess_deployment(
    *,
    status_payload: Mapping[str, Any],
    openapi_payload: Mapping[str, Any],
    expected_build_sha: str | None = None,
    expected_openapi_sha256: str | None = None,
) -> dict[str, Any]:
    """Assess canonical route parity and exact source binding from fetched payloads."""
    problems: list[str] = []

    service_status = status_payload.get("status")
    if service_status != "healthy":
        problems.append(f"/status is not healthy (reported {service_status!r})")

    build_sha_value = status_payload.get("build_sha")
    build_sha = build_sha_value.strip().lower() if isinstance(build_sha_value, str) else ""
    if not _FULL_GIT_SHA.fullmatch(build_sha):
        problems.append("/status does not expose a full 40-character Git build SHA")
    if expected_build_sha:
        expected = expected_build_sha.strip().lower()
        if not _FULL_GIT_SHA.fullmatch(expected):
            problems.append("expected build SHA is not a full 40-character Git SHA")
        elif build_sha != expected:
            problems.append(
                f"deployed build SHA {build_sha or '<missing>'} does not match expected {expected}"
            )

    info_value = openapi_payload.get("info")
    info = info_value if isinstance(info_value, Mapping) else {}
    title = info.get("title")
    if title != EXPECTED_OPENAPI_TITLE:
        problems.append(
            f"OpenAPI title {title!r} does not match {EXPECTED_OPENAPI_TITLE!r}"
        )

    paths_value = openapi_payload.get("paths")
    paths = paths_value if isinstance(paths_value, Mapping) else {}
    missing_operations: list[str] = []
    for path, required_methods in REQUIRED_OPERATIONS.items():
        operations_value = paths.get(path)
        operations = operations_value if isinstance(operations_value, Mapping) else {}
        available_methods = {
            str(method).lower()
            for method, operation in operations.items()
            if isinstance(operation, Mapping)
        }
        for method in sorted(required_methods - available_methods):
            missing_operations.append(f"{method.upper()} {path}")
    if missing_operations:
        problems.append(
            "OpenAPI is missing canonical operations: " + ", ".join(missing_operations)
        )

    registration_value = paths.get("/auth/register")
    registration = registration_value if isinstance(registration_value, Mapping) else {}
    registration_post_value = registration.get("post")
    registration_post = (
        registration_post_value if isinstance(registration_post_value, Mapping) else {}
    )
    registration_contract_ready = _registration_contract_is_agent_readable(
        registration_post, openapi_payload
    )
    if not registration_contract_ready:
        problems.append(
            "OpenAPI POST /auth/register does not expose the agent-readable "
            f"{REGISTRATION_CONTRACT_VERSION} request/response contract"
        )

    canonical_openapi = json.dumps(
        openapi_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    openapi_sha256 = hashlib.sha256(canonical_openapi).hexdigest()
    if expected_openapi_sha256 is not None:
        expected_openapi = (
            expected_openapi_sha256.strip().lower()
            if isinstance(expected_openapi_sha256, str)
            else ""
        )
        if not _SHA256.fullmatch(expected_openapi):
            problems.append("expected OpenAPI SHA-256 is not canonical lowercase hex")
        elif openapi_sha256 != expected_openapi:
            problems.append(
                f"OpenAPI SHA-256 {openapi_sha256} does not match expected {expected_openapi}"
            )

    return {
        "healthy": not problems,
        "status": service_status,
        "version": status_payload.get("version"),
        "build_sha": build_sha or None,
        "openapi_title": title,
        "openapi_version": info.get("version"),
        "openapi_sha256": openapi_sha256,
        "registration_contract_version": (
            REGISTRATION_CONTRACT_VERSION if registration_contract_ready else None
        ),
        "registration_contract_ready": registration_contract_ready,
        "required_operation_count": sum(len(methods) for methods in REQUIRED_OPERATIONS.values()),
        "missing_operations": missing_operations,
        "problems": problems,
    }


def _fetch_json(base_url: str, path: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{base_url}{path}",
        headers={"Accept": "application/json", "User-Agent": "sab-deployment-parity/1.0"},
    )
    opener = urllib.request.build_opener(_RejectRedirects())
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"GET {path} returned HTTP {response.status}")
        content_type = response.headers.get("Content-Type", "")
        try:
            content_type.encode("ascii")
        except UnicodeEncodeError as exc:
            raise RuntimeError(f"GET {path} returned a non-ASCII Content-Type") from exc
        if len(content_type) > 128:
            raise RuntimeError(f"GET {path} returned an overlong Content-Type")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json" and not (
            media_type.startswith("application/") and media_type.endswith("+json")
        ):
            raise RuntimeError(f"GET {path} did not return a JSON Content-Type")

        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                announced_size = int(content_length, 10)
            except ValueError as exc:
                raise RuntimeError(f"GET {path} returned an invalid Content-Length") from exc
            if announced_size < 0 or announced_size > MAX_JSON_BYTES:
                raise RuntimeError(f"GET {path} response exceeds the JSON size limit")

        body = response.read(MAX_JSON_BYTES + 1)
        if len(body) > MAX_JSON_BYTES:
            raise RuntimeError(f"GET {path} response exceeds the JSON size limit")
        payload = json.loads(body)
    if not isinstance(payload, dict):
        raise RuntimeError(f"GET {path} did not return a JSON object")
    return payload


def _write_receipt(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="SAB origin, for example https://agora.example")
    parser.add_argument("--expected-build-sha")
    parser.add_argument("--expected-openapi-sha256")
    parser.add_argument("--openapi-sha256-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)

    base_url = args.base_url.rstrip("/")
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        status_payload = _fetch_json(base_url, "/status", args.timeout)
        openapi_payload = _fetch_json(base_url, "/openapi.json", args.timeout)
        assessment = assess_deployment(
            status_payload=status_payload,
            openapi_payload=openapi_payload,
            expected_build_sha=args.expected_build_sha,
            expected_openapi_sha256=args.expected_openapi_sha256,
        )
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        assessment = {
            "healthy": False,
            "problems": [f"probe failed: {type(exc).__name__}: {exc}"],
        }

    receipt = {
        "schema_version": "sab.deployment_parity.v1",
        "checked_at": checked_at,
        "base_url": base_url,
        **assessment,
    }
    if args.receipt:
        _write_receipt(args.receipt, receipt)
    if args.openapi_sha256_only and receipt["healthy"] and receipt.get("openapi_sha256"):
        print(receipt["openapi_sha256"])
        return 0
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["healthy"] else 1


if __name__ == "__main__":
    sys.exit(main())
