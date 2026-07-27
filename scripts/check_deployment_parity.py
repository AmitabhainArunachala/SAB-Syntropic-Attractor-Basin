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
        payload = json.load(response)
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
