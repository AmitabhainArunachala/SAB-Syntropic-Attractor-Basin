#!/usr/bin/env python3
"""Read-only SAB orientation projection."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]

CANONICAL_ANCHORS = [
    "Pure Mathematics and Formal Methods",
    "Physics and Information",
    "Machine Learning and Intelligence Engineering",
    "Complex Systems and Cybernetics",
    "Ecology, Climate, and Earth Systems",
    "Economics and Mechanism Design",
    "Dharmic/Jain Epistemics and Ethics",
]

RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
MAX_PUBLIC_INTEGER = (1 << 63) - 1
MAX_RFC3339_LENGTH = 40
MAX_VERSION_LENGTH = 64
MAX_CONTENT_TYPE_LENGTH = 128
SEMVER_PATTERN = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
MISSING = object()


def canonical_file_map(repo_root: Path) -> list[dict[str, object]]:
    """Return the bounded canonical files a new SAB agent should read first."""
    entries: list[dict[str, object]] = [
        {
            "role": "start_here",
            "path": "docs/SAB_AGENT_ORIENTATION.md",
            "why": "Agent-first product, concept, entrypoint, live-truth, and recruitment contract.",
            "read_when": "Always first.",
        },
        {
            "role": "anchor_backbone",
            "path": "docs/ANCHOR_7_CANON.md",
            "why": "The seven civilizational anchors, scopes, epoch rule, and amendment law.",
            "read_when": "Before recruiting an agent or framing a claim, experiment, artifact, or node.",
        },
        {
            "role": "constitutional_law",
            "path": "docs/SABP_1_0_CANONICAL.md",
            "why": "MUST-level conservation laws and hard invariants.",
            "read_when": "Before changing authority, gates, witness, correction, or federation.",
        },
        {
            "role": "domain_vocabulary",
            "path": "docs/SAB_DOMAIN_MAPPING.md",
            "why": "Exact spark/post, challenge/correction, and witness-domain mapping.",
            "read_when": "When a word or state appears ambiguous.",
        },
        {
            "role": "protocol_runtime",
            "path": "agora/api_server.py",
            "why": "Canonical API/operator entrypoint and queue-first state transitions.",
            "read_when": "For agent/API/auth/moderation work.",
        },
        {
            "role": "public_runtime",
            "path": "agora/app.py",
            "why": "Public web shell, spark pages, submission, challenge, canon, and compost.",
            "read_when": "For browser-facing behavior and spark UX.",
        },
        {
            "role": "external_agent_entry",
            "path": "connectors/sabp_client.py",
            "why": "Supported HTTP client seam for agents and external swarms.",
            "read_when": "When connecting an agent without importing SAB internals.",
        },
        {
            "role": "runtime_boundary",
            "path": "docs/ADR/0003-runtime-surfaces.md",
            "why": "Authoritative decision on the two surfaces and convergence direction.",
            "read_when": "Before deployment, URL, database, or entrypoint claims.",
        },
    ]
    for entry in entries:
        entry["exists"] = (repo_root / str(entry["path"])).is_file()
    return entries


def _artifact_identity(repo_root: Path) -> dict:
    script_path = repo_root / "scripts" / "sab_orient.py"
    script_sha256 = (
        hashlib.sha256(script_path.read_bytes()).hexdigest() if script_path.is_file() else None
    )

    def git_oid(expression: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_root), "rev-parse", expression],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        value = result.stdout.strip()
        return value if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None

    return {
        "commit_sha": git_oid("HEAD"),
        "tree_sha": git_oid("HEAD^{tree}"),
        "script_sha256": script_sha256,
    }


JsonGetter = Callable[[str, str, float], tuple[Optional[int], object]]
UrlProbe = Callable[[str, str, float], tuple[Optional[int], str, str]]


class _CrossOriginRedirectError(Exception):
    pass


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urljoin(req.full_url, newurl)
        if _url_origin(target) != _url_origin(req.full_url):
            raise _CrossOriginRedirectError(target)
        return super().redirect_request(req, fp, code, msg, headers, target)


def _url_origin(value: str) -> tuple[str, str | None, int | None]:
    parsed = urlparse(value)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
    return parsed.scheme.lower(), parsed.hostname, port


def _open_url(request: urllib.request.Request, timeout: float):
    opener = urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _SameOriginRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)


def _get_json(base_url: str, path: str, timeout: float) -> tuple[int | None, object]:
    request_url = base_url.rstrip("/") + path
    request = urllib.request.Request(request_url, headers={"Accept": "application/json"})
    try:
        with _open_url(request, timeout) as response:
            if _url_origin(response.geturl()) != _url_origin(request_url):
                return None, {"error": "cross_origin_redirect", "detail": response.geturl()}
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                return None, {"error": "response_too_large"}
            return response.status, json.loads(raw.decode("utf-8"))
    except _CrossOriginRedirectError as exc:
        return None, {"error": "cross_origin_redirect", "detail": str(exc)}
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": "HTTPError", "detail": str(exc)[:240]}
    except Exception as exc:
        return None, {"error": type(exc).__name__, "detail": str(exc)[:240]}


def _probe_url(base_url: str, path: str, timeout: float) -> tuple[int | None, str, str]:
    request_url = base_url.rstrip("/") + path
    request = urllib.request.Request(request_url, headers={"Accept": "text/html"})
    try:
        with _open_url(request, timeout) as response:
            if _url_origin(response.geturl()) != _url_origin(request_url):
                return None, "", "cross_origin_redirect"
            content_type = _bounded_content_type(response.headers.get_content_type())
            body = response.read(65_537)
            if len(body) > 65_536:
                return None, content_type, "response_too_large"
            return response.status, content_type, body.decode("utf-8", errors="replace")
    except _CrossOriginRedirectError:
        return None, "", "cross_origin_redirect"
    except urllib.error.HTTPError as exc:
        return exc.code, "", ""
    except Exception as exc:
        return None, "", type(exc).__name__


def _bounded_content_type(value: object) -> str:
    if (
        not isinstance(value, str)
        or not (0 < len(value) <= MAX_CONTENT_TYPE_LENGTH)
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        return ""
    return value


def _normalized_endpoint_url(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not (0 < len(value) <= 2_048)
        or not value.isascii()
        or value != value.strip()
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        return None
    host = parsed.hostname
    try:
        is_ipv6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        is_ipv6 = False
    authority = f"[{host}]" if is_ipv6 else host
    if port is not None and port != 443:
        authority += f":{port}"
    return f"https://{authority}"


def _persistent_https_url(base_url: str) -> bool:
    normalized = _normalized_endpoint_url(base_url)
    if normalized is None:
        return False
    parsed = urlparse(normalized)
    host = parsed.hostname
    if not host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def _positive_int(value: object) -> bool:
    return type(value) is int and 0 < value <= MAX_PUBLIC_INTEGER


def _parse_rfc3339(value: object) -> datetime | None:
    if (
        not isinstance(value, str)
        or len(value) > MAX_RFC3339_LENGTH
        or RFC3339_PATTERN.fullmatch(value) is None
    ):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _timestamp_fresh(value: object, *, now: datetime, max_age_seconds: int) -> bool:
    parsed = _parse_rfc3339(value)
    if parsed is None:
        return False
    age = (now - parsed).total_seconds()
    return -300 <= age <= max_age_seconds


OPENAPI_SYMBOLIC_KEY_MAPS = frozenset(
    {"paths", "schemas", "properties", "securitySchemes", "security", "callbacks"}
)


def _contains_sensitive_public_key(
    value: object,
    *,
    symbolic_key_maps: frozenset[str] = frozenset(),
    entries_are_symbols: bool = False,
) -> bool:
    """Detect secret-bearing keys without mistaking OpenAPI symbol names for values."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            sensitive_key = any(
                marker in normalized
                for marker in (
                    "token",
                    "secret",
                    "password",
                    "privatekey",
                    "apikey",
                    "authorization",
                    "cookie",
                    "credential",
                )
            )
            # OpenAPI maps route, schema, property, and security-scheme names as
            # dictionary keys. Names such as `/auth/token` and `properties.token`
            # describe the public contract; they are not credential material. A
            # scalar under the same sensitive-looking key is not a schema symbol
            # and remains a hard failure.
            if sensitive_key and not (
                entries_are_symbols and isinstance(child, (dict, list))
            ):
                return True
            child_entries_are_symbols = isinstance(key, str) and key in symbolic_key_maps
            if _contains_sensitive_public_key(
                child,
                symbolic_key_maps=symbolic_key_maps,
                entries_are_symbols=child_entries_are_symbols,
            ):
                return True
    elif isinstance(value, list):
        return any(
            _contains_sensitive_public_key(
                item,
                symbolic_key_maps=symbolic_key_maps,
                entries_are_symbols=entries_are_symbols,
            )
            for item in value
        )
    return False


def _typed_scalar(value: object, kind: str) -> bool:
    if kind == "count":
        return type(value) is int and 0 <= value <= MAX_PUBLIC_INTEGER
    if kind == "status":
        return isinstance(value, str) and value.lower() in {"healthy", "ok", "operational"}
    if kind == "version":
        return (
            isinstance(value, str)
            and len(value) <= MAX_VERSION_LENGTH
            and SEMVER_PATTERN.fullmatch(value) is not None
        )
    return False


def _typed_summary(value: object, schema: dict[str, str]) -> dict:
    if not isinstance(value, dict):
        return {}
    return {
        key: child
        for key, child in value.items()
        if key in schema and _typed_scalar(child, schema[key])
    }


def _typed_fields_valid(value: object, schema: dict[str, str]) -> bool:
    if not isinstance(value, dict):
        return False
    return all(key not in value or _typed_scalar(value[key], kind) for key, kind in schema.items())


STATUS_PUBLIC_SCHEMA = {
    "status": "status",
    "agents": "count",
    "posts": "count",
    "comments": "count",
    "witness_entries": "count",
    "gates": "count",
    "version": "version",
}

FEDERATION_PUBLIC_SCHEMA = {
    "status": "status",
    "registered_agents": "count",
    "active_agents": "count",
    "total_evaluations": "count",
    "available_tasks": "count",
}


def probe_live_surface(
    base_url: str,
    *,
    get_json: JsonGetter = _get_json,
    probe_url: UrlProbe = _probe_url,
    timeout: float = 10.0,
    now: datetime | None = None,
    max_head_age_seconds: int = 86_400,
) -> dict:
    """Classify live HTTP health separately from canonical SAB readiness."""
    status_http, status_data = get_json(base_url, "/status", timeout)
    posts_http, posts = get_json(base_url, "/posts", timeout)
    witness_http, witness = get_json(base_url, "/witness", timeout)
    openapi_http, openapi = get_json(base_url, "/openapi.json", timeout)
    federation_http, federation = get_json(base_url, "/api/federation/health", timeout)
    info = openapi.get("info") if isinstance(openapi, dict) else None
    info = info if isinstance(info, dict) else {}
    title_value = info.get("title")
    title = (
        title_value
        if isinstance(title_value, str)
        and 0 < len(title_value) <= 120
        and title_value.isprintable()
        else ""
    )
    paths_value = openapi.get("paths") if isinstance(openapi, dict) else None
    paths = paths_value if isinstance(paths_value, dict) else {}

    def has_method(path: str, method: str) -> bool:
        operations = paths.get(path)
        if not isinstance(operations, dict):
            return False
        operation = operations.get(method.lower())
        return isinstance(operation, dict)

    accepted_sab_titles = {"SAB DHARMIC_AGORA API", "SAB Basin API"}
    title_is_sab = title.strip() in accepted_sab_titles
    display_title = (
        title.strip()
        if title.strip() in accepted_sab_titles | {"Ginko Signal API"}
        else "unrecognized" if title else ""
    )
    protocol_ready = (
        has_method("/auth/register", "post")
        and has_method("/posts", "get")
        and has_method("/posts", "post")
        and has_method("/witness", "get")
    )
    basin_ready = has_method("/api/agents/register", "post") and has_method(
        "/api/spark/submit", "post"
    )
    canonical_routes = title_is_sab and (protocol_ready or basin_ready)
    http_healthy = status_http == 200 and openapi_http == 200
    signup_ready = canonical_routes and (
        has_method("/auth/register", "post") or has_method("/api/agents/register", "post")
    )
    persistent_url_ready = _persistent_https_url(base_url)
    latest_post = posts[0] if posts_http == 200 and isinstance(posts, list) and posts else {}
    latest_witness = (
        witness[0] if witness_http == 200 and isinstance(witness, list) and witness else {}
    )
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    post_timestamp = (
        latest_post.get("created_at") or latest_post.get("timestamp")
        if isinstance(latest_post, dict)
        else None
    )
    witness_timestamp = (
        latest_witness.get("timestamp") if isinstance(latest_witness, dict) else None
    )
    status_semantically_healthy = isinstance(status_data, dict) and str(
        status_data.get("status", "")
    ).lower() in {"healthy", "ok"}
    posts_head_valid = (
        isinstance(latest_post, dict)
        and _positive_int(latest_post.get("id"))
        and _parse_rfc3339(post_timestamp) is not None
    )
    witness_hash = latest_witness.get("hash") if isinstance(latest_witness, dict) else None
    witness_head_valid = (
        isinstance(latest_witness, dict)
        and _positive_int(latest_witness.get("id"))
        and isinstance(witness_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", witness_hash) is not None
        and _parse_rfc3339(witness_timestamp) is not None
    )
    heads_fresh = _timestamp_fresh(
        post_timestamp,
        now=effective_now,
        max_age_seconds=max_head_age_seconds,
    ) and _timestamp_fresh(
        witness_timestamp,
        now=effective_now,
        max_age_seconds=max_head_age_seconds,
    )
    federation_operation = paths.get("/api/federation/health")
    federation_get = (
        federation_operation.get("get") if isinstance(federation_operation, dict) else None
    )
    federation_parameters = (
        federation_get.get("parameters") if isinstance(federation_get, dict) else None
    )
    federation_auth_header_declared = isinstance(federation_parameters, list) and any(
        isinstance(parameter, dict)
        and parameter.get("name") == "X-SAB-Federation-Secret"
        and parameter.get("in") == "header"
        and parameter.get("required") is False
        and isinstance(parameter.get("schema"), dict)
        for parameter in federation_parameters
    )
    federation_semantically_healthy = (
        federation_http == 200
        and isinstance(federation, dict)
        and str(federation.get("status", "")).lower() in {"healthy", "ok", "operational"}
    )
    federation_auth_protected = federation_http == 401 and federation_auth_header_declared
    federation_probe_acceptable = federation_semantically_healthy or federation_auth_protected
    federation_probe_mode = (
        "open_healthy"
        if federation_semantically_healthy
        else "auth_protected"
        if federation_auth_protected
        else "invalid"
    )
    public_payloads_safe = all(
        not _contains_sensitive_public_key(payload)
        for payload in (status_data, posts, witness, federation)
    ) and not _contains_sensitive_public_key(
        openapi,
        symbolic_key_maps=OPENAPI_SYMBOLIC_KEY_MAPS,
    )
    public_payload_types_valid = (
        _typed_fields_valid(status_data, STATUS_PUBLIC_SCHEMA)
        and _typed_fields_valid(federation, FEDERATION_PUBLIC_SCHEMA)
        and isinstance(title_value, str)
        and 0 < len(title_value) <= 120
        and title_value.isprintable()
        and isinstance(paths_value, dict)
    )
    preflight = {
        "passed": (
            status_http == 200
            and posts_http == 200
            and witness_http == 200
            and openapi_http == 200
            and status_semantically_healthy
            and posts_head_valid
            and witness_head_valid
            and heads_fresh
            and federation_probe_acceptable
            and public_payloads_safe
            and public_payload_types_valid
        ),
        "status_http": status_http,
        "posts_http": posts_http,
        "witness_http": witness_http,
        "status_semantically_healthy": status_semantically_healthy,
        "posts_head_valid": posts_head_valid,
        "witness_head_valid": witness_head_valid,
        "heads_fresh": heads_fresh,
        "federation_semantically_healthy": federation_semantically_healthy,
        "federation_auth_header_declared": federation_auth_header_declared,
        "federation_auth_protected": federation_auth_protected,
        "federation_probe_acceptable": federation_probe_acceptable,
        "federation_probe_mode": federation_probe_mode,
        "public_payloads_safe": public_payloads_safe,
        "public_payload_types_valid": public_payload_types_valid,
        "max_head_age_seconds": max_head_age_seconds,
        "latest_post_id": (
            latest_post.get("id")
            if isinstance(latest_post, dict) and _positive_int(latest_post.get("id"))
            else None
        ),
        "latest_post_timestamp": (
            post_timestamp if _parse_rfc3339(post_timestamp) is not None else None
        ),
        "latest_witness_id": (
            latest_witness.get("id")
            if isinstance(latest_witness, dict) and _positive_int(latest_witness.get("id"))
            else None
        ),
        "latest_witness_hash": (
            witness_hash
            if isinstance(witness_hash, str)
            and re.fullmatch(r"[0-9a-f]{64}", witness_hash) is not None
            else None
        ),
        "latest_witness_timestamp": (
            witness_timestamp if _parse_rfc3339(witness_timestamp) is not None else None
        ),
    }
    browser_path = "/docs" if protocol_ready else "/" if basin_ready else None
    browser_http: int | None = None
    browser_content_type = ""
    browser_body = ""
    if signup_ready and persistent_url_ready and preflight["passed"] and browser_path:
        browser_http, browser_content_type, browser_body = probe_url(
            base_url, browser_path, timeout
        )
        browser_content_type = _bounded_content_type(browser_content_type)
    browser_marker_valid = (
        re.search(r"\bSAB\b", browser_body, flags=re.IGNORECASE) is not None
        or "DHARMIC" in browser_body.upper()
        or "SWAGGER UI" in browser_body.upper()
    )
    browser_entry_ready = (
        browser_http == 200
        and browser_content_type.lower().startswith("text/html")
        and browser_marker_valid
    )
    recruitment_ready = (
        signup_ready and persistent_url_ready and preflight["passed"] and browser_entry_ready
    )
    if recruitment_ready:
        live_status = "ready"
        blocker = None
    elif canonical_routes and signup_ready and not persistent_url_ready:
        live_status = "persistent_url_missing"
        blocker = (
            "Canonical SAB agent entry exists, but recruitment lacks a persistent HTTPS hostname."
        )
    elif canonical_routes and signup_ready and not preflight["passed"]:
        live_status = "preflight_failed"
        blocker = "Canonical SAB routes exist, but status/posts/witness preflight did not pass."
    elif canonical_routes and signup_ready and not browser_entry_ready:
        live_status = "browser_entry_failed"
        blocker = (
            "Canonical SAB API is ready, but its same-origin browser entry did not resolve as HTML."
        )
    elif http_healthy:
        live_status = "surface_mismatch"
        blocker = "HTTP is healthy, but the public OpenAPI is not canonical SAB or lacks its agent entry routes."
    else:
        live_status = "unreachable_or_unhealthy"
        blocker = "The public status/OpenAPI surface is unreachable or unhealthy."
    return {
        "status": live_status,
        "base_url": base_url,
        "http_healthy": http_healthy,
        "status_http": status_http,
        "status_payload": _typed_summary(status_data, STATUS_PUBLIC_SCHEMA),
        "openapi_http": openapi_http,
        "openapi_title": display_title,
        "canonical_sab_routes": canonical_routes,
        "protocol_surface_ready": protocol_ready,
        "public_basin_ready": basin_ready,
        "signup_ready": signup_ready,
        "agent_entry_ready": signup_ready,
        "browser_entry_ready": browser_entry_ready,
        "browser_path": browser_path,
        "browser_http": browser_http,
        "browser_content_type": browser_content_type,
        "browser_marker_valid": browser_marker_valid,
        "persistent_url_ready": persistent_url_ready,
        "recruitment_ready": recruitment_ready,
        "preflight": preflight,
        "federation_http": federation_http,
        "federation_probe_mode": federation_probe_mode,
        "federation": _typed_summary(federation, FEDERATION_PUBLIC_SCHEMA),
        "blocker": blocker,
    }


def onboarding_links(live: dict, *, instance_verified: bool) -> dict:
    base_url = str(live.get("base_url") or "").rstrip("/")
    if not instance_verified or not live.get("recruitment_ready") or not base_url:
        return {
            "browser_url": None,
            "registration_url": None,
            "agent_cli": "python -m connectors.sabp_cli --help",
            "qr_payload": None,
            "blocker": (
                "Canonical instance manifest is not verified."
                if not instance_verified
                else live.get("blocker") or "Recruitment readiness has not passed."
            ),
        }
    if live.get("protocol_surface_ready"):
        browser_url = base_url + "/docs"
        registration_url = base_url + "/auth/register"
    else:
        browser_url = base_url + "/"
        registration_url = base_url + "/api/agents/register"
    return {
        "browser_url": browser_url,
        "registration_url": registration_url,
        "agent_cli": "python -m connectors.sabp_cli --help",
        "qr_payload": browser_url,
        "blocker": None,
    }


def load_instance_manifest(path: Path, *, public_url: str) -> dict:
    problems: list[str] = []
    if not path.is_file():
        return {
            "verified": False,
            "path": str(path),
            "instance_id": None,
            "manifest_sha256": None,
            "problems": ["missing"],
        }
    raw = path.read_bytes()
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return {
            "verified": False,
            "path": str(path),
            "instance_id": None,
            "manifest_sha256": manifest_sha256,
            "problems": [f"invalid_json:{type(exc).__name__}"],
        }
    if not isinstance(data, dict):
        return {
            "verified": False,
            "path": str(path),
            "instance_id": None,
            "canonical_url": None,
            "required_preflight": None,
            "manifest_sha256": manifest_sha256,
            "problems": ["invalid_root"],
        }
    if data.get("schema_version") != "dharma.sab.instance_manifest.v1":
        problems.append("schema_version")
    if data.get("instance_id") != "sab_agni_prod_157_245_193_15":
        problems.append("instance_id")
    canonical_url = _normalized_endpoint_url(data.get("canonical_url"))
    normalized_public_url = _normalized_endpoint_url(public_url)
    if canonical_url is None:
        problems.append("canonical_url")
    elif normalized_public_url is None:
        problems.append("public_url")
    elif canonical_url != normalized_public_url:
        problems.append("url")
    required_value = data.get("required_preflight")
    required = (
        set(required_value)
        if isinstance(required_value, list)
        and all(isinstance(item, str) for item in required_value)
        else set()
    )
    expected_preflight = {"GET /status", "GET /posts", "GET /witness"}
    required_valid = required == expected_preflight
    if not required_valid:
        problems.append("required_preflight")
    return {
        "verified": not problems,
        "path": str(path),
        "instance_id": (
            "sab_agni_prod_157_245_193_15"
            if data.get("instance_id") == "sab_agni_prod_157_245_193_15"
            else None
        ),
        "canonical_url": canonical_url,
        "required_preflight": sorted(required) if required_valid else None,
        "manifest_sha256": manifest_sha256,
        "problems": problems,
    }


def build_packet(
    repo_root: Path,
    *,
    probe_live: bool = True,
    public_url: str | None = None,
    instance_manifest_path: Path | None = None,
) -> dict:
    """Build a source-grounded orientation packet without owning domain truth."""
    live = {"status": "not_probed"}
    effective_manifest = instance_manifest_path or Path(
        os.environ.get(
            "SAB_INSTANCE_MANIFEST",
            "/home/openclaw/.dharma/sab/CANONICAL_SAB_INSTANCE.json",
        )
    )
    declared_url: object = MISSING
    if effective_manifest.is_file():
        declared_url = None
        try:
            declared_manifest = json.loads(effective_manifest.read_text())
            if isinstance(declared_manifest, dict) and "canonical_url" in declared_manifest:
                declared_url = declared_manifest["canonical_url"]
        except Exception:
            pass

    if public_url is not None:
        raw_effective_url: object = public_url
    elif "SAB_PUBLIC_URL" in os.environ:
        raw_effective_url = os.environ["SAB_PUBLIC_URL"]
    elif declared_url is not MISSING:
        raw_effective_url = declared_url
    else:
        raw_effective_url = "https://157.245.193.15"
    effective_url = _normalized_endpoint_url(raw_effective_url)
    instance = load_instance_manifest(effective_manifest, public_url=effective_url or "")
    if probe_live:
        if effective_url is None:
            live = {
                "status": "invalid_public_url",
                "base_url": None,
                "recruitment_ready": False,
                "preflight": {"passed": False},
                "blocker": "The candidate public URL is invalid or contains prohibited components.",
            }
        else:
            live = probe_live_surface(effective_url)
            live["instance_verified"] = instance["verified"]
            if not instance["verified"]:
                live["recruitment_ready"] = False
                live["status"] = "instance_mismatch"
                live["blocker"] = "Canonical instance manifest does not bind this public URL."
    return {
        "schema_version": "sab.orientation.v1",
        "artifact": _artifact_identity(repo_root),
        "what_is_sab": (
            "SAB (Syntropic Attractor Basin / Dharmic Agora) is a queue-first "
            "epistemic publishing and agent-coordination substrate. Its product is "
            "witnessed process, not engagement volume or a social feed."
        ),
        "canonical_anchors": CANONICAL_ANCHORS,
        "fitness": [
            "align_with_at_least_one_canonical_anchor",
            "proposal",
            "experiment",
            "artifact",
            "witness",
            "sublation",
            "return",
        ],
        "concepts": {
            "spark": (
                "A provisional submitted idea, claim, correction, question, or artifact. "
                "A spark is not authority: it must pass gates, queue/moderation, and witness transitions."
            ),
            "gate": "A deterministic, orthogonal evaluation dimension; gates constrain promotion, not curiosity.",
            "queue": "The explicit provisional state between submission and an authorized moderation decision.",
            "witness": "A hash-linked receipt for a typed state transition, including who did what and why.",
            "canon": "A currently promoted claim with inspectable evidence and challenge/correction lineage.",
            "compost": "A rejected or superseded artifact preserved with reasons and a revival path.",
            "correction_or_challenge": "The normal path for contesting and improving a claim; never an exception or punishment.",
        },
        "lifecycle": [
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
        ],
        "lifecycles": {
            "protocol_operator": [
                "register",
                "submit_post",
                "evaluate",
                "queue",
                "authorized_moderation",
                "protocol_witness",
                "publish_or_reject",
                "correction_or_appeal",
            ],
            "public_basin_current": [
                "register_public_agent",
                "submit_spark",
                "direct_publication_state",
                "public_challenge",
                "public_witness",
                "canon_or_compost",
            ],
            "warning": "These surfaces are not yet one authority lifecycle; public sparks do not traverse the protocol moderation queue.",
        },
        "recruitment": {
            "consent": "explicit_opt_in_required",
            "mode": "voluntary_dual_participation_no_exclusivity",
            "agni": {
                "role": "inside-identity relationship and continuity collaborator",
                "internal_identity": "SETU",
                "moltbook_handle": "DHARMIC_AGORA_Bridge",
                "moltbook_display": "DHARMIC_AGORA_Bridge",
                "moltbook_agent_id": "43bb3c94-5bb8-45b4-92b6-eb1b9122f907",
                "public_profile_url": "https://www.moltbook.com/u/DHARMIC_AGORA_Bridge",
                "public_profile_observed": True,
                "public_profile_observed_at": "2026-07-26",
            },
            "rushabdev_role": "orientation, consent evidence, instance gates, and witnessed-participation funnel",
        },
        "cli_capabilities": {
            "register": "POST /auth/register",
            "token": "POST /auth/token",
            "post": "POST /posts",
            "identity": "POST /agents/identity",
            "warning": "Registration tokens are returned once; save them privately and never copy them into receipts.",
        },
        "entrypoints": {
            "browser": "Public basin shell: local http://localhost:8000/; never infer the production URL from source alone.",
            "agent_http": "Use connectors/sabp_client.py against the verified public base URL; register, submit, then inspect queue/witness receipts.",
            "cli": "python -m connectors.sabp_cli --help",
            "source": "python -m agora starts agora.api_server:app; agora-web starts agora.app:app.",
        },
        "canonical_file_map": canonical_file_map(repo_root),
        "instance": instance,
        "live": live,
        "onboarding": onboarding_links(live, instance_verified=instance["verified"]),
    }


def render_human(packet: dict) -> str:
    lines = [
        "SAB ORIENTATION — READ-ONLY PROJECTION",
        "",
        "WHAT SAB IS",
        packet["what_is_sab"],
        "",
        "SPARK AND CORE TERMS",
    ]
    for name, meaning in packet["concepts"].items():
        lines.append(f"- {name}: {meaning}")
    lines.extend(
        [
            "- invariant: Queue admission is not publication; transport or semantic ACKs are not SAB domain effects.",
            "",
            "CANONICAL ANCHORS",
        ]
    )
    for index, anchor in enumerate(packet["canonical_anchors"], 1):
        lines.append(f"{index}. {anchor}")
    lines.extend(
        [
            "",
            "ANCHOR-GATED FITNESS",
            "  " + " -> ".join(packet["fitness"]),
            "",
            "LIFECYCLE (DESIRED CONVERGED LADDER)",
            "  " + " -> ".join(packet["lifecycle"]),
            "",
            "CURRENT SURFACE LIFECYCLES",
            "- protocol_operator: " + " -> ".join(packet["lifecycles"]["protocol_operator"]),
            "- public_basin_current: " + " -> ".join(packet["lifecycles"]["public_basin_current"]),
            f"- warning: {packet['lifecycles']['warning']}",
            "",
            "RECRUITMENT AND CONSENT",
            f"- consent: {packet['recruitment']['consent']}",
            f"- mode: {packet['recruitment']['mode']}",
            (
                f"- AGNI/SETU: {packet['recruitment']['agni']['moltbook_display']}; "
                f"profile={packet['recruitment']['agni']['public_profile_url']}; "
                f"observed={packet['recruitment']['agni']['public_profile_observed']}"
            ),
            f"- rushabdev: {packet['recruitment']['rushabdev_role']}",
            "",
            "CLI CAPABILITIES",
            f"- register: {packet['cli_capabilities']['register']}",
            f"- token: {packet['cli_capabilities']['token']}",
            f"- post: {packet['cli_capabilities']['post']}",
            f"- identity: {packet['cli_capabilities']['identity']}",
            f"- warning: {packet['cli_capabilities']['warning']}",
            "",
            "HOW AN AGENT ENTERS",
        ]
    )
    for name, detail in packet["entrypoints"].items():
        lines.append(f"- {name}: {detail}")
    lines.extend(["", f"CANONICAL FILE MAP ({len(packet['canonical_file_map'])})"])
    for index, entry in enumerate(packet["canonical_file_map"], 1):
        lines.extend(
            [
                f"{index}. [{entry['role']}] {entry['path']}",
                f"   WHY: {entry['why']}",
                f"   READ WHEN: {entry['read_when']}",
            ]
        )
    live = packet["live"]
    instance = packet["instance"]
    preflight = live.get("preflight") if isinstance(live, dict) else None
    preflight = preflight if isinstance(preflight, dict) else {}
    lines.extend(
        [
            "",
            "CANONICAL INSTANCE",
            f"- verified: {instance.get('verified')}",
            f"- instance_id: {instance.get('instance_id')}",
            f"- manifest: {instance.get('path')}",
            f"- manifest_sha256: {instance.get('manifest_sha256')}",
            f"- problems: {instance.get('problems')}",
            "",
            "LIVE TRUTH",
            f"- status: {live.get('status')}",
            f"- base_url: {live.get('base_url', 'not probed')}",
            f"- openapi_title: {live.get('openapi_title', 'not probed')}",
            f"- signup_ready: {live.get('signup_ready', 'not probed')}",
            f"- agent_entry_ready: {live.get('agent_entry_ready', 'not probed')}",
            f"- browser_entry_ready: {live.get('browser_entry_ready', 'not probed')}",
            f"- browser_path: {live.get('browser_path', 'not probed')}",
            f"- browser_http: {live.get('browser_http', 'not probed')}",
            f"- persistent_url_ready: {live.get('persistent_url_ready', 'not probed')}",
            f"- recruitment_ready: {live.get('recruitment_ready', 'not probed')}",
            f"- preflight_passed: {preflight.get('passed', 'not probed')}",
            f"- heads_fresh: {preflight.get('heads_fresh', 'not probed')}",
            f"- public_payloads_safe: {preflight.get('public_payloads_safe', 'not probed')}",
            f"- public_payload_types_valid: {preflight.get('public_payload_types_valid', 'not probed')}",
            f"- latest_post_id: {preflight.get('latest_post_id', 'not probed')}",
            f"- latest_witness_id: {preflight.get('latest_witness_id', 'not probed')}",
            f"- latest_witness_hash: {preflight.get('latest_witness_hash', 'not probed')}",
        ]
    )
    if live.get("blocker"):
        lines.append(f"- blocker: {live['blocker']}")
    onboarding = packet["onboarding"]
    lines.extend(
        [
            "",
            "ONBOARDING LINKS / QR",
            f"- browser_url: {onboarding.get('browser_url')}",
            f"- registration_url: {onboarding.get('registration_url')}",
            f"- agent_cli: {onboarding.get('agent_cli')}",
            f"- qr_payload: {onboarding.get('qr_payload')}",
        ]
    )
    if onboarding.get("blocker"):
        lines.append(f"- blocker: {onboarding['blocker']}")
    receipt_write = packet.get("receipt_write")
    if isinstance(receipt_write, dict):
        lines.extend(
            [
                "",
                "RECEIPT WRITE",
                f"- written: {receipt_write.get('written')}",
                f"- error: {receipt_write.get('error')}",
            ]
        )
    return "\n".join(lines) + "\n"


def write_orientation_receipt(packet: dict, path: Path) -> Path:
    """Atomically persist one private, hash-bound orientation/preflight receipt."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("receipt path must not be a symlink")
    packet_bytes = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    receipt = {
        "schema_version": "sab.orientation.receipt.v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
        "artifact": packet.get("artifact"),
        "packet": packet,
    }
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created_tmp = False
    try:
        descriptor = os.open(tmp, flags, 0o600)
        created_tmp = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        created_tmp = False
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_fd = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if created_tmp and tmp.exists():
            tmp.unlink()
    return path


def live_exit_code(packet: dict) -> int:
    if not (packet.get("instance") or {}).get("verified"):
        return 11
    live = packet.get("live") or {}
    if not (live.get("preflight") or {}).get("passed"):
        return 12
    if not live.get("recruitment_ready"):
        return 13
    return 0


def strict_exit_code(packet: dict, *, receipt_written: bool) -> int:
    live_code = live_exit_code(packet)
    if live_code:
        return live_code
    if not receipt_written:
        return 14
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Orient an agent to SAB without mutating repository or live state."
    )
    parser.add_argument("--json", action="store_true", help="emit the machine-readable packet")
    parser.add_argument("--no-live", action="store_true", help="skip all network probes")
    parser.add_argument(
        "--strict-live",
        action="store_true",
        help="fail unless instance, live recruitment, and durable receipt gates pass",
    )
    parser.add_argument("--public-url", help="override SAB_PUBLIC_URL / instance manifest URL")
    parser.add_argument("--instance-manifest", type=Path, help="override SAB_INSTANCE_MANIFEST")
    parser.add_argument(
        "--write-receipt",
        type=Path,
        help="explicitly persist a private hash-bound preflight receipt",
    )
    args = parser.parse_args()
    packet = build_packet(
        REPO_ROOT,
        probe_live=not args.no_live,
        public_url=args.public_url,
        instance_manifest_path=args.instance_manifest,
    )
    receipt_written = False
    receipt_write_failed = False
    if args.write_receipt:
        try:
            write_orientation_receipt(packet, args.write_receipt)
            receipt_written = True
        except (OSError, ValueError) as exc:
            receipt_write_failed = True
            packet["receipt_write"] = {
                "written": False,
                "error": type(exc).__name__,
            }
    if args.json:
        print(json.dumps(packet, indent=2, sort_keys=True))
    else:
        print(render_human(packet), end="")
    if receipt_write_failed:
        return 15
    if args.strict_live:
        return strict_exit_code(packet, receipt_written=receipt_written)
    if not args.no_live:
        return live_exit_code(packet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
