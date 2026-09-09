#!/usr/bin/env python3
"""Exercise the deployed public inspection contract, including an empty store.

This is a transport/discovery smoke check, not a claim or standing verifier.
It sends an invalid mutation body only after verifying public read-only mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


OBSERVATION_SCHEMA = "sab.public_read_observation.v1"
AGE_STATUSES = {"not_configured", "within_limit", "stale", "future_observation", "clock_uncertain"}
_UNDISCRIMINATED_SCHEMAS = {
    "sab.operator_control_review.v1": {
        "reviewer_subject_id", "reviewer_public_key", "assessment_sha256", "observed_at", "findings", "signature",
    },
    "sab.operator_cohort_issuance.v1": {"assessment", "reviews"},
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: object, label: str) -> datetime:
    try:
        if not isinstance(value, str):
            raise ValueError("timestamp is not text")
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError("timezone is required")
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RuntimeError(f"{label}: an aware timestamp is required") from exc


def _object(value: object, label: str, keys: set[str] | None = None) -> dict:
    if not isinstance(value, dict) or (keys is not None and set(value) != keys):
        raise RuntimeError(f"{label}: unexpected observation shape")
    return value


def _json_object(raw: bytes, label: str) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("non-JSON number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RuntimeError(f"{label}: invalid JSON document") from exc
    return _object(value, label)


def _observation(value: object, headers: dict, path: str) -> dict:
    """Validate the fixed v1 wire contract without trusting a remote schema as policy."""
    observation = _object(value, path, {
        "schema", "observed_at", "source_observed_at", "manifest_sha256", "policy", "clock",
        "local_age_policy", "currentness", "historical_integrity", "warnings",
        "authority_effect", "standing_effect",
    })
    if observation["schema"] != OBSERVATION_SCHEMA:
        raise RuntimeError(f"{path}: unexpected publication observation schema")
    _timestamp(observation["observed_at"], path)
    if observation["source_observed_at"] is not None:
        _timestamp(observation["source_observed_at"], path)
    pin = observation["manifest_sha256"]
    if pin is not None and (
        not isinstance(pin, str) or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin)
    ):
        raise RuntimeError(f"{path}: invalid observation manifest pin")
    policy = _object(observation["policy"], path, {
        "id", "maximum_age_seconds", "maximum_clock_skew_seconds", "sha256",
    })
    if policy["id"] != "sab.public_read_freshness.v1" or any(
        type(policy[key]) is not int or not low <= policy[key] <= high
        for key, low, high in (
            ("maximum_age_seconds", 1, 86400), ("maximum_clock_skew_seconds", 0, 60)
        )
    ):
        raise RuntimeError(f"{path}: invalid local age policy")
    policy_bytes = json.dumps(
        {key: value for key, value in policy.items() if key != "sha256"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    if policy["sha256"] != hashlib.sha256(policy_bytes).hexdigest():
        raise RuntimeError(f"{path}: local age policy digest mismatch")
    clock = _object(observation["clock"], path, {
        "source", "externally_verified", "status", "reasons", "effective_time_basis",
    })
    if (
        clock["source"] != "local_system_utc"
        or clock["externally_verified"] is not False
        or clock["status"] not in ("stable", "uncertain")
        or not isinstance(clock["reasons"], list)
        or not all(isinstance(reason, str) for reason in clock["reasons"])
        or not isinstance(clock["effective_time_basis"], str)
        or not clock["effective_time_basis"]
    ):
        raise RuntimeError(f"{path}: unsupported clock observation or claimed clock authority")
    currentness = _object(observation["currentness"], path, {"status", "reasons"})
    if (
        currentness["status"] != "unestablished"
        or currentness["reasons"] != ["trusted_utc_unverified", "revocation_currentness_unverified",
                                      "operator_control_currentness_unverified"]
        or observation["authority_effect"] != "none"
        or observation["standing_effect"] != "none"
    ):
        raise RuntimeError(f"{path}: observation claims currentness, authority, or standing")
    age = _object(observation["local_age_policy"], path, {
        "status", "age_seconds", "remaining_seconds",
    })
    if not isinstance(age["status"], str) or age["status"] not in AGE_STATUSES:
        raise RuntimeError(f"{path}: unsupported publication age status")
    for key in ("age_seconds", "remaining_seconds"):
        number = age[key]
        try:
            valid = number is None or (
                type(number) in (int, float) and math.isfinite(number) and number >= 0
            )
        except OverflowError:
            valid = False
        if not valid:
            raise RuntimeError(f"{path}: invalid publication age")
    if age["age_seconds"] is None:
        if age["status"] != "not_configured" or age["remaining_seconds"] is not None:
            raise RuntimeError(f"{path}: incomplete publication age")
    else:
        remaining = max(0, policy["maximum_age_seconds"] - age["age_seconds"])
        if age["remaining_seconds"] != remaining:
            raise RuntimeError(f"{path}: inconsistent remaining publication age")
        if (
            age["status"] == "within_limit" and age["age_seconds"] >= policy["maximum_age_seconds"]
        ) or (age["status"] == "stale" and age["age_seconds"] < policy["maximum_age_seconds"]):
            raise RuntimeError(f"{path}: inconsistent publication age boundary")
    if (
        observation["historical_integrity"] not in ("validated", "not_configured")
        or not isinstance(observation["warnings"], list)
        or not observation["warnings"]
        or not all(isinstance(warning, str) for warning in observation["warnings"])
    ):
        raise RuntimeError(f"{path}: missing historical inspection limitations")
    configured = pin is not None
    if (
        (observation["source_observed_at"] is not None) != configured
        or (age["age_seconds"] is not None) != configured
        or (age["status"] != "not_configured") != configured
        or (observation["historical_integrity"] == "validated") != configured
        or (configured and clock["status"] == "uncertain" and age["status"] != "clock_uncertain")
        or (age["status"] == "clock_uncertain" and clock["status"] != "uncertain")
    ):
        raise RuntimeError(f"{path}: inconsistent publication observation state")
    expected_headers = {
        "sab-publication-age-status": age["status"],
        "sab-clock-state": clock["status"],
        "sab-currentness": "unestablished",
    }
    if any(headers.get(name) != expected for name, expected in expected_headers.items()):
        raise RuntimeError(f"{path}: publication observation headers disagree with the body")
    return observation


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A discovered resource must answer at the inspected origin. Never send
        # the probe body or follow resource links to another service.
        return None


def inspect(
    origin: str, *, expected_manifest_sha256: str | None = None,
    max_snapshot_age_seconds: int | None = None,
) -> dict:
    origin = origin.rstrip("/")
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username is not None:
        raise ValueError("origin must be an HTTP(S) origin without credentials")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("origin must not include a path, query, or fragment")
    if expected_manifest_sha256 is not None and (
        not isinstance(expected_manifest_sha256, str)
        or len(expected_manifest_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_manifest_sha256)
    ):
        raise ValueError("expected manifest pin must be a lowercase SHA-256 digest")
    if max_snapshot_age_seconds is not None and (
        type(max_snapshot_age_seconds) is not int or not 1 <= max_snapshot_age_seconds <= 86400
    ):
        raise ValueError("maximum snapshot age must be an integer from 1 through 86400 seconds")
    if max_snapshot_age_seconds is not None and expected_manifest_sha256 is None:
        raise ValueError("client age admission requires an independently expected manifest pin")
    client_now = None
    if max_snapshot_age_seconds is not None:
        sample = _utc_now()
        if not isinstance(sample, datetime) or sample.tzinfo is None or sample.utcoffset() is None:
            raise ValueError("client age admission requires one aware local UTC clock sample")
        client_now = sample.astimezone(timezone.utc)
    checked = []
    observations = {}
    response_headers = {}
    opener = build_opener(_NoRedirect())

    def read(path: str, *, method: str = "GET", expected: int = 200):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("discovery links must stay on the inspected origin")
        request = Request(
            origin + path, method=method, data=b"not-json" if method == "POST" else None
        )
        try:
            # Only HTTP(S) origins without credentials reach this request.
            response = opener.open(request, timeout=10)  # nosec B310
        except HTTPError as error:
            response = error
        with response:
            body = response.read()
            if response.status != expected:
                raise RuntimeError(f"{method} {path}: expected {expected}, got {response.status}")
            if response.headers.get("Set-Cookie"):
                raise RuntimeError(f"{path}: public inspection created a cookie")
            if response.headers.get("Cache-Control") != "no-store":
                raise RuntimeError(f"{path}: public response is cacheable")
            response_headers[path] = {key.lower(): value for key, value in response.headers.items()}
            checked.append({"method": method, "path": path, "status": response.status})
            return body

    def document(path):
        return _json_object(read(path), path)

    def observe(label, envelope, path):
        observation = _observation(
            envelope.get("publication_observation"), response_headers[path], path
        )
        if "configured" in envelope and (
            envelope.get("manifest_sha256") != observation["manifest_sha256"]
            or envelope.get("observed_at") != observation["source_observed_at"]
        ):
            raise RuntimeError(f"{path}: publication metadata disagrees with its observation")
        if envelope.get("schema") == "sab.claim_dossier.v1" and (
            envelope.get("observed_at") != observation["observed_at"]
        ):
            raise RuntimeError(f"{path}: dossier time disagrees with its observation")
        observations[label] = observation

    descriptor = document("/.well-known/sab-standing.json")
    if (
        descriptor.get("runtime_mode") != "public_readonly"
        or descriptor.get("public_mutation_enabled") is not False
        or descriptor.get("authority_effect") != "none"
        or descriptor.get("standing_effect") != "none"
    ):
        raise RuntimeError("instance does not advertise public read-only mode")
    for name in ("home", "claims", "skill", "rules", "openapi", "standing", "status"):
        read(descriptor["links"][name])
    observation_schema_path = descriptor["links"]["publication_observation_schema"]
    observation_schema = document(observation_schema_path)
    if observation_schema.get("properties", {}).get("schema", {}).get("const") != OBSERVATION_SCHEMA:
        raise RuntimeError("discovered publication observation schema has the wrong identity")
    publication_path = descriptor["links"]["publication"]
    publication = document(publication_path)
    observe("publication", publication, publication_path)
    if type(publication.get("configured")) is not bool:
        raise RuntimeError("publication configuration is not explicit")
    if expected_manifest_sha256 is not None and (
        not publication["configured"]
        or publication.get("manifest_sha256") != expected_manifest_sha256
    ):
        raise RuntimeError("publication does not match the independently expected manifest pin")
    if publication["configured"]:
        manifest_bytes = read(descriptor["links"]["publication_manifest"])
        manifest = _json_object(manifest_bytes, "publication manifest")
        if hashlib.sha256(manifest_bytes).hexdigest() != publication["manifest_sha256"]:
            raise RuntimeError("served manifest bytes do not match the advertised publication pin")
        if manifest.get("schema") != "sab.public_snapshot.v1":
            raise RuntimeError("unexpected publication manifest schema")
        source_observed_at = manifest.get("observed_at")
        source_time = _timestamp(source_observed_at, "publication manifest")
    else:
        read(descriptor["links"]["publication_manifest"], expected=404)
        source_observed_at = None
    client_age_admission = {"requested": max_snapshot_age_seconds is not None, "status": "not_requested"}
    if client_now is not None:
        age = (client_now - source_time).total_seconds()
        if age < -5:
            raise RuntimeError("publication observation is more than 5 seconds ahead of the client clock")
        if age >= max_snapshot_age_seconds:
            raise RuntimeError("publication has reached the independently requested maximum snapshot age")
        client_age_admission = {
            "requested": True,
            "status": "within_limit",
            "maximum_age_seconds": max_snapshot_age_seconds,
            "maximum_future_skew_seconds": 5,
            "observed_at": client_now.isoformat(),
            "source_observed_at": source_observed_at,
            "age_seconds": max(0.0, age),
            "clock": {"source": "client_local_system_utc", "externally_verified": False},
            "currentness": "unestablished",
            "authority_effect": "none",
        }
    for name in ("seed.md", "auth.md", "heartbeat.md"):
        read("/" + name)
    for name in (
        "web.css",
        "seed_fusion.css",
        "frontier.css",
        "reliance.css",
        "dossier.css",
        "web.js",
        "favicon.svg",
    ):
        read("/static/" + name)
    readiness = document("/readyz")
    if "db_path" in readiness:
        raise RuntimeError("public readiness disclosed a private database path")
    if readiness.get("readiness_scope") != "historical_inspection" or readiness.get("current_use_eligible") is not False:
        raise RuntimeError("readiness claims eligibility beyond historical inspection")
    observe("readiness", _object(readiness.get("publication"), "/readyz"), "/readyz")
    if readiness.get("timestamp") != observations["readiness"]["observed_at"]:
        raise RuntimeError("/readyz: readiness time disagrees with its observation")
    for path in ("/api/feed", "/api/v1/agents/me/home", "/api/cache/stats"):
        unpublished = _json_object(read(path, expected=404), path)
        if unpublished.get("code") != "not_published":
            raise RuntimeError("an unapproved read route reached the application")
    ledger_path = descriptor["links"]["claim_ledger"]
    ledger = document(ledger_path)
    observe("ledger", ledger, ledger_path)
    schemas = document(descriptor["links"]["schemas"])
    for item in schemas["schemas"]:
        item = _object(item, "schema discovery", {"schema", "url"})
        name = item["schema"]
        if not isinstance(name, str) or item["url"] != "/schemas/" + name + ".schema.json":
            raise RuntimeError("schema identity or envelope mismatch")
        schema_document = document(item["url"])
        properties = _object(schema_document.get("properties"), item["url"])
        if schema_document.get("$id") != "https://sab.local" + item["url"]:
            raise RuntimeError("schema identity or envelope mismatch")
        if name in _UNDISCRIMINATED_SCHEMAS:
            # Exact signed envelopes have no extra instance discriminator.
            required = schema_document.get("required")
            if (schema_document.get("additionalProperties") is not False
                    or set(properties) != _UNDISCRIMINATED_SCHEMAS[name]
                    or not isinstance(required, list) or any(not isinstance(field, str) for field in required)
                    or len(required) != len(set(required))
                    or set(required) != _UNDISCRIMINATED_SCHEMAS[name]):
                raise RuntimeError("schema identity or envelope mismatch")
        elif _object(properties.get("schema"), item["url"]).get("const") != name:
            raise RuntimeError("schema identity or envelope mismatch")
    if ledger["items"]:
        item = ledger["items"][0]
        dossier_path = item["links"]["dossier"]
        dossier = document(dossier_path)
        observe("dossier", dossier, dossier_path)
        read(dossier["links"]["html"])
        if dossier["identity"]["seed_id"] != item["seed_id"]:
            raise RuntimeError("ledger and dossier identify different submitted seeds")
        if (
            dossier.get("authority_effect") != "none" or dossier.get("standing_effect") != "none"
            or dossier.get("reliance", {}).get("status") != "unestablished"
        ):
            raise RuntimeError("dossier inspection claims authority, standing, or reliance")
        standing_items = _object(dossier.get("standing"), "dossier standing").get("items")
        if not isinstance(standing_items, list):
            raise RuntimeError("historical dossier has no standing observation collection")
        for standing in standing_items:
            standing = _object(standing, "dossier standing")
            if (not isinstance(standing.get("status"), str)
                    or standing["status"] not in {"unknown", "revoked", "expired", "compost", "superseded"}
                    or "stored_status" not in standing or standing.get("reliance_status") != "unestablished"
                    or standing.get("operator_control_eligible", False) is not False
                    or standing.get("current_standing_eligible", False) is not False):
                raise RuntimeError("historical dossier claims current standing or operator-control eligibility")
    for label, observation in observations.items():
        if (
            observation["manifest_sha256"] != publication["manifest_sha256"]
            or observation["source_observed_at"] != source_observed_at
            or observation["historical_integrity"] != ("validated" if publication["configured"] else "not_configured")
        ):
            raise RuntimeError(f"{label}: observation is not bound to the pinned publication")
    rejection = _json_object(read("/api/v1/seeds", method="POST", expected=403), "mutation rejection")
    if rejection.get("code") != "public_readonly":
        raise RuntimeError("unexpected public mutation error contract")
    return {
        "public_readonly": True,
        "checked": checked,
        "claim_count": ledger["total"],
        "publication": publication,
        "expected_manifest_sha256": expected_manifest_sha256,
        "independent_pin_checked": expected_manifest_sha256 is not None,
        "populated_dossier_exercised": bool(ledger["items"]),
        "publication_observations": observations,
        "client_age_admission": client_age_admission,
        "currentness": "unestablished",
        "authority_effect": "none",
        "standing_effect": "none",
        "authorizes_use": False,
        "verification_scope": "Public HTTP discovery, resources, observation consistency, and write boundary; never authority to use",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin")
    parser.add_argument(
        "--expected-manifest-sha256",
        help="independently retained approved manifest pin; required for a publication acceptance check",
    )
    parser.add_argument(
        "--max-snapshot-age-seconds", type=int,
        help="independent client local age limit, 1..86400 seconds; requires an expected manifest pin",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            inspect(
                args.origin, expected_manifest_sha256=args.expected_manifest_sha256,
                max_snapshot_age_seconds=args.max_snapshot_age_seconds,
            ), indent=2
        )
    )


if __name__ == "__main__":
    main()
