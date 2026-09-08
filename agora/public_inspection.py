#!/usr/bin/env python3
"""Exercise the deployed public inspection contract, including an empty store.

This is a transport/discovery smoke check, not a claim or standing verifier.
It sends an invalid mutation body only after verifying public read-only mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A discovered resource must answer at the inspected origin. Never send
        # the probe body or follow resource links to another service.
        return None


def inspect(origin: str, *, expected_manifest_sha256: str | None = None) -> dict:
    origin = origin.rstrip("/")
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username is not None:
        raise ValueError("origin must be an HTTP(S) origin without credentials")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("origin must not include a path, query, or fragment")
    if expected_manifest_sha256 is not None and (
        len(expected_manifest_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_manifest_sha256)
    ):
        raise ValueError("expected manifest pin must be a lowercase SHA-256 digest")
    checked = []
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
            checked.append({"method": method, "path": path, "status": response.status})
            return body

    descriptor = json.loads(read("/.well-known/sab-standing.json"))
    if (
        descriptor.get("runtime_mode") != "public_readonly"
        or descriptor.get("public_mutation_enabled") is not False
    ):
        raise RuntimeError("instance does not advertise public read-only mode")
    for name in ("home", "claims", "skill", "rules", "openapi", "standing"):
        read(descriptor["links"][name])
    publication = json.loads(read(descriptor["links"]["publication"]))
    if expected_manifest_sha256 is not None and (
        not publication["configured"]
        or publication.get("manifest_sha256") != expected_manifest_sha256
    ):
        raise RuntimeError("publication does not match the independently expected manifest pin")
    if publication["configured"]:
        manifest_bytes = read(descriptor["links"]["publication_manifest"])
        manifest = json.loads(manifest_bytes)
        if hashlib.sha256(manifest_bytes).hexdigest() != publication["manifest_sha256"]:
            raise RuntimeError("served manifest bytes do not match the advertised publication pin")
        if manifest.get("schema") != "sab.public_snapshot.v1":
            raise RuntimeError("unexpected publication manifest schema")
    else:
        read(descriptor["links"]["publication_manifest"], expected=404)
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
    readiness = json.loads(read("/readyz"))
    if "db_path" in readiness:
        raise RuntimeError("public readiness disclosed a private database path")
    for path in ("/api/feed", "/api/v1/agents/me/home", "/api/cache/stats"):
        unpublished = json.loads(read(path, expected=404))
        if unpublished.get("code") != "not_published":
            raise RuntimeError("an unapproved read route reached the application")
    ledger = json.loads(read(descriptor["links"]["claim_ledger"]))
    schemas = json.loads(read(descriptor["links"]["schemas"]))
    for item in schemas["schemas"]:
        document = json.loads(read(item["url"]))
        if document["properties"]["schema"]["const"] != item["schema"]:
            raise RuntimeError(f"schema identity mismatch: {item['url']}")
    if ledger["items"]:
        item = ledger["items"][0]
        dossier = json.loads(read(item["links"]["dossier"]))
        read(dossier["links"]["html"])
        if dossier["identity"]["seed_id"] != item["seed_id"]:
            raise RuntimeError("ledger and dossier identify different submitted seeds")
    rejection = json.loads(read("/api/v1/seeds", method="POST", expected=403))
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
        "verification_scope": "Public HTTP discovery, resources, and write boundary only",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin")
    parser.add_argument(
        "--expected-manifest-sha256",
        help="independently retained approved manifest pin; required for a publication acceptance check",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            inspect(args.origin, expected_manifest_sha256=args.expected_manifest_sha256), indent=2
        )
    )


if __name__ == "__main__":
    main()
