#!/usr/bin/env python3
"""Exercise the deployed public inspection contract, including an empty store.

This is a transport/discovery smoke check, not a claim or standing verifier.
It sends an invalid mutation body only after verifying public read-only mode.
"""
from __future__ import annotations

import argparse
import json
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def inspect(origin: str) -> dict:
    origin = origin.rstrip("/")
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username is not None:
        raise ValueError("origin must be an HTTP(S) origin without credentials")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("origin must not include a path, query, or fragment")
    checked = []

    def read(path: str, *, method: str = "GET", expected: int = 200):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("discovery links must stay on the inspected origin")
        request = Request(origin + path, method=method, data=b"not-json" if method == "POST" else None)
        try:
            # Only HTTP(S) origins without credentials reach this request.
            response = urlopen(request, timeout=10)  # nosec B310
        except HTTPError as error:
            response = error
        with response:
            body = response.read()
            if response.status != expected:
                raise RuntimeError(f"{method} {path}: expected {expected}, got {response.status}")
            if response.headers.get("Set-Cookie"):
                raise RuntimeError(f"{path}: public inspection created a cookie")
            checked.append({"method": method, "path": path, "status": response.status})
            return body

    descriptor = json.loads(read("/.well-known/sab-standing.json"))
    if descriptor.get("runtime_mode") != "public_readonly" or descriptor.get("public_mutation_enabled") is not False:
        raise RuntimeError("instance does not advertise public read-only mode")
    for name in ("home", "claims", "skill", "rules", "openapi", "standing"):
        read(descriptor["links"][name])
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
    return {"public_readonly": True, "checked": checked, "claim_count": ledger["total"],
            "populated_dossier_exercised": bool(ledger["items"]),
            "verification_scope": "Public HTTP discovery, resources, and write boundary only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin")
    args = parser.parse_args()
    print(json.dumps(inspect(args.origin), indent=2))


if __name__ == "__main__":
    main()
