#!/usr/bin/env python3
"""Check a non-editable wheel from an unrelated directory, using runtime deps only.

Run with the installed environment's ``python -I -B``. Canonical source files
are read only for byte comparison; this script never adds them to sys.path.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, wheel, output = (path.resolve() for path in (args.source, args.wheel, args.output))
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise RuntimeError("run with an installed interpreter's python -I -B")
    if Path.cwd().is_relative_to(source):
        raise RuntimeError("run from outside the source checkout")
    output.mkdir(mode=0o700)
    for name in list(os.environ):
        if name.startswith("SAB_") or name in {"PYTHONPATH", "PYTHONHOME"}:
            del os.environ[name]
    private = output / "must-stay-absent"
    os.environ.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "SAB_PUBLIC_MODE": "public_readonly",
            "SAB_SPARK_DB_PATH": str(private / "spark.sqlite3"),
            "SAB_AUTHORITY_DB_PATH": str(private / "authority.sqlite3"),
            "SAB_SYSTEM_WITNESS_KEY": str(private / "signing.key"),
            "SAB_SEED_CLAIMS_PATH": str(private / "claims.json"),
        }
    )

    import agora

    package = Path(agora.__file__).resolve().parent
    if not package.is_relative_to(Path(sys.prefix).resolve()) or package.is_relative_to(source):
        raise RuntimeError("agora was not imported from the installed environment")
    before = {
        str(path.relative_to(package)): digest(path.read_bytes())
        for path in package.rglob("*")
        if path.is_file()
    }
    metadata = importlib.metadata.distribution("dharmic-agora")
    verified_files = 0
    public_data = {
        *(
            f"agora/_public_resources/docs/{name}.md"
            for name in ("skill", "seed", "auth", "heartbeat", "rules")
        ),
        *(
            f"agora/_public_resources/schemas/sab.{name}.v1.schema.json"
            for name in (
                "seed_packet",
                "claim_dossier",
                "public_snapshot",
                "public_read_observation",
            )
        ),
        *(
            f"agora/static/{name}"
            for name in (
                "web.css",
                "seed_fusion.css",
                "frontier.css",
                "reliance.css",
                "dossier.css",
                "web.js",
                "favicon.svg",
            )
        ),
    }
    metadata_files = {
        "METADATA",
        "WHEEL",
        "RECORD",
        "entry_points.txt",
        "top_level.txt",
        "licenses/LICENSE",
        "LICENSE",
    }
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            root, _, relative = name.partition("/")
            allowed = (
                (root in {"agora", "connectors"} and name.endswith(".py"))
                or (name.startswith("agora/templates/") and name.endswith(".html"))
                or name in public_data
                or (
                    root == f"dharmic_agora-{metadata.version}.dist-info"
                    and relative in metadata_files
                )
            )
            if not allowed or ".." in Path(name).parts:
                raise RuntimeError(f"unexpected wheel member: {name}")
            if name.startswith(("agora/", "connectors/")):
                if Path(metadata.locate_file(name)).read_bytes() != archive.read(name):
                    raise RuntimeError(f"installed file does not match wheel: {name}")
                verified_files += 1

    from fastapi.testclient import TestClient
    from agora.app import app

    resources = {
        f"/{name}.md": source / "site" / f"{name}.md"
        for name in ("skill", "seed", "auth", "heartbeat", "rules")
    }
    resources.update(
        {
            f"/schemas/sab.{name}.v1.schema.json": source
            / "nodes"
            / "schemas"
            / f"sab.{name}.v1.schema.json"
            for name in (
                "seed_packet",
                "claim_dossier",
                "public_snapshot",
                "public_read_observation",
            )
        }
    )
    resources.update(
        {
            f"/static/{name}": source / "agora" / "static" / name
            for name in (
                "web.css",
                "seed_fusion.css",
                "frontier.css",
                "reliance.css",
                "dossier.css",
                "web.js",
                "favicon.svg",
            )
        }
    )
    served = {}
    with TestClient(app) as client:

        def read(path: str, expected: int = 200):
            response = client.get(path, follow_redirects=False)
            if response.status_code != expected:
                raise RuntimeError(f"{path}: expected {expected}, got {response.status_code}")
            if (
                response.headers.get("cache-control") != "no-store"
                or "set-cookie" in response.headers
            ):
                raise RuntimeError(f"{path}: public caching/cookie contract failed")
            if path not in {"/api/feed", "/api/cache/stats", "/api/v1/agents/me/home"} and (
                response.headers.get("sab-currentness") != "unestablished"
                or response.headers.get("sab-publication-age-status") != "not_configured"
            ):
                raise RuntimeError(
                    f"{path}: empty installation freshness headers are missing or invalid"
                )
            return response

        for path in (
            "/",
            "/claims",
            "/about",
            "/status",
            "/health",
            "/readyz",
            "/openapi.json",
            "/.well-known/sab-standing.json",
            "/schemas/index.json",
        ):
            read(path)
        for path, canonical in resources.items():
            content = read(path).content
            if content != canonical.read_bytes():
                raise RuntimeError(f"{path}: served bytes differ from canonical source")
            served[path] = digest(content)
        publication = read("/publication").json()
        if publication["configured"] or publication["status"] != "not_configured":
            raise RuntimeError("unconfigured installation inferred a publication")
        observation = publication["publication_observation"]
        if (
            observation["schema"] != "sab.public_read_observation.v1"
            or observation["currentness"]["status"] != "unestablished"
            or observation["clock"]["externally_verified"] is not False
            or observation["historical_integrity"] != "not_configured"
            or observation["local_age_policy"]["status"] != "not_configured"
        ):
            raise RuntimeError("unconfigured installation inferred integrity or currentness")
        readiness = read("/readyz").json()
        if (
            readiness["readiness_scope"] != "historical_inspection"
            or readiness["current_use_eligible"] is not False
        ):
            raise RuntimeError("historical readiness inferred current-use eligibility")
        if read("/api/v1/claims").json()["total"] != 0:
            raise RuntimeError("unconfigured installation exposed claims")
        read("/publication/manifest", 404)
        read("/claims/absent", 404)
        for path in ("/api/feed", "/api/cache/stats", "/api/v1/agents/me/home"):
            if read(path, 404).json().get("code") != "not_published":
                raise RuntimeError("an unapproved route reached the application")
        rejection = client.post("/api/v1/seeds", content=b"not-json")
        if rejection.status_code != 403 or rejection.json().get("code") != "public_readonly":
            raise RuntimeError("installed public app accepted a write")

    entrypoints = {entry.name: entry.value for entry in metadata.entry_points}
    for command, target in {
        "agora-public-snapshot": "agora.public_snapshot_cli:main",
        "agora-public-inspect": "agora.public_inspection:main",
    }.items():
        if entrypoints.get(command) != target:
            raise RuntimeError(f"missing installed command: {command}")
        subprocess.run(
            [str(Path(sys.executable).parent / command), "--help"],
            check=True,
            capture_output=True,
            timeout=15,
        )
    empty = subprocess.run(
        [
            str(Path(sys.executable).parent / "agora-public-snapshot"),
            "empty",
            "--bundle",
            str(output / "offline-empty"),
            "--observed-at",
            "2026-01-01T00:00:00Z",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if json.loads(empty.stdout)["seed_count"] != 0:
        raise RuntimeError("offline empty command unexpectedly published claims")
    after = {
        str(path.relative_to(package)): digest(path.read_bytes())
        for path in package.rglob("*")
        if path.is_file()
    }
    if before != after or private.exists():
        raise RuntimeError("installed public inspection wrote package or private runtime files")
    receipt = {
        "status": "passed",
        "python": sys.version.split()[0],
        "wheel_sha256": digest(wheel.read_bytes()),
        "wheel_files_verified": verified_files,
        "canonical_resources": served,
        "runtime_dependencies_only": True,
        "package_unchanged": True,
        "private_runtime_paths_absent": True,
        "publication_observation": observation,
        "scope": "Non-editable installed wheel, empty public app and offline CLI",
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
