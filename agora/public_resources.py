"""Read the exact allowlisted public resources without extraction or runtime writes.

Wheels carry documents and schemas staged from their canonical source files.
An unpackaged checkout (including the explicit Docker source layout) may read
those canonical files only beneath this module's own marked source root.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

DOCUMENT_SOURCES = {
    name: ("site", name) for name in ("skill.md", "seed.md", "auth.md", "heartbeat.md", "rules.md")
}
SCHEMA_SOURCES = {
    name: ("nodes", "schemas", name)
    for name in (
        "sab.seed_packet.v1.schema.json",
        "sab.claim_dossier.v1.schema.json",
        "sab.public_snapshot.v1.schema.json",
        "sab.public_read_observation.v1.schema.json",
        "sab.authority_policy.v1.schema.json",
        "sab.authority_lease.v2.schema.json",
        "sab.authority_issuance_witness.v1.schema.json",
        "sab.authority_revocation.v1.schema.json",
    )
}
STATIC_MEDIA_TYPES = {
    "web.css": "text/css",
    "seed_fusion.css": "text/css",
    "frontier.css": "text/css",
    "reliance.css": "text/css",
    "dossier.css": "text/css",
    "web.js": "text/javascript",
    "favicon.svg": "image/svg+xml",
}
STAGED_RESOURCES = {
    **{("docs", name): source for name, source in DOCUMENT_SOURCES.items()},
    **{("schemas", name): source for name, source in SCHEMA_SOURCES.items()},
}


class PublicResourceError(FileNotFoundError):
    """An advertised resource is absent or a resource name is not allowlisted."""


def _checkout_root() -> Path | None:
    module = Path(__file__).resolve()
    root = module.parent.parent
    if (
        module == root / "agora" / "public_resources.py"
        and (root / "pyproject.toml").is_file()
        and (root / "_build_public_resources.py").is_file()
    ):
        return root
    return None


def read_public_resource(group: str, name: str) -> bytes:
    """Read only an advertised document/schema; never search the working directory."""
    source = STAGED_RESOURCES.get((group, name))
    if source is None:
        raise PublicResourceError("The requested public resource is not allowlisted.")
    staged = resources.files("agora").joinpath("_public_resources")
    try:
        return staged.joinpath(group, name).read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        # A partial packaged resource tree is a broken artifact, never a reason
        # to substitute source files that happen to exist beside it.
        if staged.is_dir():
            raise PublicResourceError("The packaged public resource is missing.") from None
    root = _checkout_root()
    if root is not None:
        path = root.joinpath(*source)
        if path.resolve().is_relative_to(root):
            try:
                return path.read_bytes()
            except (FileNotFoundError, NotADirectoryError):
                pass
    raise PublicResourceError("The public resource is unavailable in this distribution.")


def read_public_static(name: str) -> bytes:
    """Read one fixed package asset, with no checkout or filesystem fallback."""
    if name not in STATIC_MEDIA_TYPES:
        raise PublicResourceError("The requested static resource is not allowlisted.")
    try:
        return resources.files("agora").joinpath("static", name).read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        raise PublicResourceError("The packaged static resource is missing.") from None
