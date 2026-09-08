from __future__ import annotations

import importlib
import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = ("skill.md", "seed.md", "auth.md", "heartbeat.md", "rules.md")
SCHEMAS = (
    "sab.seed_packet.v1.schema.json",
    "sab.claim_dossier.v1.schema.json",
    "sab.public_snapshot.v1.schema.json",
    "sab.public_read_observation.v1.schema.json",
    "sab.authority_policy.v1.schema.json",
    "sab.authority_lease.v2.schema.json",
    "sab.authority_issuance_witness.v1.schema.json",
    "sab.authority_revocation.v1.schema.json",
)
STATIC = (
    "web.css",
    "seed_fusion.css",
    "frontier.css",
    "reliance.css",
    "dossier.css",
    "web.js",
    "favicon.svg",
)


@pytest.fixture
def reader():
    return importlib.import_module("agora.public_resources")


def test_source_resource_bytes_are_canonical_and_independent_of_cwd(reader, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "skill.md").write_bytes(b"unrelated working-directory resource")
    for name in DOCUMENTS:
        assert reader.read_public_resource("docs", name) == (REPO_ROOT / "site" / name).read_bytes()
    for name in SCHEMAS:
        assert (
            reader.read_public_resource("schemas", name)
            == (REPO_ROOT / "nodes" / "schemas" / name).read_bytes()
        )
    for name in STATIC:
        assert (
            reader.read_public_static(name) == (REPO_ROOT / "agora" / "static" / name).read_bytes()
        )


def test_packaged_resource_bytes_take_precedence_without_extraction(reader, monkeypatch):
    archive_bytes = io.BytesIO()
    expected = {}
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        for (group, name), source in reader.STAGED_RESOURCES.items():
            content = (REPO_ROOT.joinpath(*source)).read_bytes()
            expected[group, name] = content
            archive.writestr(f"agora/_public_resources/{group}/{name}", content)
        for name in STATIC:
            archive.writestr(
                f"agora/static/{name}", (REPO_ROOT / "agora" / "static" / name).read_bytes()
            )
    archive_bytes.seek(0)
    with zipfile.ZipFile(archive_bytes) as archive:
        package = zipfile.Path(archive, "agora/")
        monkeypatch.setattr(reader.resources, "files", lambda name: package)
        monkeypatch.setattr(
            reader.resources, "as_file", lambda *args: pytest.fail("resource extraction")
        )
        monkeypatch.setattr(
            reader, "_checkout_root", lambda: pytest.fail("packaged checkout fallback")
        )
        for (group, name), content in expected.items():
            assert reader.read_public_resource(group, name) == content
        for name in STATIC:
            assert (
                reader.read_public_static(name)
                == (REPO_ROOT / "agora" / "static" / name).read_bytes()
            )


@pytest.mark.parametrize(
    "group,name",
    [
        ("docs", "../README.md"),
        ("docs", "standing.md"),
        ("schemas", "../../README.md"),
        ("schemas", "sab.agent_identity.v1.schema.json"),
        ("site", "skill.md"),
    ],
)
def test_unadvertised_documents_never_access_resources(reader, monkeypatch, group, name):
    monkeypatch.setattr(reader.resources, "files", lambda *args: pytest.fail("unallowlisted read"))
    with pytest.raises(reader.PublicResourceError, match="not allowlisted"):
        reader.read_public_resource(group, name)


@pytest.mark.parametrize(
    "name", ["../public_snapshot.py", "web.css/extra", "sab/sab.css", "unknown.css"]
)
def test_unadvertised_static_never_accesses_resources(reader, monkeypatch, name):
    monkeypatch.setattr(reader.resources, "files", lambda *args: pytest.fail("unallowlisted read"))
    with pytest.raises(reader.PublicResourceError, match="not allowlisted"):
        reader.read_public_static(name)


def test_partial_package_cannot_fall_back_to_checkout(reader, tmp_path, monkeypatch):
    package = tmp_path / "agora"
    (package / "_public_resources").mkdir(parents=True)
    monkeypatch.setattr(reader.resources, "files", lambda name: package)
    monkeypatch.setattr(reader, "_checkout_root", lambda: pytest.fail("partial package fallback"))
    with pytest.raises(reader.PublicResourceError, match="packaged public resource is missing"):
        reader.read_public_resource("docs", "skill.md")


def test_installed_package_cannot_read_sibling_or_cwd_source_files(reader, tmp_path, monkeypatch):
    package = tmp_path / "site-packages" / "agora"
    package.mkdir(parents=True)
    (package.parent / "site").mkdir()
    (package.parent / "site" / "skill.md").write_bytes(b"not in this distribution")
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "skill.md").write_bytes(b"unrelated cwd resource")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(reader, "__file__", str(package / "public_resources.py"))
    monkeypatch.setattr(reader.resources, "files", lambda name: package)
    assert reader._checkout_root() is None
    with pytest.raises(reader.PublicResourceError, match="unavailable in this distribution"):
        reader.read_public_resource("docs", "skill.md")


def test_source_requires_both_markers_and_never_uses_stale_schema(reader, tmp_path, monkeypatch):
    package = tmp_path / "agora"
    package.mkdir()
    monkeypatch.setattr(reader, "__file__", str(package / "public_resources.py"))
    monkeypatch.setattr(reader.resources, "files", lambda name: package)
    (tmp_path / "pyproject.toml").write_text("source marker")
    assert reader._checkout_root() is None
    (tmp_path / "_build_public_resources.py").write_text("build marker")
    assert reader._checkout_root() == tmp_path.resolve()
    stale = tmp_path / "site" / "schemas" / SCHEMAS[0]
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale noncanonical schema")
    with pytest.raises(reader.PublicResourceError):
        reader.read_public_resource("schemas", SCHEMAS[0])


def test_source_canonical_symlink_cannot_escape_marked_root(reader, tmp_path, monkeypatch):
    source = tmp_path / "source"
    package = source / "agora"
    package.mkdir(parents=True)
    (source / "pyproject.toml").write_text("source marker")
    (source / "_build_public_resources.py").write_text("build marker")
    (source / "site").mkdir()
    unrelated = tmp_path / "outside.md"
    unrelated.write_bytes(b"outside resource")
    (source / "site" / "skill.md").symlink_to(unrelated)
    monkeypatch.setattr(reader, "__file__", str(package / "public_resources.py"))
    monkeypatch.setattr(reader.resources, "files", lambda name: package)
    with pytest.raises(reader.PublicResourceError):
        reader.read_public_resource("docs", "skill.md")


def test_public_routes_return_exact_resource_bytes_without_runtime_writes(tmp_path, monkeypatch):
    from publication_fixtures import import_public_app

    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT", raising=False)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    monkeypatch.chdir(tmp_path)
    app = import_public_app(tmp_path, monkeypatch)
    # The router's former checkout-root path must no longer choose resources.
    monkeypatch.setattr(app, "REPO_ROOT", tmp_path / "not-a-checkout")
    with TestClient(app.app) as client:
        for name in DOCUMENTS:
            response = client.get("/" + name)
            assert response.status_code == 200
            assert response.content == (REPO_ROOT / "site" / name).read_bytes()
            assert response.headers["content-type"].startswith("text/markdown")
            assert response.headers["cache-control"] == "no-store"
        for name in SCHEMAS:
            response = client.get("/schemas/" + name)
            assert response.status_code == 200
            assert response.content == (REPO_ROOT / "nodes" / "schemas" / name).read_bytes()
            assert response.headers["content-type"] == "application/schema+json"
        for name in STATIC:
            response = client.get("/static/" + name)
            assert response.status_code == 200
            assert response.content == (REPO_ROOT / "agora" / "static" / name).read_bytes()
            assert response.headers["cache-control"] == "no-store"
            assert client.head("/static/" + name).status_code == 200
        for path in ("/", "/claims", "/about", "/frontier"):
            assert client.get(path).status_code == 200
        assert "evidence_url" in app.templates.env.filters
        assert "url_for" in app.templates.env.globals
    assert list(tmp_path.iterdir()) == []


def test_missing_allowed_resource_has_safe_404(tmp_path, monkeypatch):
    from publication_fixtures import import_public_app

    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT", raising=False)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    app = import_public_app(tmp_path, monkeypatch)

    def missing(*args):
        raise app.PublicResourceError("missing source path must not leak")

    monkeypatch.setattr(app, "read_public_resource", missing)
    monkeypatch.setattr(app, "read_public_static", missing)
    with TestClient(app.app) as client:
        for path in ("/skill.md", "/schemas/" + SCHEMAS[0], "/static/web.css"):
            response = client.get(path)
            assert response.status_code == 404
            assert "source path" not in response.text
